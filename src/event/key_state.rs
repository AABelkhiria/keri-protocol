//! Key state records.
//!
//! A key state record is one actor's summary of an identifier's log at its latest event: the
//! sequence number and SAID of that event, the current signing keys and threshold, the next-key
//! commitment, the witness set and threshold, the latest establishment event, and the delegator.
//! It travels as the `a` block of a `/ksn/{source}` reply, which is how witnesses and watchers
//! answer a `ksn` query, and it is what KERIA returns from its key-state endpoints.
//!
//! This ports keripy's `KeyStateRecord` (`src/keri/db/basing.py`), the `state` function that
//! builds and validates one (`src/keri/core/eventing.py`), and `diffState`
//! (`src/keri/app/watching.py`), which compares a reported record against the local one. The
//! pinned signify-ts reference only reads this shape from KERIA and never builds or checks it.
//!
//! [`KeyStateBuilder`] applies every check keripy's `state` applies, and [`KeyStateRecord::from_sad`]
//! applies the same checks to a record read from the wire, so a record of this type is always one
//! keripy would have been willing to build. [`compare`] is the comparison a validator makes before
//! it trusts or refuses what a witness or watcher reports.

use keri_cesr::crypto::digest::Digest;
use keri_cesr::crypto::verifier::VerificationKey;
use keri_cesr::number::CesrNumber;
use serde_json::Value;

use crate::event::config::ConfigurationTrait;
use crate::event::error::{EventError, bounded_label};
use crate::event::key_event::{
    check_distinct, check_next_threshold, check_signing_threshold, check_witness_threshold, default_next_threshold,
    default_signing_threshold, digests_value, keys_value, prefixes_value, sequence_value, textual_threshold,
    traits_value,
};
use crate::event::kind::EventKind;
use crate::event::timestamp::Timestamp;
use crate::prefix::IdentifierPrefix;
use crate::said::Said;
use crate::serialization::{Sad, SadValue};
use crate::threshold::SigningThreshold;

/// The field labels of a key state record, in protocol order.
pub const FIELD_LABELS: [&str; 17] = [
    "vn", "i", "s", "p", "d", "f", "dt", "et", "kt", "k", "nt", "n", "bt", "b", "c", "ee", "di",
];
/// The field labels of the latest-establishment block, in protocol order.
pub const ESTABLISHMENT_LABELS: [&str; 4] = ["s", "d", "br", "ba"];

/// The KERI protocol version every record here carries, written as `vn`.
const VERSION: [i64; 2] = [1, 0];

/// The latest establishment event a key state names, keripy's `StateEERecord`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LatestEstablishment {
    sequence_number: u128,
    said: Said,
    removed: Vec<IdentifierPrefix>,
    added: Vec<IdentifierPrefix>,
}

impl LatestEstablishment {
    /// Names the establishment event `said` at `sequence_number`, with no witness changes.
    #[must_use]
    pub const fn new(sequence_number: u128, said: Said) -> Self {
        Self {
            sequence_number,
            said,
            removed: Vec::new(),
            added: Vec::new(),
        }
    }

    /// Sets the witnesses that event removed (`br`).
    #[must_use]
    pub fn removed(mut self, removed: Vec<IdentifierPrefix>) -> Self {
        self.removed = removed;
        self
    }

    /// Sets the witnesses that event added (`ba`).
    #[must_use]
    pub fn added(mut self, added: Vec<IdentifierPrefix>) -> Self {
        self.added = added;
        self
    }

    /// Returns the establishment event's sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> u128 {
        self.sequence_number
    }

    /// Returns the establishment event's SAID.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Returns the witnesses it removed.
    #[must_use]
    pub fn witnesses_removed(&self) -> &[IdentifierPrefix] {
        &self.removed
    }

    /// Returns the witnesses it added.
    #[must_use]
    pub fn witnesses_added(&self) -> &[IdentifierPrefix] {
        &self.added
    }

    /// Applies keripy's checks: no duplicates in either list, and nothing both removed and added.
    fn check(&self) -> Result<(), EventError> {
        let removed = check_distinct(&self.removed, "br")?;
        let added = check_distinct(&self.added, "ba")?;
        if removed.iter().any(|prefix| added.contains(prefix)) {
            return Err(EventError::ConflictingWitnessLists {
                first: "br",
                second: "ba",
            });
        }
        Ok(())
    }

    fn to_sad(&self) -> Result<Sad, EventError> {
        let mut block = Sad::new();
        let mut insert = |label: &str, value: SadValue| -> Result<(), EventError> {
            block.insert(label.to_owned(), value).map_err(EventError::sad)
        };
        insert("s", sequence_value(self.sequence_number))?;
        insert("d", SadValue::Text(self.said.qb64().map_err(EventError::said)?))?;
        insert("br", prefixes_value(&self.removed)?)?;
        insert("ba", prefixes_value(&self.added)?)?;
        Ok(block)
    }

    fn from_sad(block: &Sad) -> Result<Self, EventError> {
        check_layout(block, &ESTABLISHMENT_LABELS, "s, d, br, ba")?;
        Ok(Self {
            sequence_number: hex_field(block, "s")?,
            said: said_field(block, "d")?,
            removed: prefix_list(block, "br")?,
            added: prefix_list(block, "ba")?,
        })
    }
}

/// One identifier's key state at its latest event, keripy's `KeyStateRecord`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyStateRecord {
    identifier: IdentifierPrefix,
    sequence_number: u128,
    prior: Option<Said>,
    said: Said,
    first_seen: u128,
    timestamp: Timestamp,
    latest_kind: EventKind,
    signing_threshold: SigningThreshold,
    keys: Vec<VerificationKey>,
    next_threshold: SigningThreshold,
    next_digests: Vec<Digest>,
    witness_threshold: u32,
    witnesses: Vec<IdentifierPrefix>,
    configuration: Vec<ConfigurationTrait>,
    establishment: LatestEstablishment,
    delegator: Option<IdentifierPrefix>,
}

impl KeyStateRecord {
    /// Reads a record from its field map, as it appears in a `/ksn` reply or a KERIA response.
    ///
    /// The map must carry exactly the seventeen fields in protocol order, and the values must pass
    /// the checks [`KeyStateBuilder::build`] applies.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::UnexpectedFieldLayout`] when the fields are not exactly the record's,
    /// [`EventError::UnexpectedFieldShape`] when a field holds the wrong shape or `vn` is not
    /// `[1, 0]`, the validation errors of [`KeyStateBuilder::build`], and layered prefix, SAID,
    /// key, digest, threshold, timestamp or CESR failures for malformed values.
    pub fn from_sad(record: &Sad) -> Result<Self, EventError> {
        check_layout(
            record,
            &FIELD_LABELS,
            "vn, i, s, p, d, f, dt, et, kt, k, nt, n, bt, b, c, ee, di",
        )?;
        let version: Vec<i64> = record
            .get("vn")
            .and_then(SadValue::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| match item {
                        SadValue::Integer(value) => Some(*value),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        if version != VERSION {
            return Err(EventError::UnexpectedFieldShape { label: "vn" });
        }

        let latest_kind = text_field(record, "et")?;
        let latest_kind = latest_kind
            .parse::<EventKind>()
            .map_err(|_| EventError::InvalidLatestEventKind {
                found: bounded_label(latest_kind),
            })?;
        let prior = match text_field(record, "p")? {
            "" => None,
            text => Some(Said::from_qb64(text).map_err(EventError::said)?),
        };
        let delegator = match text_field(record, "di")? {
            "" => None,
            text => Some(IdentifierPrefix::from_qb64(text).map_err(EventError::prefix)?),
        };
        let witness_threshold = u32::try_from(hex_field(record, "bt")?).map_err(|_| EventError::ValueOutOfRange {
            context: "witness threshold",
        })?;
        let establishment = record
            .get("ee")
            .and_then(SadValue::as_map)
            .ok_or(EventError::UnexpectedFieldShape { label: "ee" })
            .and_then(LatestEstablishment::from_sad)?;
        let configuration = text_list(record, "c")?
            .into_iter()
            .map(|text| {
                text.parse::<ConfigurationTrait>()
                    .map_err(|error| EventError::UnknownConfigurationTrait {
                        found: error.found().to_owned(),
                    })
            })
            .collect::<Result<_, _>>()?;

        let built = KeyStateBuilder {
            identifier: prefix_field(record, "i")?,
            sequence_number: hex_field(record, "s")?,
            prior,
            said: said_field(record, "d")?,
            first_seen: hex_field(record, "f")?,
            timestamp: Timestamp::parse(text_field(record, "dt")?).map_err(EventError::timestamp)?,
            latest_kind,
            signing_threshold: Some(threshold_field(record, "kt")?),
            keys: text_list(record, "k")?
                .into_iter()
                .map(|text| VerificationKey::from_qb64(text).map_err(EventError::crypto))
                .collect::<Result<_, _>>()?,
            next_threshold: Some(threshold_field(record, "nt")?),
            next_digests: text_list(record, "n")?
                .into_iter()
                .map(|text| Digest::from_qb64(text).map_err(EventError::crypto))
                .collect::<Result<_, _>>()?,
            witness_threshold: Some(witness_threshold),
            witnesses: prefix_list(record, "b")?,
            configuration,
            establishment,
            delegator,
        };
        built.build()
    }

    /// Writes the record as its field map, in protocol order.
    ///
    /// # Errors
    ///
    /// Returns layered prefix, SAID, key, digest or SAD failures when a value cannot be encoded.
    pub fn to_sad(&self) -> Result<Sad, EventError> {
        let mut record = Sad::new();
        let mut insert = |label: &str, value: SadValue| -> Result<(), EventError> {
            record.insert(label.to_owned(), value).map_err(EventError::sad)
        };
        insert(
            "vn",
            SadValue::Array(VERSION.iter().copied().map(SadValue::Integer).collect()),
        )?;
        insert("i", SadValue::Text(self.identifier.qb64().map_err(EventError::prefix)?))?;
        insert("s", sequence_value(self.sequence_number))?;
        let prior = self
            .prior
            .map(|said| said.qb64())
            .transpose()
            .map_err(EventError::said)?;
        insert("p", SadValue::Text(prior.unwrap_or_default()))?;
        insert("d", SadValue::Text(self.said.qb64().map_err(EventError::said)?))?;
        insert("f", sequence_value(self.first_seen))?;
        insert("dt", SadValue::text(self.timestamp.as_str()))?;
        insert("et", SadValue::text(self.latest_kind.as_str()))?;
        insert("kt", textual_threshold(&self.signing_threshold))?;
        insert("k", keys_value(&self.keys)?)?;
        insert("nt", textual_threshold(&self.next_threshold))?;
        insert("n", digests_value(&self.next_digests)?)?;
        insert("bt", sequence_value(u128::from(self.witness_threshold)))?;
        insert("b", prefixes_value(&self.witnesses)?)?;
        insert("c", traits_value(&self.configuration))?;
        insert("ee", SadValue::Map(self.establishment.to_sad()?))?;
        let delegator = self
            .delegator
            .as_ref()
            .map(IdentifierPrefix::qb64)
            .transpose()
            .map_err(EventError::prefix)?;
        insert("di", SadValue::Text(delegator.unwrap_or_default()))?;
        Ok(record)
    }

    /// Returns the identifier this state belongs to.
    #[must_use]
    pub const fn identifier(&self) -> &IdentifierPrefix {
        &self.identifier
    }

    /// Returns the sequence number of the latest event.
    #[must_use]
    pub const fn sequence_number(&self) -> u128 {
        self.sequence_number
    }

    /// Returns the SAID of the event before the latest one; `None` at inception.
    #[must_use]
    pub const fn prior(&self) -> Option<Said> {
        self.prior
    }

    /// Returns the SAID of the latest event.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Returns the first-seen ordinal of the latest event in the reporting actor's log.
    #[must_use]
    pub const fn first_seen(&self) -> u128 {
        self.first_seen
    }

    /// Returns when the reporting actor first saw the latest event.
    #[must_use]
    pub const fn timestamp(&self) -> &Timestamp {
        &self.timestamp
    }

    /// Returns the kind of the latest event.
    #[must_use]
    pub const fn latest_kind(&self) -> EventKind {
        self.latest_kind
    }

    /// Returns the current signing threshold.
    #[must_use]
    pub const fn signing_threshold(&self) -> &SigningThreshold {
        &self.signing_threshold
    }

    /// Returns the current signing keys.
    #[must_use]
    pub fn keys(&self) -> &[VerificationKey] {
        &self.keys
    }

    /// Returns the next-key threshold.
    #[must_use]
    pub const fn next_threshold(&self) -> &SigningThreshold {
        &self.next_threshold
    }

    /// Returns the next-key digests.
    #[must_use]
    pub fn next_digests(&self) -> &[Digest] {
        &self.next_digests
    }

    /// Returns the witness threshold.
    #[must_use]
    pub const fn witness_threshold(&self) -> u32 {
        self.witness_threshold
    }

    /// Returns the current witnesses.
    #[must_use]
    pub fn witnesses(&self) -> &[IdentifierPrefix] {
        &self.witnesses
    }

    /// Returns the configuration traits.
    #[must_use]
    pub fn configuration(&self) -> &[ConfigurationTrait] {
        &self.configuration
    }

    /// Returns the latest establishment event.
    #[must_use]
    pub const fn establishment(&self) -> &LatestEstablishment {
        &self.establishment
    }

    /// Returns the delegator, for a delegated identifier.
    #[must_use]
    pub const fn delegator(&self) -> Option<&IdentifierPrefix> {
        self.delegator.as_ref()
    }
}

/// Builds a [`KeyStateRecord`], keripy's `state`.
///
/// The thresholds default as keripy defaults them: a simple majority of the keys, never zero, for
/// signing; a simple majority of the digests, or zero with none, for the next keys; and for
/// witnesses a simple majority of the set, never zero, or zero with none.
#[derive(Clone, Debug)]
pub struct KeyStateBuilder {
    identifier: IdentifierPrefix,
    sequence_number: u128,
    prior: Option<Said>,
    said: Said,
    first_seen: u128,
    timestamp: Timestamp,
    latest_kind: EventKind,
    signing_threshold: Option<SigningThreshold>,
    keys: Vec<VerificationKey>,
    next_threshold: Option<SigningThreshold>,
    next_digests: Vec<Digest>,
    witness_threshold: Option<u32>,
    witnesses: Vec<IdentifierPrefix>,
    configuration: Vec<ConfigurationTrait>,
    establishment: LatestEstablishment,
    delegator: Option<IdentifierPrefix>,
}

impl KeyStateBuilder {
    /// Starts the state of `identifier` at its latest event `said`, of kind `latest_kind` at
    /// `sequence_number`, first seen at `timestamp`, signed by `keys`, with `establishment` as its
    /// latest establishment event.
    #[must_use]
    pub const fn new(
        identifier: IdentifierPrefix,
        sequence_number: u128,
        said: Said,
        latest_kind: EventKind,
        timestamp: Timestamp,
        keys: Vec<VerificationKey>,
        establishment: LatestEstablishment,
    ) -> Self {
        Self {
            identifier,
            sequence_number,
            prior: None,
            said,
            first_seen: 0,
            timestamp,
            latest_kind,
            signing_threshold: None,
            keys,
            next_threshold: None,
            next_digests: Vec::new(),
            witness_threshold: None,
            witnesses: Vec::new(),
            configuration: Vec::new(),
            establishment,
            delegator: None,
        }
    }

    /// Sets the SAID of the event before the latest one.
    #[must_use]
    pub const fn prior(mut self, prior: Said) -> Self {
        self.prior = Some(prior);
        self
    }

    /// Sets the first-seen ordinal; zero by default.
    #[must_use]
    pub const fn first_seen(mut self, first_seen: u128) -> Self {
        self.first_seen = first_seen;
        self
    }

    /// Sets the signing threshold instead of the default.
    #[must_use]
    pub fn signing_threshold(mut self, threshold: SigningThreshold) -> Self {
        self.signing_threshold = Some(threshold);
        self
    }

    /// Sets the next-key digests; none by default.
    #[must_use]
    pub fn next_digests(mut self, digests: Vec<Digest>) -> Self {
        self.next_digests = digests;
        self
    }

    /// Sets the next-key threshold instead of the default.
    #[must_use]
    pub fn next_threshold(mut self, threshold: SigningThreshold) -> Self {
        self.next_threshold = Some(threshold);
        self
    }

    /// Sets the current witnesses; none by default.
    #[must_use]
    pub fn witnesses(mut self, witnesses: Vec<IdentifierPrefix>) -> Self {
        self.witnesses = witnesses;
        self
    }

    /// Sets the witness threshold instead of the default.
    #[must_use]
    pub const fn witness_threshold(mut self, threshold: u32) -> Self {
        self.witness_threshold = Some(threshold);
        self
    }

    /// Sets the configuration traits; none by default.
    #[must_use]
    pub fn configuration(mut self, configuration: Vec<ConfigurationTrait>) -> Self {
        self.configuration = configuration;
        self
    }

    /// Sets the delegator, for a delegated identifier.
    #[must_use]
    pub fn delegator(mut self, delegator: IdentifierPrefix) -> Self {
        self.delegator = Some(delegator);
        self
    }

    /// Applies keripy's checks and returns the record.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::InvalidLatestEventKind`] unless the latest event is `icp`, `rot`,
    /// `ixn`, `dip` or `drt`; [`EventError::SigningThresholdIsZero`] and
    /// [`EventError::SigningThresholdExceedsKeys`] for an unsatisfiable signing threshold;
    /// [`EventError::NextThresholdExceedsDigests`] for an unsatisfiable next threshold;
    /// [`EventError::DuplicateWitness`] for a repeated witness in `b`, `br` or `ba`;
    /// [`EventError::InvalidWitnessThreshold`] for a witness threshold outside what the set allows;
    /// and [`EventError::ConflictingWitnessLists`] when the latest establishment event both removed
    /// and added the same witness.
    pub fn build(self) -> Result<KeyStateRecord, EventError> {
        if !matches!(
            self.latest_kind,
            EventKind::Inception
                | EventKind::Rotation
                | EventKind::Interaction
                | EventKind::DelegatedInception
                | EventKind::DelegatedRotation
        ) {
            return Err(EventError::InvalidLatestEventKind {
                found: self.latest_kind.as_str().to_owned(),
            });
        }

        let signing_threshold = match self.signing_threshold {
            Some(threshold) => threshold,
            None => default_signing_threshold(self.keys.len())?,
        };
        check_signing_threshold(&signing_threshold, self.keys.len())?;

        let next_threshold = match self.next_threshold {
            Some(threshold) => threshold,
            None => default_next_threshold(self.next_digests.len())?,
        };
        check_next_threshold(&next_threshold, self.next_digests.len())?;

        check_distinct(&self.witnesses, "b")?;
        let witness_threshold = match self.witness_threshold {
            Some(threshold) => threshold,
            None => default_witness_threshold(self.witnesses.len())?,
        };
        check_witness_threshold(witness_threshold, self.witnesses.len())?;
        self.establishment.check()?;

        Ok(KeyStateRecord {
            identifier: self.identifier,
            sequence_number: self.sequence_number,
            prior: self.prior,
            said: self.said,
            first_seen: self.first_seen,
            timestamp: self.timestamp,
            latest_kind: self.latest_kind,
            signing_threshold,
            keys: self.keys,
            next_threshold,
            next_digests: self.next_digests,
            witness_threshold,
            witnesses: self.witnesses,
            configuration: self.configuration,
            establishment: self.establishment,
            delegator: self.delegator,
        })
    }
}

/// keripy's witness-threshold default for a key state: a simple majority, never zero, or zero with
/// no witnesses.
///
/// keripy's `state` has a second default after this one, `ample`, which can never run because the
/// first already assigned a value. The reachable default is reproduced.
fn default_witness_threshold(witnesses: usize) -> Result<u32, EventError> {
    let count = u32::try_from(witnesses).map_err(|_| EventError::ValueOutOfRange {
        context: "witness count",
    })?;
    Ok(if count == 0 { 0 } else { count.div_ceil(2) })
}

/// How a reported key state relates to the local one, keripy's `Stateage`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StateComparison {
    /// The same latest event.
    Even,
    /// The reporter has a later event than the local log.
    Ahead,
    /// The reporter is missing events the local log has.
    Behind,
    /// A different event at the same sequence number.
    Duplicitous,
}

/// The outcome of comparing a reported key state against the local one, keripy's `DiffState`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateDifference {
    comparison: StateComparison,
    sequence_number: u128,
    said: Said,
}

impl StateDifference {
    /// Returns how the reported state relates to the local one.
    #[must_use]
    pub const fn comparison(&self) -> StateComparison {
        self.comparison
    }

    /// Returns the reported state's sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> u128 {
        self.sequence_number
    }

    /// Returns the reported state's latest-event SAID.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }
}

/// Compares a `reported` key state against the `local` one, keripy's `diffState`.
///
/// Only the latest sequence number and SAID are compared, as keripy compares them: at the same
/// sequence number a different SAID is duplicity; otherwise the higher sequence number is ahead.
///
/// # Errors
///
/// Returns [`EventError::IdentifierMismatch`] when the two records belong to different
/// identifiers, which keripy refuses with a `ValueError`.
pub fn compare(local: &KeyStateRecord, reported: &KeyStateRecord) -> Result<StateDifference, EventError> {
    if local.identifier != reported.identifier {
        return Err(EventError::IdentifierMismatch);
    }
    let comparison = match local.sequence_number.cmp(&reported.sequence_number) {
        core::cmp::Ordering::Equal if local.said == reported.said => StateComparison::Even,
        core::cmp::Ordering::Equal => StateComparison::Duplicitous,
        core::cmp::Ordering::Greater => StateComparison::Behind,
        core::cmp::Ordering::Less => StateComparison::Ahead,
    };
    Ok(StateDifference {
        comparison,
        sequence_number: reported.sequence_number,
        said: reported.said,
    })
}

fn check_layout(map: &Sad, expected: &[&str], description: &'static str) -> Result<(), EventError> {
    let labels: Vec<&str> = map.entries().map(|(label, _)| label).collect();
    if labels != expected {
        return Err(EventError::UnexpectedFieldLayout {
            expected: description,
            found: bounded_label(&labels.join(", ")),
        });
    }
    Ok(())
}

fn text_field<'a>(map: &'a Sad, label: &'static str) -> Result<&'a str, EventError> {
    map.get_text(label).ok_or(EventError::UnexpectedFieldShape { label })
}

fn hex_field(map: &Sad, label: &'static str) -> Result<u128, EventError> {
    let number = CesrNumber::from_hex(text_field(map, label)?).map_err(EventError::cesr)?;
    Ok(number.value())
}

fn said_field(map: &Sad, label: &'static str) -> Result<Said, EventError> {
    Said::from_qb64(text_field(map, label)?).map_err(EventError::said)
}

fn prefix_field(map: &Sad, label: &'static str) -> Result<IdentifierPrefix, EventError> {
    IdentifierPrefix::from_qb64(text_field(map, label)?).map_err(EventError::prefix)
}

fn text_list<'a>(map: &'a Sad, label: &'static str) -> Result<Vec<&'a str>, EventError> {
    map.get(label)
        .and_then(SadValue::as_array)
        .ok_or(EventError::UnexpectedFieldShape { label })?
        .iter()
        .map(|item| item.as_text().ok_or(EventError::UnexpectedFieldShape { label }))
        .collect()
}

fn prefix_list(map: &Sad, label: &'static str) -> Result<Vec<IdentifierPrefix>, EventError> {
    text_list(map, label)?
        .into_iter()
        .map(|text| IdentifierPrefix::from_qb64(text).map_err(EventError::prefix))
        .collect()
}

/// Reads a threshold written as hexadecimal text or as weight arrays.
///
/// keripy's deprecated `intive` option writes a numeric threshold as a JSON number; KERI does not,
/// and neither does KERIA, so a number is refused as the wrong shape.
fn threshold_field(map: &Sad, label: &'static str) -> Result<SigningThreshold, EventError> {
    let value = map.get(label).ok_or(EventError::UnexpectedFieldShape { label })?;
    threshold_value(value, label, false)
}

/// Reads a threshold value: hexadecimal text, weight arrays, and, when `allow_integer` is set, a
/// JSON number, which key events may carry and key state records may not.
pub(crate) fn threshold_value(
    value: &SadValue,
    label: &'static str,
    allow_integer: bool,
) -> Result<SigningThreshold, EventError> {
    if let SadValue::Integer(number) = value
        && allow_integer
    {
        let number = u128::try_from(*number).map_err(|_| EventError::UnexpectedFieldShape { label })?;
        return Ok(SigningThreshold::numeric(number));
    }
    let json = threshold_json(value).ok_or(EventError::UnexpectedFieldShape { label })?;
    SigningThreshold::from_json(&json.to_string()).map_err(EventError::threshold)
}

fn threshold_json(value: &SadValue) -> Option<Value> {
    match value {
        SadValue::Text(text) => Some(Value::String(text.clone())),
        SadValue::Array(items) => items
            .iter()
            .map(threshold_json)
            .collect::<Option<Vec<_>>>()
            .map(Value::Array),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const IDENTIFIER: &str = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";
    const OTHER_IDENTIFIER: &str = "EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W";
    const KEY: &str = "DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH";
    const WITNESS: &str = "BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
    const STAMP: &str = "2021-01-01T00:00:00.000000+00:00";

    fn builder(sequence_number: u128, said: &str, kind: EventKind) -> Result<KeyStateBuilder, Box<dyn Error>> {
        Ok(KeyStateBuilder::new(
            IdentifierPrefix::from_qb64(IDENTIFIER)?,
            sequence_number,
            Said::from_qb64(said)?,
            kind,
            Timestamp::parse(STAMP)?,
            vec![VerificationKey::from_qb64(KEY)?],
            LatestEstablishment::new(0, Said::from_qb64(IDENTIFIER)?),
        ))
    }

    #[test]
    fn a_record_round_trips_through_its_field_map_in_protocol_order() -> Result<(), Box<dyn Error>> {
        let record = builder(0, IDENTIFIER, EventKind::Inception)?
            .next_digests(vec![Digest::from_qb64(OTHER_IDENTIFIER)?])
            .witnesses(vec![IdentifierPrefix::from_qb64(WITNESS)?])
            .configuration(vec![ConfigurationTrait::EstablishmentOnly])
            .build()?;
        let map = record.to_sad()?;
        let labels: Vec<&str> = map.entries().map(|(label, _)| label).collect();
        assert_eq!(labels, FIELD_LABELS);
        assert_eq!(map.get_text("p"), Some(""));
        assert_eq!(map.get_text("kt"), Some("1"));
        assert_eq!(map.get_text("nt"), Some("1"));
        assert_eq!(map.get_text("bt"), Some("1"));
        assert_eq!(map.get_text("di"), Some(""));
        assert_eq!(KeyStateRecord::from_sad(&map)?, record);
        Ok(())
    }

    #[test]
    fn defaults_follow_keripy() -> Result<(), Box<dyn Error>> {
        let witnesses: Vec<IdentifierPrefix> = [WITNESS, "BCmsuuFBvMrwsi4alNNNC8c2HlJtC_4SyJeUvJMilm3X"]
            .into_iter()
            .map(IdentifierPrefix::from_qb64)
            .collect::<Result<_, _>>()?;
        let record = builder(0, IDENTIFIER, EventKind::Inception)?
            .witnesses(witnesses)
            .build()?;
        assert_eq!(record.signing_threshold().numeric_value(), Some(1));
        assert_eq!(record.next_threshold().numeric_value(), Some(0));
        assert_eq!(record.witness_threshold(), 1);
        assert_eq!(default_witness_threshold(4)?, 2);
        assert_eq!(default_witness_threshold(0)?, 0);
        Ok(())
    }

    #[test]
    fn invalid_states_are_refused() -> Result<(), Box<dyn Error>> {
        assert!(matches!(
            builder(0, IDENTIFIER, EventKind::Receipt)?.build(),
            Err(EventError::InvalidLatestEventKind { found }) if found == "rct"
        ));
        assert!(matches!(
            builder(0, IDENTIFIER, EventKind::Inception)?
                .signing_threshold(SigningThreshold::numeric(2))
                .build(),
            Err(EventError::SigningThresholdExceedsKeys { .. })
        ));
        assert!(matches!(
            builder(0, IDENTIFIER, EventKind::Inception)?
                .witness_threshold(1)
                .build(),
            Err(EventError::InvalidWitnessThreshold { .. })
        ));
        let witness = IdentifierPrefix::from_qb64(WITNESS)?;
        assert!(matches!(
            builder(0, IDENTIFIER, EventKind::Inception)?
                .witnesses(vec![witness.clone(), witness.clone()])
                .build(),
            Err(EventError::DuplicateWitness { label: "b" })
        ));
        let mut conflicting = builder(1, OTHER_IDENTIFIER, EventKind::Rotation)?;
        conflicting.establishment = LatestEstablishment::new(1, Said::from_qb64(OTHER_IDENTIFIER)?)
            .removed(vec![witness.clone()])
            .added(vec![witness]);
        assert!(matches!(
            conflicting.build(),
            Err(EventError::ConflictingWitnessLists { .. })
        ));
        Ok(())
    }

    #[test]
    fn comparison_follows_keripy_diff_state() -> Result<(), Box<dyn Error>> {
        let local = builder(1, IDENTIFIER, EventKind::Interaction)?.build()?;
        let same = builder(1, IDENTIFIER, EventKind::Interaction)?.build()?;
        let fork = builder(1, OTHER_IDENTIFIER, EventKind::Interaction)?.build()?;
        let ahead = builder(2, OTHER_IDENTIFIER, EventKind::Interaction)?.build()?;
        let behind = builder(0, IDENTIFIER, EventKind::Inception)?.build()?;
        assert_eq!(compare(&local, &same)?.comparison(), StateComparison::Even);
        assert_eq!(compare(&local, &fork)?.comparison(), StateComparison::Duplicitous);
        assert_eq!(compare(&local, &ahead)?.comparison(), StateComparison::Ahead);
        assert_eq!(compare(&local, &ahead)?.sequence_number(), 2);
        assert_eq!(compare(&local, &behind)?.comparison(), StateComparison::Behind);

        let mut stranger = builder(1, IDENTIFIER, EventKind::Interaction)?;
        stranger.identifier = IdentifierPrefix::from_qb64(OTHER_IDENTIFIER)?;
        assert!(matches!(
            compare(&local, &stranger.build()?),
            Err(EventError::IdentifierMismatch)
        ));
        Ok(())
    }

    #[test]
    fn integer_thresholds_and_unknown_traits_are_refused_on_read() -> Result<(), Box<dyn Error>> {
        let record = builder(0, IDENTIFIER, EventKind::Inception)?.build()?;
        let rewrite = |label: &str, value: SadValue| -> Result<Sad, Box<dyn Error>> {
            let mut map = Sad::new();
            for (existing, existing_value) in record.to_sad()?.entries() {
                map.insert(
                    existing,
                    if existing == label {
                        value.clone()
                    } else {
                        existing_value.clone()
                    },
                )?;
            }
            Ok(map)
        };
        assert!(matches!(
            KeyStateRecord::from_sad(&rewrite("kt", SadValue::Integer(1))?),
            Err(EventError::UnexpectedFieldShape { label: "kt" })
        ));
        assert!(matches!(
            KeyStateRecord::from_sad(&rewrite("c", SadValue::Array(vec![SadValue::text("XX")]))?),
            Err(EventError::UnknownConfigurationTrait { found }) if found == "XX"
        ));
        assert!(matches!(
            KeyStateRecord::from_sad(&rewrite(
                "vn",
                SadValue::Array(vec![SadValue::Integer(2), SadValue::Integer(0)])
            )?),
            Err(EventError::UnexpectedFieldShape { label: "vn" })
        ));
        Ok(())
    }
}
