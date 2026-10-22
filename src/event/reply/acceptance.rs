//! Best-available-data acceptance of replies.
//!
//! A reply is authoritative data, an endpoint role, a location, a key state, that its signer may
//! replace at any time with a newer one. Best-available-data acceptance (BADA) decides whether an
//! incoming reply replaces the one already accepted for the same route key:
//!
//! - signed by a non-transferable key, it is newer when its timestamp is later;
//! - signed by a transferable identifier, it is newer when the establishment event whose keys
//!   signed it is later, or the same one with a later timestamp.
//!
//! The signature must also be the authority's own, and must verify: a non-transferable signature
//! against its key, a transferable group against the keys and threshold of the signer's
//! establishment event at the sequence number the group names. When that event is not yet known,
//! or the group falls short of the threshold, the reply is escrowed for later rather than refused.
//!
//! This ports `Revery.acceptReply` from keripy's `src/keri/core/routing.py`, with
//! `validateSigs` and `verifySigs` from `src/keri/core/eventing.py`, as a decision: it reads no
//! database and writes none. The caller says what was accepted before ([`AcceptedReply`]) and
//! supplies the signer's events ([`SignerEvents`]); [`accept`] says, for each attached signature,
//! whether it was accepted, skipped or escrowed, and why. Storing the reply, escrowing it and
//! asking for the signer's key state are the caller's.
//!
//! keripy also skips a signature made with the caller's own keys on a reply that did not originate
//! locally, unless it runs in its default `lax` mode. That is a policy about the caller's identity,
//! so it is left to the caller here.
//!
//! One behaviour differs. keripy indexes the signer's key list with each signature's index before
//! checking the index is in range, so an index past the end raises `IndexError` and aborts the
//! whole acceptance. Such a signature is skipped here instead, like any other that does not verify.

use keri_cesr::crypto::signature::IndexedSignature;
use keri_cesr::crypto::verifier::VerificationKey;

use crate::event::error::EventError;
use crate::event::key_state::threshold_value;
use crate::event::reply::ReplyMessage;
use crate::event::timestamp::Timestamp;
use crate::prefix::IdentifierPrefix;
use crate::serialization::SerializedEvent;
use crate::stream::{Attachments, TransferableSignatureGroup};

/// What was accepted before for the same route key, keripy's stored date and signature group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedReply {
    timestamp: Timestamp,
    establishment: Option<u128>,
}

impl AcceptedReply {
    /// A reply accepted at `timestamp`, signed by a non-transferable key.
    #[must_use]
    pub const fn new(timestamp: Timestamp) -> Self {
        Self {
            timestamp,
            establishment: None,
        }
    }

    /// Records that it was signed by a transferable identifier from its establishment event at
    /// `sequence_number`.
    #[must_use]
    pub const fn signed_at(mut self, sequence_number: u128) -> Self {
        self.establishment = Some(sequence_number);
        self
    }

    /// Returns when the accepted reply was made.
    #[must_use]
    pub const fn timestamp(&self) -> &Timestamp {
        &self.timestamp
    }

    /// Returns the establishment event that signed it, when transferable.
    #[must_use]
    pub const fn establishment(&self) -> Option<u128> {
        self.establishment
    }
}

/// The signer's key event log, as far as the caller holds it.
pub trait SignerEvents {
    /// Returns the latest event `signer` accepted at `sequence_number`, keripy's `getKeLast`.
    fn event_at(&self, signer: &IdentifierPrefix, sequence_number: u128) -> Option<SerializedEvent>;
}

/// Why a signature was passed over.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Skip {
    /// It was made by someone other than the reply's authority.
    NotFromAuthority,
    /// The reply is not newer than the one already accepted.
    Stale,
    /// The signature does not verify.
    InvalidSignature,
}

/// Why a reply was set aside for later.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Escrow {
    /// The signer's establishment event at the named sequence number is not yet known.
    MissingEstablishment,
    /// The verified signatures do not yet meet the signer's threshold.
    BelowThreshold,
}

/// What became of one attached signature or signature group.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Outcome {
    /// It establishes the reply.
    Accepted,
    /// It was passed over.
    Skipped(Skip),
    /// The reply waits on it.
    Escrowed(Escrow),
}

/// The decision over every signature attached to one reply.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Acceptance {
    couples: Vec<Outcome>,
    groups: Vec<Outcome>,
}

impl Acceptance {
    /// Returns whether any signature established the reply.
    #[must_use]
    pub fn is_accepted(&self) -> bool {
        self.couples
            .iter()
            .chain(&self.groups)
            .any(|outcome| *outcome == Outcome::Accepted)
    }

    /// Returns whether any signature group set the reply aside for later.
    #[must_use]
    pub fn is_escrowed(&self) -> bool {
        self.groups
            .iter()
            .any(|outcome| matches!(outcome, Outcome::Escrowed(_)))
    }

    /// Returns the outcome of each non-transferable receipt couple, in attachment order.
    ///
    /// Couples after the first accepted one are not considered, as in keripy.
    #[must_use]
    pub fn couples(&self) -> &[Outcome] {
        &self.couples
    }

    /// Returns the outcome of each transferable signature group, in attachment order.
    #[must_use]
    pub fn groups(&self) -> &[Outcome] {
        &self.groups
    }
}

/// Decides whether `reply`, signed as `attachments` say, replaces what was accepted before for
/// the same route key on behalf of `authority`.
///
/// # Errors
///
/// Returns, as keripy raises, [`EventError::SignatureGroupMismatch`] when the signer's event at
/// the group's sequence number is not the one the group names; [`EventError::NoSigningKeys`] when
/// that event carries no keys; [`EventError::SigningThresholdExceedsKeys`] when its threshold needs
/// more keys than it lists; [`EventError::NoVerifiedSignatures`] when not one signature in the
/// group verifies; and layered parsing failures for a malformed signer event.
pub fn accept(
    reply: &ReplyMessage,
    attachments: &Attachments,
    authority: &IdentifierPrefix,
    prior: Option<&AcceptedReply>,
    events: &impl SignerEvents,
) -> Result<Acceptance, EventError> {
    let mut acceptance = Acceptance::default();
    let newer_than_prior = prior.is_none_or(|prior| reply.timestamp() > &prior.timestamp);

    for couple in attachments.receipt_couples() {
        let outcome =
            if authority.qb64().map_err(EventError::prefix)? != couple.verifier().qb64().map_err(EventError::crypto)? {
                Outcome::Skipped(Skip::NotFromAuthority)
            } else if !newer_than_prior {
                Outcome::Skipped(Skip::Stale)
            } else if couple.verifier().verify(couple.signature().raw(), reply.raw()).is_err() {
                Outcome::Skipped(Skip::InvalidSignature)
            } else {
                Outcome::Accepted
            };
        acceptance.couples.push(outcome);
        if outcome == Outcome::Accepted {
            break;
        }
    }

    for group in attachments.transferable_signature_groups() {
        let outcome = group_outcome(reply, group, authority, prior, events)?;
        acceptance.groups.push(outcome);
    }
    Ok(acceptance)
}

fn group_outcome(
    reply: &ReplyMessage,
    group: &TransferableSignatureGroup,
    authority: &IdentifierPrefix,
    prior: Option<&AcceptedReply>,
    events: &impl SignerEvents,
) -> Result<Outcome, EventError> {
    if group.identifier() != authority {
        return Ok(Outcome::Skipped(Skip::NotFromAuthority));
    }
    let sequence_number = group.sequence_number().value();
    // keripy compares establishment events only when the prior reply was itself signed by a
    // transferable group, and compares timestamps only when both name the same event.
    if let Some(prior) = prior
        && let Some(prior_establishment) = prior.establishment
    {
        if sequence_number < prior_establishment {
            return Ok(Outcome::Skipped(Skip::Stale));
        }
        if sequence_number == prior_establishment && reply.timestamp() <= &prior.timestamp {
            return Ok(Outcome::Skipped(Skip::Stale));
        }
    }

    let Some(event) = events.event_at(group.identifier(), sequence_number) else {
        return Ok(Outcome::Escrowed(Escrow::MissingEstablishment));
    };
    if event.said() != Some(group.said().qb64().map_err(EventError::said)?.as_str()) {
        return Err(EventError::SignatureGroupMismatch { sequence_number });
    }
    let keys = event.verification_keys().map_err(EventError::serialization)?;
    if keys.is_empty() {
        return Err(EventError::NoSigningKeys { sequence_number });
    }
    let threshold = event
        .sad()
        .get("kt")
        .ok_or(EventError::UnexpectedFieldShape { label: "kt" })
        .and_then(|value| threshold_value(value, "kt", true))?;
    if threshold.size() > u128::try_from(keys.len()).unwrap_or(u128::MAX) {
        return Err(EventError::SigningThresholdExceedsKeys {
            required: threshold.size(),
            keys: keys.len(),
        });
    }

    let indices = verified_indices(group.signatures(), &keys, reply.raw());
    if indices.is_empty() {
        return Err(EventError::NoVerifiedSignatures { sequence_number });
    }
    if threshold.is_satisfied_by(&indices).map_err(EventError::threshold)? {
        Ok(Outcome::Accepted)
    } else {
        Ok(Outcome::Escrowed(Escrow::BelowThreshold))
    }
}

/// keripy's `verifySigs`: drops repeated signatures, then keeps the index of every signature that
/// verifies against the key at its index. A signature whose index is past the end is dropped.
fn verified_indices(signatures: &[IndexedSignature], keys: &[VerificationKey], message: &[u8]) -> Vec<usize> {
    let mut seen: Vec<&IndexedSignature> = Vec::with_capacity(signatures.len());
    let mut indices = Vec::new();
    for signature in signatures {
        if seen.contains(&signature) {
            continue;
        }
        seen.push(signature);
        let Ok(index) = usize::try_from(signature.index()) else {
            continue;
        };
        if let Some(key) = keys.get(index)
            && key.verify(signature.raw(), message).is_ok()
        {
            indices.push(index);
        }
    }
    indices
}
