//! Query messages.
//!
//! A query (`qry`) asks another actor, a witness or watcher, for what it holds about an
//! identifier: its key state (`ksn`), its key event log (`logs`), or a mailbox (`mbx`). The message
//! names a route, a reply route the asker wants the answer on, a timestamp, and a query block
//! whose keys depend on the route. The asker signs it with a last-establishment signature group
//! (`-H`) when transferable or a receipt couple (`-C`) when not, through
//! [`SignedMessageBuilder`](crate::attachment::SignedMessageBuilder).
//!
//! This ports `query` from keripy's `src/keri/core/eventing.py`, the field layout keripy's
//! `SerderKERI` enforces when reading one, and the query-block layout keripy's own askers write.
//! The pinned signify-ts reference has no `qry` at all, not even in its ilk table, because KERIA
//! queries on its behalf.
//!
//! # The query block
//!
//! keripy builds the block as the route's own keys first, then the identifier being asked about
//! (`i`) and the actor being asked (`src`), always last. [`QueryArguments`] writes that order and
//! reads it back; a caller with a block the typed arguments cannot express passes a [`Sad`] to
//! [`QueryBuilder::query`] directly.
//!
//! | Route | Keys keripy writes, in order |
//! |---|---|
//! | `logs` | `s` (hex sequence floor), `fn` (hex first-seen floor), optional `a` (anchor seal), `i`, `src` |
//! | `ksn` | `s`, `fn`, `i`, `src` |
//! | `mbx` | `pre`, `topics` (topic to next index), `i`, `src` |
//!
//! Nothing here verifies the signature or answers the query. The reader establishes what is being
//! asked; the actor holding a log decides what to say.

use keri_cesr::crypto::digest::DigestAlgorithm;
use keri_cesr::number::CesrNumber;

use crate::event::error::{EventError, bounded_label};
use crate::event::kind::EventKind;
use crate::event::reply::{MAX_ROUTE_BYTES, ROUTE_LABEL, TIMESTAMP_LABEL};
use crate::event::timestamp::Timestamp;
use crate::prefix::IdentifierPrefix;
use crate::said::{DEFAULT_SAID_LABEL, Said, SaidVerification};
use crate::serialization::{KIND_LABEL, SAID_LABEL, Sad, SadValue, SerializedEvent, VERSION_LABEL};

/// Field label carrying the route the asker wants the answer on.
pub const REPLY_ROUTE_LABEL: &str = "rr";
/// Field label carrying the query block.
pub const QUERY_LABEL: &str = "q";
/// The field labels of a query, in protocol order.
pub const FIELD_LABELS: [&str; 7] = [
    VERSION_LABEL,
    KIND_LABEL,
    SAID_LABEL,
    TIMESTAMP_LABEL,
    ROUTE_LABEL,
    REPLY_ROUTE_LABEL,
    QUERY_LABEL,
];

/// Query-block key naming the identifier being asked about.
pub const IDENTIFIER_KEY: &str = "i";
/// Query-block key naming the actor being asked.
pub const SOURCE_KEY: &str = "src";
/// Query-block key carrying the hexadecimal sequence-number floor.
pub const SEQUENCE_KEY: &str = "s";
/// Query-block key carrying the hexadecimal first-seen floor.
pub const FIRST_SEEN_KEY: &str = "fn";
/// Query-block key carrying an anchor seal to search for.
pub const ANCHOR_KEY: &str = "a";
/// Query-block key carrying mailbox topics and the next index wanted for each.
pub const TOPICS_KEY: &str = "topics";

/// The typed query block: what keripy's askers write, and what its `processQuery` reads.
///
/// The identifier and source are required on every route. The rest are optional and written only
/// when set, in keripy's order: sequence floor, first-seen floor, anchor, topics, then identifier
/// and source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryArguments {
    identifier: IdentifierPrefix,
    source: IdentifierPrefix,
    sequence_number: Option<u128>,
    first_seen: Option<u128>,
    anchor: Option<Sad>,
    topics: Option<Sad>,
}

impl QueryArguments {
    /// Asks `source` about `identifier`.
    #[must_use]
    pub const fn new(identifier: IdentifierPrefix, source: IdentifierPrefix) -> Self {
        Self {
            identifier,
            source,
            sequence_number: None,
            first_seen: None,
            anchor: None,
            topics: None,
        }
    }

    /// Sets the sequence-number floor (`s`).
    #[must_use]
    pub const fn sequence_number(mut self, sequence_number: u128) -> Self {
        self.sequence_number = Some(sequence_number);
        self
    }

    /// Sets the first-seen floor (`fn`).
    #[must_use]
    pub const fn first_seen(mut self, first_seen: u128) -> Self {
        self.first_seen = Some(first_seen);
        self
    }

    /// Sets the anchor seal to search for (`a`).
    #[must_use]
    pub fn anchor(mut self, anchor: Sad) -> Self {
        self.anchor = Some(anchor);
        self
    }

    /// Sets the mailbox topics (`topics`).
    #[must_use]
    pub fn topics(mut self, topics: Sad) -> Self {
        self.topics = Some(topics);
        self
    }

    /// Returns the identifier being asked about.
    #[must_use]
    pub const fn identifier(&self) -> &IdentifierPrefix {
        &self.identifier
    }

    /// Returns the actor being asked.
    #[must_use]
    pub const fn source(&self) -> &IdentifierPrefix {
        &self.source
    }

    /// Returns the sequence-number floor, when set.
    #[must_use]
    pub const fn sequence_floor(&self) -> Option<u128> {
        self.sequence_number
    }

    /// Returns the first-seen floor, when set.
    #[must_use]
    pub const fn first_seen_floor(&self) -> Option<u128> {
        self.first_seen
    }

    /// Returns the anchor seal, when set.
    #[must_use]
    pub const fn anchor_seal(&self) -> Option<&Sad> {
        self.anchor.as_ref()
    }

    /// Returns the mailbox topics, when set.
    #[must_use]
    pub const fn mailbox_topics(&self) -> Option<&Sad> {
        self.topics.as_ref()
    }

    /// Reads the typed arguments out of a query block, ignoring keys it does not know.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::MissingQueryKey`] when `i` or `src` is absent or not text,
    /// [`EventError::UnexpectedFieldShape`] when a known key has the wrong shape, and layered
    /// [`EventError::Prefix`] or [`EventError::Cesr`] failures for malformed values.
    pub fn from_sad(block: &Sad) -> Result<Self, EventError> {
        let identifier = required_prefix(block, IDENTIFIER_KEY)?;
        let source = required_prefix(block, SOURCE_KEY)?;
        let sequence_number = optional_hex(block, SEQUENCE_KEY)?;
        let first_seen = optional_hex(block, FIRST_SEEN_KEY)?;
        let anchor = optional_map(block, ANCHOR_KEY)?;
        let topics = optional_map(block, TOPICS_KEY)?;
        Ok(Self {
            identifier,
            source,
            sequence_number,
            first_seen,
            anchor,
            topics,
        })
    }

    /// Writes the block in keripy's order.
    ///
    /// # Errors
    ///
    /// Returns layered [`EventError::Prefix`] or [`EventError::Sad`] failures when a value cannot
    /// be encoded.
    pub fn into_sad(self) -> Result<Sad, EventError> {
        let mut block = Sad::new();
        let mut insert = |label: &str, value: SadValue| -> Result<(), EventError> {
            block.insert(label.to_owned(), value).map_err(EventError::sad)
        };
        if let Some(sequence_number) = self.sequence_number {
            insert(SEQUENCE_KEY, SadValue::text(CesrNumber::new(sequence_number).hex()))?;
        }
        if let Some(first_seen) = self.first_seen {
            insert(FIRST_SEEN_KEY, SadValue::text(CesrNumber::new(first_seen).hex()))?;
        }
        if let Some(anchor) = self.anchor {
            insert(ANCHOR_KEY, SadValue::Map(anchor))?;
        }
        if let Some(topics) = self.topics {
            insert(TOPICS_KEY, SadValue::Map(topics))?;
        }
        insert(
            IDENTIFIER_KEY,
            SadValue::Text(self.identifier.qb64().map_err(EventError::prefix)?),
        )?;
        insert(
            SOURCE_KEY,
            SadValue::Text(self.source.qb64().map_err(EventError::prefix)?),
        )?;
        Ok(block)
    }
}

fn required_prefix(block: &Sad, key: &'static str) -> Result<IdentifierPrefix, EventError> {
    let text = block.get_text(key).ok_or(EventError::MissingQueryKey { key })?;
    IdentifierPrefix::from_qb64(text).map_err(EventError::prefix)
}

fn optional_hex(block: &Sad, key: &'static str) -> Result<Option<u128>, EventError> {
    match block.get(key) {
        None => Ok(None),
        Some(value) => {
            let text = value.as_text().ok_or(EventError::UnexpectedFieldShape { label: key })?;
            let number = CesrNumber::from_hex(text).map_err(EventError::cesr)?;
            Ok(Some(number.value()))
        }
    }
}

fn optional_map(block: &Sad, key: &'static str) -> Result<Option<Sad>, EventError> {
    match block.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_map()
            .cloned()
            .map(Some)
            .ok_or(EventError::UnexpectedFieldShape { label: key }),
    }
}

/// A query message, built here or read from a stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryMessage {
    serialized: SerializedEvent,
    said: Said,
    timestamp: Timestamp,
}

impl QueryMessage {
    /// Reads the query a parsed message carries, verifying its SAID.
    ///
    /// The message must be a `qry` with exactly the seven query fields in protocol order, as
    /// keripy's `SerderKERI` requires, and its `d` must be the digest of its own bytes, which
    /// keripy also checks on the way in.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::UnexpectedKind`] when the message is not a query,
    /// [`EventError::UnexpectedFieldLayout`] when its fields are not exactly the query's,
    /// [`EventError::UnexpectedFieldShape`] when a field has the wrong shape,
    /// [`EventError::Timestamp`] for a malformed `dt`, and layered [`EventError::Said`] failures
    /// when `d` is malformed or does not match the message.
    pub fn from_serialized(serialized: SerializedEvent) -> Result<Self, EventError> {
        let kind = serialized.sad().get_text(KIND_LABEL).unwrap_or_default();
        if kind != EventKind::Query.as_str() {
            return Err(EventError::UnexpectedKind {
                expected: EventKind::Query,
                found: bounded_label(kind),
            });
        }
        let labels: Vec<&str> = serialized.sad().entries().map(|(label, _)| label).collect();
        if labels != FIELD_LABELS {
            return Err(EventError::UnexpectedFieldLayout {
                expected: "v, t, d, dt, r, rr, q",
                found: bounded_label(&labels.join(", ")),
            });
        }
        for label in [TIMESTAMP_LABEL, ROUTE_LABEL, REPLY_ROUTE_LABEL] {
            if serialized.sad().get_text(label).is_none() {
                return Err(EventError::UnexpectedFieldShape { label });
            }
        }
        if serialized.sad().get(QUERY_LABEL).and_then(SadValue::as_map).is_none() {
            return Err(EventError::UnexpectedFieldShape { label: QUERY_LABEL });
        }
        let timestamp = serialized
            .sad()
            .get_text(TIMESTAMP_LABEL)
            .map(Timestamp::parse)
            .transpose()
            .map_err(EventError::timestamp)?
            .ok_or(EventError::UnexpectedFieldShape { label: TIMESTAMP_LABEL })?;
        let said = serialized
            .said()
            .ok_or(EventError::UnexpectedFieldShape { label: SAID_LABEL })
            .and_then(|text| Said::from_qb64(text).map_err(EventError::said))?;
        said.verify(serialized.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict())
            .map_err(EventError::said)?;
        Ok(Self {
            serialized,
            said,
            timestamp,
        })
    }

    /// Returns the exact serialized message bytes.
    #[must_use]
    pub fn raw(&self) -> &[u8] {
        self.serialized.raw()
    }

    /// Borrows the ordered message fields.
    #[must_use]
    pub const fn sad(&self) -> &Sad {
        self.serialized.sad()
    }

    /// Borrows the serialized message, to sign it or read its version string.
    #[must_use]
    pub const fn serialized(&self) -> &SerializedEvent {
        &self.serialized
    }

    /// Returns the message's self-addressing identifier.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Returns the route being queried.
    #[must_use]
    pub fn route(&self) -> &str {
        self.sad().get_text(ROUTE_LABEL).unwrap_or_default()
    }

    /// Returns the route the asker wants the answer on; empty when it names none.
    #[must_use]
    pub fn reply_route(&self) -> &str {
        self.sad().get_text(REPLY_ROUTE_LABEL).unwrap_or_default()
    }

    /// Returns when the query was made.
    #[must_use]
    pub const fn timestamp(&self) -> &Timestamp {
        &self.timestamp
    }

    /// Borrows the query block as written.
    #[must_use]
    pub fn query(&self) -> &Sad {
        static EMPTY: Sad = Sad::new();
        self.sad().get(QUERY_LABEL).and_then(SadValue::as_map).unwrap_or(&EMPTY)
    }

    /// Reads the typed arguments out of the query block.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`QueryArguments::from_sad`].
    pub fn arguments(&self) -> Result<QueryArguments, EventError> {
        QueryArguments::from_sad(self.query())
    }

    /// Takes the serialized message out.
    #[must_use]
    pub fn into_serialized(self) -> SerializedEvent {
        self.serialized
    }
}

/// Builds a query (`qry`) message.
///
/// ```
/// use keri_protocol::event::query::{QueryArguments, QueryBuilder};
/// use keri_protocol::event::timestamp::Timestamp;
/// use keri_protocol::prefix::IdentifierPrefix;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let identifier = IdentifierPrefix::from_qb64("EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL")?;
/// let witness = IdentifierPrefix::from_qb64("BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4")?;
/// let query = QueryBuilder::new("ksn", "2021-01-01T00:00:00.000000+00:00".parse::<Timestamp>()?)
///     .query(QueryArguments::new(identifier, witness).sequence_number(0).first_seen(0).into_sad()?)
///     .build()?;
///
/// assert_eq!(query.route(), "ksn");
/// assert_eq!(query.arguments()?.sequence_floor(), Some(0));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct QueryBuilder {
    route: String,
    reply_route: String,
    timestamp: Timestamp,
    query: Sad,
}

impl QueryBuilder {
    /// Starts a query of `route`, stamped at `timestamp`.
    ///
    /// The timestamp is required for the same reason as on a reply: keripy defaults it to the
    /// system clock, which would make the message and its SAID depend on when it was built.
    #[must_use]
    pub fn new(route: impl Into<String>, timestamp: Timestamp) -> Self {
        Self {
            route: route.into(),
            reply_route: String::new(),
            timestamp,
            query: Sad::new(),
        }
    }

    /// Sets the route the answer should come back on; empty by default, as keripy writes it.
    #[must_use]
    pub fn reply_route(mut self, reply_route: impl Into<String>) -> Self {
        self.reply_route = reply_route.into();
        self
    }

    /// Sets the query block; empty by default.
    #[must_use]
    pub fn query(mut self, query: Sad) -> Self {
        self.query = query;
        self
    }

    /// Validates the routes and serializes the message.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::RouteTooLong`] for either route above [`MAX_ROUTE_BYTES`], and
    /// layered [`EventError::Said`], [`EventError::Sad`] or [`EventError::Serialization`]
    /// failures when the block cannot be encoded.
    pub fn build(self) -> Result<QueryMessage, EventError> {
        for route in [&self.route, &self.reply_route] {
            if route.len() > MAX_ROUTE_BYTES {
                return Err(EventError::RouteTooLong { length: route.len() });
            }
        }

        let mut fields = Sad::new();
        let mut insert = |label: &str, value: SadValue| -> Result<(), EventError> {
            fields.insert(label.to_owned(), value).map_err(EventError::sad)
        };
        insert(VERSION_LABEL, SadValue::text("KERI10JSON000000_"))?;
        insert(KIND_LABEL, SadValue::text(EventKind::Query.as_str()))?;
        insert(SAID_LABEL, SadValue::text(""))?;
        insert(TIMESTAMP_LABEL, SadValue::text(self.timestamp.as_str()))?;
        insert(ROUTE_LABEL, SadValue::Text(self.route))?;
        insert(REPLY_ROUTE_LABEL, SadValue::Text(self.reply_route))?;
        insert(QUERY_LABEL, SadValue::Map(self.query))?;

        let computation =
            Said::compute(&fields, DigestAlgorithm::Blake3_256, DEFAULT_SAID_LABEL).map_err(EventError::said)?;
        let (said, completed) = computation.into_parts();
        let serialized = SerializedEvent::from_sad(completed).map_err(EventError::serialization)?;
        Ok(QueryMessage {
            serialized,
            said,
            timestamp: self.timestamp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const STAMP: &str = "2021-01-01T00:00:00.000000+00:00";
    const IDENTIFIER: &str = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";
    const WITNESS: &str = "BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";

    fn arguments() -> Result<QueryArguments, Box<dyn Error>> {
        Ok(QueryArguments::new(
            IdentifierPrefix::from_qb64(IDENTIFIER)?,
            IdentifierPrefix::from_qb64(WITNESS)?,
        ))
    }

    fn query(route: &str, arguments: QueryArguments) -> Result<QueryMessage, Box<dyn Error>> {
        Ok(QueryBuilder::new(route, Timestamp::parse(STAMP)?)
            .query(arguments.into_sad()?)
            .build()?)
    }

    #[test]
    fn field_order_is_the_protocol_order() -> Result<(), Box<dyn Error>> {
        let query = query("logs", arguments()?)?;
        let labels: Vec<&str> = query.sad().entries().map(|(label, _)| label).collect();
        assert_eq!(labels, FIELD_LABELS);
        assert_eq!(query.sad().get_text("t"), Some("qry"));
        assert_eq!(query.reply_route(), "");
        assert_eq!(query.timestamp().as_str(), STAMP);
        Ok(())
    }

    #[test]
    fn the_query_block_is_written_in_keripy_order() -> Result<(), Box<dyn Error>> {
        let mut anchor = Sad::new();
        anchor.insert("i", SadValue::text(IDENTIFIER))?;
        let mut topics = Sad::new();
        topics.insert("/receipt", SadValue::integer(0)?)?;
        let block = arguments()?
            .sequence_number(5)
            .first_seen(2)
            .anchor(anchor)
            .topics(topics)
            .into_sad()?;
        let keys: Vec<&str> = block.entries().map(|(key, _)| key).collect();
        assert_eq!(keys, ["s", "fn", "a", "topics", "i", "src"]);
        assert_eq!(block.get_text("s"), Some("5"));
        assert_eq!(block.get_text("fn"), Some("2"));

        let bare = arguments()?.into_sad()?;
        let keys: Vec<&str> = bare.entries().map(|(key, _)| key).collect();
        assert_eq!(keys, ["i", "src"]);
        Ok(())
    }

    #[test]
    fn a_built_query_reads_back_into_itself() -> Result<(), Box<dyn Error>> {
        let query = query("ksn", arguments()?.sequence_number(10))?;
        let read = QueryMessage::from_serialized(SerializedEvent::parse(query.raw())?)?;
        assert_eq!(read, query);
        assert_eq!(read.route(), "ksn");
        let arguments = read.arguments()?;
        assert_eq!(arguments.sequence_floor(), Some(10));
        assert_eq!(arguments.first_seen_floor(), None);
        assert_eq!(arguments.identifier().qb64()?, IDENTIFIER);
        assert_eq!(arguments.source().qb64()?, WITNESS);
        Ok(())
    }

    #[test]
    fn unknown_query_keys_are_kept_but_not_typed() -> Result<(), Box<dyn Error>> {
        let mut block = Sad::new();
        block.insert("pre", SadValue::text(IDENTIFIER))?;
        block.insert("i", SadValue::text(IDENTIFIER))?;
        block.insert("src", SadValue::text(WITNESS))?;
        let query = QueryBuilder::new("mbx", Timestamp::parse(STAMP)?)
            .query(block)
            .build()?;
        assert_eq!(query.query().get_text("pre"), Some(IDENTIFIER));
        assert!(query.arguments()?.mailbox_topics().is_none());
        Ok(())
    }

    #[test]
    fn other_messages_other_layouts_and_bad_saids_are_refused() -> Result<(), Box<dyn Error>> {
        let query = query("logs", arguments()?)?;

        let mut wrong_kind = Sad::new();
        for (label, value) in query.sad().entries() {
            wrong_kind.insert(
                label,
                if label == "t" {
                    SadValue::text("rpy")
                } else {
                    value.clone()
                },
            )?;
        }
        let event = SerializedEvent::from_sad(wrong_kind)?;
        assert!(matches!(
            QueryMessage::from_serialized(event),
            Err(EventError::UnexpectedKind { expected: EventKind::Query, found }) if found == "rpy"
        ));

        let mut extra = query.sad().clone();
        extra.insert("x", SadValue::text("y"))?;
        let event = SerializedEvent::from_sad(extra)?;
        assert!(matches!(
            QueryMessage::from_serialized(event),
            Err(EventError::UnexpectedFieldLayout { .. })
        ));

        let mut tampered = Sad::new();
        for (label, value) in query.sad().entries() {
            tampered.insert(
                label,
                if label == "r" {
                    SadValue::text("ksn")
                } else {
                    value.clone()
                },
            )?;
        }
        let event = SerializedEvent::from_sad(tampered)?;
        assert!(matches!(
            QueryMessage::from_serialized(event),
            Err(EventError::Said { .. })
        ));

        let mut no_source = Sad::new();
        no_source.insert("i", SadValue::text(IDENTIFIER))?;
        let query = QueryBuilder::new("logs", Timestamp::parse(STAMP)?)
            .query(no_source)
            .build()?;
        assert!(matches!(
            query.arguments(),
            Err(EventError::MissingQueryKey { key: "src" })
        ));

        let long = "x".repeat(MAX_ROUTE_BYTES + 1);
        assert!(matches!(
            QueryBuilder::new("logs", Timestamp::parse(STAMP)?)
                .reply_route(long)
                .build(),
            Err(EventError::RouteTooLong { .. })
        ));
        Ok(())
    }
}
