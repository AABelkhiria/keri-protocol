//! Receipt messages.
//!
//! A receipt (`rct`) is an endorser's acknowledgement of one key event. It names the identifier,
//! sequence number and SAID of the event being receipted and nothing else; who receipted it is in
//! the attachments: witness indexed signatures (`-B`), non-transferable receipt couples (`-C`) or
//! transferable receipt quadruples (`-D`). Its `d` field is the receipted event's SAID, not a SAID
//! of the receipt itself, so two witnesses receipting the same event produce identical bytes and
//! differ only in what they attach.
//!
//! This ports `receipt` from keripy's `src/keri/core/eventing.py`, and the field layout keripy's
//! `SerderKERI` enforces when it reads one back. The pinned signify-ts reference declares the
//! `rct` ilk but never constructs or parses one, because KERIA receipts events on its behalf.
//!
//! A receipt is signed and attached with the same [`SignedMessageBuilder`] as a key event, and read
//! back with [`stream`]: this module builds the message and extracts its fields, nothing more. The
//! checks keripy's `processReceipt` makes, that the named event exists locally and that its SAID
//! matches, belong to a validator that holds a log.
//!
//! [`SignedMessageBuilder`]: crate::attachment::SignedMessageBuilder
//! [`stream`]: crate::stream

use keri_cesr::number::CesrNumber;

use crate::event::error::{EventError, bounded_label};
use crate::event::kind::EventKind;
use crate::prefix::IdentifierPrefix;
use crate::said::Said;
use crate::serialization::{
    IDENTIFIER_LABEL, KIND_LABEL, SAID_LABEL, SEQUENCE_LABEL, Sad, SadValue, SerializedEvent, VERSION_LABEL,
};

/// The field labels of a receipt, in protocol order.
pub const FIELD_LABELS: [&str; 5] = [VERSION_LABEL, KIND_LABEL, SAID_LABEL, IDENTIFIER_LABEL, SEQUENCE_LABEL];

/// A receipt message, built here or read from a stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptMessage {
    serialized: SerializedEvent,
    identifier: IdentifierPrefix,
    sequence_number: u128,
    said: Said,
}

impl ReceiptMessage {
    /// Reads the receipt a parsed message carries.
    ///
    /// The message must be a `rct` with exactly the five receipt fields in protocol order, as
    /// keripy's `SerderKERI` requires: `v`, `t`, `d`, `i`, `s`.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::UnexpectedKind`] when the message is not a receipt,
    /// [`EventError::UnexpectedFieldLayout`] when its fields are not exactly the receipt's, and
    /// layered [`EventError::Prefix`], [`EventError::Said`] or [`EventError::Serialization`]
    /// failures when a field holds malformed material.
    pub fn from_serialized(serialized: SerializedEvent) -> Result<Self, EventError> {
        let kind = serialized.sad().get_text(KIND_LABEL).unwrap_or_default();
        if kind != EventKind::Receipt.as_str() {
            return Err(EventError::UnexpectedKind {
                expected: EventKind::Receipt,
                found: bounded_label(kind),
            });
        }
        let labels: Vec<&str> = serialized.sad().entries().map(|(label, _)| label).collect();
        if labels != FIELD_LABELS {
            return Err(EventError::UnexpectedFieldLayout {
                expected: "v, t, d, i, s",
                found: bounded_label(&labels.join(", ")),
            });
        }
        let identifier = serialized
            .identifier_prefix()
            .ok_or(EventError::UnexpectedFieldLayout {
                expected: "v, t, d, i, s",
                found: bounded_label("i is not text"),
            })
            .and_then(|text| IdentifierPrefix::from_qb64(text).map_err(EventError::prefix))?;
        let said = serialized
            .said()
            .ok_or(EventError::UnexpectedFieldLayout {
                expected: "v, t, d, i, s",
                found: bounded_label("d is not text"),
            })
            .and_then(|text| Said::from_qb64(text).map_err(EventError::said))?;
        let sequence_number = serialized
            .sequence_number()
            .map_err(EventError::serialization)?
            .ok_or(EventError::UnexpectedFieldLayout {
                expected: "v, t, d, i, s",
                found: bounded_label("s is not text"),
            })?
            .value();
        Ok(Self {
            serialized,
            identifier,
            sequence_number,
            said,
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

    /// Returns the identifier whose event is receipted.
    #[must_use]
    pub const fn identifier(&self) -> &IdentifierPrefix {
        &self.identifier
    }

    /// Returns the sequence number of the receipted event.
    #[must_use]
    pub const fn sequence_number(&self) -> u128 {
        self.sequence_number
    }

    /// Returns the SAID of the receipted event.
    ///
    /// This is the receipt's `d` field. It identifies the event, not the receipt, so it is not
    /// verifiable against the receipt's own bytes.
    #[must_use]
    pub const fn said(&self) -> Said {
        self.said
    }

    /// Takes the serialized message out.
    #[must_use]
    pub fn into_serialized(self) -> SerializedEvent {
        self.serialized
    }
}

/// Builds a receipt (`rct`) message for one key event.
///
/// ```
/// use keri_protocol::event::receipt::ReceiptBuilder;
/// use keri_protocol::prefix::IdentifierPrefix;
/// use keri_protocol::said::Said;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let identifier = IdentifierPrefix::from_qb64("EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL")?;
/// let said = Said::from_qb64("EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL")?;
/// let receipt = ReceiptBuilder::new(identifier, 0, said).build()?;
///
/// assert_eq!(receipt.sequence_number(), 0);
/// assert_eq!(receipt.sad().get_text("t"), Some("rct"));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct ReceiptBuilder {
    identifier: IdentifierPrefix,
    sequence_number: u128,
    said: Said,
}

impl ReceiptBuilder {
    /// Starts a receipt of the event `said` at `sequence_number` in `identifier`'s log.
    #[must_use]
    pub const fn new(identifier: IdentifierPrefix, sequence_number: u128, said: Said) -> Self {
        Self {
            identifier,
            sequence_number,
            said,
        }
    }

    /// Serializes the message.
    ///
    /// # Errors
    ///
    /// Returns layered [`EventError::Prefix`], [`EventError::Said`], [`EventError::Sad`] or
    /// [`EventError::Serialization`] failures when a field cannot be encoded.
    pub fn build(self) -> Result<ReceiptMessage, EventError> {
        let mut fields = Sad::new();
        let mut insert = |label: &str, value: SadValue| -> Result<(), EventError> {
            fields.insert(label.to_owned(), value).map_err(EventError::sad)
        };
        insert(VERSION_LABEL, SadValue::text("KERI10JSON000000_"))?;
        insert(KIND_LABEL, SadValue::text(EventKind::Receipt.as_str()))?;
        insert(SAID_LABEL, SadValue::Text(self.said.qb64().map_err(EventError::said)?))?;
        insert(
            IDENTIFIER_LABEL,
            SadValue::Text(self.identifier.qb64().map_err(EventError::prefix)?),
        )?;
        insert(
            SEQUENCE_LABEL,
            SadValue::Text(CesrNumber::new(self.sequence_number).hex()),
        )?;

        let serialized = SerializedEvent::from_sad(fields).map_err(EventError::serialization)?;
        Ok(ReceiptMessage {
            serialized,
            identifier: self.identifier,
            sequence_number: self.sequence_number,
            said: self.said,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    const IDENTIFIER: &str = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";
    const EVENT_SAID: &str = "EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W";

    fn receipt(sequence_number: u128) -> Result<ReceiptMessage, Box<dyn Error>> {
        Ok(ReceiptBuilder::new(
            IdentifierPrefix::from_qb64(IDENTIFIER)?,
            sequence_number,
            Said::from_qb64(EVENT_SAID)?,
        )
        .build()?)
    }

    #[test]
    fn field_order_is_the_protocol_order() -> Result<(), Box<dyn Error>> {
        let receipt = receipt(0)?;
        let labels: Vec<&str> = receipt.sad().entries().map(|(label, _)| label).collect();
        assert_eq!(labels, FIELD_LABELS);
        assert_eq!(receipt.sad().get_text("t"), Some("rct"));
        assert_eq!(receipt.sad().get_text("d"), Some(EVENT_SAID));
        assert_eq!(receipt.sad().get_text("i"), Some(IDENTIFIER));
        assert_eq!(receipt.sad().get_text("s"), Some("0"));
        Ok(())
    }

    #[test]
    fn the_sequence_number_is_lowercase_hex_without_leading_zeros() -> Result<(), Box<dyn Error>> {
        for (sequence_number, text) in [(0, "0"), (10, "a"), (255, "ff"), (4096, "1000")] {
            assert_eq!(receipt(sequence_number)?.sad().get_text("s"), Some(text));
        }
        Ok(())
    }

    #[test]
    fn a_built_receipt_reads_back_into_itself() -> Result<(), Box<dyn Error>> {
        let receipt = receipt(42)?;
        let parsed = SerializedEvent::parse(receipt.raw())?;
        let read = ReceiptMessage::from_serialized(parsed)?;
        assert_eq!(read, receipt);
        assert_eq!(read.sequence_number(), 42);
        assert_eq!(read.said().qb64()?, EVENT_SAID);
        assert_eq!(read.identifier().qb64()?, IDENTIFIER);
        Ok(())
    }

    #[test]
    fn other_messages_and_other_layouts_are_refused() -> Result<(), Box<dyn Error>> {
        let receipt = receipt(1)?;

        let mut wrong_kind = receipt.sad().clone();
        wrong_kind.replace_existing(KIND_LABEL, SadValue::text("ixn"))?;
        let event = SerializedEvent::from_sad(wrong_kind)?;
        assert!(matches!(
            ReceiptMessage::from_serialized(event),
            Err(EventError::UnexpectedKind { expected: EventKind::Receipt, found }) if found == "ixn"
        ));

        let mut extra_field = receipt.sad().clone();
        extra_field.insert("a", SadValue::Array(Vec::new()))?;
        let event = SerializedEvent::from_sad(extra_field)?;
        assert!(matches!(
            ReceiptMessage::from_serialized(event),
            Err(EventError::UnexpectedFieldLayout { found, .. }) if found == "v, t, d, i, s, a"
        ));

        let mut bad_said = receipt.sad().clone();
        bad_said.replace_existing(SAID_LABEL, SadValue::text("not-a-said"))?;
        let event = SerializedEvent::from_sad(bad_said)?;
        assert!(matches!(
            ReceiptMessage::from_serialized(event),
            Err(EventError::Said { .. })
        ));

        let mut bad_sequence = receipt.sad().clone();
        bad_sequence.replace_existing(SEQUENCE_LABEL, SadValue::text("zz"))?;
        let event = SerializedEvent::from_sad(bad_sequence)?;
        assert!(matches!(
            ReceiptMessage::from_serialized(event),
            Err(EventError::Serialization { .. })
        ));
        Ok(())
    }
}
