//! Property and invalid-near-miss coverage for receipt messages.

use keri_protocol::event::EventError;
use keri_protocol::event::receipt::{FIELD_LABELS, ReceiptBuilder, ReceiptMessage};
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::serialization::{Sad, SadValue, SerializedEvent};
use proptest::{prelude::*, test_runner::TestCaseError};

const IDENTIFIER: &str = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";
const BASIC_IDENTIFIER: &str = "BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
const EVENT_SAID: &str = "EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W";

fn fail<T, E: core::fmt::Display>(result: Result<T, E>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn sequence_strategy() -> impl Strategy<Value = u128> {
    prop_oneof![
        0_u128..=16,
        0_u128..=u128::from(u32::MAX),
        0_u128..=u128::from(u64::MAX),
        any::<u128>(),
        Just(u128::MAX),
    ]
}

/// Copies a message's fields with its kind replaced.
fn with_kind(sad: &Sad, kind: &str) -> Result<Sad, TestCaseError> {
    let mut copy = Sad::new();
    for (label, value) in sad.entries() {
        let value = if label == "t" {
            SadValue::text(kind)
        } else {
            value.clone()
        };
        fail(copy.insert(label, value))?;
    }
    Ok(copy)
}

fn identifier_strategy() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just(IDENTIFIER), Just(BASIC_IDENTIFIER)]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(192))]

    /// Every receipt reads back into itself through the generic parser, and its sequence number
    /// is written as lowercase hexadecimal without leading zeros.
    #[test]
    fn a_receipt_reads_back_into_itself(sequence_number in sequence_strategy(), identifier in identifier_strategy()) {
        let receipt = fail(
            ReceiptBuilder::new(fail(IdentifierPrefix::from_qb64(identifier))?, sequence_number, fail(Said::from_qb64(EVENT_SAID))?)
                .build(),
        )?;
        let expected_hex = format!("{sequence_number:x}");
        prop_assert_eq!(receipt.sad().get_text("s"), Some(expected_hex.as_str()));
        prop_assert_eq!(receipt.serialized().size(), receipt.raw().len());
        let labels: Vec<&str> = receipt.sad().entries().map(|(label, _)| label).collect();
        prop_assert_eq!(labels, FIELD_LABELS);

        let read = fail(ReceiptMessage::from_serialized(fail(SerializedEvent::parse(receipt.raw()))?))?;
        prop_assert_eq!(&read, &receipt);
        prop_assert_eq!(read.sequence_number(), sequence_number);
        prop_assert_eq!(fail(read.identifier().qb64())?, identifier);
    }

    /// Any other message kind, or a receipt with a field added, removed or reordered, is refused
    /// with the error that names what was wrong.
    #[test]
    fn near_misses_are_refused(
        sequence_number in sequence_strategy(),
        extra_label in "[a-z]{1,4}",
        kind in prop_oneof![Just("icp"), Just("ixn"), Just("rpy"), Just("vrc"), Just("qry")],
    ) {
        let receipt = fail(
            ReceiptBuilder::new(fail(IdentifierPrefix::from_qb64(IDENTIFIER))?, sequence_number, fail(Said::from_qb64(EVENT_SAID))?)
                .build(),
        )?;

        let event = fail(SerializedEvent::from_sad(with_kind(receipt.sad(), kind)?))?;
        let refused_kind = matches!(ReceiptMessage::from_serialized(event), Err(EventError::UnexpectedKind { .. }));
        prop_assert!(refused_kind, "kind {} was read as a receipt", kind);

        if !FIELD_LABELS.contains(&extra_label.as_str()) {
            let mut extra = receipt.sad().clone();
            fail(extra.insert(extra_label.clone(), SadValue::text("x")))?;
            let event = fail(SerializedEvent::from_sad(extra))?;
            let refused_layout =
                matches!(ReceiptMessage::from_serialized(event), Err(EventError::UnexpectedFieldLayout { .. }));
            prop_assert!(refused_layout, "extra field {} was accepted", extra_label);
        }
    }
}
