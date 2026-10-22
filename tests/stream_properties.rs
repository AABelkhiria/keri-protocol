//! Property and invalid-near-miss coverage for message-stream parsing.

use keri_cesr::crypto::signature::{IndexedSignature, UnindexedSignature};
use keri_cesr::crypto::verifier::VerificationKey;
use keri_cesr::sequence::SequenceNumber;
use keri_protocol::attachment::{AttachmentFraming, ReceiptCouple, SignatureSeal, SignedMessageBuilder};
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::serialization::SerializedEvent;
use keri_protocol::stream::{Message, StreamError, TransferableSignatureGroup, parse_stream};
use proptest::{prelude::*, test_runner::TestCaseError};

const EVENT: &str = concat!(
    r#"{"v":"KERI10JSON000125_","t":"icp","d":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","#,
    r#""i":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","s":"0","kt":1,"#,
    r#""k":["DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":1,"#,
    r#""n":["EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"],"bt":0,"b":[],"c":[],"a":[]}"#
);
const SIGNATURE: &str = "AABB3MJGmBXxSEryNHw3YwZZLRl_6Ws4Me2WFq8PrQ6WlluSOpPqbwXuiG9RvNWZkqeW8A_0VRjokGMVRZ3m-c0I";
const IDENTIFIER: &str = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";
/// Witness material from `fixtures/attachment-keripy/v1.json`.
const WITNESS_KEY: &str = "BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
const WITNESS_SIGNATURE: &str =
    "AACeNL17UI34xJZBhC7GUkw8SoJoCIVSx4Kv6tHVroHY7AvRUWIy1bIpzA8VkvxLl6bJxD4Xr4IXiLrTXi66aBcG";
const RECEIPT_SIGNATURE: &str =
    "0BCeNL17UI34xJZBhC7GUkw8SoJoCIVSx4Kv6tHVroHY7AvRUWIy1bIpzA8VkvxLl6bJxD4Xr4IXiLrTXi66aBcG";

fn fail<T, E: core::fmt::Display>(result: Result<T, E>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn witness_signature() -> Result<IndexedSignature, TestCaseError> {
    let key = fail(VerificationKey::from_qb64(WITNESS_KEY))?;
    fail(fail(IndexedSignature::from_qb64(WITNESS_SIGNATURE))?.with_verifier(key))
}

fn receipt_couple() -> Result<ReceiptCouple, TestCaseError> {
    let key = fail(VerificationKey::from_qb64(WITNESS_KEY))?;
    fail(ReceiptCouple::new(
        key,
        fail(UnindexedSignature::from_qb64(RECEIPT_SIGNATURE))?,
    ))
}

/// The shape of one composed message: how many of each group, which seal, which framing.
#[derive(Clone, Debug)]
struct Shape {
    controller: usize,
    witness: usize,
    receipts: usize,
    seal: Option<(bool, u128)>,
    pipelined: bool,
}

fn shape_strategy() -> impl Strategy<Value = Shape> {
    (
        0_usize..=5,
        0_usize..=3,
        0_usize..=3,
        prop_oneof![
            Just(None),
            (any::<bool>(), 0_u128..=u128::from(u32::MAX)).prop_map(Some)
        ],
        any::<bool>(),
    )
        .prop_filter(
            "a message needs at least one signature group",
            |(controller, witness, receipts, seal, _)| {
                controller + witness + receipts > 0 && (seal.is_none() || *controller > 0)
            },
        )
        .prop_map(|(controller, witness, receipts, seal, pipelined)| Shape {
            controller,
            witness,
            receipts,
            seal,
            pipelined,
        })
}

fn compose(shape: &Shape) -> Result<Vec<u8>, TestCaseError> {
    let event = fail(SerializedEvent::parse(EVENT.as_bytes()))?;
    let signature = fail(IndexedSignature::from_qb64(SIGNATURE))?;
    let identifier = fail(IdentifierPrefix::from_qb64(IDENTIFIER))?;
    let said = fail(Said::from_qb64(IDENTIFIER))?;
    let mut builder = SignedMessageBuilder::new(&event)
        .controller_signatures(core::iter::repeat_n(signature, shape.controller).collect())
        .witness_signatures(core::iter::repeat_n(witness_signature()?, shape.witness).collect())
        .receipt_couples(core::iter::repeat_n(receipt_couple()?, shape.receipts).collect())
        .framing(if shape.pipelined {
            AttachmentFraming::Pipelined
        } else {
            AttachmentFraming::Plain
        });
    if let Some((last, sequence_number)) = shape.seal {
        builder = builder.seal(if last {
            SignatureSeal::Last { identifier }
        } else {
            SignatureSeal::Event {
                identifier,
                sequence_number: SequenceNumber::new(sequence_number),
                said,
            }
        });
    }
    Ok(fail(builder.build())?.into_bytes())
}

/// Checks that one parsed message carries exactly the groups `shape` composed.
fn check(message: &Message, shape: &Shape) -> Result<(), TestCaseError> {
    let attachments = message.attachments();
    prop_assert_eq!(message.event().raw(), EVENT.as_bytes());
    prop_assert_eq!(
        attachments.framing(),
        if shape.pipelined {
            AttachmentFraming::Pipelined
        } else {
            AttachmentFraming::Plain
        }
    );
    match shape.seal {
        None => {
            prop_assert_eq!(attachments.controller_signatures().len(), shape.controller);
            prop_assert!(attachments.transferable_signature_groups().is_empty());
            prop_assert!(attachments.last_establishment_signature_groups().is_empty());
        }
        Some((true, _)) => {
            let groups = attachments.last_establishment_signature_groups();
            prop_assert_eq!(groups.len(), 1);
            prop_assert_eq!(
                groups.first().map(|group| group.signatures().len()),
                Some(shape.controller)
            );
            prop_assert!(attachments.controller_signatures().is_empty());
        }
        Some((false, sequence_number)) => {
            let groups = attachments.transferable_signature_groups();
            prop_assert_eq!(groups.len(), 1);
            prop_assert_eq!(
                groups.first().map(|group| group.signatures().len()),
                Some(shape.controller)
            );
            prop_assert_eq!(
                groups.first().map(TransferableSignatureGroup::sequence_number),
                Some(SequenceNumber::new(sequence_number))
            );
            prop_assert!(attachments.controller_signatures().is_empty());
        }
    }
    prop_assert_eq!(attachments.witness_signatures().len(), shape.witness);
    prop_assert_eq!(attachments.receipt_couples().len(), shape.receipts);
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Whatever the builder composes, the parser reads back group for group, and the raw halves
    /// it reports reassemble into the input.
    #[test]
    fn every_composed_message_parses_back(shape in shape_strategy()) {
        let bytes = compose(&shape)?;
        let message = fail(Message::from_bytes(&bytes))?;
        check(&message, &shape)?;
        let reassembled = [message.event().raw(), message.attachments().raw()].concat();
        prop_assert_eq!(reassembled, bytes);
    }

    /// A stream of composed messages splits at every message boundary, in order.
    #[test]
    fn a_stream_splits_into_its_messages(shapes in prop::collection::vec(shape_strategy(), 1..=4)) {
        let mut stream = Vec::new();
        for shape in &shapes {
            stream.extend_from_slice(&compose(shape)?);
        }
        let messages = fail(parse_stream(&stream))?;
        prop_assert_eq!(messages.len(), shapes.len());
        for (message, shape) in messages.iter().zip(&shapes) {
            check(message, shape)?;
        }
    }

    /// Cutting a valid message anywhere never panics: a cut inside the event or a group is a
    /// truncation, and a cut exactly between groups leaves a shorter but valid message.
    #[test]
    fn a_truncated_message_is_refused_or_shortened(shape in shape_strategy(), cut in 0_usize..=400) {
        let bytes = compose(&shape)?;
        let cut = cut.min(bytes.len());
        let prefix = bytes.get(..cut).unwrap_or_default();
        match Message::parse(prefix) {
            Ok(parsed) => {
                prop_assert_eq!(parsed.consumed(), cut, "a successful parse consumes the whole prefix");
                prop_assert!(cut >= EVENT.len());
            }
            Err(StreamError::Truncated { .. } | StreamError::EmptyInput) => {}
            Err(error) => return Err(TestCaseError::fail(format!("unexpected error {error}"))),
        }
    }

    /// Arbitrary bytes never panic the parser.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=256)) {
        let _ = parse_stream(&bytes);
        let _ = Message::parse(&bytes);
    }

    /// Arbitrary text after a valid event never panics either, and only a counter or a message
    /// may follow an event.
    #[test]
    fn arbitrary_text_after_an_event_is_refused_cleanly(
        suffix in "[A-Za-z0-9_-]{0,96}",
    ) {
        let mut stream = EVENT.as_bytes().to_vec();
        stream.extend_from_slice(suffix.as_bytes());
        match Message::parse(&stream) {
            Ok(_) => prop_assert!(suffix.is_empty() || suffix.starts_with('-')),
            Err(StreamError::UnexpectedStreamStart { .. }) => prop_assert!(!suffix.starts_with('-')),
            Err(_) => prop_assert!(suffix.starts_with('-')),
        }
    }
}
