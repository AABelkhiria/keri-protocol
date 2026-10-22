//! Property coverage for best-available-data acceptance.

use keri_cesr::crypto::signer::Signer;
use keri_cesr::crypto::verifier::KeyTransferability;
use keri_cesr::sequence::SequenceNumber;
use keri_protocol::attachment::{ReceiptCouple, SignatureSeal, SignedMessageBuilder};
use keri_protocol::event::reply::acceptance::{AcceptedReply, Escrow, Outcome, SignerEvents, Skip, accept};
use keri_protocol::event::reply::{ReplyBuilder, ReplyMessage};
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::Said;
use keri_protocol::serialization::SerializedEvent;
use keri_protocol::stream::Message;
use proptest::{prelude::*, test_runner::TestCaseError};

const IDENTIFIER: &str = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";

fn fail<T, E: core::fmt::Display>(result: Result<T, E>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn stamp(second: u8) -> Result<Timestamp, TestCaseError> {
    fail(Timestamp::parse(&format!("2021-01-01T00:00:{second:02}.000000+00:00")))
}

fn reply(second: u8) -> Result<ReplyMessage, TestCaseError> {
    fail(ReplyBuilder::new("/loc/scheme", stamp(second)?).build())
}

/// No signer's log is known, so every transferable group that passes the staleness rules escrows.
struct NoEvents;

impl SignerEvents for NoEvents {
    fn event_at(&self, _signer: &IdentifierPrefix, _sequence_number: u128) -> Option<SerializedEvent> {
        None
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(160))]

    /// A non-transferable reply replaces its prior exactly when its timestamp is later, and only
    /// when signed by the authority itself.
    #[test]
    fn a_non_transferable_reply_is_newer_only_when_later(
        new in 0_u8..60,
        prior in prop::option::of(0_u8..60),
        seed in any::<[u8; 32]>(),
        by_authority in any::<bool>(),
    ) {
        let signer = fail(Signer::from_seed(&seed, KeyTransferability::NonTransferable))?;
        let other = fail(Signer::from_seed(&[seed[0] ^ 0xff; 32], KeyTransferability::NonTransferable))?;
        let message = reply(new)?;
        let signature = fail(signer.sign_unindexed(message.raw()))?;
        let couple = fail(ReceiptCouple::new(signer.verifier().clone(), signature))?;
        let bytes = fail(SignedMessageBuilder::new(message.serialized()).receipt_couples(vec![couple]).build())?;
        let parsed = fail(Message::from_bytes(bytes.as_bytes()))?;
        let authority = if by_authority { signer.verifier() } else { other.verifier() };
        let authority = fail(IdentifierPrefix::from_qb64(&fail(authority.qb64())?))?;
        let prior = prior.map(|second| stamp(second).map(AcceptedReply::new)).transpose()?;

        let acceptance = fail(accept(&message, parsed.attachments(), &authority, prior.as_ref(), &NoEvents))?;
        let expected = if !by_authority {
            Outcome::Skipped(Skip::NotFromAuthority)
        } else if prior.as_ref().is_some_and(|prior| message.timestamp() <= prior.timestamp()) {
            Outcome::Skipped(Skip::Stale)
        } else {
            Outcome::Accepted
        };
        prop_assert_eq!(acceptance.couples(), [expected]);
    }

    /// A transferable reply is stale when it names an earlier establishment event than its prior,
    /// or the same one at a time no later; otherwise it goes on to the signer's log, which here is
    /// unknown, so it escrows.
    #[test]
    fn a_transferable_reply_is_ordered_by_establishment_then_time(
        new_second in 0_u8..60,
        new_event in 0_u128..4,
        prior in prop::option::of((0_u8..60, prop::option::of(0_u128..4))),
    ) {
        let message = reply(new_second)?;
        let identifier = fail(IdentifierPrefix::from_qb64(IDENTIFIER))?;
        let signer = fail(Signer::from_seed(&[7; 32], KeyTransferability::Transferable))?;
        let signature = fail(signer.sign_indexed(
            message.raw(),
            keri_cesr::crypto::signer::SignaturePlacement::both_lists(0),
        ))?;
        let bytes = fail(
            SignedMessageBuilder::new(message.serialized())
                .controller_signatures(vec![signature])
                .seal(SignatureSeal::Event {
                    identifier: identifier.clone(),
                    sequence_number: SequenceNumber::new(new_event),
                    said: fail(Said::from_qb64(IDENTIFIER))?,
                })
                .build(),
        )?;
        let parsed = fail(Message::from_bytes(bytes.as_bytes()))?;
        let prior = prior
            .map(|(second, event)| -> Result<AcceptedReply, TestCaseError> {
                let accepted = AcceptedReply::new(stamp(second)?);
                Ok(match event {
                    Some(event) => accepted.signed_at(event),
                    None => accepted,
                })
            })
            .transpose()?;

        let acceptance = fail(accept(&message, parsed.attachments(), &identifier, prior.as_ref(), &NoEvents))?;
        let stale = prior.as_ref().is_some_and(|prior| match prior.establishment() {
            Some(event) => new_event < event || (new_event == event && message.timestamp() <= prior.timestamp()),
            None => false,
        });
        let expected = if stale {
            Outcome::Skipped(Skip::Stale)
        } else {
            Outcome::Escrowed(Escrow::MissingEstablishment)
        };
        prop_assert_eq!(acceptance.groups(), [expected]);
        prop_assert!(!acceptance.is_accepted());
    }
}
