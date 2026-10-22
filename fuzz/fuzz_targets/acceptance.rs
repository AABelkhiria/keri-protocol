#![no_main]
#![forbid(unsafe_code)]

use keri_protocol::event::reply::ReplyMessage;
use keri_protocol::event::reply::acceptance::{AcceptedReply, SignerEvents, accept};
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::serialization::SerializedEvent;
use keri_protocol::stream::Message;
use libfuzzer_sys::fuzz_target;

/// The inception event pinned across the crate's fixtures, standing in for every signer's log.
const EVENT: &str = concat!(
    r#"{"v":"KERI10JSON000125_","t":"icp","d":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","#,
    r#""i":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","s":"0","kt":1,"#,
    r#""k":["DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":1,"#,
    r#""n":["EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"],"bt":0,"b":[],"c":[],"a":[]}"#
);

struct OneEvent(Option<SerializedEvent>);

impl SignerEvents for OneEvent {
    fn event_at(&self, _signer: &IdentifierPrefix, sequence_number: u128) -> Option<SerializedEvent> {
        if sequence_number == 0 { self.0.clone() } else { None }
    }
}

fuzz_target!(|data: &[u8]| {
    // A signed reply from anyone: the decision never panics, and whatever it accepts it accepts on
    // the strength of a signature, never of an empty attachment list.
    let events = OneEvent(SerializedEvent::parse(EVENT.as_bytes()).ok());
    if let Ok(message) = Message::from_bytes(data)
        && let Ok(reply) = ReplyMessage::from_serialized(message.event().clone())
    {
        let attachments = message.attachments();
        for authority in attachments
            .transferable_signature_groups()
            .iter()
            .map(|group| group.identifier().clone())
            .chain(
                attachments
                    .receipt_couples()
                    .iter()
                    .filter_map(|couple| couple.verifier().qb64().ok())
                    .filter_map(|text| IdentifierPrefix::from_qb64(&text).ok()),
            )
        {
            let prior = AcceptedReply::new(reply.timestamp().clone());
            for prior in [None, Some(&prior)] {
                if let Ok(acceptance) = accept(&reply, attachments, &authority, prior, &events) {
                    if acceptance.is_accepted() {
                        assert!(
                            !attachments.receipt_couples().is_empty()
                                || !attachments.transferable_signature_groups().is_empty(),
                            "a reply with no signatures was accepted"
                        );
                    }
                    if prior.is_some() && attachments.transferable_signature_groups().is_empty() {
                        assert!(
                            !acceptance.is_accepted(),
                            "a reply no newer than its prior was accepted"
                        );
                    }
                }
            }
        }
    }
});
