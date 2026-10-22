#![no_main]
#![forbid(unsafe_code)]

use keri_protocol::stream::{Attachments, Message, parse_stream};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Whole streams: a successful parse accounts for every byte, and each message re-parses alone.
    if let Ok(messages) = parse_stream(data) {
        let mut reassembled = Vec::new();
        for message in &messages {
            reassembled.extend_from_slice(message.event().raw());
            reassembled.extend_from_slice(message.attachments().raw());
            let alone = [message.event().raw(), message.attachments().raw()].concat();
            match Message::from_bytes(&alone) {
                Ok(again) => assert_eq!(&again, message, "a message did not re-parse to itself"),
                Err(error) => panic!("a parsed message failed to re-parse alone: {error}"),
            }
        }
        assert_eq!(reassembled, data, "a parsed stream does not reassemble into its input");
    }

    // Attachments alone: whatever is consumed must re-parse to the same groups.
    if let Ok(parsed) = Attachments::parse(data) {
        let consumed = data.get(..parsed.consumed()).unwrap_or_default();
        match Attachments::from_bytes(consumed) {
            Ok(again) => assert_eq!(
                &again,
                parsed.attachments(),
                "attachments did not re-parse to themselves"
            ),
            Err(error) => panic!("consumed attachments failed to re-parse: {error}"),
        }
    }
});
