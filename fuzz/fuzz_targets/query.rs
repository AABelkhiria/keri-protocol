#![no_main]
#![forbid(unsafe_code)]

use keri_protocol::event::query::{QueryBuilder, QueryMessage};
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::serialization::{Sad, SerializedEvent};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Anything the generic parser accepts is either a query the reader reads whole, with a SAID
    // that verifies, or refused; a query it reads must rebuild to the same bytes.
    if let Ok(event) = SerializedEvent::parse(data) {
        let raw = event.raw().to_vec();
        if let Ok(query) = QueryMessage::from_serialized(event) {
            assert_eq!(query.raw(), raw, "a read query does not hold its own bytes");
            let rebuilt = QueryBuilder::new(query.route(), query.timestamp().clone())
                .reply_route(query.reply_route())
                .query(query.query().clone())
                .build();
            match rebuilt {
                Ok(rebuilt) => assert_eq!(rebuilt.raw(), raw, "a query did not rebuild from what was read"),
                Err(error) => panic!("a read query failed to rebuild: {error}"),
            }
            // The typed view never panics on an arbitrary block.
            let _ = query.arguments();
        }
    }

    // A hostile query block is either serialized whole or refused, never mangled.
    if let Ok(block) = Sad::from_json_bytes(data) {
        let Ok(stamp) = Timestamp::parse("2021-01-01T00:00:00.000000+00:00") else {
            return;
        };
        if let Ok(query) = QueryBuilder::new("logs", stamp).query(block.clone()).build() {
            assert_eq!(query.query(), &block, "a query block was not written verbatim");
            assert_eq!(query.serialized().size(), query.raw().len());
        }
    }
});
