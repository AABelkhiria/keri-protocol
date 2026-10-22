#![no_main]
#![forbid(unsafe_code)]

use keri_protocol::event::reply::ReplyMessage;
use keri_protocol::event::reply::route::ReplyRoute;
use keri_protocol::serialization::SerializedEvent;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Replies arrive from any actor. Whatever the reader accepts must have a verifying SAID, and a
    // route it reads must rebuild into a reply that reads back to the same route.
    if let Ok(event) = SerializedEvent::parse(data) {
        if let Ok(reply) = ReplyMessage::from_serialized(event) {
            if let Ok(route) = ReplyRoute::from_reply(&reply) {
                match route.to_reply(reply.timestamp().clone()) {
                    Ok(rebuilt) => match ReplyRoute::from_reply(&rebuilt) {
                        Ok(again) => assert_eq!(again, route, "a rebuilt reply read back differently"),
                        Err(error) => panic!("a rebuilt reply failed to read: {error}"),
                    },
                    Err(error) => panic!("a read route failed to rebuild: {error}"),
                }
            }
        }
    }
});
