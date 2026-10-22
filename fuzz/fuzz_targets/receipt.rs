#![no_main]
#![forbid(unsafe_code)]

use keri_protocol::event::receipt::{ReceiptBuilder, ReceiptMessage};
use keri_protocol::serialization::SerializedEvent;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Anything the generic parser accepts is either a receipt the reader reads whole, or refused;
    // a receipt it reads must rebuild to the same bytes from what it read.
    if let Ok(event) = SerializedEvent::parse(data) {
        let raw = event.raw().to_vec();
        if let Ok(receipt) = ReceiptMessage::from_serialized(event) {
            assert_eq!(receipt.raw(), raw, "a read receipt does not hold its own bytes");
            match ReceiptBuilder::new(receipt.identifier().clone(), receipt.sequence_number(), receipt.said()).build() {
                Ok(rebuilt) => assert_eq!(rebuilt.raw(), raw, "a receipt did not rebuild from what was read"),
                Err(error) => panic!("a read receipt failed to rebuild: {error}"),
            }
        }
    }
});
