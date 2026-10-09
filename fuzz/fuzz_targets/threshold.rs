#![no_main]
#![forbid(unsafe_code)]

use keri_cesr::bytes::utf8_text;
use keri_protocol::threshold::{RationalWeight, SigningThreshold};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = utf8_text(data) {
        let _ = RationalWeight::parse(text);
        let _ = SigningThreshold::from_sith(text);
        let _ = SigningThreshold::from_json(text);
    }
});
