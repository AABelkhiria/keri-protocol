//! Microbenchmarks for message-stream parsing.
//!
//! A witness, watcher or agent parses every message it receives before it can decide anything
//! about it, over input an attacker controls. The composed message is the same inception event
//! the attachment benchmarks use, with the group counts a receipted event carries in practice.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use keri_cesr::crypto::signature::{IndexedSignature, UnindexedSignature};
use keri_cesr::crypto::verifier::VerificationKey;
use keri_protocol::attachment::{AttachmentFraming, ReceiptCouple, SignedMessage, SignedMessageBuilder};
use keri_protocol::serialization::SerializedEvent;
use keri_protocol::stream::{Message, parse_stream};

const EVENT: &str = concat!(
    r#"{"v":"KERI10JSON000125_","t":"icp","d":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","#,
    r#""i":"EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL","s":"0","kt":1,"#,
    r#""k":["DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":1,"#,
    r#""n":["EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"],"bt":0,"b":[],"c":[],"a":[]}"#
);
const SIGNATURE: &str = "AABB3MJGmBXxSEryNHw3YwZZLRl_6Ws4Me2WFq8PrQ6WlluSOpPqbwXuiG9RvNWZkqeW8A_0VRjokGMVRZ3m-c0I";
const WITNESS_KEY: &str = "BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
const WITNESS_SIGNATURE: &str =
    "AACeNL17UI34xJZBhC7GUkw8SoJoCIVSx4Kv6tHVroHY7AvRUWIy1bIpzA8VkvxLl6bJxD4Xr4IXiLrTXi66aBcG";
const RECEIPT_SIGNATURE: &str =
    "0BCeNL17UI34xJZBhC7GUkw8SoJoCIVSx4Kv6tHVroHY7AvRUWIy1bIpzA8VkvxLl6bJxD4Xr4IXiLrTXi66aBcG";

/// One signed, receipted event: two controller signatures, three witness signatures, three
/// receipt couples. Returns an empty vector if the pinned material fails to parse, which the
/// first measurement makes obvious.
fn composed(framing: AttachmentFraming) -> Vec<u8> {
    let Ok(event) = SerializedEvent::parse(EVENT.as_bytes()) else {
        return Vec::new();
    };
    let Ok(signature) = IndexedSignature::from_qb64(SIGNATURE) else {
        return Vec::new();
    };
    let Ok(key) = VerificationKey::from_qb64(WITNESS_KEY) else {
        return Vec::new();
    };
    let Ok(witness) = IndexedSignature::from_qb64(WITNESS_SIGNATURE).and_then(|sig| sig.with_verifier(key.clone()))
    else {
        return Vec::new();
    };
    let Ok(receipt) = UnindexedSignature::from_qb64(RECEIPT_SIGNATURE) else {
        return Vec::new();
    };
    let Ok(couple) = ReceiptCouple::new(key, receipt) else {
        return Vec::new();
    };
    SignedMessageBuilder::new(&event)
        .controller_signatures(vec![signature.clone(), signature])
        .witness_signatures(vec![witness.clone(), witness.clone(), witness])
        .receipt_couples(vec![couple.clone(), couple.clone(), couple])
        .framing(framing)
        .build()
        .map(SignedMessage::into_bytes)
        .unwrap_or_default()
}

fn bench_stream(c: &mut Criterion) {
    let plain = composed(AttachmentFraming::Plain);
    let pipelined = composed(AttachmentFraming::Pipelined);
    let stream: Vec<u8> = (0..16).flat_map(|_| plain.clone()).collect();

    c.bench_function("stream/message/plain", |b| {
        b.iter(|| Message::from_bytes(black_box(&plain)));
    });
    c.bench_function("stream/message/pipelined", |b| {
        b.iter(|| Message::from_bytes(black_box(&pipelined)));
    });
    c.bench_function("stream/sixteen-messages", |b| {
        b.iter(|| parse_stream(black_box(&stream)));
    });
}

criterion_group!(benches, bench_stream);
criterion_main!(benches);
