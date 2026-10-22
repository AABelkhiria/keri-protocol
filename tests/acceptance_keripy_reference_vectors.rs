//! Exact reply-acceptance decisions recorded from the pinned keripy reference.
//!
//! The pinned signify-ts reference never decides whether a reply replaces an older one, so the
//! decision is verified against keripy's `Revery.acceptReply` run over real identifiers. See
//! `fixtures/acceptance-keripy/README.md`.

use std::error::Error;

use keri_protocol::event::EventError;
use keri_protocol::event::reply::ReplyMessage;
use keri_protocol::event::reply::acceptance::{Acceptance, AcceptedReply, Escrow, Outcome, SignerEvents, Skip, accept};
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::serialization::SerializedEvent;
use keri_protocol::stream::Message;
use serde::Deserialize;

const REFERENCE_SHA: &str = "4ce4cc79e06653f77342be1bf604086b89b1f090";

#[derive(Debug, Deserialize)]
struct Fixture {
    schema_version: u8,
    upstream: String,
    reference_sha: String,
    reference_version: String,
    generated_on: String,
    sources: Vec<String>,
    signer_events: Vec<SignerEvent>,
    inception_said: String,
    cases: Vec<Case>,
    reference_quirk_index_out_of_range: QuirkCase,
}

#[derive(Debug, Deserialize)]
struct SignerEvent {
    identifier: String,
    sequence_number: u128,
    said: String,
    raw: String,
}

#[derive(Debug, Deserialize)]
struct Case {
    name: String,
    authority: String,
    prior: Option<Signed>,
    new: Signed,
    keripy: Keripy,
    rust_outcome: Option<String>,
    rust_error_category: Option<String>,
}

#[derive(Debug, Deserialize)]
struct QuirkCase {
    name: String,
    authority: String,
    new: Signed,
    keripy: Keripy,
    rust_error_category: Option<String>,
    note: String,
}

#[derive(Debug, Deserialize)]
struct Signed {
    raw: String,
    raw_hex: String,
    timestamp: String,
    establishment: Option<u128>,
}

#[derive(Debug, Deserialize)]
struct Keripy {
    #[serde(default)]
    accepted: Option<bool>,
    #[serde(default)]
    escrowed: Option<bool>,
    #[serde(default)]
    error_category: Option<String>,
    #[serde(default)]
    error_message: Option<String>,
}

fn fixture() -> Result<Fixture, Box<dyn Error>> {
    Ok(serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/acceptance-keripy/v1.json"
    )))?)
}

fn decode_hex(input: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !input.len().is_multiple_of(2) {
        return Err("odd-length hexadecimal fixture field".into());
    }
    (0..input.len())
        .step_by(2)
        .map(|index| {
            input
                .get(index..index + 2)
                .ok_or_else(|| Box::<dyn Error>::from("hexadecimal fixture slice out of range"))
                .and_then(|pair| u8::from_str_radix(pair, 16).map_err(Into::into))
        })
        .collect()
}

/// The signers' logs as keripy held them, served the way keripy's `getKeLast` serves them.
struct Logs(Vec<(IdentifierPrefix, u128, SerializedEvent)>);

impl SignerEvents for Logs {
    fn event_at(&self, signer: &IdentifierPrefix, sequence_number: u128) -> Option<SerializedEvent> {
        self.0
            .iter()
            .rev()
            .find(|(identifier, number, _)| identifier == signer && *number == sequence_number)
            .map(|(_, _, event)| event.clone())
    }
}

fn logs(fixture: &Fixture) -> Result<Logs, Box<dyn Error>> {
    let mut entries = Vec::new();
    for event in &fixture.signer_events {
        let parsed = SerializedEvent::parse(event.raw.as_bytes())?;
        assert_eq!(parsed.said(), Some(event.said.as_str()));
        entries.push((
            IdentifierPrefix::from_qb64(&event.identifier)?,
            event.sequence_number,
            parsed,
        ));
    }
    Ok(Logs(entries))
}

fn decide(
    authority: &str,
    new: &Signed,
    prior: Option<&Signed>,
    logs: &Logs,
) -> Result<Result<Acceptance, EventError>, Box<dyn Error>> {
    let raw = decode_hex(&new.raw_hex)?;
    assert_eq!(raw, new.raw.as_bytes());
    let message = Message::from_bytes(&raw)?;
    let reply = ReplyMessage::from_serialized(message.event().clone())?;
    assert_eq!(reply.timestamp().as_str(), new.timestamp);
    let prior = prior
        .map(|prior| -> Result<AcceptedReply, Box<dyn Error>> {
            let accepted = AcceptedReply::new(Timestamp::parse(&prior.timestamp)?);
            Ok(match prior.establishment {
                Some(sequence_number) => accepted.signed_at(sequence_number),
                None => accepted,
            })
        })
        .transpose()?;
    Ok(accept(
        &reply,
        message.attachments(),
        &IdentifierPrefix::from_qb64(authority)?,
        prior.as_ref(),
        logs,
    ))
}

fn expected_outcome(name: &str) -> Result<Outcome, Box<dyn Error>> {
    Ok(match name {
        "Accepted" => Outcome::Accepted,
        "Stale" => Outcome::Skipped(Skip::Stale),
        "NotFromAuthority" => Outcome::Skipped(Skip::NotFromAuthority),
        "InvalidSignature" => Outcome::Skipped(Skip::InvalidSignature),
        "MissingEstablishment" => Outcome::Escrowed(Escrow::MissingEstablishment),
        "BelowThreshold" => Outcome::Escrowed(Escrow::BelowThreshold),
        other => return Err(format!("unknown outcome {other}").into()),
    })
}

fn error_matches(error: &EventError, category: &str) -> Result<bool, Box<dyn Error>> {
    Ok(match category {
        "SignatureGroupMismatch" => matches!(error, EventError::SignatureGroupMismatch { .. }),
        "NoSigningKeys" => matches!(error, EventError::NoSigningKeys { .. }),
        "NoVerifiedSignatures" => matches!(error, EventError::NoVerifiedSignatures { .. }),
        other => return Err(format!("unknown rust error category {other}").into()),
    })
}

#[test]
fn fixture_metadata_matches_the_pinned_keripy_reference() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.upstream, "https://github.com/WebOfTrust/keripy.git");
    assert_eq!(fixture.reference_sha, REFERENCE_SHA);
    assert_eq!(fixture.reference_version, "1.3.6");
    assert_ne!(fixture.generated_on, "");
    assert_eq!(
        fixture.sources,
        ["src/keri/core/routing.py", "src/keri/core/eventing.py"]
    );
    assert_eq!(fixture.signer_events.len(), 4);
    let first = fixture.signer_events.first().ok_or("no signer events")?;
    assert_eq!(first.said, fixture.inception_said);
    Ok(())
}

#[test]
fn every_decision_matches_keripy() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let logs = logs(&fixture)?;
    assert_eq!(fixture.cases.len(), 19);
    for case in &fixture.cases {
        let decision = decide(&case.authority, &case.new, case.prior.as_ref(), &logs)?;
        match (&case.rust_outcome, &case.rust_error_category) {
            (Some(expected), None) => {
                let acceptance = decision.map_err(|error| format!("case {} failed: {error}", case.name))?;
                let outcomes: Vec<Outcome> = acceptance
                    .couples()
                    .iter()
                    .chain(acceptance.groups())
                    .copied()
                    .collect();
                assert_eq!(outcomes, [expected_outcome(expected)?], "case {}", case.name);
                assert_eq!(
                    Some(acceptance.is_accepted()),
                    case.keripy.accepted,
                    "case {} accepted",
                    case.name
                );
                assert_eq!(
                    Some(acceptance.is_escrowed()),
                    case.keripy.escrowed,
                    "case {} escrowed",
                    case.name
                );
            }
            (None, Some(category)) => {
                assert_eq!(
                    case.keripy.error_category.as_deref(),
                    Some("ValidationError"),
                    "case {}",
                    case.name
                );
                assert!(
                    case.keripy
                        .error_message
                        .as_deref()
                        .is_some_and(|message| !message.is_empty())
                );
                let Err(error) = decision else {
                    return Err(format!("case {} was decided without error", case.name).into());
                };
                assert!(
                    error_matches(&error, category)?,
                    "case {} produced {error:?}",
                    case.name
                );
            }
            _ => return Err(format!("case {} names neither an outcome nor an error", case.name).into()),
        }
    }
    Ok(())
}

#[test]
fn an_index_past_the_keys_is_skipped_where_keripy_crashes() -> Result<(), Box<dyn Error>> {
    let fixture = fixture()?;
    let logs = logs(&fixture)?;
    let quirk = &fixture.reference_quirk_index_out_of_range;
    assert_eq!(quirk.name, "index_out_of_range");
    assert_ne!(quirk.note, "");
    assert_eq!(quirk.keripy.error_category.as_deref(), Some("IndexError"));
    let Err(error) = decide(&quirk.authority, &quirk.new, None, &logs)? else {
        return Err("an out-of-range signature was accepted".into());
    };
    let category = quirk
        .rust_error_category
        .as_deref()
        .ok_or("quirk names no rust error")?;
    assert!(error_matches(&error, category)?, "produced {error:?}");
    Ok(())
}
