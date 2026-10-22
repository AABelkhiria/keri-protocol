//! Property and invalid-near-miss coverage for query messages.

use keri_protocol::event::EventError;
use keri_protocol::event::query::{FIELD_LABELS, QueryArguments, QueryBuilder, QueryMessage};
use keri_protocol::event::reply::MAX_ROUTE_BYTES;
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::said::{DEFAULT_SAID_LABEL, SaidVerification};
use keri_protocol::serialization::{Sad, SadValue, SerializedEvent};
use proptest::{prelude::*, test_runner::TestCaseError};

const STAMP: &str = "2021-01-01T00:00:00.000000+00:00";
const IDENTIFIER: &str = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";
const WITNESS: &str = "BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";

fn fail<T, E: core::fmt::Display>(result: Result<T, E>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn route_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("logs".to_owned()),
        Just("ksn".to_owned()),
        Just("mbx".to_owned()),
        "[a-z]{1,8}(/[a-z]{1,8}){0,3}",
    ]
}

fn arguments_strategy() -> impl Strategy<Value = (Option<u128>, Option<u128>, bool, bool)> {
    (
        prop::option::of(any::<u128>()),
        prop::option::of(any::<u128>()),
        any::<bool>(),
        any::<bool>(),
    )
}

fn arguments(
    sequence_number: Option<u128>,
    first_seen: Option<u128>,
    anchor: bool,
    topics: bool,
) -> Result<QueryArguments, TestCaseError> {
    let mut arguments = QueryArguments::new(
        fail(IdentifierPrefix::from_qb64(IDENTIFIER))?,
        fail(IdentifierPrefix::from_qb64(WITNESS))?,
    );
    if let Some(sequence_number) = sequence_number {
        arguments = arguments.sequence_number(sequence_number);
    }
    if let Some(first_seen) = first_seen {
        arguments = arguments.first_seen(first_seen);
    }
    if anchor {
        let mut seal = Sad::new();
        fail(seal.insert("i", SadValue::text(IDENTIFIER)))?;
        arguments = arguments.anchor(seal);
    }
    if topics {
        let mut map = Sad::new();
        fail(map.insert("/receipt", fail(SadValue::integer(0))?))?;
        arguments = arguments.topics(map);
    }
    Ok(arguments)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Every query the builder accepts reads back into itself, with a verified SAID and the typed
    /// arguments it was built from.
    #[test]
    fn a_query_reads_back_into_itself(
        route in route_strategy(),
        reply_route in prop_oneof![Just(String::new()), "/[a-z]{1,8}(/[a-z]{1,8}){0,2}"],
        (sequence_number, first_seen, anchor, topics) in arguments_strategy(),
    ) {
        let built = arguments(sequence_number, first_seen, anchor, topics)?;
        let query = fail(
            QueryBuilder::new(route.as_str(), fail(Timestamp::parse(STAMP))?)
                .reply_route(reply_route.as_str())
                .query(fail(built.clone().into_sad())?)
                .build(),
        )?;
        let labels: Vec<&str> = query.sad().entries().map(|(label, _)| label).collect();
        prop_assert_eq!(labels, FIELD_LABELS);
        prop_assert_eq!(query.route(), route.as_str());
        prop_assert_eq!(query.reply_route(), reply_route.as_str());
        prop_assert!(query.said().verify(query.sad(), DEFAULT_SAID_LABEL, SaidVerification::strict()).is_ok());

        let read = fail(QueryMessage::from_serialized(fail(SerializedEvent::parse(query.raw()))?))?;
        prop_assert_eq!(&read, &query);
        prop_assert_eq!(fail(read.arguments())?, built);
    }

    /// A route or reply route over the bound is refused, and nothing under it is.
    #[test]
    fn routes_are_bounded(length in 0_usize..=MAX_ROUTE_BYTES + 64, on_reply_route in any::<bool>()) {
        let text = "r".repeat(length);
        let builder = QueryBuilder::new(if on_reply_route { "logs" } else { text.as_str() }, fail(Timestamp::parse(STAMP))?)
            .reply_route(if on_reply_route { text.as_str() } else { "" });
        match builder.build() {
            Ok(_) => prop_assert!(length <= MAX_ROUTE_BYTES),
            Err(EventError::RouteTooLong { length: reported }) => {
                prop_assert!(length > MAX_ROUTE_BYTES);
                prop_assert_eq!(reported, length);
            }
            Err(error) => return Err(TestCaseError::fail(format!("unexpected error {error}"))),
        }
    }

    /// Any change to a built query's bytes that still parses as a message is refused by the
    /// reader, because the SAID no longer matches.
    #[test]
    fn a_tampered_query_is_refused(replacement in "[a-z]{1,8}") {
        let query = fail(
            QueryBuilder::new("logs", fail(Timestamp::parse(STAMP))?)
                .query(fail(arguments(Some(1), None, false, false)?.into_sad())?)
                .build(),
        )?;
        let mut tampered = Sad::new();
        for (label, value) in query.sad().entries() {
            let value = if label == "r" { SadValue::text(replacement.as_str()) } else { value.clone() };
            fail(tampered.insert(label, value))?;
        }
        if replacement != "logs" {
            let event = fail(SerializedEvent::from_sad(tampered))?;
            let refused = matches!(QueryMessage::from_serialized(event), Err(EventError::Said { .. }));
            prop_assert!(refused, "a tampered route kept a valid SAID");
        }
    }
}
