//! Property and invalid-near-miss coverage for replies read back and their typed routes.

use keri_protocol::event::EventError;
use keri_protocol::event::reply::route::{
    EndRole, LocationScheme, ReplyRoute, Role, RouteAction, Scheme, WatcherObservation,
};
use keri_protocol::event::reply::{ReplyBuilder, ReplyMessage};
use keri_protocol::event::timestamp::Timestamp;
use keri_protocol::prefix::IdentifierPrefix;
use keri_protocol::serialization::SerializedEvent;
use proptest::{prelude::*, test_runner::TestCaseError};

const STAMP: &str = "2021-01-01T00:00:00.000000+00:00";
const CONTROLLER: &str = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";
const ENDPOINT: &str = "BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";

fn fail<T, E: core::fmt::Display>(result: Result<T, E>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

fn prefix(text: &str) -> Result<IdentifierPrefix, TestCaseError> {
    fail(IdentifierPrefix::from_qb64(text))
}

fn role_strategy() -> impl Strategy<Value = Role> {
    proptest::sample::select(Role::ALL.as_slice())
}

fn scheme_strategy() -> impl Strategy<Value = Scheme> {
    proptest::sample::select(Scheme::ALL.as_slice())
}

fn route_strategy() -> impl Strategy<Value = (u8, bool, Role, Scheme, Option<String>)> {
    (
        0_u8..3,
        any::<bool>(),
        role_strategy(),
        scheme_strategy(),
        prop::option::of("[a-z0-9./:]{0,24}"),
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(160))]

    /// Every route this crate writes reads back into itself through the generic parser, with the
    /// SAID verified on the way.
    #[test]
    fn every_route_reads_back_into_itself((kind, add, role, scheme, text) in route_strategy()) {
        let action = if add { RouteAction::Add } else { RouteAction::Cut };
        let route = match kind {
            0 => ReplyRoute::EndRole {
                action,
                end_role: EndRole::new(prefix(CONTROLLER)?, role, prefix(ENDPOINT)?),
            },
            1 => {
                let url = text.map(|path| format!("{scheme}://{path}")).unwrap_or_default();
                ReplyRoute::LocationScheme(fail(LocationScheme::new(prefix(ENDPOINT)?, scheme, url))?)
            }
            _ => {
                let mut observation = WatcherObservation::new(prefix(CONTROLLER)?, prefix(CONTROLLER)?);
                if let Some(oobi) = text {
                    observation = observation.oobi(oobi);
                }
                ReplyRoute::WatcherObservation { watcher: prefix(ENDPOINT)?, action, observation }
            }
        };
        let reply = fail(route.to_reply(fail(Timestamp::parse(STAMP))?))?;
        let read = fail(ReplyMessage::from_serialized(fail(SerializedEvent::parse(reply.raw()))?))?;
        prop_assert_eq!(&read, &reply);
        prop_assert_eq!(fail(ReplyRoute::from_reply(&read))?, route);
    }

    /// Any route outside the four keripy handles is refused, never misread as one of them.
    #[test]
    fn unknown_routes_are_refused(route in "/[a-z]{1,8}(/[a-zA-Z0-9_-]{0,8}){0,3}") {
        let reply = fail(ReplyBuilder::new(route.as_str(), fail(Timestamp::parse(STAMP))?).build())?;
        let segments: Vec<&str> = route.split('/').collect();
        let known = match segments.as_slice() {
            ["", "end", "role", "add" | "cut"] | ["", "loc", "scheme"] => true,
            ["", "ksn", source] => !source.is_empty(),
            ["", "watcher", watcher, "add" | "cut"] => !watcher.is_empty(),
            _ => false,
        };
        match ReplyRoute::from_reply(&reply) {
            Ok(read) => return Err(TestCaseError::fail(format!("{route} read as {read:?}"))),
            Err(EventError::UnknownReplyRoute { .. }) => prop_assert!(!known, "known route {} refused as unknown", route),
            Err(_) => prop_assert!(known, "unknown route {} failed on its attributes", route),
        }
    }

    /// A URL whose scheme differs from the declared one is refused, and one that agrees or has no
    /// scheme is accepted.
    #[test]
    fn url_schemes_must_agree(declared in scheme_strategy(), named in scheme_strategy(), path in "[a-z0-9.]{1,12}") {
        let result = LocationScheme::new(prefix(ENDPOINT)?, declared, format!("{named}://{path}"));
        prop_assert_eq!(result.is_ok(), declared == named);
        let without_scheme = format!("//{path}");
        prop_assert!(LocationScheme::new(prefix(ENDPOINT)?, declared, without_scheme).is_ok());
    }
}
