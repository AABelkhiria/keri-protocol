//! Typed reply routes.
//!
//! A reply's meaning is its route plus its attributes. KERI actors exchange four of them:
//!
//! | Route | Attributes | Signed by |
//! |---|---|---|
//! | `/end/role/add`, `/end/role/cut` | `cid`, `role`, `eid` | the controller `cid` |
//! | `/loc/scheme` | `eid`, `scheme`, `url` | the endpoint `eid` |
//! | `/ksn/{source}` | a [`KeyStateRecord`] | the actor `source` reporting it |
//! | `/watcher/{watcher}/add`, `/watcher/{watcher}/cut` | `cid`, `oid`, optional `oobi` | the controller `cid` |
//!
//! This ports the routes keripy's `Kevery.registerReplyRoutes` registers
//! (`src/keri/core/eventing.py`) and the checks each `processReply…` handler makes before it
//! applies best-available-data acceptance, which is not this module's: [`ReplyRoute::from_reply`]
//! establishes what a reply asserts, and whoever holds the stored replies decides whether it is
//! newer than what they have.
//!
//! keripy's router matches a route against its templates in full and ignoring case, then each
//! handler checks the literal part again with a case-sensitive `startswith`. The literal parts
//! are therefore effectively lowercase, and that is what is matched here.
//!
//! Two checks are stricter than keripy's. A watcher reply's `cid` and `oid`, and every route
//! parameter, must be valid identifier prefixes; keripy stores them as given. Both are always
//! prefixes when keripy itself writes them.

use core::fmt;
use std::str::FromStr;

use crate::event::error::{EventError, bounded_label};
use crate::event::key_state::KeyStateRecord;
use crate::event::reply::{ReplyBuilder, ReplyMessage};
use crate::event::timestamp::Timestamp;
use crate::prefix::IdentifierPrefix;
use crate::serialization::{Sad, SadValue};

/// Whether a reply grants or withdraws what it names.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RouteAction {
    /// The route ends in `add`.
    Add,
    /// The route ends in `cut`.
    Cut,
}

impl RouteAction {
    /// Returns the route segment.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Cut => "cut",
        }
    }

    fn parse(segment: &str, route: &str) -> Result<Self, EventError> {
        match segment {
            "add" => Ok(Self::Add),
            "cut" => Ok(Self::Cut),
            _ => Err(unknown_route(route)),
        }
    }
}

/// An endpoint role, keripy's `Roles`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Role {
    /// `controller`
    Controller,
    /// `witness`
    Witness,
    /// `registrar`
    Registrar,
    /// `gateway`
    Gateway,
    /// `watcher`
    Watcher,
    /// `judge`
    Judge,
    /// `juror`
    Juror,
    /// `peer`
    Peer,
    /// `mailbox`
    Mailbox,
    /// `agent`
    Agent,
    /// `indexer`
    Indexer,
}

impl Role {
    /// Every role, in keripy's table order.
    pub const ALL: [Self; 11] = [
        Self::Controller,
        Self::Witness,
        Self::Registrar,
        Self::Gateway,
        Self::Watcher,
        Self::Judge,
        Self::Juror,
        Self::Peer,
        Self::Mailbox,
        Self::Agent,
        Self::Indexer,
    ];

    /// Returns the role as written in a reply.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Controller => "controller",
            Self::Witness => "witness",
            Self::Registrar => "registrar",
            Self::Gateway => "gateway",
            Self::Watcher => "watcher",
            Self::Judge => "judge",
            Self::Juror => "juror",
            Self::Peer => "peer",
            Self::Mailbox => "mailbox",
            Self::Agent => "agent",
            Self::Indexer => "indexer",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Role {
    type Err = EventError;

    /// Parses a role exactly as keripy spells it.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|role| role.as_str() == input)
            .ok_or_else(|| EventError::UnknownRole {
                found: bounded_label(input),
            })
    }
}

/// A transport scheme an endpoint is reachable by, keripy's `Schemes`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Scheme {
    /// `tcp`
    Tcp,
    /// `http`
    Http,
    /// `https`
    Https,
}

impl Scheme {
    /// Every scheme, in keripy's table order.
    pub const ALL: [Self; 3] = [Self::Tcp, Self::Http, Self::Https];

    /// Returns the scheme as written in a reply.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Scheme {
    type Err = EventError;

    /// Parses a scheme exactly as keripy spells it.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|scheme| scheme.as_str() == input)
            .ok_or_else(|| EventError::UnknownScheme {
                found: bounded_label(input),
            })
    }
}

/// A controller authorising an endpoint to act for it in a role: the attributes of
/// `/end/role/add` and `/end/role/cut`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndRole {
    controller: IdentifierPrefix,
    role: Role,
    endpoint: IdentifierPrefix,
}

impl EndRole {
    /// Authorises `endpoint` to act for `controller` as `role`.
    #[must_use]
    pub const fn new(controller: IdentifierPrefix, role: Role, endpoint: IdentifierPrefix) -> Self {
        Self {
            controller,
            role,
            endpoint,
        }
    }

    /// Returns the controller granting the role (`cid`), who signs the reply.
    #[must_use]
    pub const fn controller(&self) -> &IdentifierPrefix {
        &self.controller
    }

    /// Returns the role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Returns the endpoint given the role (`eid`).
    #[must_use]
    pub const fn endpoint(&self) -> &IdentifierPrefix {
        &self.endpoint
    }
}

/// Where an endpoint is reachable: the attributes of `/loc/scheme`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocationScheme {
    endpoint: IdentifierPrefix,
    scheme: Scheme,
    url: String,
}

impl LocationScheme {
    /// Announces that `endpoint` is reachable at `url` over `scheme`.
    ///
    /// An empty URL withdraws the location, as in keripy.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::UrlSchemeMismatch`] when the URL names a scheme other than `scheme`.
    pub fn new(endpoint: IdentifierPrefix, scheme: Scheme, url: impl Into<String>) -> Result<Self, EventError> {
        let url = url.into();
        if let Some(found) = url_scheme(&url)
            && found != scheme.as_str()
        {
            return Err(EventError::UrlSchemeMismatch {
                scheme: scheme.as_str(),
                found: bounded_label(&found),
            });
        }
        Ok(Self { endpoint, scheme, url })
    }

    /// Returns the endpoint (`eid`), who signs the reply.
    #[must_use]
    pub const fn endpoint(&self) -> &IdentifierPrefix {
        &self.endpoint
    }

    /// Returns the scheme.
    #[must_use]
    pub const fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// Returns the URL; empty when the location is withdrawn.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// A controller asking a watcher to observe an identifier: the attributes of
/// `/watcher/{watcher}/add` and `/watcher/{watcher}/cut`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatcherObservation {
    controller: IdentifierPrefix,
    observed: IdentifierPrefix,
    oobi: Option<String>,
}

impl WatcherObservation {
    /// Asks for `observed` to be watched on behalf of `controller`.
    #[must_use]
    pub const fn new(controller: IdentifierPrefix, observed: IdentifierPrefix) -> Self {
        Self {
            controller,
            observed,
            oobi: None,
        }
    }

    /// Sets the OOBI the watcher can resolve the observed identifier through.
    #[must_use]
    pub fn oobi(mut self, oobi: impl Into<String>) -> Self {
        self.oobi = Some(oobi.into());
        self
    }

    /// Returns the controller asking (`cid`), who signs the reply.
    #[must_use]
    pub const fn controller(&self) -> &IdentifierPrefix {
        &self.controller
    }

    /// Returns the identifier to observe (`oid`).
    #[must_use]
    pub const fn observed(&self) -> &IdentifierPrefix {
        &self.observed
    }

    /// Returns the OOBI to resolve it through, when given.
    #[must_use]
    pub fn oobi_url(&self) -> Option<&str> {
        self.oobi.as_deref()
    }
}

/// What a reply asserts, by route.
#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(
    clippy::large_enum_variant,
    reason = "every variant holds identifier prefixes, which carry a decompressed key; a route is a \
              short-lived value read from one reply, so boxing would add allocations for no benefit"
)]
pub enum ReplyRoute {
    /// `/end/role/add` or `/end/role/cut`.
    EndRole {
        /// Whether the role is granted or withdrawn.
        action: RouteAction,
        /// Who grants which role to whom.
        end_role: EndRole,
    },
    /// `/loc/scheme`.
    LocationScheme(LocationScheme),
    /// `/ksn/{source}`.
    KeyStateNotice {
        /// The actor reporting the state, from the route.
        source: IdentifierPrefix,
        /// The reported state.
        state: Box<KeyStateRecord>,
    },
    /// `/watcher/{watcher}/add` or `/watcher/{watcher}/cut`.
    WatcherObservation {
        /// The watcher being asked, from the route.
        watcher: IdentifierPrefix,
        /// Whether observation starts or stops.
        action: RouteAction,
        /// Who asks to observe what.
        observation: WatcherObservation,
    },
}

impl ReplyRoute {
    /// Reads what a reply asserts from its route and attributes.
    ///
    /// # Errors
    ///
    /// Returns [`EventError::UnknownReplyRoute`] for a route keripy registers no handler for,
    /// [`EventError::MissingAttribute`] when an attribute the route requires is absent,
    /// [`EventError::UnexpectedFieldShape`] when one is not text, [`EventError::UnknownRole`],
    /// [`EventError::UnknownScheme`] or [`EventError::UrlSchemeMismatch`] for a value keripy
    /// refuses, and layered prefix and key-state failures.
    pub fn from_reply(reply: &ReplyMessage) -> Result<Self, EventError> {
        let route = reply.route().unwrap_or_default();
        let attributes = reply.attributes();
        let segments: Vec<&str> = route.split('/').collect();
        match segments.as_slice() {
            ["", "end", "role", action] => Ok(Self::EndRole {
                action: RouteAction::parse(action, route)?,
                end_role: EndRole::new(
                    required_prefix(attributes, "cid")?,
                    required_text(attributes, "role")?.parse()?,
                    required_prefix(attributes, "eid")?,
                ),
            }),
            ["", "loc", "scheme"] => Ok(Self::LocationScheme(LocationScheme::new(
                required_prefix(attributes, "eid")?,
                required_text(attributes, "scheme")?.parse()?,
                required_text(attributes, "url")?,
            )?)),
            ["", "ksn", source] if !source.is_empty() => Ok(Self::KeyStateNotice {
                source: route_prefix(source)?,
                state: Box::new(KeyStateRecord::from_sad(attributes)?),
            }),
            ["", "watcher", watcher, action] if !watcher.is_empty() => {
                let mut observation =
                    WatcherObservation::new(required_prefix(attributes, "cid")?, required_prefix(attributes, "oid")?);
                if let Some(value) = attributes.get("oobi") {
                    let oobi = value
                        .as_text()
                        .ok_or(EventError::UnexpectedFieldShape { label: "oobi" })?;
                    observation = observation.oobi(oobi);
                }
                Ok(Self::WatcherObservation {
                    watcher: route_prefix(watcher)?,
                    action: RouteAction::parse(action, route)?,
                    observation,
                })
            }
            _ => Err(unknown_route(route)),
        }
    }

    /// Returns the route string this assertion is addressed to.
    ///
    /// # Errors
    ///
    /// Returns a layered prefix failure when a route parameter cannot be encoded.
    pub fn route(&self) -> Result<String, EventError> {
        Ok(match self {
            Self::EndRole { action, .. } => format!("/end/role/{}", action.as_str()),
            Self::LocationScheme(_) => "/loc/scheme".to_owned(),
            Self::KeyStateNotice { source, .. } => format!("/ksn/{}", source.qb64().map_err(EventError::prefix)?),
            Self::WatcherObservation { watcher, action, .. } => format!(
                "/watcher/{}/{}",
                watcher.qb64().map_err(EventError::prefix)?,
                action.as_str()
            ),
        })
    }

    /// Returns the attributes this assertion is written as, in keripy's order.
    ///
    /// # Errors
    ///
    /// Returns layered prefix, key-state or SAD failures when a value cannot be encoded.
    pub fn attributes(&self) -> Result<Sad, EventError> {
        let mut attributes = Sad::new();
        let mut insert = |label: &str, value: SadValue| -> Result<(), EventError> {
            attributes.insert(label.to_owned(), value).map_err(EventError::sad)
        };
        match self {
            Self::EndRole { end_role, .. } => {
                insert("cid", prefix_value(&end_role.controller)?)?;
                insert("role", SadValue::text(end_role.role.as_str()))?;
                insert("eid", prefix_value(&end_role.endpoint)?)?;
            }
            Self::LocationScheme(location) => {
                insert("eid", prefix_value(&location.endpoint)?)?;
                insert("scheme", SadValue::text(location.scheme.as_str()))?;
                insert("url", SadValue::text(location.url.as_str()))?;
            }
            Self::KeyStateNotice { state, .. } => return state.to_sad(),
            Self::WatcherObservation { observation, .. } => {
                insert("cid", prefix_value(&observation.controller)?)?;
                insert("oid", prefix_value(&observation.observed)?)?;
                if let Some(oobi) = &observation.oobi {
                    insert("oobi", SadValue::text(oobi.as_str()))?;
                }
            }
        }
        Ok(attributes)
    }

    /// Builds the reply carrying this assertion, stamped at `timestamp`.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::route`], [`Self::attributes`] and [`ReplyBuilder::build`].
    pub fn to_reply(&self, timestamp: Timestamp) -> Result<ReplyMessage, EventError> {
        ReplyBuilder::new(self.route()?, timestamp)
            .attributes(self.attributes()?)
            .build()
    }
}

fn unknown_route(route: &str) -> EventError {
    EventError::UnknownReplyRoute {
        route: bounded_label(route),
    }
}

fn required_text<'a>(attributes: &'a Sad, label: &'static str) -> Result<&'a str, EventError> {
    attributes
        .get(label)
        .ok_or(EventError::MissingAttribute { label })?
        .as_text()
        .ok_or(EventError::UnexpectedFieldShape { label })
}

fn required_prefix(attributes: &Sad, label: &'static str) -> Result<IdentifierPrefix, EventError> {
    IdentifierPrefix::from_qb64(required_text(attributes, label)?).map_err(EventError::prefix)
}

fn route_prefix(segment: &str) -> Result<IdentifierPrefix, EventError> {
    IdentifierPrefix::from_qb64(segment).map_err(EventError::prefix)
}

fn prefix_value(prefix: &IdentifierPrefix) -> Result<SadValue, EventError> {
    prefix.qb64().map(SadValue::Text).map_err(EventError::prefix)
}

/// The scheme Python's `urlsplit` finds in `url`, lowercased, or `None` when it finds none.
///
/// keripy compares this against the reply's `scheme`, so the same rule decides here: leading
/// control characters and spaces are skipped, tabs and line breaks are dropped, and a scheme is the
/// text before the first `:` when it starts with an ASCII letter and holds only letters, digits,
/// `+`, `-` and `.`. That is why `localhost:5631` has the scheme `localhost`.
fn url_scheme(url: &str) -> Option<String> {
    let cleaned: String = url
        .trim_start_matches(|character: char| character <= ' ')
        .chars()
        .filter(|character| !matches!(character, '\t' | '\r' | '\n'))
        .collect();
    let (candidate, _) = cleaned.split_once(':')?;
    let mut characters = candidate.chars();
    let first = characters.next()?;
    let valid = first.is_ascii_alphabetic()
        && characters.all(|character| character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.'));
    valid.then(|| candidate.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialization::SerializedEvent;
    use std::error::Error;

    const CONTROLLER: &str = "EIflL4H4134zYoRM6ls6Q086RLC_BhfNFh5uk-WxvhsL";
    const WITNESS: &str = "BAOhB7_zzhC-HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4";
    const STAMP: &str = "2021-01-01T00:00:00.000000+00:00";

    fn round_trip(route: &ReplyRoute) -> Result<ReplyRoute, Box<dyn Error>> {
        let reply = route.to_reply(Timestamp::parse(STAMP)?)?;
        let read = ReplyMessage::from_serialized(SerializedEvent::parse(reply.raw())?)?;
        assert_eq!(read, reply);
        Ok(ReplyRoute::from_reply(&read)?)
    }

    #[test]
    fn every_route_reads_back_into_itself() -> Result<(), Box<dyn Error>> {
        let controller = IdentifierPrefix::from_qb64(CONTROLLER)?;
        let witness = IdentifierPrefix::from_qb64(WITNESS)?;
        let routes = [
            ReplyRoute::EndRole {
                action: RouteAction::Add,
                end_role: EndRole::new(controller.clone(), Role::Watcher, witness.clone()),
            },
            ReplyRoute::LocationScheme(LocationScheme::new(
                witness.clone(),
                Scheme::Http,
                "http://127.0.0.1:5642/",
            )?),
            ReplyRoute::WatcherObservation {
                watcher: witness.clone(),
                action: RouteAction::Cut,
                observation: WatcherObservation::new(controller.clone(), controller).oobi("http://x/oobi"),
            },
        ];
        for route in routes {
            assert_eq!(round_trip(&route)?, route);
        }
        Ok(())
    }

    #[test]
    fn the_url_scheme_follows_python_urlsplit() {
        assert_eq!(url_scheme("http://127.0.0.1:5642/"), Some("http".to_owned()));
        assert_eq!(url_scheme("HTTPS://x"), Some("https".to_owned()));
        assert_eq!(url_scheme("localhost:5631"), Some("localhost".to_owned()));
        assert_eq!(url_scheme("  http://x"), Some("http".to_owned()));
        assert_eq!(url_scheme("ht\ttp://x"), Some("http".to_owned()));
        assert_eq!(url_scheme("//127.0.0.1:5642"), None);
        assert_eq!(url_scheme("1http://x"), None);
        assert_eq!(url_scheme(""), None);
    }

    #[test]
    fn values_keripy_refuses_are_refused() -> Result<(), Box<dyn Error>> {
        let witness = IdentifierPrefix::from_qb64(WITNESS)?;
        assert!(matches!(
            LocationScheme::new(witness, Scheme::Http, "https://x"),
            Err(EventError::UrlSchemeMismatch { scheme: "http", found }) if found == "https"
        ));
        assert!(matches!("Watcher".parse::<Role>(), Err(EventError::UnknownRole { .. })));
        assert!(matches!("ftp".parse::<Scheme>(), Err(EventError::UnknownScheme { .. })));
        for route in [
            "/end/role/drop",
            "/END/role/add",
            "/loc/scheme/",
            "/ksn",
            "/ksn/",
            "/watcher//add",
            "/x",
        ] {
            let reply = ReplyBuilder::new(route, Timestamp::parse(STAMP)?).build()?;
            assert!(
                matches!(
                    ReplyRoute::from_reply(&reply),
                    Err(EventError::UnknownReplyRoute { .. })
                ),
                "route {route} was accepted"
            );
        }
        Ok(())
    }
}
