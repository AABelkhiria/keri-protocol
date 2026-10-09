//! KERI protocol messages: events, SAIDs, prefixes, thresholds and CESR attachments.
//!
//! [`serialization`] holds the protocol versions, the deterministic self-addressing-data codec and
//! the message serializer and parser; [`said`] and [`prefix`] derive and verify self-addressing
//! identifiers and identifier prefixes; [`threshold`] holds exact signing thresholds; [`event`]
//! builds key events, exchange and reply messages; [`attachment`] composes CESR attachments around
//! a message; and [`registry`] builds the TEL registry inception event.

#![forbid(unsafe_code)]

pub mod attachment;
pub mod event;
pub mod prefix;
pub mod registry;
pub mod said;
pub mod serialization;
pub mod threshold;
