//! KERI and ACDC event structures and builders.
//!
//! [`kind`] holds the typed event-kind (ilk) table. [`inception`] creates an identifier,
//! [`rotation`] replaces its keys, and [`interaction`] anchors data without changing them. Every
//! builder produces a [`KeyEvent`] carrying the exact wire bytes together with the identifier and
//! SAID a caller needs for the next event in the log.
//!
//! [`reply`] is the only supporting event builder the pinned signify-ts reference exports.
//! [`receipt`] builds and reads the `rct` message that reference never constructs, ported from
//! keripy instead. Validator-receipt and key-state messages have no builder in either reference's
//! public API, and the `qry` ilk is absent from signify-ts's table, so those are not invented
//! here.
//!
//! [`exchange`] builds the routed message controllers send each other, together with the embedded
//! messages and transposed attachments it carries. CESR attachments themselves are the
//! [`attachment`](crate::attachment) module's.

pub mod config;
mod error;
pub mod exchange;
pub mod inception;
pub mod interaction;
mod key_event;
pub mod kind;
pub mod receipt;
pub mod reply;
pub mod rotation;
pub mod timestamp;
pub mod witness;

pub use config::ConfigurationTrait;
pub use error::EventError;
pub use key_event::{
    KeyEvent, ThresholdEncoding, check_distinct, check_next_threshold, check_signing_threshold, check_witness_threshold,
};
pub(crate) use key_event::{replace, traits_value};
pub use timestamp::{Timestamp, TimestampError};
