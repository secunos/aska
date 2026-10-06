//! # aska-core
//!
//! The Aska core library. Everything that touches a secret lives here:
//! the Block Format v1 container, the key hierarchy, Shamir Shares, the
//! human-facing encodings, and (from M3) the Dead Drop client and Session.
//!
//! The byte layout and every derivation are specified in
//! *Aska Block Format Specification v1* and fixed by `reference/test_vectors.json`.
//! Section references in doc comments (`§n.n`) point to that specification.
//!
//! Secret-bearing types implement `Zeroize`/`ZeroizeOnDrop` and are `!Clone`. Secrets at rest
//! live in `secret::LockedBuf` owned by the `session::Session` (M3).
//!
//! `unsafe` is confined to `secret` (page-aligned locked allocation) and `platform`
//! (process limits); every other module forbids it.

#![deny(unsafe_code)]
#![deny(missing_debug_implementations)]
#![warn(clippy::all)]

pub mod block;
pub mod cancel;
pub mod consts;
pub mod cover;
pub mod doctor;
pub mod drop;
pub mod encodings;
pub mod error;
pub mod fingerprint;
pub mod kdf;
pub mod keys;
pub mod platform;
pub mod profile;
pub mod qr;
pub mod rng;
pub mod secret;
pub mod session;
pub mod shares;
pub mod tor;
pub mod utc;
pub mod xwing;

pub use block::{open, seal, OpenedSlot, Slot};
pub use consts::*;
pub use error::Error;
pub use keys::Root;
pub use session::{Level, Session, SessionConfig, SessionError, State};
pub use shares::{combine, split, Share};
