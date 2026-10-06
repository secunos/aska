//! Aska Dead Drop relay (ADP/1) — library half. The binary in `main.rs` parses the four
//! configuration flags, hardens the process and calls [`server::serve`].
//!
//! Design constraints implemented here (Dead Drop Protocol Specification draft 0.2):
//! RAM-only store with monotonic deadlines and expire-only TTL (§5); per-class caps; idempotent
//! duplicate rule (P-04); adaptive label-bound proof-of-work (§6.2); CSPRNG-randomised GET_ALL
//! (§4.4); 30-second timeouts (§6.3); no logging code path anywhere (RLY-04).
//!
//! Licence: AGPL-3.0-only (the relay is the one component that runs on someone else's machine).
#![deny(unsafe_code)]

pub mod harden;
pub mod server;
pub mod store;

pub use server::{handle_connection, serve, SharedStore};
pub use store::{Config, Store};
