//! ADP/1 — the Aska Dead Drop Protocol wire format (Dead Drop Protocol Specification, draft 0.2).
//!
//! This crate is the single definition of the bytes on the wire, shared by the relay
//! (`aska-drop`) and the client core (`aska-core`). It contains no I/O of its own: the
//! `wire` module encodes and decodes fixed-length fields into plain structs, and the optional
//! `client` module (feature `client`) drives one request over any async byte stream.
//!
//! Layout recap (§4):
//!
//! ```text
//! Request  = MAGIC(4) ‖ version(1) ‖ op(1)     ‖ body
//! Response = MAGIC(4) ‖ version(1) ‖ status(1) ‖ body
//! INFO     body: —                → resp: max_ttl_hours(2) ‖ classes_bitmap(1) ‖ pow_base(1)
//! PUT      body: class(1) ‖ ttl(2) ‖ label(32) ‖ challenge(16) ‖ nonce(8) ‖ block(class size)
//!                                 → resp: empty, or for ST_POW_REQUIRED challenge(16) ‖ difficulty(1)
//! GET_ALL  body: class(1)         → resp: count(4) ‖ count × ( label(32) ‖ block(class size) )
//! ```
//!
//! Exactly one request per connection; the relay answers and closes.
#![forbid(unsafe_code)]

pub mod pow;
pub mod wire;

#[cfg(feature = "client")]
pub mod client;
/// Blocking counterpart of `client` (std only, always available).
pub mod client_sync;

pub use pow::{pow_check, pow_solve};
pub use wire::*;

// ---- §3 Constants ----
pub const MAGIC: [u8; 4] = *b"ASKD";
pub const PROTO_VERSION: u8 = 0x01;
pub const OP_INFO: u8 = 0x01;
pub const OP_PUT: u8 = 0x02;
pub const OP_GET_ALL: u8 = 0x03;
pub const LABEL_LEN: usize = 32;
pub const CHALLENGE_LEN: usize = 16;
pub const NONCE_LEN: usize = 8;
pub const POW_DOMAIN: &[u8] = b"aska/adp1/pow";
/// Hard ceiling for `max_ttl_hours` (D-05: seven days).
pub const MAX_TTL_HOURS_CEILING: u16 = 168;
pub const DEFAULT_MAX_TTL_HOURS: u16 = 168;
pub const DEFAULT_TTL_HOURS: u16 = 24;
/// Default relay port on loopback, behind `HiddenServicePort 4567`.
pub const DEFAULT_PORT: u16 = 4567;
/// Default per-class capacity in Blocks (class 1, 2, 3).
pub const DEFAULT_CAPS: [usize; 3] = [2000, 800, 200];
/// PoW challenges are valid for this long and single use (§6.2).
pub const CHALLENGE_TTL_SECS: u64 = 120;
/// Relay-side timeout per read (§3).
pub const RELAY_READ_TIMEOUT_SECS: u64 = 30;
/// Client-side ceiling on records accepted in one GET_ALL listing, per class: twice the
/// default relay caps (2000/800/200) with a floor for class 1. A hostile relay could otherwise
/// stream until the client runs out of memory (class 3 records are 64 KiB each).
pub const MAX_LISTING_RECORDS: [u32; 3] = [4096, 1600, 400];
/// Client-side ceiling on the proof-of-work difficulty a relay may demand: 2^24 hashes is
/// roughly ten to twenty seconds on a laptop; anything higher is treated as a broken relay.
pub const MAX_POW_DIFFICULTY: u8 = 24;

/// Listing ceiling for a class (`None` for an unknown class).
pub fn max_listing_records(class: u8) -> Option<u32> {
    MAX_LISTING_RECORDS
        .get(class.checked_sub(1)? as usize)
        .copied()
}

/// One GET_ALL listing record: `(label, block)`.
pub type Record = ([u8; LABEL_LEN], Vec<u8>);

/// `MAGIC ‖ version ‖ op|status`.
pub const HEADER_LEN: usize = 6;
/// PUT fixed fields before the Block: class(1) ‖ ttl(2) ‖ label(32) ‖ challenge(16) ‖ nonce(8).
pub const PUT_FIXED_LEN: usize = 1 + 2 + LABEL_LEN + CHALLENGE_LEN + NONCE_LEN;
/// INFO response body length.
pub const INFO_BODY_LEN: usize = 4;
/// ST_POW_REQUIRED response body length.
pub const POW_REQUIRED_BODY_LEN: usize = CHALLENGE_LEN + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Ok = 0x00,
    BadRequest = 0x01,
    BadClass = 0x02,
    BadTtl = 0x03,
    BadLength = 0x04,
    Full = 0x05,
    Duplicate = 0x06,
    PowRequired = 0x07,
    PowInvalid = 0x08,
}

impl Status {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0x00 => Self::Ok,
            0x01 => Self::BadRequest,
            0x02 => Self::BadClass,
            0x03 => Self::BadTtl,
            0x04 => Self::BadLength,
            0x05 => Self::Full,
            0x06 => Self::Duplicate,
            0x07 => Self::PowRequired,
            0x08 => Self::PowInvalid,
            _ => return None,
        })
    }
}

/// Size class → Block length in bytes (Block Format §3).
pub fn class_size(class: u8) -> Option<usize> {
    match class {
        1 => Some(4096),
        2 => Some(16384),
        3 => Some(65536),
        _ => None,
    }
}

/// Block length → size class.
pub fn class_of_len(len: usize) -> Option<u8> {
    match len {
        4096 => Some(1),
        16384 => Some(2),
        65536 => Some(3),
        _ => None,
    }
}

/// Errors from decoding or from the optional client.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("truncated message")]
    Truncated,
    #[error("bad magic")]
    BadMagic,
    #[error("unsupported protocol version")]
    BadVersion,
    #[error("unknown status byte {0:#04x}")]
    BadStatus(u8),
    #[error("unknown size class")]
    BadClass,
    #[error("block length does not match a size class")]
    BadLength,
    #[error("relay answered {0:?}")]
    Status(Status),
    #[error("relay listing exceeds the client limit ({0} records)")]
    ListingTooLarge(u32),
    #[error("relay demands an unreasonable proof-of-work difficulty ({0} bits)")]
    PowTooHard(u8),
    #[error("proof-of-work retry exhausted")]
    PowRetryExhausted,
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}
