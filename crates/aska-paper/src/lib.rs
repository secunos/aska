//! Aska paper mode — Design Change DC-04 (release 1.2).
//!
//! The one-time pad is the only cipher with a proof; every recorded failure of it is an
//! artefact left behind. This crate holds the arithmetic and the pipeline so that the clients
//! can offer the pad without adding artefacts of their own:
//!
//! * [`checkerboard`] — the fixed public table that turns text into digits (DC-04 §3.1);
//! * [`pad`] — modulo-10 enciphering and deciphering (§3.2);
//! * [`handtag`] — the four-digit one-time tag a person computes with pencil (§3.3);
//! * [`devtag`] — the nineteen-digit one-time tag the app computes (§3.4);
//! * [`page`] and [`booklet`] — the page format, its checksum and row checks, and the
//!   directional booklet (§3.5);
//! * [`entropy`] — the two-source randomness pipeline: raw sources, health tests, the
//!   min-entropy estimate, the seeded Toeplitz extractor, rejection sampling, mixing with the
//!   operating system's generator, the finished-booklet statistics and the PHYSICAL/SEEDED
//!   label (§4);
//! * [`cards`] — Block cards (a Block cut into QR-sized chunks) and Share cards (§7);
//! * [`print`] — the printing rule (volatile spool, USB printer), the IPP client for the
//!   local CUPS socket and the PostScript carrier (§5.2);
//! * [`render`] — a page drawn into a one-bit raster from an embedded bitmap font, so no font
//!   cache or toolkit ever sees a pad digit (§8.1).
//!
//! Every digit, key, tag and plaintext lives in a [`LockedBuf`] (pinned, excluded from dumps,
//! zeroised on drop) or a `Zeroizing` wrapper; nothing in this crate opens a file for writing,
//! and no secret type implements `Display` or a revealing `Debug`.

#![forbid(unsafe_code)]

pub mod booklet;
pub mod cards;
pub mod checkerboard;
pub mod devtag;
pub mod entropy;
pub mod handtag;
pub mod pad;
pub mod page;
pub mod print;
pub mod render;

pub use aska_core::secret::LockedBuf;

/// Errors of the paper mode. None carries secret material.
#[derive(Debug, thiserror::Error)]
pub enum PaperError {
    /// A character the checkerboard cannot represent (after normalisation).
    #[error("not in the paper alphabet: {0:?}")]
    Alphabet(char),
    /// The message needs more digits than the page holds.
    #[error("the message needs {need} digits but the page holds {have}")]
    TooLong { need: usize, have: usize },
    /// A digit string that is not digits, or a dangling prefix.
    #[error("malformed digits: {0}")]
    Digits(&'static str),
    /// A page whose canonical string does not parse.
    #[error("malformed page: {0}")]
    Page(&'static str),
    /// The page checksum or a row check does not match.
    #[error("the page's check does not match — a digit was mis-copied or mis-read")]
    Checksum,
    /// The tag does not verify.
    #[error("the tag does not verify — the message was altered or the wrong page was used")]
    Tag,
    /// The randomness pipeline refused to continue.
    #[error("randomness: {0}")]
    Entropy(String),
    /// More raw samples are needed before the booklet can be finished.
    #[error("more raw samples are needed")]
    NeedMore,
    /// A Block card set problem.
    #[error("card: {0}")]
    Card(&'static str),
    /// Printing: the print system could not be reached or refused the job.
    #[error("printing: {0}")]
    Print(String),
    /// The operating system's random source failed.
    #[error("the system random source failed")]
    Rng,
    /// Memory could not be locked.
    #[error("{0}")]
    Lock(#[from] aska_core::secret::LockError),
}

/// `true` when every byte is an ASCII digit.
pub(crate) fn all_digits(b: &[u8]) -> bool {
    b.iter().all(u8::is_ascii_digit)
}

/// Parse a run of ASCII digits as an unsigned number (no sign, no overflow check beyond u64).
pub(crate) fn digits_to_u64(b: &[u8]) -> Option<u64> {
    if b.is_empty() || b.len() > 19 || !all_digits(b) {
        return None;
    }
    let mut v: u64 = 0;
    for &d in b {
        v = v.checked_mul(10)?.checked_add(u64::from(d - b'0'))?;
    }
    Some(v)
}

/// Write `v` as exactly `width` ASCII digits (leading zeros) into `out`. Panics if it does not fit.
pub(crate) fn put_digits(out: &mut [u8], mut v: u64, width: usize) {
    assert_eq!(out.len(), width);
    for slot in out.iter_mut().rev() {
        *slot = b'0' + (v % 10) as u8;
        v /= 10;
    }
    assert_eq!(v, 0, "value does not fit in {width} digits");
}
