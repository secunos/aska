//! The page (DC-04 §3.5): the unit of use. A page is held as its **canonical string** — one
//! run of ASCII digits in locked memory — and every view (pad, keys, header) is a slice of it.
//!
//! Canonical string (all digits, so the QR uses numeric mode):
//!
//! ```text
//! 1          format version
//! SSSS       set code
//! D          direction: 1 = A, 2 = B
//! PP         page number 01…50
//! NNN        pad length N ∈ {200, 400, 600}
//! k₁…k_N     pad digits
//! H          1 = hand-tag keys follow, 0 = none
//! a₀…a_{N/2}, b   (N/2 + 1 + 1) × 4 digits, when H = 1
//! r, s       19 + 19 digits (device-tag keys)
//! ```
//!
//! The six-digit **checksum** is SHA3-256 of the canonical string, first eight bytes as a
//! big-endian number, modulo 10⁶. It is printed on the page and appended to the QR payload; it
//! is not part of the canonical string. **Row check digits** (sum of a printed row's digits
//! mod 10) are a rendering aid for hand copying and are recomputed from the digits.

use crate::handtag::{self, HandKeys};
use crate::{all_digits, devtag, digits_to_u64, put_digits, LockedBuf, PaperError};
use sha3::{Digest, Sha3_256};
use subtle::ConstantTimeEq;

pub const FORMAT_VERSION: u8 = b'1';
pub const SET_DIGITS: usize = 4;
pub const PAGE_MAX: u8 = 50;
/// Allowed pad lengths.
pub const PAD_LENGTHS: [usize; 3] = [200, 400, 600];
pub const DEFAULT_PAD_LEN: usize = 400;
pub const CHECKSUM_DIGITS: usize = 6;
/// Pad digits per printed row.
pub const ROW: usize = 50;
/// Hand-tag multipliers per printed row.
pub const KEYS_PER_ROW: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    A,
    B,
}

impl Direction {
    fn digit(self) -> u8 {
        match self {
            Direction::A => b'1',
            Direction::B => b'2',
        }
    }
    fn from_digit(d: u8) -> Option<Self> {
        match d {
            b'1' => Some(Direction::A),
            b'2' => Some(Direction::B),
            _ => None,
        }
    }
    pub fn letter(self) -> char {
        match self {
            Direction::A => 'A',
            Direction::B => 'B',
        }
    }
}

/// What a page is, apart from its digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageSpec {
    pub set_code: u16,
    pub direction: Direction,
    pub number: u8,
    pub pad_len: usize,
    pub hand_tag: bool,
}

impl PageSpec {
    pub fn validate(&self) -> Result<(), PaperError> {
        if self.set_code > 9_999 {
            return Err(PaperError::Page("set code"));
        }
        if self.number == 0 || self.number > PAGE_MAX {
            return Err(PaperError::Page("page number"));
        }
        if !PAD_LENGTHS.contains(&self.pad_len) {
            return Err(PaperError::Page("pad length"));
        }
        Ok(())
    }

    /// Number of hand-tag multipliers (a₀ … a_{N/2}).
    pub fn multiplier_count(&self) -> usize {
        self.pad_len / 2 + 1
    }

    /// Length of the canonical string.
    pub fn canonical_len(&self) -> usize {
        let keys = if self.hand_tag {
            (self.multiplier_count() + 1) * handtag::KEY_DIGITS
        } else {
            0
        };
        1 + SET_DIGITS + 1 + 2 + 3 + self.pad_len + 1 + keys + 2 * devtag::KEY_DIGITS
    }
}

const OFF_SET: usize = 1;
const OFF_DIR: usize = OFF_SET + SET_DIGITS;
const OFF_NUM: usize = OFF_DIR + 1;
const OFF_LEN: usize = OFF_NUM + 2;
const OFF_PAD: usize = OFF_LEN + 3;

/// A pad page in locked memory.
pub struct Page {
    canon: LockedBuf,
    spec: PageSpec,
}

impl std::fmt::Debug for Page {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Page({:04} {} {:02}, N={}, <digits redacted>)",
            self.spec.set_code,
            self.spec.direction.letter(),
            self.spec.number,
            self.spec.pad_len
        )
    }
}

impl Page {
    /// Assemble a page from its parts. `pad` is N ASCII digits; `hand_keys` is
    /// `(N/2 + 2) × 4` ASCII digits (a₀…a_{N/2}, then b) or empty when the spec has no hand
    /// tag; `r` and `s` are below the device prime.
    pub fn assemble(
        spec: PageSpec,
        pad: &[u8],
        hand_keys: &[u8],
        r: u64,
        s: u64,
    ) -> Result<Page, PaperError> {
        spec.validate()?;
        if pad.len() != spec.pad_len || !all_digits(pad) {
            return Err(PaperError::Page("pad digits"));
        }
        let want_keys = if spec.hand_tag {
            (spec.multiplier_count() + 1) * handtag::KEY_DIGITS
        } else {
            0
        };
        if hand_keys.len() != want_keys || !all_digits(hand_keys) {
            return Err(PaperError::Page("hand-tag keys"));
        }
        if spec.hand_tag {
            for k in hand_keys.chunks(handtag::KEY_DIGITS) {
                if digits_to_u64(k).ok_or(PaperError::Page("hand key"))? >= handtag::P {
                    return Err(PaperError::Page("hand key out of range"));
                }
            }
        }
        if r >= devtag::P || s >= devtag::P {
            return Err(PaperError::Page("device key out of range"));
        }
        let mut canon = LockedBuf::with_capacity(spec.canonical_len());
        canon.extend_from_slice(&[FORMAT_VERSION]);
        let mut tmp = [0u8; 19];
        put_digits(&mut tmp[..4], u64::from(spec.set_code), 4);
        canon.extend_from_slice(&tmp[..4]);
        canon.extend_from_slice(&[spec.direction.digit()]);
        put_digits(&mut tmp[..2], u64::from(spec.number), 2);
        canon.extend_from_slice(&tmp[..2]);
        put_digits(&mut tmp[..3], spec.pad_len as u64, 3);
        canon.extend_from_slice(&tmp[..3]);
        canon.extend_from_slice(pad);
        canon.extend_from_slice(&[if spec.hand_tag { b'1' } else { b'0' }]);
        canon.extend_from_slice(hand_keys);
        put_digits(&mut tmp, r, 19);
        canon.extend_from_slice(&tmp);
        put_digits(&mut tmp, s, 19);
        canon.extend_from_slice(&tmp);
        debug_assert_eq!(canon.len(), spec.canonical_len());
        Ok(Page { canon, spec })
    }

    /// Parse a canonical string (from a scan or typed rows) **without** a checksum.
    pub fn parse(canon: &[u8]) -> Result<Page, PaperError> {
        if canon.len() < OFF_PAD + 1 + 2 * devtag::KEY_DIGITS || !all_digits(canon) {
            return Err(PaperError::Page("too short or not digits"));
        }
        if canon[0] != FORMAT_VERSION {
            return Err(PaperError::Page("unknown format version"));
        }
        let set_code = digits_to_u64(&canon[OFF_SET..OFF_DIR]).ok_or(PaperError::Page("set"))?;
        let direction =
            Direction::from_digit(canon[OFF_DIR]).ok_or(PaperError::Page("direction"))?;
        let number = digits_to_u64(&canon[OFF_NUM..OFF_LEN]).ok_or(PaperError::Page("number"))?;
        let pad_len = digits_to_u64(&canon[OFF_LEN..OFF_PAD]).ok_or(PaperError::Page("length"))?;
        let pad_len = pad_len as usize;
        if !PAD_LENGTHS.contains(&pad_len) {
            return Err(PaperError::Page("pad length"));
        }
        let off_h = OFF_PAD + pad_len;
        let hand_tag = match canon.get(off_h) {
            Some(b'1') => true,
            Some(b'0') => false,
            _ => return Err(PaperError::Page("hand-tag flag")),
        };
        let spec = PageSpec {
            set_code: set_code as u16,
            direction,
            number: number as u8,
            pad_len,
            hand_tag,
        };
        if canon.len() != spec.canonical_len() {
            return Err(PaperError::Page("length does not match the header"));
        }
        let keys_end = canon.len() - 2 * devtag::KEY_DIGITS;
        let keys = &canon[off_h + 1..keys_end];
        let r = devtag::parse(&canon[keys_end..keys_end + 19])?;
        let s = devtag::parse(&canon[keys_end + 19..])?;
        let pad = &canon[OFF_PAD..off_h];
        Self::assemble(spec, pad, keys, r, s)
    }

    /// Parse a QR payload: canonical string followed by the six-digit checksum, verified.
    pub fn parse_with_checksum(payload: &[u8]) -> Result<Page, PaperError> {
        if payload.len() <= CHECKSUM_DIGITS {
            return Err(PaperError::Page("too short"));
        }
        let (canon, sum) = payload.split_at(payload.len() - CHECKSUM_DIGITS);
        let page = Self::parse(canon)?;
        if !page.checksum_matches(sum) {
            return Err(PaperError::Checksum);
        }
        Ok(page)
    }

    pub fn spec(&self) -> &PageSpec {
        &self.spec
    }

    /// The whole canonical string.
    pub fn canonical(&self) -> &[u8] {
        self.canon.as_slice()
    }

    /// The N pad digits.
    pub fn pad(&self) -> &[u8] {
        &self.canon.as_slice()[OFF_PAD..OFF_PAD + self.spec.pad_len]
    }

    /// The hand-tag keys, when the page has them.
    pub fn hand_keys(&self) -> Option<HandKeys<'_>> {
        if !self.spec.hand_tag {
            return None;
        }
        let start = OFF_PAD + self.spec.pad_len + 1;
        let n = self.spec.multiplier_count() * handtag::KEY_DIGITS;
        let c = self.canon.as_slice();
        Some(HandKeys {
            multipliers: &c[start..start + n],
            offset: &c[start + n..start + n + handtag::KEY_DIGITS],
        })
    }

    /// Device-tag keys (r, s).
    pub fn device_keys(&self) -> (u64, u64) {
        let c = self.canon.as_slice();
        let end = c.len();
        let r = digits_to_u64(&c[end - 38..end - 19]).expect("validated");
        let s = digits_to_u64(&c[end - 19..]).expect("validated");
        (r, s)
    }

    /// Six ASCII digits.
    pub fn checksum(&self) -> [u8; CHECKSUM_DIGITS] {
        checksum_of(self.canonical())
    }

    pub fn checksum_matches(&self, printed: &[u8]) -> bool {
        let want = self.checksum();
        printed.len() == CHECKSUM_DIGITS && bool::from(want.ct_eq(printed))
    }

    /// QR payload: canonical string ‖ checksum (all digits).
    pub fn qr_payload(&self) -> LockedBuf {
        let mut out = LockedBuf::with_capacity(self.canon.len() + CHECKSUM_DIGITS);
        out.extend_from_slice(self.canonical());
        out.extend_from_slice(&self.checksum());
        out
    }

    /// Pad rows for printing/copying: (row index from 1, the row's digits, check digit).
    pub fn pad_rows(&self) -> impl Iterator<Item = (usize, &[u8], u8)> {
        self.pad()
            .chunks(ROW)
            .enumerate()
            .map(|(i, r)| (i + 1, r, row_check(r)))
    }

    /// Hand-key rows for printing: (first multiplier index, the row's digits, check digit).
    /// The last row carries b after the last multiplier.
    pub fn key_rows(&self) -> Vec<(usize, &[u8], u8)> {
        let Some(k) = self.hand_keys() else {
            return Vec::new();
        };
        let per_row = KEYS_PER_ROW * handtag::KEY_DIGITS;
        let mut rows: Vec<(usize, &[u8], u8)> = k
            .multipliers
            .chunks(per_row)
            .enumerate()
            .map(|(i, r)| (i * KEYS_PER_ROW, r, row_check(r)))
            .collect();
        // b is appended as its own row entry with index usize::MAX.
        rows.push((usize::MAX, k.offset, row_check(k.offset)));
        rows
    }

    /// Compute the hand tag of a ciphertext with this page's keys.
    pub fn hand_tag(&self, cipher: &[u8]) -> Result<u16, PaperError> {
        let keys = self
            .hand_keys()
            .ok_or(PaperError::Page("page has no hand-tag keys"))?;
        handtag::compute(cipher, &keys)
    }

    /// Compute the device tag of a ciphertext with this page's keys.
    pub fn device_tag(&self, cipher: &[u8]) -> Result<u64, PaperError> {
        let (r, s) = self.device_keys();
        devtag::compute(cipher, r, s)
    }

    /// Zeroise the page now (also happens on drop).
    pub fn clear(&mut self) {
        self.canon.clear();
    }
}

/// Sum of a row's digits modulo 10.
pub fn row_check(digits: &[u8]) -> u8 {
    (digits
        .iter()
        .map(|&d| u32::from(d.wrapping_sub(b'0')))
        .sum::<u32>()
        % 10) as u8
}

/// The six-digit checksum of a canonical string.
pub fn checksum_of(canon: &[u8]) -> [u8; CHECKSUM_DIGITS] {
    let h = Sha3_256::digest(canon);
    let v = u64::from_be_bytes(h[..8].try_into().expect("8 bytes")) % 1_000_000;
    let mut out = [0u8; CHECKSUM_DIGITS];
    put_digits(&mut out, v, CHECKSUM_DIGITS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_page(hand: bool) -> Page {
        let spec = PageSpec {
            set_code: 7342,
            direction: Direction::A,
            number: 3,
            pad_len: 200,
            hand_tag: hand,
        };
        let pad: Vec<u8> = (0..200).map(|i| b'0' + ((i * 7 + 3) % 10) as u8).collect();
        let keys: Vec<u8> = if hand {
            (0..102)
                .flat_map(|i| format!("{:04}", (i * 97 + 11) % 9973).into_bytes())
                .collect()
        } else {
            Vec::new()
        };
        Page::assemble(
            spec,
            &pad,
            &keys,
            1_231_961_752_939_033_616,
            1_450_779_715_753_509_526,
        )
        .unwrap()
    }

    #[test]
    fn canonical_round_trip_with_and_without_hand_keys() {
        for hand in [true, false] {
            let p = sample_page(hand);
            assert_eq!(p.canonical().len(), p.spec().canonical_len());
            assert!(all_digits(p.canonical()));
            let q = Page::parse(p.canonical()).unwrap();
            assert_eq!(q.canonical(), p.canonical());
            assert_eq!(q.spec(), p.spec());
            assert_eq!(q.hand_keys().is_some(), hand);
            assert_eq!(
                q.device_keys(),
                (1_231_961_752_939_033_616, 1_450_779_715_753_509_526)
            );
            let payload = p.qr_payload();
            let r = Page::parse_with_checksum(payload.as_slice()).unwrap();
            assert_eq!(r.canonical(), p.canonical());
        }
    }

    #[test]
    fn checksum_catches_one_wrong_digit() {
        let p = sample_page(true);
        let mut payload = p.qr_payload().as_slice().to_vec();
        let i = 40;
        payload[i] = if payload[i] == b'9' {
            b'0'
        } else {
            payload[i] + 1
        };
        assert!(matches!(
            Page::parse_with_checksum(&payload),
            Err(PaperError::Checksum)
        ));
        let mut short = p.canonical().to_vec();
        short.pop();
        assert!(Page::parse(&short).is_err());
    }

    #[test]
    fn rows_and_checks() {
        let p = sample_page(true);
        let rows: Vec<_> = p.pad_rows().collect();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0].1.len(), ROW);
        assert_eq!(rows[0].2, row_check(&p.pad()[..ROW]));
        let krows = p.key_rows();
        assert_eq!(krows.len(), 11 + 1); // 101 multipliers → 11 rows, then b
        assert_eq!(krows.last().unwrap().0, usize::MAX);
        assert_eq!(row_check(b"279749132099457148372454626642"), 2); // DC-04 example, row 1
    }

    #[test]
    fn invalid_specs_refused() {
        let pad = vec![b'1'; 400];
        let keys = vec![b'0'; 202 * 4];
        let ok = PageSpec {
            set_code: 1,
            direction: Direction::B,
            number: 50,
            pad_len: 400,
            hand_tag: true,
        };
        assert!(Page::assemble(ok, &pad, &keys, 1, 2).is_ok());
        let bad_num = PageSpec { number: 51, ..ok };
        assert!(Page::assemble(bad_num, &pad, &keys, 1, 2).is_err());
        let bad_len = PageSpec { pad_len: 300, ..ok };
        assert!(Page::assemble(bad_len, &pad[..300], &keys, 1, 2).is_err());
        assert!(Page::assemble(ok, &pad, &keys, devtag::P, 2).is_err());
        let mut hi = keys.clone();
        hi[..4].copy_from_slice(b"9973");
        assert!(Page::assemble(ok, &pad, &hi, 1, 2).is_err());
    }
}
