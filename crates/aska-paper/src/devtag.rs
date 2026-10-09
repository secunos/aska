//! The device tag (DC-04 §3.4): a nineteen-digit one-time authentication tag over the
//! ciphertext, computed and checked by the app.
//!
//! p = 2⁶¹ − 1. The ciphertext digits are read in groups of eighteen as integers M₁…M_K; the
//! sequence [L, M₁, …, M_K] is hashed by Horner's rule with the one-time key r, then the
//! one-time offset s is added: h ← (h + x)·r mod p for each x, tag = (h + s) mod p. The leading
//! length term binds L, so no padding convention is needed. Forgery probability ≤ (K + 2)/p.
//!
//! Arithmetic is constant-time: a 128-bit product, two shift-and-add folds and one masked
//! conditional subtraction; no branch depends on a digit or a key.

use crate::{all_digits, digits_to_u64, PaperError};
use subtle::ConstantTimeEq;

/// The Mersenne prime 2⁶¹ − 1.
pub const P: u64 = (1u64 << 61) - 1;
/// Digits in a printed key or tag.
pub const KEY_DIGITS: usize = 19;
/// Ciphertext digits per group (10¹⁸ < p).
pub const GROUP: usize = 18;

/// Reduce a 128-bit value modulo p, constant time.
#[inline]
fn reduce(x: u128) -> u64 {
    let p = u128::from(P);
    // x < 2^122 → after one fold < 2^62 + 2^61; after two < 2^61 + 2.
    let x = (x & p) + (x >> 61);
    let x = (x & p) + (x >> 61);
    let x = x as u64;
    // Conditional subtraction without a branch.
    let over = x.wrapping_sub(P); // if x >= P this is x - P, else wraps high
    let mask = ((over >> 63) ^ 1).wrapping_neg(); // all ones when x >= P (no wrap → top bit 0)
    (x & !mask) | (over & mask)
}

#[inline]
fn mul_mod(a: u64, b: u64) -> u64 {
    reduce(u128::from(a) * u128::from(b))
}

#[inline]
fn add_mod(a: u64, b: u64) -> u64 {
    reduce(u128::from(a) + u128::from(b))
}

/// Compute the tag over ASCII ciphertext digits with keys r and s (each < p).
pub fn compute(cipher: &[u8], r: u64, s: u64) -> Result<u64, PaperError> {
    if !all_digits(cipher) || cipher.is_empty() {
        return Err(PaperError::Digits("ciphertext must be digits"));
    }
    if r >= P || s >= P {
        return Err(PaperError::Page("device key out of range"));
    }
    let mut h = mul_mod(cipher.len() as u64, r); // (0 + L)·r
    for g in cipher.chunks(GROUP) {
        let m = digits_to_u64(g).ok_or(PaperError::Digits("group"))?;
        h = mul_mod(add_mod(h, m), r);
    }
    Ok(add_mod(h, s))
}

/// Parse a printed 19-digit key or tag.
pub fn parse(digits: &[u8]) -> Result<u64, PaperError> {
    if digits.len() != KEY_DIGITS {
        return Err(PaperError::Digits("nineteen digits expected"));
    }
    let v = digits_to_u64(digits).ok_or(PaperError::Digits("nineteen digits expected"))?;
    if v >= P {
        return Err(PaperError::Digits("value is not below the prime"));
    }
    Ok(v)
}

/// Verify a printed/typed tag (19 ASCII digits) in constant time.
pub fn verify(cipher: &[u8], r: u64, s: u64, tag: &[u8]) -> Result<(), PaperError> {
    let want = compute(cipher, r, s)?;
    let got = parse(tag)?;
    if want.ct_eq(&got).into() {
        Ok(())
    } else {
        Err(PaperError::Tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduce_agrees_with_u128_modulo() {
        let p = u128::from(P);
        for x in [
            0u128,
            1,
            p - 1,
            p,
            p + 1,
            2 * p,
            2 * p + 5,
            (1u128 << 122) - 1,
            (u128::from(u64::MAX) * u128::from(u64::MAX)) >> 6,
            0x0123_4567_89ab_cdef_0123_4567_89ab_cdefu128 >> 6,
        ] {
            assert_eq!(u128::from(reduce(x)), x % p, "{x}");
        }
        assert_eq!(mul_mod(P - 1, P - 1), 1); // (−1)² = 1
    }

    #[test]
    fn dc04_worked_example() {
        let c = b"939757023937300976225155334511585";
        let (r, s) = (1_231_961_752_939_033_616u64, 1_450_779_715_753_509_526u64);
        let t = compute(c, r, s).unwrap();
        assert_eq!(t, 876_449_745_860_556_196);
        verify(c, r, s, b"0876449745860556196").unwrap();
        assert!(matches!(
            verify(c, r, s, b"0876449745860556197"),
            Err(PaperError::Tag)
        ));
        assert!(verify(c, r, s, b"876449745860556196").is_err()); // 18 digits
    }

    #[test]
    fn length_is_bound() {
        let (r, s) = (12_345u64, 67_890u64);
        assert_ne!(compute(b"1", r, s).unwrap(), compute(b"10", r, s).unwrap());
        assert_ne!(compute(b"01", r, s).unwrap(), compute(b"1", r, s).unwrap());
        assert!(compute(b"1", P, 0).is_err());
    }
}
