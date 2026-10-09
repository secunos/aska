//! The hand tag (DC-04 §3.3): a four-digit one-time authentication tag over the ciphertext
//! that a person can compute with pencil.
//!
//! tag = ( a₀·L + a₁·G₁ + … + a_J·G_J + b ) mod 9 973
//!
//! where L is the number of ciphertext digits, G_j the j-th pair of ciphertext digits (the
//! last group is a single digit when L is odd), and a₀…a_J, b are one-time keys printed on the
//! page, each uniform in 0…9 972. For two different ciphertexts at least one coefficient of the
//! key difference is a non-zero number below the prime, so the tags differ with probability
//! 1 − 1/9 973 whatever the adversary knows — unconditionally.

use crate::{all_digits, digits_to_u64, PaperError};
use subtle::ConstantTimeEq;

/// The prime.
pub const P: u64 = 9_973;
/// Digits in a printed key or tag.
pub const KEY_DIGITS: usize = 4;

/// Keys of one page: multipliers a₀…a_J and the offset b, as ASCII digits (4 each, back to
/// back) — borrowed from the page's locked canonical string.
pub struct HandKeys<'a> {
    /// `(J_max + 1) × 4` ASCII digits: a₀ … a_{J_max}.
    pub multipliers: &'a [u8],
    /// 4 ASCII digits.
    pub offset: &'a [u8],
}

impl HandKeys<'_> {
    /// Multiplier a_j as a number.
    pub fn a(&self, j: usize) -> Option<u64> {
        let s = self.multipliers.get(j * KEY_DIGITS..(j + 1) * KEY_DIGITS)?;
        digits_to_u64(s)
    }

    pub fn b(&self) -> Option<u64> {
        digits_to_u64(self.offset)
    }

    /// Number of multipliers (a₀ included).
    pub fn count(&self) -> usize {
        self.multipliers.len() / KEY_DIGITS
    }
}

/// The ciphertext pairs G₁…G_J (the last a single digit when L is odd).
pub fn groups(cipher: &[u8]) -> impl Iterator<Item = u64> + '_ {
    cipher.chunks(2).map(|g| {
        g.iter()
            .fold(0u64, |acc, &d| acc * 10 + u64::from(d - b'0'))
    })
}

/// The unreduced sum (for the worksheet's worked steps) and the tag.
pub fn compute_with_sum(cipher: &[u8], keys: &HandKeys<'_>) -> Result<(u64, u16), PaperError> {
    if !all_digits(cipher) || cipher.is_empty() {
        return Err(PaperError::Digits("ciphertext must be digits"));
    }
    let n_groups = cipher.len().div_ceil(2);
    if keys.count() < n_groups + 1 {
        return Err(PaperError::TooLong {
            need: n_groups + 1,
            have: keys.count(),
        });
    }
    let mut sum: u64 = keys.a(0).ok_or(PaperError::Page("hand key a0"))? * cipher.len() as u64;
    for (j, g) in groups(cipher).enumerate() {
        let a = keys.a(j + 1).ok_or(PaperError::Page("hand key"))?;
        if a >= P {
            return Err(PaperError::Page("hand key out of range"));
        }
        sum += a * g;
    }
    let b = keys.b().ok_or(PaperError::Page("hand key b"))?;
    if b >= P {
        return Err(PaperError::Page("hand key b out of range"));
    }
    sum += b;
    Ok((sum, (sum % P) as u16))
}

/// The four-digit tag.
pub fn compute(cipher: &[u8], keys: &HandKeys<'_>) -> Result<u16, PaperError> {
    compute_with_sum(cipher, keys).map(|(_, t)| t)
}

/// Verify a printed/typed tag (4 ASCII digits) in constant time.
pub fn verify(cipher: &[u8], keys: &HandKeys<'_>, tag: &[u8]) -> Result<(), PaperError> {
    let want = compute(cipher, keys)?;
    let got = digits_to_u64(tag).ok_or(PaperError::Digits("tag must be four digits"))?;
    if tag.len() != KEY_DIGITS {
        return Err(PaperError::Digits("tag must be four digits"));
    }
    if (u64::from(want)).ct_eq(&got).into() {
        Ok(())
    } else {
        Err(PaperError::Tag)
    }
}

/// The reduction a person does on the worksheet, using 10 000 ≡ 27 (mod 9 973): split
/// x = q·10 000 + r and replace it by r + 27·q until the value is below the prime. Returns the
/// intermediate values (for printing the worked example) and the result.
pub fn reduce_by_hand(mut x: u64) -> (Vec<u64>, u16) {
    let mut steps = Vec::new();
    while x >= P {
        let (q, r) = (x / 10_000, x % 10_000);
        x = if q == 0 { x - P } else { r + 27 * q };
        steps.push(x);
    }
    (steps, x as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys_from(a: &[u64], b: u64) -> (Vec<u8>, Vec<u8>) {
        let mut m = Vec::new();
        for &v in a {
            m.extend_from_slice(format!("{v:04}").as_bytes());
        }
        (m, format!("{b:04}").into_bytes())
    }

    #[test]
    fn dc04_worked_example() {
        let a = [
            5849u64, 1573, 2769, 6170, 2106, 5152, 6831, 4251, 1107, 6609, 5096, 2484, 272, 5425,
            7676, 2832, 7115, 6601, 5314, 5029, 8369, 9720, 9153, 768, 658, 7564, 9899, 7707, 5061,
            499, 4489,
        ];
        let (m, b) = keys_from(&a, 2691);
        let keys = HandKeys {
            multipliers: &m,
            offset: &b,
        };
        let c = b"939757023937300976225155334511585";
        let (sum, tag) = compute_with_sum(c, &keys).unwrap();
        assert_eq!(sum, 3_314_972);
        assert_eq!(tag, 3936);
        let (steps, t) = reduce_by_hand(sum);
        assert_eq!(steps, vec![13_909, 3_936]);
        assert_eq!(t, 3936);
        verify(c, &keys, b"3936").unwrap();
        assert!(matches!(verify(c, &keys, b"3937"), Err(PaperError::Tag)));
        assert!(verify(c, &keys, b"393").is_err());
    }

    #[test]
    fn reduction_matches_modulo_everywhere() {
        for x in [
            0u64,
            9_972,
            9_973,
            10_000,
            19_945,
            3_314_972,
            20_000_000,
            u32::MAX as u64,
        ] {
            assert_eq!(u64::from(reduce_by_hand(x).1), x % P, "{x}");
        }
    }

    #[test]
    fn different_lengths_and_contents_change_the_tag() {
        let a: Vec<u64> = (0..41).map(|i| (i * 2_477 + 13) % P).collect();
        let (m, b) = keys_from(&a, 17);
        let keys = HandKeys {
            multipliers: &m,
            offset: &b,
        };
        let t1 = compute(b"1234", &keys).unwrap();
        let t2 = compute(b"12340", &keys).unwrap();
        let t3 = compute(b"1235", &keys).unwrap();
        assert!(t1 != t2 && t1 != t3);
        // Too few keys for a long ciphertext is an error, not a wrong tag.
        assert!(compute(&[b'1'; 100], &keys).is_err());
    }
}
