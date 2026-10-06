//! Identifier-free proof-of-work on PUT (§6.2, RLY-09).
//!
//! A solution is an 8-byte nonce such that
//! `SHA-256(POW_DOMAIN ‖ challenge ‖ label ‖ nonce)` has `difficulty` leading zero bits.
//! The challenge is relay-specific, single use and valid for two minutes; the label binds the
//! solution to one Block so it cannot be reused.

use crate::{CHALLENGE_LEN, LABEL_LEN, NONCE_LEN, POW_DOMAIN};
use sha2::{Digest, Sha256};

fn pow_hash(
    challenge: &[u8; CHALLENGE_LEN],
    label: &[u8; LABEL_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(POW_DOMAIN);
    h.update(challenge);
    h.update(label);
    h.update(nonce);
    h.finalize().into()
}

/// Leading zero bits of `d`, capped at 256.
fn leading_zero_bits(d: &[u8; 32]) -> u32 {
    let mut n = 0;
    for b in d {
        if *b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros();
            break;
        }
    }
    n
}

/// True if `nonce` solves the puzzle at `difficulty` bits (difficulty 0 always verifies).
pub fn pow_check(
    challenge: &[u8; CHALLENGE_LEN],
    label: &[u8; LABEL_LEN],
    nonce: &[u8; NONCE_LEN],
    difficulty: u8,
) -> bool {
    difficulty == 0 || leading_zero_bits(&pow_hash(challenge, label, nonce)) >= difficulty as u32
}

/// Find the smallest big-endian counter nonce that solves the puzzle (same search order as the
/// Python reference, so both produce identical nonces for identical inputs).
pub fn pow_solve(
    challenge: &[u8; CHALLENGE_LEN],
    label: &[u8; LABEL_LEN],
    difficulty: u8,
) -> [u8; NONCE_LEN] {
    let mut n: u64 = 0;
    loop {
        let nonce = n.to_be_bytes();
        if pow_check(challenge, label, &nonce, difficulty) {
            return nonce;
        }
        n = n.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn difficulty_zero_always_ok() {
        assert!(pow_check(&[0; 16], &[0; 32], &[0xff; 8], 0));
    }

    #[test]
    fn solve_then_check() {
        let ch = [7u8; 16];
        let lb = [9u8; 32];
        for d in [1u8, 4, 8, 12] {
            let n = pow_solve(&ch, &lb, d);
            assert!(pow_check(&ch, &lb, &n, d));
        }
    }

    /// Cross-language vectors computed with the Python reference (`aska_drop.pow_solve`):
    /// challenge = bytes(range(16)), label = bytes(range(32)).
    #[test]
    fn matches_python_reference_vectors() {
        let ch: [u8; 16] = core::array::from_fn(|i| i as u8);
        let lb: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(hex::encode(pow_solve(&ch, &lb, 12)), "0000000000000080");
        assert_eq!(hex::encode(pow_solve(&ch, &lb, 16)), "0000000000003590");
        // label binding: the 16-bit solution does not verify for a neighbouring label
        let mut other = lb;
        other[31] ^= 1;
        let n16 = hex_to_nonce("0000000000003590");
        assert!(pow_check(&ch, &lb, &n16, 16));
        assert!(!pow_check(&ch, &other, &n16, 16));
        // challenge binding
        let mut ch2 = ch;
        ch2[0] ^= 1;
        assert!(!pow_check(&ch2, &lb, &n16, 16));
    }

    fn hex_to_nonce(s: &str) -> [u8; 8] {
        let v = hex::decode(s).unwrap();
        v.try_into().unwrap()
    }
}
