//! Shamir secret sharing of R over GF(2^8) with verification (§8).

use crate::consts::FORMAT_VERSION;
use crate::error::Error;
use crate::kdf::share_verify_tag;
use crate::keys::Root;
use crate::rng::RandomSource;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// GF(2^8) with the AES polynomial 0x11B.
/// Branch-free: eight fixed rounds, masks instead of conditionals (review finding A-4 — the
/// operands are secret coefficients and share bytes).
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut r = 0u8;
    for _ in 0..8 {
        let lsb_mask = (b & 1).wrapping_neg(); // 0xFF if b&1 else 0
        r ^= a & lsb_mask;
        let hi_mask = ((a >> 7) & 1).wrapping_neg(); // 0xFF if top bit set
        a = (a << 1) ^ (0x1B & hi_mask);
        b >>= 1;
    }
    r
}

fn gf_inv(a: u8) -> u8 {
    // a^254
    let mut r = 1u8;
    let mut base = a;
    let mut e = 254u8;
    while e != 0 {
        if e & 1 != 0 {
            r = gf_mul(r, base);
        }
        base = gf_mul(base, base);
        e >>= 1;
    }
    r
}

pub const SHARE_LEN: usize = 41;

/// One Share (§8.2): `ver(1) ‖ set_id(2) ‖ k(1) ‖ x(1) ‖ y(32) ‖ verify(4)`.
#[derive(Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct Share {
    pub set_id: [u8; 2],
    pub k: u8,
    pub x: u8,
    pub y: [u8; 32],
    pub verify: [u8; 4],
}

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Share(set={:02x}{:02x}, k={}, x={}, y=<redacted>)",
            self.set_id[0], self.set_id[1], self.k, self.x
        )
    }
}

impl Share {
    pub fn to_bytes(&self) -> zeroize::Zeroizing<[u8; SHARE_LEN]> {
        let mut b = zeroize::Zeroizing::new([0u8; SHARE_LEN]);
        b[0] = FORMAT_VERSION;
        b[1..3].copy_from_slice(&self.set_id);
        b[3] = self.k;
        b[4] = self.x;
        b[5..37].copy_from_slice(&self.y);
        b[37..41].copy_from_slice(&self.verify);
        b
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        if b.len() != SHARE_LEN {
            return Err(Error::BadShare);
        }
        if b[0] != FORMAT_VERSION {
            return Err(Error::Version);
        }
        let mut y = [0u8; 32];
        y.copy_from_slice(&b[5..37]);
        let s = Share {
            set_id: [b[1], b[2]],
            k: b[3],
            x: b[4],
            y,
            verify: [b[37], b[38], b[39], b[40]],
        };
        if s.k < 2 || s.x == 0 {
            return Err(Error::BadShare);
        }
        Ok(s)
    }
}

/// Split `root` into `n` Shares of which any `k` reconstruct it (§8.1).
/// Randomness draw order: set_id(2), then for each byte position 0..31, (k−1) coefficient bytes.
pub fn split<R: RandomSource>(root: &Root, k: u8, n: u8, rng: &mut R) -> Result<Vec<Share>, Error> {
    if k < 2 || n < k {
        return Err(Error::BadShare);
    }
    let set_id: [u8; 2] = rng.array()?;
    let mut coeffs: Vec<Vec<u8>> = Vec::with_capacity(32);
    for j in 0..32 {
        let mut c = vec![root.as_bytes()[j]];
        c.extend_from_slice(&rng.bytes(k as usize - 1)?);
        coeffs.push(c);
    }
    let tag = share_verify_tag(root);
    let mut out = Vec::with_capacity(n as usize);
    for x in 1..=n {
        let mut y = [0u8; 32];
        for j in 0..32 {
            let mut acc = 0u8;
            let mut xp = 1u8;
            for &c in &coeffs[j] {
                acc ^= gf_mul(c, xp);
                xp = gf_mul(xp, x);
            }
            y[j] = acc;
        }
        out.push(Share {
            set_id,
            k,
            x,
            y,
            verify: tag,
        });
    }
    for c in coeffs.iter_mut() {
        c.zeroize();
    }
    Ok(out)
}

/// Reconstruct R from at least `k` Shares (§8.3). Fails on inconsistent sets or bad verification.
pub fn combine(shares: &[Share]) -> Result<Root, Error> {
    let first = shares.first().ok_or(Error::ShareSet)?;
    let k = first.k as usize;
    if shares
        .iter()
        .any(|s| s.k != first.k || s.set_id != first.set_id || s.verify != first.verify)
    {
        return Err(Error::ShareSet);
    }
    if shares.len() < k {
        return Err(Error::ShareSet);
    }
    let use_ = &shares[..k];
    for (a, s) in use_.iter().enumerate() {
        if s.x == 0 || use_[..a].iter().any(|t| t.x == s.x) {
            return Err(Error::ShareSet);
        }
    }
    let mut r = [0u8; 32];
    for (j, rj) in r.iter_mut().enumerate() {
        let mut acc = 0u8;
        for (a, s) in use_.iter().enumerate() {
            let mut num = 1u8;
            let mut den = 1u8;
            for (b, t) in use_.iter().enumerate() {
                if a != b {
                    num = gf_mul(num, t.x);
                    den = gf_mul(den, s.x ^ t.x);
                }
            }
            acc ^= gf_mul(s.y[j], gf_mul(num, gf_inv(den)));
        }
        *rj = acc;
    }
    let root = Root::from_bytes(r);
    let ok: bool = share_verify_tag(&root).ct_eq(&first.verify).into();
    if !ok {
        return Err(Error::ShareVerify);
    }
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gf_basics() {
        assert_eq!(gf_mul(0x53, 0xCA), 0x01); // known AES inverse pair
        for a in 1..=255u8 {
            assert_eq!(gf_mul(a, gf_inv(a)), 1);
        }
    }
}
