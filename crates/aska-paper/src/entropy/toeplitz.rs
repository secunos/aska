//! Seeded Toeplitz extractor over GF(2) (DC-04 §4.3 step 4).
//!
//! A Toeplitz matrix T (m × n) is defined by n + m − 1 seed bits: T[i][j] = t[i − j + n − 1].
//! The family {x ↦ T·x} is 2-universal, so by the leftover-hash lemma the output is within
//! ε = 2^{−(H − m)/2} of uniform when the input has min-entropy H — for any seed, against any
//! adversary. The seed is public in principle; here it comes from the OS generator and is kept
//! in locked memory because there is no reason to let it out.
//!
//! Computation: out = XOR over every set input bit j of the seed window
//! t[(n − 1 − j) .. (n − 1 − j + m)], done a 64-bit word at a time.

/// Seed bytes needed for an input of `n_bits` and the largest output (n/2 bits).
pub fn seed_len_bytes(n_bits: usize) -> usize {
    (n_bits + n_bits / 2).div_ceil(8) + 8
}

/// Read `m` bits of `seed` starting at bit `start` into `out` (packed MSB-first, zero-padded).
fn window_xor(seed: &[u8], start: usize, m: usize, out: &mut [u8]) {
    // Byte-aligned fast path when start % 8 == 0 would be nice; the general case shifts.
    let shift = start % 8;
    let nbytes = m.div_ceil(8);
    for (i, o) in (start / 8..).zip(out.iter_mut().take(nbytes)) {
        let hi = (u16::from(seed[i]) << 8) | u16::from(*seed.get(i + 1).unwrap_or(&0));
        *o ^= (hi >> (8 - shift)) as u8;
    }
    // Clear the bits beyond m in the last byte.
    let extra = nbytes * 8 - m;
    if extra > 0 {
        out[nbytes - 1] &= 0xFFu8 << extra;
    }
}

/// Extract `m` bits from `input` (n = 8·len bits) into `out` (packed, at least ⌈m/8⌉ bytes).
/// `seed` must hold at least n + m − 1 bits.
pub fn extract(seed: &[u8], input: &[u8], m: usize, out: &mut crate::LockedBuf) {
    let n = input.len() * 8;
    assert!(seed.len() * 8 >= n + m, "seed too short");
    let nbytes = m.div_ceil(8);
    let mut acc = vec![0u8; nbytes];
    for (byte_i, &byte) in input.iter().enumerate() {
        if byte == 0 {
            continue;
        }
        for bit in 0..8 {
            if (byte >> (7 - bit)) & 1 == 1 {
                let j = byte_i * 8 + bit;
                window_xor(seed, n - 1 - j, m, &mut acc);
            }
        }
    }
    out.set(&acc);
    use zeroize::Zeroize;
    acc.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LockedBuf;

    /// Bit-by-bit reference: out_i = XOR_j T[i][j] x_j, T[i][j] = t[i − j + n − 1].
    fn reference(seed: &[u8], input: &[u8], m: usize) -> Vec<u8> {
        let n = input.len() * 8;
        let bit = |bytes: &[u8], p: usize| (bytes[p / 8] >> (7 - p % 8)) & 1;
        let mut out = vec![0u8; m.div_ceil(8)];
        for i in 0..m {
            let mut acc = 0u8;
            for j in 0..n {
                acc ^= bit(seed, i + n - 1 - j) & bit(input, j);
            }
            out[i / 8] |= acc << (7 - i % 8);
        }
        out
    }

    #[test]
    fn matches_the_bitwise_definition() {
        let seed: Vec<u8> = (0..64u32).map(|i| (i * 73 + 29) as u8).collect();
        for (input, m) in [
            (vec![0b1000_0000u8, 0, 0, 0], 13usize),
            (vec![0xFFu8; 8], 32),
            (vec![0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc], 17),
            (vec![0u8; 4], 9),
            (vec![1u8, 2, 3], 24),
        ] {
            let mut out = LockedBuf::with_capacity(16);
            extract(&seed, &input, m, &mut out);
            assert_eq!(out.as_slice(), &reference(&seed, &input, m)[..], "m={m}");
        }
    }

    #[test]
    fn linear_in_the_input() {
        let seed: Vec<u8> = (0..200u32).map(|i| (i * 131 + 7) as u8).collect();
        let a = [0x3c, 0xa5, 0x0f, 0xf0, 0x11, 0x22, 0x33, 0x44];
        let b = [0x99, 0x01, 0xfe, 0x10, 0xab, 0xcd, 0xef, 0x12];
        let ab: Vec<u8> = a.iter().zip(&b).map(|(x, y)| x ^ y).collect();
        let (mut oa, mut ob, mut oab) = (
            LockedBuf::with_capacity(8),
            LockedBuf::with_capacity(8),
            LockedBuf::with_capacity(8),
        );
        extract(&seed, &a, 30, &mut oa);
        extract(&seed, &b, 30, &mut ob);
        extract(&seed, &ab, 30, &mut oab);
        let x: Vec<u8> = oa
            .as_slice()
            .iter()
            .zip(ob.as_slice())
            .map(|(p, q)| p ^ q)
            .collect();
        assert_eq!(x, oab.as_slice());
    }

    #[test]
    fn output_of_a_biased_source_looks_uniform() {
        // Input bits are 1 with probability ~0.9 (min-entropy ≈ 0.15 bit/bit); extract 1/16 of
        // the length and check the output bits are balanced.
        let mut seed = vec![0u8; seed_len_bytes(8192)];
        getrandom::getrandom(&mut seed).unwrap();
        let mut lcg: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut ones = 0usize;
        let mut total = 0usize;
        for _ in 0..40 {
            let mut input = vec![0u8; 1024];
            for b in input.iter_mut() {
                for bit in 0..8 {
                    lcg = lcg
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    let r = (lcg >> 33) as u32 % 10;
                    if r != 0 {
                        *b |= 1 << bit;
                    }
                }
            }
            let mut out = LockedBuf::with_capacity(64);
            extract(&seed, &input, 512, &mut out);
            for byte in out.as_slice() {
                ones += byte.count_ones() as usize;
                total += 8;
            }
        }
        let frac = ones as f64 / total as f64;
        assert!((0.47..0.53).contains(&frac), "{frac}");
    }
}
