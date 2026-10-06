//! Randomness sources.
//!
//! `OsRng` is the production source (`getrandom(2)`). `TestRng` is the deterministic
//! SHAKE256 stream defined in §9 for test vectors; it is never used in a product path.

use crate::error::Error;

/// A source of random bytes. Implemented by the OS source and the test-vector source.
pub trait RandomSource {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error>;

    fn bytes(&mut self, n: usize) -> Result<Vec<u8>, Error> {
        let mut v = vec![0u8; n];
        self.fill(&mut v)?;
        Ok(v)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut a = [0u8; N];
        self.fill(&mut a)?;
        Ok(a)
    }
}

/// Operating-system CSPRNG.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRng;

impl RandomSource for OsRng {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        getrandom::getrandom(out).map_err(|_| Error::Rng)
    }
}

/// Deterministic test RNG: `SHAKE256("aska-test-vectors" ‖ seed)` consumed sequentially (§9).
#[derive(Clone)]
pub struct TestRng {
    reader: sha3::Shake256Reader,
}

impl std::fmt::Debug for TestRng {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TestRng(SHAKE256 stream)")
    }
}

impl TestRng {
    pub fn new(seed: &[u8]) -> Self {
        use sha3::digest::{ExtendableOutput, Update};
        let mut h = sha3::Shake256::default();
        h.update(b"aska-test-vectors");
        h.update(seed);
        TestRng {
            reader: h.finalize_xof(),
        }
    }
}

impl RandomSource for TestRng {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        use sha3::digest::XofReader;
        self.reader.read(out);
        Ok(())
    }
}
