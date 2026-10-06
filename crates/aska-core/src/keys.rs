//! The root R and its 24-word encoding (§5.2, §7.1).

use crate::error::Error;
use crate::rng::{OsRng, RandomSource};
use std::os::unix::fs::OpenOptionsExt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The 32-byte root from which everything for one Block derives. Zeroised on drop; not clonable.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Root([u8; 32]);

impl std::fmt::Debug for Root {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Root(<redacted>)")
    }
}

impl Root {
    /// Constant-time equality (review finding A-5: `Root` no longer derives `PartialEq`).
    pub fn ct_eq(&self, other: &Root) -> bool {
        use subtle::ConstantTimeEq;
        self.0.ct_eq(&other.0).into()
    }

    /// Fresh random root from the given source (production: `OsRng`).
    pub fn generate<R: RandomSource>(rng: &mut R) -> Result<Self, Error> {
        Ok(Root(rng.array()?))
    }

    /// Production root generation (Client Design §3.2): the OS CSPRNG is the salt of an
    /// HKDF whose input keying material is a burst of timing jitter and, when readable,
    /// `/dev/hwrng`. The secondary sources are defence in depth for live systems whose entropy
    /// state at boot is uncertain; their failure cannot weaken the OS randomness because the
    /// output depends on the salt in full.
    pub fn generate_mixed() -> Result<Self, Error> {
        use sha2::{Digest, Sha512};
        use zeroize::Zeroizing;
        // Salt and every input are zeroising: salt + ikm together determine R.
        let salt: Zeroizing<[u8; 32]> = Zeroizing::new(OsRng.array()?);
        // Timing jitter: 512 samples of the monotonic clock interleaved with hashing work.
        let mut h = Sha512::new();
        let mut acc = Zeroizing::new([0u8; 64]);
        for i in 0..512u32 {
            let t = std::time::Instant::now();
            h.update(*acc);
            h.update(i.to_le_bytes());
            acc.copy_from_slice(&h.clone().finalize());
            h.update(t.elapsed().as_nanos().to_le_bytes());
        }
        let mut ikm: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(96));
        ikm.extend_from_slice(&h.finalize());
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open("/dev/hwrng")
        {
            use std::io::Read;
            let mut hw = Zeroizing::new([0u8; 32]);
            if f.read_exact(&mut hw[..]).is_ok() {
                ikm.extend_from_slice(&hw[..]);
            }
        }
        let mut r = Root([0u8; 32]);
        crate::kdf::hkdf_sha512(&salt[..], &ikm, b"aska/v1/root-mix", &mut r.0);
        Ok(r)
    }

    /// Construct from raw bytes (test vectors, Share reconstruction, decoded words).
    pub fn from_bytes(b: [u8; 32]) -> Self {
        Root(b)
    }

    /// Construct by copying from a slice (panics if not 32 bytes). Writes straight into the
    /// zeroising struct so no intermediate array is left behind.
    pub fn from_slice(b: &[u8]) -> Self {
        let mut r = Root([0u8; 32]);
        r.0.copy_from_slice(b);
        r
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 24 BIP-39 English words: 256 bits of R + 8-bit SHA-256 checksum (§7.1).
    /// The returned string is zeroised on drop; the caller displays it and lets it go.
    pub fn to_words(&self) -> zeroize::Zeroizing<String> {
        let m = bip39::Mnemonic::from_entropy_in(bip39::Language::English, &self.0)
            .expect("32 bytes is valid BIP-39 entropy");
        let mut s = String::with_capacity(24 * 9);
        for (i, w) in m.words().enumerate() {
            if i > 0 {
                s.push(' ');
            }
            s.push_str(w);
        }
        zeroize::Zeroizing::new(s)
    }

    /// Parse 24 words (any whitespace, any case); verifies the checksum.
    pub fn from_words(words: &str) -> Result<Self, Error> {
        // One pass, one zeroising buffer: no per-word String copies of the secret.
        let mut normalised: zeroize::Zeroizing<String> =
            zeroize::Zeroizing::new(String::with_capacity(words.len()));
        let mut prev_space = true;
        for c in words.chars() {
            if c.is_whitespace() {
                if !prev_space {
                    normalised.push(' ');
                    prev_space = true;
                }
            } else {
                for l in c.to_lowercase() {
                    normalised.push(l);
                }
                prev_space = false;
            }
        }
        while normalised.ends_with(' ') {
            normalised.pop();
        }
        let m = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &normalised)
            .map_err(|_| Error::Encoding)?;
        let (mut ent, n) = m.to_entropy_array();
        if n != 32 {
            ent.zeroize();
            return Err(Error::Encoding);
        }
        let r = Root::from_slice(&ent[..32]);
        ent.zeroize();
        Ok(r)
    }
}
