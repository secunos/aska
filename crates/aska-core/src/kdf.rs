//! Key hierarchy (§5): HKDF-SHA-512, Argon2id KDF profiles, label and slot keys.

use crate::consts::*;
use crate::error::Error;
use crate::keys::Root;
use hkdf::Hkdf;
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HKDF-SHA-512 (RFC 5869). An empty salt means 64 zero bytes.
pub fn hkdf_sha512(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let zero = [0u8; 64];
    let salt = if salt.is_empty() { &zero[..] } else { salt };
    Hkdf::<Sha512>::new(Some(salt), ikm)
        .expand(info, out)
        .expect("HKDF output length is always within bounds here");
}

/// KDF profiles (§5.3, S-01). Parameters of an existing profile MUST never change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum KdfProfile {
    /// Desktop default: Argon2id t=3, m=256 MiB, p=1.
    P1 = 1,
    /// Reserved for mobile: Argon2id t=3, m=64 MiB, p=1.
    P2 = 2,
}

impl KdfProfile {
    pub const DEFAULT: KdfProfile = KdfProfile::P1;

    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::P1),
            2 => Some(Self::P2),
            _ => None,
        }
    }

    fn params(self) -> argon2::Params {
        let (t, m_kib) = match self {
            KdfProfile::P1 => (3, 256 * 1024),
            KdfProfile::P2 => (3, 64 * 1024),
        };
        argon2::Params::new(m_kib, t, 1, Some(ARGON2_LEN)).expect("valid Argon2 params")
    }
}

/// A derived 32-byte key. Zeroised on drop; not clonable.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SlotKey(pub(crate) [u8; 32]);

impl std::fmt::Debug for SlotKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SlotKey(<redacted>)")
    }
}

/// `A_p = Argon2id(NFKC(passphrase) as UTF-8, salt, profile params, 32)` (§5.2).
///
/// NFKC normalisation is the caller's responsibility at the boundary where the passphrase
/// is collected (the Session); this function takes the already-normalised bytes.
pub fn argon2id_passphrase(
    passphrase_nfkc: &[u8],
    salt: &[u8; SALT_LEN],
    profile: KdfProfile,
) -> Result<[u8; 32], Error> {
    let a = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        profile.params(),
    );
    let mut out = [0u8; 32];
    // Caller-owned working memory so that it can be zeroised afterwards (review finding
    // C-11): `hash_password_into` frees its blocks without wiping, and the final blocks
    // determine the output. 64–256 MiB cannot be mlock'ed under common RLIMIT_MEMLOCK
    // defaults, so this memory is wiped but not locked (Client Design §3.1, revised).
    let m_blocks = profile.params().block_count();
    let mut blocks = vec![argon2::Block::default(); m_blocks];
    let r = a.hash_password_into_with_memory(passphrase_nfkc, salt, &mut out, &mut blocks);
    blocks.iter_mut().for_each(|b| b.zeroize());
    drop(blocks);
    r.map_err(|_| Error::Kdf)?;
    Ok(out)
}

/// `L = HKDF(salt="", ikm=R, info="aska/v1/label", 32)` (§5.2). Not secret.
pub fn derive_label(root: &Root) -> [u8; 32] {
    let mut l = [0u8; 32];
    hkdf_sha512(b"", root.as_bytes(), INFO_LABEL, &mut l);
    l
}

/// `K_slot = HKDF(salt, R ‖ A_p, "aska/v1/slot/p" ‖ profile, 32)` (§5.2).
/// `passphrase_nfkc = None` selects an open slot: `A_p` is all zeros and the profile is P1.
pub fn derive_slot_key(
    root: &Root,
    salt: &[u8; SALT_LEN],
    passphrase_nfkc: Option<&[u8]>,
    profile: KdfProfile,
) -> Result<SlotKey, Error> {
    let (profile, mut a_p) = match passphrase_nfkc {
        None => (KdfProfile::DEFAULT, [0u8; 32]),
        Some(p) => (profile, argon2id_passphrase(p, salt, profile)?),
    };
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(root.as_bytes());
    ikm[32..].copy_from_slice(&a_p);
    let mut info = Vec::with_capacity(INFO_SLOT_PREFIX.len() + 1);
    info.extend_from_slice(INFO_SLOT_PREFIX);
    info.push(profile as u8);
    let mut k = [0u8; 32];
    hkdf_sha512(salt, &ikm, &info, &mut k);
    ikm.zeroize();
    a_p.zeroize();
    Ok(SlotKey(k))
}

/// Share verification tag: `HKDF("", R, "aska/v1/share-verify", 4)` (§8.2).
pub fn share_verify_tag(root: &Root) -> [u8; 4] {
    let mut t = [0u8; 4];
    hkdf_sha512(b"", root.as_bytes(), INFO_SHARE_VERIFY, &mut t);
    t
}

/// Payload nonce: `HKDF(salt=nonce_h, ikm=K_slot, "aska/v1/payload-nonce", 24)` (§4.4).
pub fn derive_payload_nonce(
    k_slot: &SlotKey,
    nonce_h: &[u8; HDR_NONCE_LEN],
) -> [u8; HDR_NONCE_LEN] {
    let mut n = [0u8; HDR_NONCE_LEN];
    hkdf_sha512(nonce_h, &k_slot.0, INFO_PAY_NONCE, &mut n);
    n
}
