//! Key-committing AEAD: the UtC transform over XChaCha20-Poly1305 (§5.4).
//!
//! `(K_enc, P) = HKDF(salt = nonce, ikm = K, info, 64)`; committed ciphertext = `P ‖ AEAD_{K_enc}(nonce, ad, m)`.

use crate::consts::*;
use crate::error::Error;
use crate::kdf::{hkdf_sha512, SlotKey};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

fn derive(key: &SlotKey, nonce: &[u8; HDR_NONCE_LEN], info: &[u8]) -> ([u8; 32], [u8; 32]) {
    let mut okm = [0u8; 64];
    hkdf_sha512(nonce, &key.0, info, &mut okm);
    let mut enc = [0u8; 32];
    let mut commit = [0u8; 32];
    enc.copy_from_slice(&okm[..32]);
    commit.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (enc, commit)
}

/// Seal `msg` under `key`/`nonce` with associated data `ad`. Output: `P(32) ‖ ct ‖ tag(16)`.
pub fn seal(
    key: &SlotKey,
    nonce: &[u8; HDR_NONCE_LEN],
    ad: &[u8],
    msg: &[u8],
    info: &[u8],
) -> Vec<u8> {
    let (mut enc, commit) = derive(key, nonce, info);
    let cipher = XChaCha20Poly1305::new((&enc).into());
    let ct = cipher
        .encrypt(XNonce::from_slice(nonce), Payload { msg, aad: ad })
        .expect("XChaCha20-Poly1305 encryption cannot fail for in-range lengths");
    enc.zeroize();
    let mut out = Vec::with_capacity(HDR_P_LEN + ct.len());
    out.extend_from_slice(&commit);
    out.extend_from_slice(&ct);
    out
}

/// Open a committed ciphertext. `Err(NoSlot)` when the commitment does not match (wrong key);
/// `Err(Malformed)` when the commitment matches but the AEAD tag fails (tampering).
pub fn open(
    key: &SlotKey,
    nonce: &[u8; HDR_NONCE_LEN],
    ad: &[u8],
    blob: &[u8],
    info: &[u8],
) -> Result<Vec<u8>, Error> {
    if blob.len() < HDR_P_LEN + TAG_LEN {
        return Err(Error::NoSlot);
    }
    let (mut enc, commit) = derive(key, nonce, info);
    let ok: bool = commit.ct_eq(&blob[..HDR_P_LEN]).into();
    if !ok {
        enc.zeroize();
        return Err(Error::NoSlot);
    }
    let cipher = XChaCha20Poly1305::new((&enc).into());
    let r = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: &blob[HDR_P_LEN..],
                aad: ad,
            },
        )
        .map_err(|_| Error::Malformed);
    enc.zeroize();
    r
}
