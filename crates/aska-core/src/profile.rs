//! The optional encrypted profile (Client Design Table 3 `profile`, decision C-07): relay
//! addresses and an optional circle auth key in **one random-looking file**, protected by a
//! passphrase through Argon2id profile 1 — reusing the Block Format container rather than
//! inventing a format.
//!
//! How it reuses the container: a Block's slot key is `HKDF(root, Argon2id(passphrase, salt))`.
//! A profile has no root to hand over, so it uses a fixed, public root derived from a constant
//! string; the passphrase alone then carries the protection, exactly as C-07 intends. The
//! plaintext is a Key Card TLV (§7) carrying the relays and the auth key, with that same public
//! root in TLV 0x01 so the existing parser accepts it. The file is a class-1 Block: 4 KiB of
//! uniformly random-looking bytes, indistinguishable from a note.
//!
//! The profile is the single thing the client ever writes to disk, and only when the user names
//! a file (Client Design §3.1). Reading it back needs the passphrase; there is nothing else.

use crate::block::{open, seal, Slot};
use crate::consts::{SizeClass, PTYPE_BINARY};
use crate::drop::{secret32, Relay, Secret32};
use crate::encodings::KeyCard;
use crate::error::Error;
use crate::kdf::KdfProfile;
use crate::keys::Root;
use crate::rng::OsRng;
use sha2::{Digest, Sha512};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// Domain-separation constant for the public profile root.
const PROFILE_ROOT_INFO: &[u8] = b"aska/v1/profile-root";

/// What a profile holds. The auth key is the only secret and is zeroised on drop.
pub struct Profile {
    /// Relay onion public keys (Key Card TLV 0x03 order).
    pub relays: Vec<[u8; 32]>,
    /// Circle client-authorisation key (TLV 0x06), applying to every listed relay.
    pub auth_key: Option<Secret32>,
}

impl std::fmt::Debug for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Profile({} relays, auth={})",
            self.relays.len(),
            self.auth_key.is_some()
        )
    }
}

impl Profile {
    /// The relays as the Session wants them.
    pub fn relays(&self) -> Vec<Relay> {
        self.relays
            .iter()
            .map(|pk| Relay {
                pubkey: *pk,
                port: aska_proto::DEFAULT_PORT,
                auth_key: self.auth_key.clone(),
            })
            .collect()
    }
}

/// The fixed public root every profile is sealed under.
fn profile_root() -> Root {
    let d = Sha512::digest(PROFILE_ROOT_INFO);
    Root::from_slice(&d[..32])
}

/// NFKC-normalise the passphrase straight into a pre-sized zeroising buffer: two passes over
/// the normalisation iterator (size, then bytes through a 4-byte scratch), so no partial copy
/// is left behind in a reallocated `String` (pre-review C-5, applied to profiles in 1.1).
fn nfkc(passphrase: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    use zeroize::Zeroize;
    if passphrase.nfkc().all(char::is_whitespace) {
        return Err(Error::Encoding);
    }
    let len: usize = passphrase.nfkc().map(char::len_utf8).sum();
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    let mut scratch = [0u8; 4];
    for c in passphrase.nfkc() {
        out.extend_from_slice(c.encode_utf8(&mut scratch).as_bytes());
    }
    scratch.zeroize();
    Ok(out)
}

/// Seal a profile under `passphrase`. Returns the 4 KiB file contents.
/// A profile file is exactly one class-1 Block (4 096 bytes).
pub const PROFILE_LEN: usize = 4096;

pub fn seal_profile(p: &Profile, passphrase: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut card = KeyCard::new(profile_root());
    card.relays = p.relays.clone();
    card.auth_key = p.auth_key.as_ref().map(|k| ***k);
    let data = card.to_bytes();
    let slot = Slot {
        data: data.to_vec(),
        ptype: PTYPE_BINARY,
        passphrase_nfkc: Some(nfkc(passphrase)?.to_vec()),
        distress: false,
        profile: KdfProfile::P1,
    };
    let block = seal(
        &profile_root(),
        SizeClass::C1,
        &[slot],
        &mut OsRng,
        None,
        None,
    )?;
    Ok(Zeroizing::new(block))
}

/// Open a profile file. A wrong passphrase, a damaged file or a file that is not a profile all
/// fail the same way (`Error::NoSlot`): nothing about the file says what it is.
pub fn open_profile(bytes: &[u8], passphrase: &str) -> Result<Profile, Error> {
    let opened = open(
        bytes,
        &profile_root(),
        Some(&nfkc(passphrase)?),
        &[KdfProfile::P1],
    )?;
    let card = KeyCard::from_bytes(&opened.data)?;
    if card.root.as_bytes() != profile_root().as_bytes() {
        // A real Key Card sealed under this root would be a misuse; refuse rather than leak it.
        return Err(Error::Encoding);
    }
    Ok(Profile {
        relays: card.relays.clone(),
        auth_key: card.auth_key.map(secret32),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Profile {
        Profile {
            relays: vec![[7u8; 32], [9u8; 32]],
            auth_key: Some(secret32([0x42u8; 32])),
        }
    }

    #[test]
    fn round_trip_and_wrong_passphrase() {
        let file = seal_profile(&sample(), "correct horse").unwrap();
        assert_eq!(file.len(), SizeClass::C1.len());
        assert_eq!(file.len(), PROFILE_LEN);
        let p = open_profile(&file, "correct horse").unwrap();
        assert_eq!(p.relays, vec![[7u8; 32], [9u8; 32]]);
        assert_eq!(p.auth_key.as_ref().map(|k| ***k), Some([0x42u8; 32]));
        assert_eq!(p.relays().len(), 2);
        assert!(p.relays()[0].auth_key.is_some());
        assert!(open_profile(&file, "correct horse!").is_err());
        assert!(open_profile(&[0u8; 4096], "correct horse").is_err());
        assert!(seal_profile(&sample(), "   ").is_err());
    }

    #[test]
    fn two_seals_differ_and_look_random() {
        let a = seal_profile(&sample(), "x").unwrap();
        let b = seal_profile(&sample(), "x").unwrap();
        assert_ne!(a[..], b[..]);
        // Crude randomness sanity: every byte value class appears.
        let mut seen = [false; 256];
        for &v in a.iter() {
            seen[v as usize] = true;
        }
        assert!(seen.iter().filter(|s| **s).count() > 240);
    }
}
