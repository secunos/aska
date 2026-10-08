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
//! Since 1.1 (RM-09) the profile can also keep **receiving seeds** — the 32-byte secrets behind
//! a user's Receiving Keys — as TLV 0x10 elements after the Key Card fields, so that a receiver
//! who keeps a long-lived Receiving Key need not type its 24 words each time. The Key Card
//! decoder skips 0x10 as an unknown type, so a 1.0.x client opens a 1.1 profile and simply
//! sees no seeds. At most `MAX_SEEDS` seeds; the file stays one class-1 Block.
//!
//! The profile is the single thing the client ever writes to disk, and only when the user names
//! a file (Client Design §3.1). Reading it back needs the passphrase; there is nothing else.

use crate::block::{open, seal, Slot};
use crate::consts::{SizeClass, PTYPE_BINARY};
use crate::drop::{secret32, Relay, Secret32};
use crate::encodings::{KeyCard, ReceivingKey, TLV_PROFILE_SEED};
use crate::error::Error;
use crate::kdf::KdfProfile;
use crate::keys::Root;
use crate::rng::OsRng;
use sha2::{Digest, Sha512};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// Domain-separation constant for the public profile root.
const PROFILE_ROOT_INFO: &[u8] = b"aska/v1/profile-root";

/// Most receiving seeds a profile holds (the file is one 4 KiB Block; eight seeds and a few
/// relays leave ample room).
pub const MAX_SEEDS: usize = 8;

/// What a profile holds. The auth key and the seeds are secrets and are zeroised on drop.
pub struct Profile {
    /// Relay onion public keys (Key Card TLV 0x03 order).
    pub relays: Vec<[u8; 32]>,
    /// Circle client-authorisation key (TLV 0x06), applying to every listed relay.
    pub auth_key: Option<Secret32>,
    /// Stored receiving seeds (TLV 0x10), in file order. Empty for profiles written by 1.0.x.
    pub seeds: Vec<Secret32>,
}

impl std::fmt::Debug for Profile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Profile({} relays, auth={}, {} seeds)",
            self.relays.len(),
            self.auth_key.is_some(),
            self.seeds.len()
        )
    }
}

/// One stored seed as the user sees it: never the seed itself, only the public key it yields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSeed {
    /// Position in the profile (stable until the profile is rewritten).
    pub index: usize,
    /// The twelve-character check of the seed's Receiving Key (three groups of four), the
    /// name a user recognises a key by.
    pub check: String,
}

impl Profile {
    /// The stored seeds by their Receiving Key checks (no relay hints: the check depends on
    /// the public key only). Derives each public key; a few milliseconds per seed.
    pub fn stored_seeds(&self) -> Vec<StoredSeed> {
        self.seeds
            .iter()
            .enumerate()
            .map(|(index, s)| StoredSeed {
                index,
                check: ReceivingKey::new(crate::xwing::Expanded::from_seed(s).public_key()).check(),
            })
            .collect()
    }

    /// The stored seed whose Receiving Key check is `check` (case-insensitive; the dashes may
    /// be omitted).
    pub fn seed_by_check(&self, check: &str) -> Option<usize> {
        let want: String = check
            .chars()
            .filter(|c| *c != '-')
            .flat_map(char::to_lowercase)
            .collect();
        self.stored_seeds()
            .into_iter()
            .find(|s| s.check.replace('-', "") == want)
            .map(|s| s.index)
    }

    /// Add a seed (refused when the profile is full or already holds it).
    pub fn add_seed(&mut self, seed: Secret32) -> Result<usize, Error> {
        if self.seeds.len() >= MAX_SEEDS {
            return Err(Error::TooLarge);
        }
        if self.seeds.iter().any(|s| s.as_slice() == seed.as_slice()) {
            return Err(Error::Encoding);
        }
        self.seeds.push(seed);
        Ok(self.seeds.len() - 1)
    }

    /// Remove the seed at `index`; it is zeroised when dropped.
    pub fn remove_seed(&mut self, index: usize) -> Option<Secret32> {
        (index < self.seeds.len()).then(|| self.seeds.remove(index))
    }

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
    if p.seeds.len() > MAX_SEEDS {
        return Err(Error::TooLarge);
    }
    let mut card = KeyCard::new(profile_root());
    card.relays = p.relays.clone();
    card.auth_key = p.auth_key.as_ref().map(|k| ***k);
    let card_bytes = card.to_bytes();
    // Card fields first (as any Key Card), then the profile-only seed elements.
    let mut data = Zeroizing::new(Vec::with_capacity(card_bytes.len() + 34 * p.seeds.len()));
    data.extend_from_slice(&card_bytes);
    for s in &p.seeds {
        data.extend_from_slice(&[TLV_PROFILE_SEED, 32]);
        data.extend_from_slice(s.as_slice());
    }
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
        seeds: profile_seeds(&opened.data)?,
    })
}

/// The 0x10 elements of a profile's TLV (the Key Card decoder has already validated the
/// framing and skipped them as unknown). Exactly 32 bytes each, at most `MAX_SEEDS`.
fn profile_seeds(tlv: &[u8]) -> Result<Vec<Secret32>, Error> {
    let mut seeds = Vec::new();
    let mut i = 0;
    while i + 2 <= tlv.len() {
        let (t, l) = (tlv[i], tlv[i + 1] as usize);
        let v = tlv.get(i + 2..i + 2 + l).ok_or(Error::Encoding)?;
        i += 2 + l;
        if t == TLV_PROFILE_SEED {
            if seeds.len() >= MAX_SEEDS {
                return Err(Error::Encoding);
            }
            seeds.push(secret32(
                <[u8; 32]>::try_from(v).map_err(|_| Error::Encoding)?,
            ));
        }
    }
    Ok(seeds)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Profile {
        Profile {
            relays: vec![[7u8; 32], [9u8; 32]],
            auth_key: Some(secret32([0x42u8; 32])),
            seeds: Vec::new(),
        }
    }

    #[test]
    fn seeds_round_trip_are_named_by_their_check_and_are_invisible_to_a_card_decoder() {
        let mut p = sample();
        let s1 = crate::xwing::generate_seed().unwrap();
        let s2 = crate::xwing::generate_seed().unwrap();
        assert_eq!(p.add_seed(secret32(*s1)).unwrap(), 0);
        assert_eq!(p.add_seed(secret32(*s2)).unwrap(), 1);
        assert!(p.add_seed(secret32(*s2)).is_err(), "duplicate refused");
        let file = seal_profile(&p, "correct horse").unwrap();
        assert_eq!(file.len(), PROFILE_LEN);
        let q = open_profile(&file, "correct horse").unwrap();
        assert_eq!(q.seeds.len(), 2);
        assert_eq!(q.seeds[0].as_slice(), &s1[..]);
        assert_eq!(q.seeds[1].as_slice(), &s2[..]);
        assert_eq!(q.relays, p.relays);
        // Named by the check of the Receiving Key the seed yields — the same check the
        // receiver shows when creating the key from the words.
        let words = Root::from_bytes(*s2).to_words();
        let rk = crate::xwing::receiving_key_from_words(&words, &[], None, None).unwrap();
        let named = q.stored_seeds();
        assert_eq!(named[1].check, rk.check());
        assert_eq!(q.seed_by_check(&rk.check()), Some(1));
        assert_eq!(
            q.seed_by_check(&rk.check().replace('-', "").to_uppercase()),
            Some(1)
        );
        assert_eq!(q.seed_by_check("qqqq-qqqq-qqqq"), None);
        // Removal; a full profile refuses a ninth seed.
        let mut q = q;
        assert!(q.remove_seed(0).is_some());
        assert_eq!(q.seeds.len(), 1);
        for _ in 0..7 {
            q.add_seed(secret32(*crate::xwing::generate_seed().unwrap()))
                .unwrap();
        }
        assert!(q
            .add_seed(secret32(*crate::xwing::generate_seed().unwrap()))
            .is_err());
        assert_eq!(
            seal_profile(&q, "correct horse").unwrap().len(),
            PROFILE_LEN
        );
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
