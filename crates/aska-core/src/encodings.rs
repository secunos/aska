//! bech32m text, Key Card TLV, Share text and Tor v3 onion addresses (§7).

use crate::consts::*;
use crate::error::Error;
use crate::keys::Root;
use crate::shares::Share;
use bech32::{Bech32m, Hrp};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// bech32m encode with a given HRP (BIP-350; the 90-char limit is not applied). The text
/// may carry a root or a Share, so it is returned zeroising.
pub fn bech32m_encode(hrp: &str, data: &[u8]) -> Result<Zeroizing<String>, Error> {
    let hrp = Hrp::parse(hrp).map_err(|_| Error::Encoding)?;
    bech32::encode::<Bech32m>(hrp, data)
        .map(Zeroizing::new)
        .map_err(|_| Error::Encoding)
}

/// bech32m decode; returns (hrp, data). Accepts all-lowercase or all-uppercase; rejects mixed
/// case. Every intermediate copy of the text and the payload is zeroised.
pub fn bech32m_decode(s: &str) -> Result<(String, Zeroizing<Vec<u8>>), Error> {
    let s = s.trim();
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(Error::Encoding);
    }
    let lower: Zeroizing<String> = Zeroizing::new(s.to_ascii_lowercase());
    let (hrp, data) = bech32::decode(&lower).map_err(|_| Error::Encoding)?;
    let data = Zeroizing::new(data);
    // bech32::decode accepts both bech32 and bech32m checksums; require bech32m by re-encoding.
    let re = Zeroizing::new(bech32::encode::<Bech32m>(hrp, &data).map_err(|_| Error::Encoding)?);
    if *re != *lower {
        return Err(Error::Encoding);
    }
    Ok((hrp.to_string(), data))
}

// ---- Key Card TLV (§7.3) ----
pub const TLV_VERSION: u8 = 0x01;
pub const TLV_ROOT: u8 = 0x02;
pub const TLV_RELAY: u8 = 0x03;
pub const TLV_CLASS: u8 = 0x04;
pub const TLV_TTL: u8 = 0x05;
pub const TLV_AUTH: u8 = 0x06;

/// Everything a receiver needs for the symmetric path in one QR (§7.3).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyCard {
    pub root: Root,
    /// 32-byte ed25519 onion-service public keys (§7.3, type 0x03).
    pub relays: Vec<[u8; 32]>,
    #[zeroize(skip)]
    pub size_class: Option<SizeClass>,
    pub ttl_hours: Option<u16>,
    /// Shared circle Tor client-auth private key (type 0x06, ADP/1 P-02).
    pub auth_key: Option<[u8; 32]>,
}

impl std::fmt::Debug for KeyCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "KeyCard(root=<redacted>, relays={}, class={:?}, ttl={:?}, auth={})",
            self.relays.len(),
            self.size_class,
            self.ttl_hours,
            self.auth_key.is_some()
        )
    }
}

impl KeyCard {
    pub fn new(root: Root) -> Self {
        KeyCard {
            root,
            relays: Vec::new(),
            size_class: None,
            ttl_hours: None,
            auth_key: None,
        }
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        // Sized exactly up front: a growing Vec reallocates, and the freed smaller buffer
        // would keep a plaintext copy of the root (seen by the GUI memory gate).
        let cap = 5
            + 32
            + self.relays.len() * 34
            + self.size_class.map_or(0, |_| 3)
            + self.ttl_hours.map_or(0, |_| 4)
            + self.auth_key.map_or(0, |_| 34);
        let mut out = Zeroizing::new(Vec::with_capacity(cap));
        out.extend_from_slice(&[TLV_VERSION, 1, FORMAT_VERSION, TLV_ROOT, 32]);
        out.extend_from_slice(self.root.as_bytes());
        for r in &self.relays {
            out.push(TLV_RELAY);
            out.push(32);
            out.extend_from_slice(r);
        }
        if let Some(c) = self.size_class {
            out.extend_from_slice(&[TLV_CLASS, 1, c as u8]);
        }
        if let Some(t) = self.ttl_hours {
            out.extend_from_slice(&[TLV_TTL, 2]);
            out.extend_from_slice(&t.to_be_bytes());
        }
        if let Some(a) = &self.auth_key {
            out.push(TLV_AUTH);
            out.push(32);
            out.extend_from_slice(a);
        }
        out
    }

    /// Strict decoder (Block Format §7.3, Table 5; pre-review B-7, tightened in 1.1): the
    /// version element must come first and be exactly `[FORMAT_VERSION]`; the root, class,
    /// TTL and auth elements appear at most once with exactly their defined lengths; relays
    /// are repeatable; unknown types are skipped; anything else is `Encoding`.
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        let mut i = 0;
        let mut root: Option<Zeroizing<[u8; 32]>> = None;
        let mut relays = Vec::new();
        let (mut sc, mut ttl) = (None, None);
        let mut auth: Option<Zeroizing<[u8; 32]>> = None;
        let mut first = true;
        while i < b.len() {
            if i + 2 > b.len() {
                return Err(Error::Encoding);
            }
            let (t, l) = (b[i], b[i + 1] as usize);
            let v = b.get(i + 2..i + 2 + l).ok_or(Error::Encoding)?;
            i += 2 + l;
            if first {
                // The version element MUST be first (and is therefore the only place it may be).
                if t != TLV_VERSION {
                    return Err(Error::Encoding);
                }
                if v != [FORMAT_VERSION] {
                    return Err(Error::Version);
                }
                first = false;
                continue;
            }
            match t {
                TLV_VERSION => return Err(Error::Encoding),
                TLV_ROOT if root.is_some() => return Err(Error::Encoding),
                TLV_ROOT => {
                    root = Some(Zeroizing::new(
                        <[u8; 32]>::try_from(v).map_err(|_| Error::Encoding)?,
                    ))
                }
                TLV_RELAY => relays.push(<[u8; 32]>::try_from(v).map_err(|_| Error::Encoding)?),
                TLV_CLASS if sc.is_some() || v.len() != 1 => return Err(Error::Encoding),
                TLV_CLASS => sc = Some(SizeClass::from_u8(v[0]).ok_or(Error::Encoding)?),
                TLV_TTL if ttl.is_some() => return Err(Error::Encoding),
                TLV_TTL => {
                    ttl = Some(u16::from_be_bytes(
                        <[u8; 2]>::try_from(v).map_err(|_| Error::Encoding)?,
                    ))
                }
                TLV_AUTH if auth.is_some() => return Err(Error::Encoding),
                TLV_AUTH => {
                    auth = Some(Zeroizing::new(
                        <[u8; 32]>::try_from(v).map_err(|_| Error::Encoding)?,
                    ))
                }
                _ => {} // unknown types are skipped (§7.3: "Decoders MUST skip unknown types")
            }
        }
        let root = root.ok_or(Error::Encoding)?;
        Ok(KeyCard {
            root: Root::from_slice(&root[..]),
            relays,
            size_class: sc,
            ttl_hours: ttl,
            auth_key: auth.map(|a| *a),
        })
    }

    pub fn encode(&self) -> Result<Zeroizing<String>, Error> {
        bech32m_encode(HRP_KEYCARD, &self.to_bytes())
    }

    pub fn decode(s: &str) -> Result<Self, Error> {
        let (hrp, data) = bech32m_decode(s)?;
        if hrp != HRP_KEYCARD {
            return Err(Error::Encoding);
        }
        Self::from_bytes(&data)
    }
}

// ---- Receiving Key (§7.5 as defined by DC-02 §2.5) ----
pub const HRP_RECEIVING: &str = HRP_RXKEY;
const RK_VERSION: u8 = 0x01;

/// bech32m's checksum without the 1 023-character code-length limit, for the ~2 000-character
/// Receiving Key. Same generator and target residue as bech32m (BIP-350), so the checksum is
/// computed identically; beyond 1 023 characters it is a 30-bit integrity check rather than a
/// guaranteed 3-error detector, which is what a pasted or scanned key needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bech32mLong {}

impl bech32::primitives::checksum::Checksum for Bech32mLong {
    type MidstateRepr = u32;
    const CODE_LENGTH: usize = usize::MAX;
    const CHECKSUM_LENGTH: usize = 6;
    const GENERATOR_SH: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    const TARGET_RESIDUE: u32 = 0x2bc830a3;
}

/// Encode with the long-form bech32m checksum (lowercase).
pub fn bech32m_long_encode(hrp: &str, data: &[u8]) -> Result<String, Error> {
    let hrp = Hrp::parse(hrp).map_err(|_| Error::Encoding)?;
    bech32::encode::<Bech32mLong>(hrp, data).map_err(|_| Error::Encoding)
}

/// Decode a long-form bech32m string; all-lower or all-upper case, never mixed.
pub fn bech32m_long_decode(s: &str) -> Result<(String, Vec<u8>), Error> {
    use bech32::primitives::decode::CheckedHrpstring;
    let s = s.trim();
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(Error::Encoding);
    }
    let lower = s.to_ascii_lowercase();
    let checked = CheckedHrpstring::new::<Bech32mLong>(&lower).map_err(|_| Error::Encoding)?;
    let hrp = checked.hrp().to_string();
    let data: Vec<u8> = checked.byte_iter().collect();
    Ok((hrp, data))
}

/// The public half of a receiving key with its relay hints: `version ‖ pk_M ‖ pk_X ‖ TLVs`
/// (the Key Card's TLV types 0x03/0x04/0x05). Nothing in it is secret; it must only be
/// *authentic*, which the twelve-character `check` (a hash of the public key) lets two people
/// confirm out of band.
/// Upper bound on relay hints in a Receiving Key (review finding B-3).
pub const MAX_RELAY_HINTS: usize = 8;

#[derive(Clone, PartialEq, Eq)]
pub struct ReceivingKey {
    pub pk: Box<[u8; crate::xwing::PK_LEN]>,
    pub relays: Vec<[u8; 32]>,
    pub size_class: Option<SizeClass>,
    pub ttl_hours: Option<u16>,
}

impl std::fmt::Debug for ReceivingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ReceivingKey(relays={}, class={:?}, ttl={:?})",
            self.relays.len(),
            self.size_class,
            self.ttl_hours
        )
    }
}

impl ReceivingKey {
    pub fn new(pk: Box<[u8; crate::xwing::PK_LEN]>) -> Self {
        ReceivingKey {
            pk,
            relays: Vec::new(),
            size_class: None,
            ttl_hours: None,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            1 + crate::xwing::PK_LEN
                + self.relays.len() * 34
                + self.size_class.map_or(0, |_| 3)
                + self.ttl_hours.map_or(0, |_| 4),
        );
        out.push(RK_VERSION);
        out.extend_from_slice(&self.pk[..]);
        for r in &self.relays {
            out.push(TLV_RELAY);
            out.push(32);
            out.extend_from_slice(r);
        }
        if let Some(c) = self.size_class {
            out.extend_from_slice(&[TLV_CLASS, 1, c as u8]);
        }
        if let Some(t) = self.ttl_hours {
            out.extend_from_slice(&[TLV_TTL, 2]);
            out.extend_from_slice(&t.to_be_bytes());
        }
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        if b.len() < 1 + crate::xwing::PK_LEN {
            return Err(Error::Encoding);
        }
        if b[0] != RK_VERSION {
            return Err(Error::Version);
        }
        let mut pk = Box::new([0u8; crate::xwing::PK_LEN]);
        pk.copy_from_slice(&b[1..1 + crate::xwing::PK_LEN]);
        let mut rk = ReceivingKey::new(pk);
        let mut i = 1 + crate::xwing::PK_LEN;
        while i < b.len() {
            if i + 2 > b.len() {
                return Err(Error::Encoding);
            }
            let (t, l) = (b[i], b[i + 1] as usize);
            let v = b.get(i + 2..i + 2 + l).ok_or(Error::Encoding)?;
            i += 2 + l;
            match t {
                TLV_RELAY => rk
                    .relays
                    .push(<[u8; 32]>::try_from(v).map_err(|_| Error::Encoding)?),
                TLV_CLASS => {
                    rk.size_class = Some(
                        SizeClass::from_u8(*v.first().ok_or(Error::Encoding)?)
                            .ok_or(Error::Encoding)?,
                    )
                }
                TLV_TTL => {
                    rk.ttl_hours = Some(u16::from_be_bytes(
                        <[u8; 2]>::try_from(v).map_err(|_| Error::Encoding)?,
                    ))
                }
                _ => {} // unknown types are skipped (forward compatibility)
            }
        }
        // A key carries a handful of relay hints at most; an unbounded list would make the
        // sender sweep arbitrarily many relays (review finding B-3).
        if rk.relays.len() > MAX_RELAY_HINTS {
            return Err(Error::Encoding);
        }
        Ok(rk)
    }

    /// `askar1…` text (about 2 000 characters with one relay).
    pub fn encode(&self) -> Result<String, Error> {
        bech32m_long_encode(HRP_RECEIVING, &self.to_bytes())
    }

    pub fn decode(s: &str) -> Result<Self, Error> {
        let (hrp, data) = bech32m_long_decode(s)?;
        if hrp != HRP_RECEIVING {
            return Err(Error::Encoding);
        }
        let rk = Self::from_bytes(&data)?;
        // Non-canonical strings (padding bits set, duplicate or reordered TLVs) are rejected
        // the same way the Key Card path does it: the key must re-encode to the text given
        // (review finding B-3). Unknown TLVs are therefore not accepted either — a future
        // version byte is the upgrade path.
        if rk.encode()? != s.trim().to_ascii_lowercase() {
            return Err(Error::Encoding);
        }
        Ok(rk)
    }

    /// The check (§7.5.3): the first 60 bits of `SHA3-256("aska/v1/rk-check" ‖ pk_M ‖ pk_X)`
    /// as twelve bech32 characters in three groups of four, e.g. `q7xd-9g2m-4ckv`. It is a
    /// function of the public key **only** — relay, class and TTL hints, padding and the
    /// checksum do not enter — so a substitute key with the same check costs the attacker a
    /// 2⁶⁰ second-preimage search on the hash, not the solution of a linear code (review
    /// finding B-1: the former "last eight characters" were an affine function of free fields
    /// and could be matched in milliseconds). Read to each other over a second channel.
    pub fn check(&self) -> String {
        Self::check_of(&self.pk)
    }

    /// The check of a public key (sender and receiver compute it from the decoded key, so a
    /// non-canonical re-encoding cannot make the two sides disagree).
    pub fn check_of(pk: &[u8; crate::xwing::PK_LEN]) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(RK_CHECK_DOMAIN);
        h.update(pk);
        let d = h.finalize();
        // 60 bits → 12 symbols of 5 bits, big-endian bit order.
        const ALPHABET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        let mut acc: u64 = 0;
        for &b in d.iter().take(8) {
            acc = (acc << 8) | b as u64;
        }
        let mut out = String::with_capacity(RK_CHECK_CHARS + 2);
        for i in 0..RK_CHECK_CHARS {
            let shift = 64 - 5 * (i + 1);
            let sym = ((acc >> shift) & 0x1f) as usize;
            if i > 0 && i % 4 == 0 {
                out.push('-');
            }
            out.push(ALPHABET[sym] as char);
        }
        out
    }

    /// The check of a Receiving Key given as text; `None` if the text is not a Receiving Key.
    pub fn check_of_text(text: &str) -> Option<String> {
        Self::decode(text).ok().map(|rk| rk.check())
    }
}

// ---- Shares as text (§8.2) ----
pub fn share_encode(s: &Share) -> Result<Zeroizing<String>, Error> {
    bech32m_encode(HRP_SHARE, &s.to_bytes()[..])
}

pub fn share_decode(t: &str) -> Result<Share, Error> {
    let (hrp, data) = bech32m_decode(t)?;
    if hrp != HRP_SHARE {
        return Err(Error::Encoding);
    }
    Share::from_bytes(&data)
}

// ---- Tor v3 onion addresses (rend-spec-v3) ----
fn onion_checksum(pk: &[u8; 32]) -> [u8; 2] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(pk);
    h.update([0x03]);
    let d = h.finalize();
    [d[0], d[1]]
}

pub fn onion_pubkey_to_address(pk: &[u8; 32]) -> String {
    let mut raw = Vec::with_capacity(35);
    raw.extend_from_slice(pk);
    raw.extend_from_slice(&onion_checksum(pk));
    raw.push(0x03);
    format!(
        "{}.onion",
        data_encoding::BASE32_NOPAD.encode(&raw).to_lowercase()
    )
}

pub fn onion_address_to_pubkey(addr: &str) -> Result<[u8; 32], Error> {
    let host = addr
        .trim()
        .trim_end_matches('/')
        .strip_suffix(".onion")
        .ok_or(Error::Encoding)?;
    let raw = data_encoding::BASE32_NOPAD
        .decode(host.to_uppercase().as_bytes())
        .map_err(|_| Error::Encoding)?;
    if raw.len() != 35 || raw[34] != 0x03 {
        return Err(Error::Encoding);
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&raw[..32]);
    if onion_checksum(&pk) != [raw[32], raw[33]] {
        return Err(Error::Encoding);
    }
    Ok(pk)
}

#[cfg(test)]
mod receiving_key_tests {
    #[test]
    fn check_depends_on_the_public_key_only_and_has_twelve_symbols() {
        let words = crate::xwing::new_seed_words().unwrap();
        let a = crate::xwing::receiving_key_from_words(&words, &[], None, None).unwrap();
        let b = crate::xwing::receiving_key_from_words(
            &words,
            &[[7u8; 32]],
            Some(SizeClass::C3),
            Some(48),
        )
        .unwrap();
        assert_eq!(a.check(), b.check(), "hints must not change the check");
        let c = a.check();
        assert_eq!(c.len(), 14);
        assert_eq!(c.matches('-').count(), 2);
        assert!(c
            .chars()
            .all(|ch| ch == '-' || "qpzry9x8gf2tvdw0s3jn54khce6mua7l".contains(ch)));
        // From text, through decode, equals the receiver's own value.
        assert_eq!(
            ReceivingKey::check_of_text(&a.encode().unwrap()).unwrap(),
            c
        );
        // A different key → a different check (with overwhelming probability).
        let other = crate::xwing::receiving_key_from_words(
            &crate::xwing::new_seed_words().unwrap(),
            &[],
            None,
            None,
        )
        .unwrap();
        assert_ne!(other.check(), c);
    }

    use super::*;
    use bech32::primitives::checksum::Checksum;

    #[test]
    fn long_checksum_is_bech32m_and_round_trips() {
        Bech32mLong::sanity_check();
        // Short strings encode identically under both checksums.
        let short = bech32m_encode("aska", &[1, 2, 3]).unwrap();
        assert_eq!(*short, bech32m_long_encode("aska", &[1, 2, 3]).unwrap());
        let pk = Box::new([0x42u8; crate::xwing::PK_LEN]);
        let mut rk = ReceivingKey::new(pk);
        rk.relays.push([7u8; 32]);
        rk.size_class = Some(SizeClass::C2);
        rk.ttl_hours = Some(48);
        let text = rk.encode().unwrap();
        assert!(text.starts_with("askar1"));
        assert!(text.len() > 1900);
        let back = ReceivingKey::decode(&text).unwrap();
        assert_eq!(back, rk);
        assert_eq!(
            ReceivingKey::decode(&text.to_ascii_uppercase()).unwrap(),
            rk
        );
        // One flipped character is caught; a Key Card is not a Receiving Key.
        let mut bad = text.clone().into_bytes();
        bad[100] = if bad[100] == b'q' { b'p' } else { b'q' };
        assert!(ReceivingKey::decode(std::str::from_utf8(&bad).unwrap()).is_err());
        assert!(ReceivingKey::decode(
            "aska1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz"
        )
        .is_err());
        // The check is case-insensitive in the text and does not depend on the checksum.
        assert_eq!(
            ReceivingKey::check_of_text(&text).unwrap(),
            ReceivingKey::check_of_text(&text.to_ascii_uppercase()).unwrap()
        );
    }
}

#[cfg(test)]
mod keycard_strictness_tests {
    //! Block Format §7.3 Table 5 as normative text (pre-review B-7, tightened in 1.1).
    use super::*;

    fn card() -> KeyCard {
        let mut c = KeyCard::new(Root::from_slice(&[0x11; 32]));
        c.relays.push([0x22; 32]);
        c.size_class = Some(SizeClass::C2);
        c.ttl_hours = Some(48);
        c.auth_key = Some([0x33; 32]);
        c
    }

    fn tlv(t: u8, v: &[u8]) -> Vec<u8> {
        let mut o = vec![t, v.len() as u8];
        o.extend_from_slice(v);
        o
    }

    #[test]
    fn canonical_encoding_round_trips_and_is_accepted() {
        let c = card();
        let b = c.to_bytes();
        let d = KeyCard::from_bytes(&b).unwrap();
        assert_eq!(d.to_bytes(), b);
        assert_eq!(d.relays, c.relays);
        assert_eq!(d.size_class, c.size_class);
        assert_eq!(d.ttl_hours, c.ttl_hours);
        assert_eq!(d.auth_key, c.auth_key);
    }

    #[test]
    fn version_must_be_first_and_single() {
        let b = card().to_bytes();
        // No version element at all.
        assert!(KeyCard::from_bytes(&b[3..]).is_err());
        // Version after the root.
        let mut swapped = b[3..37].to_vec();
        swapped.extend_from_slice(&b[..3]);
        swapped.extend_from_slice(&b[37..]);
        assert!(KeyCard::from_bytes(&swapped).is_err());
        // Two version elements.
        let mut twice = b[..3].to_vec();
        twice.extend_from_slice(&b);
        assert!(KeyCard::from_bytes(&twice).is_err());
        // Wrong version value, and wrong version lengths.
        let mut bad = b.clone();
        bad[2] = 9;
        assert!(matches!(KeyCard::from_bytes(&bad), Err(Error::Version)));
        let mut long = tlv(TLV_VERSION, &[FORMAT_VERSION, 0]);
        long.extend_from_slice(&b[3..]);
        assert!(KeyCard::from_bytes(&long).is_err());
    }

    #[test]
    fn duplicates_and_wrong_lengths_are_rejected() {
        let b = card().to_bytes();
        for extra in [
            tlv(TLV_ROOT, &[0x44; 32]),
            tlv(TLV_CLASS, &[1]),
            tlv(TLV_TTL, &[0, 24]),
            tlv(TLV_AUTH, &[0x55; 32]),
        ] {
            let mut dup = b.clone();
            dup.extend_from_slice(&extra);
            assert!(
                KeyCard::from_bytes(&dup).is_err(),
                "duplicate {:#x}",
                extra[0]
            );
        }
        let base = {
            let mut c = KeyCard::new(Root::from_slice(&[0x11; 32]));
            c.relays.clear();
            c.to_bytes()
        };
        for (t, v) in [
            (TLV_CLASS, vec![2u8, 0]),
            (TLV_CLASS, vec![]),
            (TLV_CLASS, vec![4]),
            (TLV_TTL, vec![24]),
            (TLV_TTL, vec![0, 0, 24]),
            (TLV_RELAY, vec![0x22; 31]),
            (TLV_AUTH, vec![0x33; 33]),
        ] {
            let mut bad = base.clone();
            bad.extend_from_slice(&tlv(t, &v));
            assert!(
                KeyCard::from_bytes(&bad).is_err(),
                "type {t:#x} len {}",
                v.len()
            );
        }
        // Root of the wrong length, and a declared length past the end.
        let mut short_root = tlv(TLV_VERSION, &[FORMAT_VERSION]);
        short_root.extend_from_slice(&tlv(TLV_ROOT, &[0x11; 31]));
        assert!(KeyCard::from_bytes(&short_root).is_err());
        let mut truncated = b.clone();
        truncated.truncate(b.len() - 1);
        assert!(KeyCard::from_bytes(&truncated).is_err());
        // Relays may repeat.
        let mut two = base.clone();
        two.extend_from_slice(&tlv(TLV_RELAY, &[0x22; 32]));
        two.extend_from_slice(&tlv(TLV_RELAY, &[0x66; 32]));
        assert_eq!(KeyCard::from_bytes(&two).unwrap().relays.len(), 2);
    }

    #[test]
    fn unknown_types_are_skipped() {
        let mut b = card().to_bytes();
        b.extend_from_slice(&tlv(0x40, &[1, 2, 3]));
        b.extend_from_slice(&tlv(0x7f, &[]));
        let d = KeyCard::from_bytes(&b).unwrap();
        assert_eq!(d.ttl_hours, Some(48));
    }
}
