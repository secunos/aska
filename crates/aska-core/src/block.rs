//! Block layout, seal and open (§4, §6).

use crate::consts::*;
use crate::error::Error;
use crate::kdf::{derive_payload_nonce, derive_slot_key, KdfProfile, SlotKey};
use crate::keys::Root;
use crate::rng::RandomSource;
use crate::utc;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// One slot to seal. `passphrase_nfkc = None` makes an *open* slot (opens with R alone).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Slot {
    pub data: Vec<u8>,
    pub ptype: u8,
    pub passphrase_nfkc: Option<Vec<u8>>,
    pub distress: bool,
    #[zeroize(skip)]
    pub profile: KdfProfile,
}

impl std::fmt::Debug for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Slot(<{} bytes>, ptype={}, passphrase={}, distress={})",
            self.data.len(),
            self.ptype,
            self.passphrase_nfkc.is_some(),
            self.distress
        )
    }
}

impl Slot {
    pub fn text(data: &[u8], passphrase_nfkc: Option<&[u8]>) -> Self {
        Slot {
            data: data.to_vec(),
            ptype: PTYPE_TEXT,
            passphrase_nfkc: passphrase_nfkc.map(|p| p.to_vec()),
            distress: false,
            profile: KdfProfile::DEFAULT,
        }
    }
    pub fn binary(data: &[u8], passphrase_nfkc: Option<&[u8]>) -> Self {
        let mut s = Slot::text(data, passphrase_nfkc);
        s.ptype = PTYPE_BINARY;
        s
    }
    pub fn distress(mut self) -> Self {
        self.distress = true;
        self
    }
    pub fn profile(mut self, p: KdfProfile) -> Self {
        self.profile = p;
        self
    }
}

/// Result of opening a Block.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OpenedSlot {
    pub index: u8,
    pub data: Vec<u8>,
    pub ptype: u8,
    pub distress: bool,
}

impl std::fmt::Debug for OpenedSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "OpenedSlot(index={}, <{} bytes>, ptype={}, distress={})",
            self.index,
            self.data.len(),
            self.ptype,
            self.distress
        )
    }
}

/// Slot region length: `ceil((32 + 6 + datalen + 16) / 256) · 256` (§4.4).
pub fn region_len(data_len: usize) -> usize {
    let raw = HDR_P_LEN + INNER_HDR_LEN + data_len + TAG_LEN;
    raw.div_ceil(PAYLOAD_GRANULE) * PAYLOAD_GRANULE
}

fn encode_header_body(flags: u8, offset: usize, length: usize, ptype: u8) -> [u8; HDR_BODY_LEN] {
    debug_assert!(offset < 1 << 24 && length < 1 << 24);
    let mut b = [0u8; HDR_BODY_LEN];
    b[0] = flags;
    b[1..4].copy_from_slice(&(offset as u32).to_be_bytes()[1..]);
    b[4..7].copy_from_slice(&(length as u32).to_be_bytes()[1..]);
    b[7] = ptype;
    b
}

fn decode_header_body(b: &[u8]) -> Option<(u8, usize, usize, u8)> {
    if b.len() != HDR_BODY_LEN || b[8..] != [0u8; 8] {
        return None;
    }
    let off = u32::from_be_bytes([0, b[1], b[2], b[3]]) as usize;
    let len = u32::from_be_bytes([0, b[4], b[5], b[6]]) as usize;
    Some((b[0], off, len, b[7]))
}

/// Seal `slots` into a Block of `class` (§6.1).
///
/// `offsets`: explicit payload offsets for each slot (granule-aligned, non-overlapping), or
/// `None` for the default placement (consecutive from a random granule start).
///
/// Randomness draw order (normative for test vectors, §9): salt(32) → KEM region(1120, unless
/// supplied) → reserved(32) → four header nonces (24 each) → [random start, if offsets is None]
/// → per occupied slot: inner padding → filler for the whole payload region → 88 random bytes
/// per unoccupied header.
pub fn seal<R: RandomSource>(
    root: &Root,
    class: SizeClass,
    slots: &[Slot],
    rng: &mut R,
    offsets: Option<&[usize]>,
    kem_region: Option<&[u8; KEM_LEN]>,
) -> Result<Vec<u8>, Error> {
    if slots.is_empty() || slots.len() > N_SLOTS {
        return Err(Error::BadSlots);
    }
    // §6.1 step 1: distinct slot keys, at most one distress slot.
    {
        let mut ids: Vec<Option<(&[u8], u8)>> = Vec::new();
        for s in slots {
            let id = s.passphrase_nfkc.as_deref().map(|p| (p, s.profile as u8));
            if ids.contains(&id) {
                return Err(Error::BadSlots);
            }
            ids.push(id);
        }
        if slots.iter().filter(|s| s.distress).count() > 1 {
            return Err(Error::BadSlots);
        }
    }
    let payload_len = class.payload_len();
    let sizes: Vec<usize> = slots.iter().map(|s| region_len(s.data.len())).collect();
    let total: usize = sizes.iter().sum();
    if total > payload_len {
        return Err(Error::TooLarge);
    }

    let salt: [u8; SALT_LEN] = rng.array()?;
    let kem: Vec<u8> = match kem_region {
        Some(k) => k.to_vec(),
        None => rng.bytes(KEM_LEN)?,
    };
    let reserved: [u8; RSV_LEN] = rng.array()?;
    let mut nonces = Vec::with_capacity(N_SLOTS);
    for _ in 0..N_SLOTS {
        nonces.push(rng.array::<HDR_NONCE_LEN>()?);
    }
    // Header permutation (§6.1, §10.3): slot `s` is written under header index `perm[s]`, so
    // the index of an opened slot — and, with default placement, its region's position — says
    // nothing about whether it was the sender's first (real) slot. Fisher–Yates with one
    // 4-byte draw per step, mirrored by the reference implementation (normative draw order).
    let mut perm: [usize; N_SLOTS] = [0, 1, 2, 3];
    for i in (1..N_SLOTS).rev() {
        let r: [u8; 4] = rng.array()?;
        let j = u32::from_be_bytes(r) as usize % (i + 1);
        perm.swap(i, j);
    }
    let idx_of = &perm[..slots.len()];

    let offsets: Vec<usize> = match offsets {
        Some(o) => {
            if o.len() != slots.len() {
                return Err(Error::BadSlots);
            }
            o.to_vec()
        }
        None => {
            let free = payload_len - total;
            let r: [u8; 4] = rng.array()?;
            let start =
                (u32::from_be_bytes(r) as usize % (free / PAYLOAD_GRANULE + 1)) * PAYLOAD_GRANULE;
            // Sequential in order of increasing header index.
            let mut order: Vec<usize> = (0..slots.len()).collect();
            order.sort_by_key(|&s| idx_of[s]);
            let mut v = vec![0usize; slots.len()];
            let mut cur = start;
            for s in order {
                v[s] = cur;
                cur += sizes[s];
            }
            v
        }
    };
    // Validate placement.
    let mut ranges: Vec<(usize, usize)> = offsets
        .iter()
        .zip(&sizes)
        .map(|(&o, &s)| (o, o + s))
        .collect();
    for &(a, b) in &ranges {
        if a % PAYLOAD_GRANULE != 0 || b > payload_len {
            return Err(Error::BadSlots);
        }
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|w| w[0].1 > w[1].0) {
        return Err(Error::BadSlots);
    }

    let mut payload = vec![0u8; payload_len];
    let mut occupied = vec![false; payload_len];
    let mut headers: Vec<Option<Vec<u8>>> = vec![None; N_SLOTS];

    for (s, slot) in slots.iter().enumerate() {
        let i = idx_of[s];
        let off = offsets[s];
        let sz = sizes[s];
        let k_slot: SlotKey =
            derive_slot_key(root, &salt, slot.passphrase_nfkc.as_deref(), slot.profile)?;
        let inner_len = sz - HDR_P_LEN - TAG_LEN;
        let pad_len = inner_len - INNER_HDR_LEN - slot.data.len();
        let mut inner = Vec::with_capacity(inner_len);
        inner.push(FORMAT_VERSION);
        inner.push(slot.ptype);
        inner.extend_from_slice(&(slot.data.len() as u32).to_be_bytes());
        inner.extend_from_slice(&slot.data);
        inner.extend_from_slice(&rng.bytes(pad_len)?);
        let pay_nonce = derive_payload_nonce(&k_slot, &nonces[i]);
        let mut ad = Vec::with_capacity(AD_PAYLOAD.len() + 1 + HDR_NONCE_LEN);
        ad.extend_from_slice(AD_PAYLOAD);
        ad.push(i as u8);
        ad.extend_from_slice(&nonces[i]);
        let blob = utc::seal(&k_slot, &pay_nonce, &ad, &inner, INFO_UTC_PAY);
        inner.zeroize();
        debug_assert_eq!(blob.len(), sz);
        payload[off..off + sz].copy_from_slice(&blob);
        occupied[off..off + sz].iter_mut().for_each(|b| *b = true);

        let flags = if slot.distress { FLAG_DISTRESS } else { 0 };
        let body = encode_header_body(flags, off, sz, slot.ptype);
        let mut had = Vec::with_capacity(AD_HEADER.len() + 1);
        had.extend_from_slice(AD_HEADER);
        had.push(i as u8);
        let mut h = Vec::with_capacity(HDR_LEN);
        h.extend_from_slice(&nonces[i]);
        h.extend_from_slice(&utc::seal(&k_slot, &nonces[i], &had, &body, INFO_UTC_HDR));
        headers[i] = Some(h);
    }

    let filler = rng.bytes(payload_len)?;
    for (j, occ) in occupied.iter().enumerate() {
        if !occ {
            payload[j] = filler[j];
        }
    }
    for h in headers.iter_mut() {
        if h.is_none() {
            *h = Some(rng.bytes(HDR_LEN)?);
        }
    }

    let mut block = Vec::with_capacity(class.len());
    block.extend_from_slice(&salt);
    block.extend_from_slice(&kem);
    for h in headers.into_iter() {
        block.extend_from_slice(&h.expect("all headers filled"));
    }
    block.extend_from_slice(&reserved);
    block.extend_from_slice(&payload);
    debug_assert_eq!(block.len(), class.len());
    Ok(block)
}

/// Try to open `block` with `root` and an optional passphrase, trying each `profiles` entry
/// (§6.2). Returns the first slot that opens.
pub fn open(
    block: &[u8],
    root: &Root,
    passphrase_nfkc: Option<&[u8]>,
    profiles: &[KdfProfile],
) -> Result<OpenedSlot, Error> {
    let class = SizeClass::from_len(block.len()).ok_or(Error::BadLength)?;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&block[SALT_OFF..SALT_OFF + SALT_LEN]);
    let profiles: &[KdfProfile] = if passphrase_nfkc.is_none() {
        &[KdfProfile::DEFAULT]
    } else {
        profiles
    };
    let mut last = Error::NoSlot;
    for &p in profiles {
        let k = derive_slot_key(root, &salt, passphrase_nfkc, p)?;
        match open_with_key(block, class, &k) {
            Ok(s) => return Ok(s),
            Err(Error::NoSlot) => continue,
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn open_with_key(block: &[u8], class: SizeClass, k_slot: &SlotKey) -> Result<OpenedSlot, Error> {
    let payload = &block[PAYLOAD_OFF..];
    let mut result: Option<Result<OpenedSlot, Error>> = None;
    // Process all four headers regardless of an early match (§6.2 step 6).
    for i in 0..N_SLOTS {
        let h = &block[HDR_OFF + i * HDR_LEN..HDR_OFF + (i + 1) * HDR_LEN];
        let mut nonce = [0u8; HDR_NONCE_LEN];
        nonce.copy_from_slice(&h[..HDR_NONCE_LEN]);
        let mut had = Vec::with_capacity(AD_HEADER.len() + 1);
        had.extend_from_slice(AD_HEADER);
        had.push(i as u8);
        let body = match utc::open(k_slot, &nonce, &had, &h[HDR_NONCE_LEN..], INFO_UTC_HDR) {
            Ok(b) => b,
            Err(Error::NoSlot) => continue,
            Err(e) => {
                result.get_or_insert(Err(e));
                continue;
            }
        };
        if result.is_some() {
            continue;
        }
        result = Some(open_payload(payload, class, k_slot, i as u8, &nonce, &body));
    }
    result.unwrap_or(Err(Error::NoSlot))
}

fn open_payload(
    payload: &[u8],
    class: SizeClass,
    k_slot: &SlotKey,
    i: u8,
    nonce: &[u8; HDR_NONCE_LEN],
    body: &[u8],
) -> Result<OpenedSlot, Error> {
    let (flags, off, len, ptype) = decode_header_body(body).ok_or(Error::Malformed)?;
    if flags & !FLAG_DISTRESS != 0
        || off % PAYLOAD_GRANULE != 0
        || len % PAYLOAD_GRANULE != 0
        || off + len > class.payload_len()
    {
        return Err(Error::Malformed);
    }
    let pay_nonce = derive_payload_nonce(k_slot, nonce);
    let mut ad = Vec::with_capacity(AD_PAYLOAD.len() + 1 + HDR_NONCE_LEN);
    ad.extend_from_slice(AD_PAYLOAD);
    ad.push(i);
    ad.extend_from_slice(nonce);
    let mut inner = utc::open(
        k_slot,
        &pay_nonce,
        &ad,
        &payload[off..off + len],
        INFO_UTC_PAY,
    )
    .map_err(|_| Error::Malformed)?;
    if inner.len() < INNER_HDR_LEN || inner[0] != FORMAT_VERSION || inner[1] != ptype {
        inner.zeroize();
        return Err(Error::Malformed);
    }
    let dlen = u32::from_be_bytes([inner[2], inner[3], inner[4], inner[5]]) as usize;
    if INNER_HDR_LEN + dlen > inner.len() {
        inner.zeroize();
        return Err(Error::Malformed);
    }
    let data = inner[INNER_HDR_LEN..INNER_HDR_LEN + dlen].to_vec();
    inner.zeroize();
    Ok(OpenedSlot {
        index: i,
        data,
        ptype,
        distress: flags & FLAG_DISTRESS != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_body_roundtrip() {
        let b = encode_header_body(1, 1024, 512, 1);
        assert_eq!(hex_of(&b), "01000400000200010000000000000000");
        assert_eq!(decode_header_body(&b), Some((1, 1024, 512, 1)));
        let mut bad = b;
        bad[15] = 1;
        assert!(decode_header_body(&bad).is_none());
    }

    fn hex_of(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
