//! The randomness pipeline (DC-04 §4).
//!
//! A pad's proof needs about 3.32 bits of *true* min-entropy per digit — some 85 000 bits for a
//! default booklet. Only a camera (or a hardware noise source) supplies that volume; dice and
//! keyboard timing can only seed a computational generator. So there are two kinds of
//! physical stream, and every booklet is labelled by which one it got:
//!
//! * **PHYSICAL** — raw samples from a [`RawSource`] pass the health tests, get a conservative
//!   min-entropy estimate, and are condensed by a seeded Toeplitz (universal-hash) extractor
//!   whose output length is set by the leftover-hash lemma. The claim then rests on the entropy
//!   estimate, not on any hash function.
//! * **SEEDED** — the physical input (dice, typing, or a camera run that did not meet its budget)
//!   seeds SHAKE256; the stream is computationally secure.
//!
//! Either physical stream is **mixed** digit by digit with the operating system's generator
//! (`k = (k_phys + k_os) mod 10`, and likewise modulo the two tag primes), so the result is
//! uniform if *either* is. Values are drawn by rejection sampling, never by a bare modulo.
//! Finished booklets pass statistical tests ([`stats`]) as a last line against gross faults.

pub mod camera;
pub mod estimate;
pub mod stats;
pub mod toeplitz;

use crate::{devtag, handtag, LockedBuf, PaperError};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use zeroize::Zeroize;

/// Which guarantee a booklet carries (DC-04 §4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label {
    Physical,
    Seeded,
}

impl Label {
    pub fn as_str(self) -> &'static str {
        match self {
            Label::Physical => "PHYSICAL",
            Label::Seeded => "SEEDED",
        }
    }
}

/// A supplier of raw 8-bit samples for the PHYSICAL pipeline.
pub trait RawSource {
    /// Fill as much of `out` as one unit of work yields (a frame, say); return the count.
    /// `Ok(0)` means "nothing this time, call again".
    fn pull(&mut self, out: &mut [u8]) -> Result<usize, PaperError>;
    /// `true` once the samples span enough independent events (frames) for the estimate to be
    /// meaningful. Sources with no notion of events return `true`.
    fn spread_enough(&self) -> bool {
        true
    }
    /// For the generation summary.
    fn describe(&self) -> String;
}

/// Uniform values drawn from some stream.
pub trait DigitStream {
    /// A digit 0–9.
    fn digit(&mut self) -> Result<u8, PaperError>;
    /// A value in 0…9 972 (hand-tag key).
    fn hand_key(&mut self) -> Result<u16, PaperError>;
    /// A value below 2⁶¹ − 1 (device-tag key).
    fn device_key(&mut self) -> Result<u64, PaperError>;
}

/// Rejection sampling over a bit supplier. `take(n)` yields the next n bits as a number or
/// `None` when the supply is exhausted.
trait BitSupply {
    fn take(&mut self, bits: u32) -> Result<Option<u64>, PaperError>;
}

const REJECT_LIMIT: u32 = 1_000_000;

fn draw<S: BitSupply>(s: &mut S, bits: u32, bound: u64) -> Result<u64, PaperError> {
    for _ in 0..REJECT_LIMIT {
        match s.take(bits)? {
            None => return Err(PaperError::NeedMore),
            Some(v) if v < bound => return Ok(v),
            Some(_) => continue,
        }
    }
    Err(PaperError::Entropy(
        "rejection sampling never accepted a value — the source is broken".into(),
    ))
}

/// Digit by rejection on a byte: values 250–255 are rejected, the rest taken modulo 10 (25
/// values per digit — exactly uniform).
fn digit_from<S: BitSupply>(s: &mut S) -> Result<u8, PaperError> {
    Ok((draw(s, 8, 250)? % 10) as u8)
}

fn hand_key_from<S: BitSupply>(s: &mut S) -> Result<u16, PaperError> {
    Ok(draw(s, 14, handtag::P)? as u16)
}

fn device_key_from<S: BitSupply>(s: &mut S) -> Result<u64, PaperError> {
    draw(s, 61, devtag::P)
}

// ---------------------------------------------------------------------------------------------
// Operating-system stream

/// The operating system's generator, buffered, with rejection sampling.
pub struct OsDigits {
    buf: LockedBuf,
    pos: usize, // bit position
}

impl Default for OsDigits {
    fn default() -> Self {
        Self::new()
    }
}

impl OsDigits {
    pub fn new() -> Self {
        OsDigits {
            buf: LockedBuf::with_capacity(4096),
            pos: usize::MAX, // forces a refill
        }
    }

    fn refill(&mut self) -> Result<(), PaperError> {
        let mut tmp = [0u8; 4096];
        getrandom::getrandom(&mut tmp).map_err(|_| PaperError::Rng)?;
        self.buf.set(&tmp);
        tmp.zeroize();
        self.pos = 0;
        Ok(())
    }
}

impl BitSupply for OsDigits {
    fn take(&mut self, bits: u32) -> Result<Option<u64>, PaperError> {
        if self.pos == usize::MAX || self.pos + bits as usize > self.buf.len() * 8 {
            self.refill()?;
        }
        let v = read_bits(self.buf.as_slice(), self.pos, bits);
        self.pos += bits as usize;
        Ok(Some(v))
    }
}

impl DigitStream for OsDigits {
    fn digit(&mut self) -> Result<u8, PaperError> {
        digit_from(self)
    }
    fn hand_key(&mut self) -> Result<u16, PaperError> {
        hand_key_from(self)
    }
    fn device_key(&mut self) -> Result<u64, PaperError> {
        device_key_from(self)
    }
}

/// Read `bits` (≤ 64) big-endian from a byte slice starting at bit `pos`.
fn read_bits(bytes: &[u8], pos: usize, bits: u32) -> u64 {
    let mut v: u64 = 0;
    for i in 0..bits as usize {
        let p = pos + i;
        let bit = (bytes[p / 8] >> (7 - (p % 8))) & 1;
        v = (v << 1) | u64::from(bit);
    }
    v
}

// ---------------------------------------------------------------------------------------------
// Extracted (PHYSICAL) stream

/// Bits produced by the extractor; consumed once.
pub struct Extracted {
    bits: LockedBuf,
    len_bits: usize,
    pos: usize,
    /// The estimate and budget, for the generation summary.
    pub report: estimate::Report,
    pub source: String,
}

impl Extracted {
    pub fn remaining_bits(&self) -> usize {
        self.len_bits.saturating_sub(self.pos)
    }
}

impl BitSupply for Extracted {
    fn take(&mut self, bits: u32) -> Result<Option<u64>, PaperError> {
        if self.pos + bits as usize > self.len_bits {
            return Ok(None);
        }
        let v = read_bits(self.bits.as_slice(), self.pos, bits);
        self.pos += bits as usize;
        Ok(Some(v))
    }
}

impl DigitStream for Extracted {
    fn digit(&mut self) -> Result<u8, PaperError> {
        digit_from(self)
    }
    fn hand_key(&mut self) -> Result<u16, PaperError> {
        hand_key_from(self)
    }
    fn device_key(&mut self) -> Result<u64, PaperError> {
        device_key_from(self)
    }
}

/// Raw samples per extractor block.
pub const BLOCK_SAMPLES: usize = 4096;
/// Security parameter of the leftover-hash lemma: ε = 2⁻⁶⁴ costs 2·64 bits per block.
pub const LHL_LOSS_BITS: usize = 128;
/// Most raw bytes a collector accepts (keeps the locked allocation bounded).
pub const MAX_RAW: usize = 4 << 20;

/// Collects raw samples for the PHYSICAL pipeline, then estimates, tests and extracts.
pub struct Collector {
    raw: LockedBuf,
    need_bits: usize,
    seed: LockedBuf,
    source: String,
}

/// Progress of a collector.
#[derive(Debug, Clone, Copy)]
pub struct Progress {
    pub raw_samples: usize,
    pub need_bits: usize,
    /// Current conservative estimate (bits per 8-bit sample), when enough samples exist.
    pub estimate: Option<f64>,
    pub extractable_bits: usize,
}

impl Collector {
    /// `need_bits`: extracted bits the booklet will consume (see [`bits_needed`]).
    pub fn new(need_bits: usize, source: String) -> Result<Self, PaperError> {
        let mut seed = LockedBuf::with_capacity(toeplitz::seed_len_bytes(BLOCK_SAMPLES * 8));
        let mut tmp = vec![0u8; seed.capacity()];
        getrandom::getrandom(&mut tmp).map_err(|_| PaperError::Rng)?;
        seed.set(&tmp);
        tmp.zeroize();
        Ok(Collector {
            raw: LockedBuf::with_capacity(MAX_RAW),
            need_bits,
            seed,
            source,
        })
    }

    pub fn push(&mut self, samples: &[u8]) {
        let room = MAX_RAW - self.raw.len();
        let n = samples.len().min(room);
        self.raw.extend_from_slice(&samples[..n]);
    }

    pub fn progress(&self) -> Progress {
        let n = self.raw.len();
        let est = estimate::min_entropy(self.raw.as_slice())
            .ok()
            .map(|r| r.bits_per_sample);
        let extractable = est
            .map(|h| (n / BLOCK_SAMPLES) * bits_per_block(h))
            .unwrap_or(0);
        Progress {
            raw_samples: n,
            need_bits: self.need_bits,
            estimate: est,
            extractable_bits: extractable,
        }
    }

    pub fn is_full(&self) -> bool {
        self.raw.len() >= MAX_RAW
    }

    /// Enough raw for the booklet (at the current estimate)?
    pub fn ready(&self) -> bool {
        let p = self.progress();
        p.extractable_bits >= p.need_bits
    }

    /// Estimate, health-test and extract. Consumes the collector; the raw samples are wiped.
    pub fn finish(mut self) -> Result<Extracted, PaperError> {
        let raw = self.raw.as_slice();
        let report = estimate::min_entropy(raw)?;
        estimate::health_tests(raw, report.bits_per_sample)?;
        let per_block = bits_per_block(report.bits_per_sample);
        let blocks = raw.len() / BLOCK_SAMPLES;
        let total_bits = blocks * per_block;
        if total_bits < self.need_bits {
            self.raw.clear();
            return Err(PaperError::NeedMore);
        }
        let mut out = LockedBuf::with_capacity(total_bits.div_ceil(8) + 8);
        let mut block_out = LockedBuf::with_capacity(per_block.div_ceil(8) + 8);
        let mut bitpos = 0usize;
        for b in 0..blocks {
            let input = &raw[b * BLOCK_SAMPLES..(b + 1) * BLOCK_SAMPLES];
            toeplitz::extract(self.seed.as_slice(), input, per_block, &mut block_out);
            append_bits(&mut out, &mut bitpos, block_out.as_slice(), per_block);
        }
        block_out.clear();
        self.raw.clear();
        Ok(Extracted {
            bits: out,
            len_bits: total_bits,
            pos: 0,
            report,
            source: std::mem::take(&mut self.source),
        })
    }
}

/// Output bits per block for an estimate of `h` bits per sample (floor, minus the LHL loss).
pub fn bits_per_block(h: f64) -> usize {
    let total = (h * BLOCK_SAMPLES as f64).floor() as usize;
    total.saturating_sub(LHL_LOSS_BITS)
}

/// Append `nbits` from `src` (packed MSB-first) at bit position `*pos` of `dst` (a LockedBuf
/// whose length grows as needed).
fn append_bits(dst: &mut LockedBuf, pos: &mut usize, src: &[u8], nbits: usize) {
    let need_bytes = (*pos + nbits).div_ceil(8);
    while dst.len() < need_bytes {
        dst.extend_from_slice(&[0]);
    }
    let d = dst.as_mut_slice();
    for i in 0..nbits {
        let bit = (src[i / 8] >> (7 - (i % 8))) & 1;
        let p = *pos + i;
        d[p / 8] |= bit << (7 - (p % 8));
    }
    *pos += nbits;
}

/// Extracted bits a booklet of `pages` pages (both directions together) will consume, with
/// the rejection-sampling overhead and a 30 % margin.
pub fn bits_needed(pages: usize, pad_len: usize, hand_tag: bool) -> usize {
    let digits = pages * pad_len;
    let mults = if hand_tag {
        pages * (pad_len / 2 + 2)
    } else {
        0
    };
    let keys = pages * 2;
    // digit: 8 bits / (250/256); multiplier: 14 bits / (9973/16384); key: 61 bits / (p/2^61).
    let bits = digits as f64 * 8.0 / (250.0 / 256.0)
        + mults as f64 * 14.0 / (9_973.0 / 16_384.0)
        + keys as f64 * 61.0 / ((devtag::P as f64) / (1u64 << 61) as f64);
    (bits * 1.3) as usize + 1024
}

// ---------------------------------------------------------------------------------------------
// SEEDED stream

/// SHAKE256 over the physical seed material; computationally secure.
pub struct Seeded {
    reader: sha3::Shake256Reader,
    buf: [u8; 64],
    pos: usize, // bit position within buf; 512 = empty
    pub source: String,
}

impl Seeded {
    /// `material` is the raw physical input (dice rolls, timings, a short camera run);
    /// `estimated_bits` the caller's conservative estimate of its entropy — at least 256.
    pub fn new(material: &[u8], estimated_bits: usize, source: String) -> Result<Self, PaperError> {
        if estimated_bits < 256 {
            return Err(PaperError::Entropy(format!(
                "the seed carries about {estimated_bits} bits; at least 256 are needed"
            )));
        }
        let mut hasher = sha3::Shake256::default();
        hasher.update(b"aska/paper/seeded/v1");
        hasher.update(&(material.len() as u64).to_be_bytes());
        hasher.update(material);
        let mut os = [0u8; 32];
        getrandom::getrandom(&mut os).map_err(|_| PaperError::Rng)?;
        // The OS contributes to the seed as well as to the mix: a seeded booklet is never worse
        // than the OS generator alone.
        hasher.update(&os);
        os.zeroize();
        Ok(Seeded {
            reader: hasher.finalize_xof(),
            buf: [0u8; 64],
            pos: 512,
            source,
        })
    }

    /// Dice: rolls 1–6, at least 100 (≈ 258 bits).
    pub fn from_dice(rolls: &[u8]) -> Result<Self, PaperError> {
        if rolls.iter().any(|&r| !(1..=6).contains(&r)) {
            return Err(PaperError::Entropy("a die roll must be 1–6".into()));
        }
        let bits = (rolls.len() as f64 * 2.58) as usize;
        Self::new(rolls, bits, format!("dice ({} rolls)", rolls.len()))
    }

    /// Keyboard timing: microsecond intervals between keys; counted at one bit each (a
    /// conservative figure), so at least 256 intervals.
    pub fn from_timings(intervals_us: &[u32]) -> Result<Self, PaperError> {
        let mut raw: Vec<u8> = intervals_us.iter().flat_map(|v| v.to_be_bytes()).collect();
        let r = Self::new(
            &raw,
            intervals_us.len(),
            format!("typing ({} intervals)", intervals_us.len()),
        );
        raw.zeroize();
        r
    }
}

impl Drop for Seeded {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl BitSupply for Seeded {
    fn take(&mut self, bits: u32) -> Result<Option<u64>, PaperError> {
        if self.pos + bits as usize > 512 {
            self.reader.read(&mut self.buf);
            self.pos = 0;
        }
        let v = read_bits(&self.buf, self.pos, bits);
        self.pos += bits as usize;
        Ok(Some(v))
    }
}

impl DigitStream for Seeded {
    fn digit(&mut self) -> Result<u8, PaperError> {
        digit_from(self)
    }
    fn hand_key(&mut self) -> Result<u16, PaperError> {
        hand_key_from(self)
    }
    fn device_key(&mut self) -> Result<u64, PaperError> {
        device_key_from(self)
    }
}

// ---------------------------------------------------------------------------------------------
// Mixing

/// The physical stream of a booklet, with its label.
pub enum Physical {
    Extracted(Extracted),
    Seeded(Box<Seeded>),
}

impl Physical {
    pub fn label(&self) -> Label {
        match self {
            Physical::Extracted(_) => Label::Physical,
            Physical::Seeded(_) => Label::Seeded,
        }
    }
    pub fn describe(&self) -> String {
        match self {
            Physical::Extracted(e) => format!(
                "{}; {} raw samples, estimate {:.2} bits/sample, budget {} bits/block",
                e.source,
                e.report.samples,
                e.report.bits_per_sample,
                bits_per_block(e.report.bits_per_sample)
            ),
            Physical::Seeded(s) => format!("{} (seeded, computational)", s.source),
        }
    }
}

impl DigitStream for Physical {
    fn digit(&mut self) -> Result<u8, PaperError> {
        match self {
            Physical::Extracted(e) => e.digit(),
            Physical::Seeded(s) => s.digit(),
        }
    }
    fn hand_key(&mut self) -> Result<u16, PaperError> {
        match self {
            Physical::Extracted(e) => e.hand_key(),
            Physical::Seeded(s) => s.hand_key(),
        }
    }
    fn device_key(&mut self) -> Result<u64, PaperError> {
        match self {
            Physical::Extracted(e) => e.device_key(),
            Physical::Seeded(s) => s.device_key(),
        }
    }
}

/// Digit-wise sum of the physical and the operating-system streams.
pub struct Mixed<'a> {
    pub physical: &'a mut Physical,
    pub os: &'a mut OsDigits,
}

impl DigitStream for Mixed<'_> {
    fn digit(&mut self) -> Result<u8, PaperError> {
        Ok((self.physical.digit()? + self.os.digit()?) % 10)
    }
    fn hand_key(&mut self) -> Result<u16, PaperError> {
        let v = u32::from(self.physical.hand_key()?) + u32::from(self.os.hand_key()?);
        Ok((v % handtag::P as u32) as u16)
    }
    fn device_key(&mut self) -> Result<u64, PaperError> {
        let v = u128::from(self.physical.device_key()?) + u128::from(self.os.device_key()?);
        Ok((v % u128::from(devtag::P)) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_stream_values_are_in_range() {
        let mut os = OsDigits::new();
        for _ in 0..5_000 {
            assert!(os.digit().unwrap() < 10);
            assert!(os.hand_key().unwrap() < handtag::P as u16);
            assert!(os.device_key().unwrap() < devtag::P);
        }
    }

    #[test]
    fn digit_rejection_is_exactly_uniform_over_bytes() {
        // Every accepted byte value maps to one digit; 25 bytes per digit.
        let mut counts = [0u32; 10];
        for b in 0u32..250 {
            counts[(b % 10) as usize] += 1;
        }
        assert!(counts.iter().all(|&c| c == 25));
    }

    #[test]
    fn seeded_stream_is_deterministic_in_its_material_but_not_across_os() {
        // Two streams from the same dice differ because the OS contributes to the seed.
        let rolls: Vec<u8> = (0..120).map(|i| (i % 6) as u8 + 1).collect();
        let mut a = Seeded::from_dice(&rolls).unwrap();
        let mut b = Seeded::from_dice(&rolls).unwrap();
        let da: Vec<u8> = (0..64).map(|_| a.digit().unwrap()).collect();
        let db: Vec<u8> = (0..64).map(|_| b.digit().unwrap()).collect();
        assert_ne!(da, db);
        assert!(Seeded::from_dice(&rolls[..50]).is_err());
        assert!(Seeded::from_dice(&[7]).is_err());
    }

    #[test]
    fn collector_pipeline_on_a_synthetic_source() {
        // A good synthetic source: SHAKE output (full entropy) → estimate near the 4-bit cap.
        let need = bits_needed(2, 200, true);
        let mut c = Collector::new(need, "synthetic".into()).unwrap();
        let mut h = sha3::Shake256::default();
        h.update(b"collector test");
        let mut r = h.finalize_xof();
        let mut chunk = [0u8; 4096];
        while !c.ready() {
            r.read(&mut chunk);
            c.push(&chunk);
        }
        let p = c.progress();
        assert!(p.estimate.unwrap() >= 3.0, "{p:?}");
        let mut e = c.finish().unwrap();
        assert!(e.remaining_bits() >= need);
        let mut os = OsDigits::new();
        let mut phys = Physical::Extracted(e);
        let mut m = Mixed {
            physical: &mut phys,
            os: &mut os,
        };
        let mut counts = [0u32; 10];
        for _ in 0..2_000 {
            counts[m.digit().unwrap() as usize] += 1;
        }
        assert!(counts.iter().all(|&c| c > 120), "{counts:?}");
        let _ = m.hand_key().unwrap();
        let _ = m.device_key().unwrap();
        e = match phys {
            Physical::Extracted(e) => e,
            _ => unreachable!(),
        };
        assert!(e.report.bits_per_sample >= 3.0);
    }

    #[test]
    fn a_bad_source_is_refused() {
        // Constant samples: estimate ≈ 0 → refused.
        let mut c = Collector::new(1024, "constant".into()).unwrap();
        c.push(&[0x5a; 32768]);
        assert!(matches!(c.finish(), Err(PaperError::Entropy(_))));
        // Low but non-zero entropy with long repeats → health test fails or estimate too low.
        let mut c = Collector::new(1024, "sticky".into()).unwrap();
        let mut v = Vec::new();
        for i in 0..32768u32 {
            v.push(((i / 97) % 4) as u8);
        }
        c.push(&v);
        assert!(c.finish().is_err());
    }
}
