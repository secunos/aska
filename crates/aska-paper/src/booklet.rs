//! The booklet (DC-04 §3.5): 2·P pages generated together — P A-pages for one holder's
//! sending, P B-pages for the other's — with one set code, one label, and the finished-digit
//! statistics as the last check. Printed twice, identically; nothing of it persists here.

use crate::entropy::{
    self, stats::DigitStats, DigitStream, Label, Mixed, OsDigits, Physical, RawSource,
};
use crate::page::{Direction, Page, PageSpec, DEFAULT_PAD_LEN, PAD_LENGTHS, PAGE_MAX};
use crate::{handtag, LockedBuf, PaperError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BookletSpec {
    /// `None` → a random set code.
    pub set_code: Option<u16>,
    /// Pages per direction, 1…50.
    pub pages_per_direction: u8,
    pub pad_len: usize,
    pub hand_tag: bool,
}

impl Default for BookletSpec {
    fn default() -> Self {
        BookletSpec {
            set_code: None,
            pages_per_direction: 10,
            pad_len: DEFAULT_PAD_LEN,
            hand_tag: true,
        }
    }
}

impl BookletSpec {
    pub fn validate(&self) -> Result<(), PaperError> {
        if self.pages_per_direction == 0 || self.pages_per_direction > PAGE_MAX {
            return Err(PaperError::Page("pages per direction must be 1–50"));
        }
        if !PAD_LENGTHS.contains(&self.pad_len) {
            return Err(PaperError::Page("pad length must be 200, 400 or 600"));
        }
        if matches!(self.set_code, Some(c) if c > 9_999) {
            return Err(PaperError::Page("set code"));
        }
        Ok(())
    }

    pub fn total_pages(&self) -> usize {
        2 * self.pages_per_direction as usize
    }

    /// Extracted bits the PHYSICAL pipeline must deliver for this booklet.
    pub fn bits_needed(&self) -> usize {
        entropy::bits_needed(self.total_pages(), self.pad_len, self.hand_tag)
    }
}

pub struct Booklet {
    pub spec: BookletSpec,
    pub set_code: u16,
    pub label: Label,
    /// A-pages 1…P, then B-pages 1…P.
    pub pages: Vec<Page>,
    pub stats: DigitStats,
    /// Human-readable summary of the physical source (no digits).
    pub source: String,
}

impl std::fmt::Debug for Booklet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Booklet(set {:04}, {} pages, {}, <digits redacted>)",
            self.set_code,
            self.pages.len(),
            self.label.as_str()
        )
    }
}

impl Booklet {
    /// Page by direction and number.
    pub fn page(&self, dir: Direction, number: u8) -> Option<&Page> {
        self.pages
            .iter()
            .find(|p| p.spec().direction == dir && p.spec().number == number)
    }

    /// Zeroise every page now.
    pub fn clear(&mut self) {
        for p in &mut self.pages {
            p.clear();
        }
        self.pages.clear();
    }
}

/// Build a booklet from a physical stream (already extracted or seeded) and the OS stream.
pub fn build(spec: BookletSpec, physical: &mut Physical) -> Result<Booklet, PaperError> {
    spec.validate()?;
    let mut os = OsDigits::new();
    let set_code = match spec.set_code {
        Some(c) => c,
        None => {
            // From the OS alone: not secret, just an identifier.
            let mut v = 0u32;
            for _ in 0..4 {
                v = v * 10 + u32::from(os.digit()?);
            }
            v as u16
        }
    };
    let label = physical.label();
    let source = physical.describe();
    let mut mixed = Mixed {
        physical,
        os: &mut os,
    };
    let per_dir = spec.pages_per_direction;
    let mut pages = Vec::with_capacity(spec.total_pages());
    let mut all_pad = LockedBuf::with_capacity(spec.total_pages() * spec.pad_len);
    let mut pad = LockedBuf::with_capacity(spec.pad_len);
    let n_keys = if spec.hand_tag {
        spec.pad_len / 2 + 2
    } else {
        0
    };
    let mut keys = LockedBuf::with_capacity((n_keys * handtag::KEY_DIGITS).max(1));
    let mut tmp = [0u8; 4];
    for dir in [Direction::A, Direction::B] {
        for number in 1..=per_dir {
            pad.clear();
            for _ in 0..spec.pad_len {
                pad.extend_from_slice(&[b'0' + mixed.digit()?]);
            }
            keys.clear();
            for _ in 0..n_keys {
                crate::put_digits(&mut tmp, u64::from(mixed.hand_key()?), 4);
                keys.extend_from_slice(&tmp);
            }
            let r = mixed.device_key()?;
            let s = mixed.device_key()?;
            let pspec = PageSpec {
                set_code,
                direction: dir,
                number,
                pad_len: spec.pad_len,
                hand_tag: spec.hand_tag,
            };
            all_pad.extend_from_slice(pad.as_slice());
            pages.push(Page::assemble(
                pspec,
                pad.as_slice(),
                keys.as_slice(),
                r,
                s,
            )?);
        }
    }
    pad.clear();
    keys.clear();
    zeroize::Zeroize::zeroize(&mut tmp);
    let stats = entropy::stats::test_digits(all_pad.as_slice());
    all_pad.clear();
    let stats = match stats {
        Ok(s) => s,
        Err(e) => {
            for p in &mut pages {
                p.clear();
            }
            return Err(e);
        }
    };
    Ok(Booklet {
        spec,
        set_code,
        label,
        pages,
        stats,
        source,
    })
}

/// Drive a raw source until the PHYSICAL pipeline has what the booklet needs, then build.
/// `progress` is called after every pull. Falls back to `NeedMore` → the caller may retry with
/// a larger margin; it never silently downgrades to SEEDED — that is the caller's decision.
pub fn generate_physical(
    spec: BookletSpec,
    source: &mut dyn RawSource,
    mut progress: impl FnMut(&entropy::Progress),
) -> Result<Booklet, PaperError> {
    spec.validate()?;
    let mut need = spec.bits_needed();
    for _attempt in 0..3 {
        let mut c = entropy::Collector::new(need, source.describe())?;
        let mut buf = vec![0u8; 8192];
        while !(c.ready() && source.spread_enough()) {
            if c.is_full() {
                return Err(PaperError::Entropy(
                    "the source gives too little entropy for this booklet; make it smaller or \
                     improve the source"
                        .into(),
                ));
            }
            let n = source.pull(&mut buf)?;
            if n > 0 {
                c.push(&buf[..n]);
            }
            progress(&c.progress());
        }
        use zeroize::Zeroize;
        buf.zeroize();
        match c.finish() {
            Ok(mut e) => {
                e.source = source.describe();
                let mut phys = Physical::Extracted(e);
                return match build(spec, &mut phys) {
                    Err(PaperError::NeedMore) => {
                        need = need * 5 / 4;
                        continue;
                    }
                    other => other,
                };
            }
            Err(PaperError::NeedMore) => {
                need = need * 5 / 4;
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(PaperError::NeedMore)
}

/// A SEEDED booklet from dice, typing or other seed material.
pub fn generate_seeded(spec: BookletSpec, seeded: entropy::Seeded) -> Result<Booklet, PaperError> {
    let mut phys = Physical::Seeded(Box::new(seeded));
    build(spec, &mut phys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    /// Full-entropy synthetic raw source.
    struct Shake(sha3::Shake256Reader, usize);
    impl RawSource for Shake {
        fn pull(&mut self, out: &mut [u8]) -> Result<usize, PaperError> {
            let n = out.len().min(4096);
            self.0.read(&mut out[..n]);
            self.1 += 1;
            Ok(n)
        }
        fn describe(&self) -> String {
            format!("synthetic ({} pulls)", self.1)
        }
    }

    fn shake(label: &str) -> Shake {
        let mut h = sha3::Shake256::default();
        h.update(label.as_bytes());
        Shake(h.finalize_xof(), 0)
    }

    #[test]
    fn physical_booklet_round_trip() {
        let spec = BookletSpec {
            set_code: Some(7342),
            pages_per_direction: 2,
            pad_len: 200,
            hand_tag: true,
        };
        let mut calls = 0;
        let b = generate_physical(spec, &mut shake("booklet"), |_| calls += 1).unwrap();
        assert!(calls > 0);
        assert_eq!(b.label, Label::Physical);
        assert_eq!(b.pages.len(), 4);
        assert_eq!(b.set_code, 7342);
        let p = b.page(Direction::B, 2).unwrap();
        assert_eq!(p.spec().number, 2);
        // Every page parses back from its QR payload and has keys in range.
        for p in &b.pages {
            let q = Page::parse_with_checksum(p.qr_payload().as_slice()).unwrap();
            assert_eq!(q.canonical(), p.canonical());
            let k = q.hand_keys().unwrap();
            for j in 0..k.count() {
                assert!(k.a(j).unwrap() < handtag::P);
            }
        }
        // Pages differ.
        assert_ne!(b.pages[0].pad(), b.pages[1].pad());
        // A message round trip on page A 01 with both tags.
        let page = b.page(Direction::A, 1).unwrap();
        let m = crate::checkerboard::encode("MEET AT NOON").unwrap();
        let c = crate::pad::encipher(m.as_slice(), page.pad()).unwrap();
        let ht = page.hand_tag(c.as_slice()).unwrap();
        let dt = page.device_tag(c.as_slice()).unwrap();
        let keys = page.hand_keys().unwrap();
        handtag::verify(c.as_slice(), &keys, format!("{ht:04}").as_bytes()).unwrap();
        let (r, s) = page.device_keys();
        crate::devtag::verify(c.as_slice(), r, s, format!("{dt:019}").as_bytes()).unwrap();
        let back = crate::pad::decipher(c.as_slice(), page.pad()).unwrap();
        assert_eq!(
            crate::checkerboard::from_digits(back.as_slice())
                .unwrap()
                .as_slice(),
            b"MEET AT NOON"
        );
    }

    #[test]
    fn seeded_booklet_without_hand_tag() {
        let rolls: Vec<u8> = (0..120).map(|i| (i * 5 % 6) as u8 + 1).collect();
        let spec = BookletSpec {
            set_code: None,
            pages_per_direction: 1,
            pad_len: 400,
            hand_tag: false,
        };
        let b = generate_seeded(spec, entropy::Seeded::from_dice(&rolls).unwrap()).unwrap();
        assert_eq!(b.label, Label::Seeded);
        assert!(b.pages[0].hand_keys().is_none());
        assert!(b.set_code <= 9999);
        assert_eq!(b.stats.digits, 800);
    }

    #[test]
    fn bad_specs() {
        let mut s = BookletSpec {
            pages_per_direction: 51,
            ..BookletSpec::default()
        };
        assert!(s.validate().is_err());
        s.pages_per_direction = 1;
        s.pad_len = 300;
        assert!(s.validate().is_err());
        s.pad_len = 200;
        s.set_code = Some(10_000);
        assert!(s.validate().is_err());
    }
}
