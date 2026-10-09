//! Block cards and Share cards (DC-04 §7).
//!
//! A Block (class 1: 4 096 bytes; class 2: 16 384 bytes) is cut into chunks of 1 024 bytes,
//! each printed as one QR code in byte mode. Chunk = `set id (4 random bytes) ‖ index (1) ‖
//! count (1) ‖ class (1) ‖ data (1 024) ‖ CRC-32 (4)`. No magic string: the six-byte header
//! looks like any other bytes; a set is recognised by its id, index/count consistency, class
//! and CRC. Class 3 (65 536 bytes, 64 cards) is not offered on paper.
//!
//! A Block is random-looking by construction and carries no key, so a card is not a secret;
//! the buffers still zeroise, because there is no reason not to.

use crate::PaperError;
use aska_core::SizeClass;
use zeroize::Zeroizing;

pub const CHUNK_DATA: usize = 1024;
pub const HEADER: usize = 7;
pub const CRC: usize = 4;
pub const CHUNK_LEN: usize = HEADER + CHUNK_DATA + CRC;

/// CRC-32 (IEEE 802.3, reflected, as in zlib). Small table built on first use.
pub fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let t = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 == 1 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *e = c;
        }
        t
    });
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c = t[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8);
    }
    !c
}

/// Cut a Block into card chunks. The set id comes from the OS generator.
pub fn split_block(block: &[u8]) -> Result<Vec<Zeroizing<Vec<u8>>>, PaperError> {
    let class = SizeClass::from_len(block.len()).ok_or(PaperError::Card("not a Block"))?;
    if class == SizeClass::C3 {
        return Err(PaperError::Card("class 3 is not offered on paper"));
    }
    let count = block.len() / CHUNK_DATA;
    let mut id = [0u8; 4];
    getrandom::getrandom(&mut id).map_err(|_| PaperError::Rng)?;
    let mut out = Vec::with_capacity(count);
    for (i, data) in block.chunks(CHUNK_DATA).enumerate() {
        let mut c = Zeroizing::new(Vec::with_capacity(CHUNK_LEN));
        c.extend_from_slice(&id);
        c.push(i as u8);
        c.push(count as u8);
        c.push(class as u8);
        c.extend_from_slice(data);
        let crc = crc32(&c);
        c.extend_from_slice(&crc.to_be_bytes());
        out.push(c);
    }
    Ok(out)
}

/// What happened to a scanned chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Accepted {
    /// New card; `have` of `count` now present.
    Added { have: usize, count: usize },
    /// Already had this one.
    Duplicate { have: usize, count: usize },
    /// All cards present; the Block is ready.
    Complete,
}

/// Reassembles a set of cards scanned in any order.
pub struct CardSet {
    id: Option<[u8; 4]>,
    count: usize,
    class: Option<SizeClass>,
    parts: Vec<Option<Zeroizing<Vec<u8>>>>,
}

impl Default for CardSet {
    fn default() -> Self {
        Self::new()
    }
}

impl CardSet {
    pub fn new() -> Self {
        CardSet {
            id: None,
            count: 0,
            class: None,
            parts: Vec::new(),
        }
    }

    pub fn have(&self) -> usize {
        self.parts.iter().filter(|p| p.is_some()).count()
    }

    pub fn count(&self) -> usize {
        self.count
    }

    /// Feed one scanned chunk.
    pub fn accept(&mut self, chunk: &[u8]) -> Result<Accepted, PaperError> {
        if chunk.len() != CHUNK_LEN {
            return Err(PaperError::Card("not a card of this format"));
        }
        let (body, crc) = chunk.split_at(CHUNK_LEN - CRC);
        if crc32(body) != u32::from_be_bytes(crc.try_into().expect("4 bytes")) {
            return Err(PaperError::Card("the card did not scan cleanly (checksum)"));
        }
        let id: [u8; 4] = body[..4].try_into().expect("4 bytes");
        let (index, count, class) = (body[4] as usize, body[5] as usize, body[6]);
        let class = SizeClass::from_u8(class).ok_or(PaperError::Card("unknown Block class"))?;
        if class == SizeClass::C3 || count != class.len() / CHUNK_DATA || index >= count {
            return Err(PaperError::Card("inconsistent card header"));
        }
        match self.id {
            None => {
                self.id = Some(id);
                self.count = count;
                self.class = Some(class);
                self.parts = (0..count).map(|_| None).collect();
            }
            Some(have_id) => {
                if have_id != id || self.count != count || self.class != Some(class) {
                    return Err(PaperError::Card("this card belongs to a different set"));
                }
            }
        }
        if self.parts[index].is_some() {
            let have = self.have();
            return Ok(if have == self.count {
                Accepted::Complete
            } else {
                Accepted::Duplicate { have, count }
            });
        }
        self.parts[index] = Some(Zeroizing::new(body[HEADER..].to_vec()));
        let have = self.have();
        Ok(if have == self.count {
            Accepted::Complete
        } else {
            Accepted::Added { have, count }
        })
    }

    /// The reassembled Block once every card is present.
    pub fn block(&self) -> Option<Zeroizing<Vec<u8>>> {
        if self.count == 0 || self.have() != self.count {
            return None;
        }
        let mut b = Zeroizing::new(Vec::with_capacity(self.count * CHUNK_DATA));
        for p in &self.parts {
            b.extend_from_slice(p.as_ref().expect("all present"));
        }
        if SizeClass::from_len(b.len()) != self.class {
            return None;
        }
        Some(b)
    }
}

/// Text of a Share card: the Share's encoding grouped in fours for hand copying, with its
/// index and threshold line. No other words (DC-04 §7.2).
pub fn share_card_text(share_text: &str, index: u8, total: u8, threshold: u8) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::with_capacity(share_text.len() + 64));
    s.push_str(&format!(
        "SHARE {index} OF {total} — ANY {threshold} OPEN THE NOTE\n"
    ));
    for (i, ch) in share_text.trim().chars().enumerate() {
        if i > 0 && i % 4 == 0 {
            s.push(if i % 40 == 0 { '\n' } else { ' ' });
        }
        s.push(ch);
    }
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_answer() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn split_and_reassemble_in_any_order() {
        let mut block = vec![0u8; 4096];
        getrandom::getrandom(&mut block).unwrap();
        let cards = split_block(&block).unwrap();
        assert_eq!(cards.len(), 4);
        assert!(cards.iter().all(|c| c.len() == CHUNK_LEN));
        let mut set = CardSet::new();
        assert_eq!(
            set.accept(&cards[2]).unwrap(),
            Accepted::Added { have: 1, count: 4 }
        );
        assert_eq!(
            set.accept(&cards[2]).unwrap(),
            Accepted::Duplicate { have: 1, count: 4 }
        );
        assert_eq!(
            set.accept(&cards[0]).unwrap(),
            Accepted::Added { have: 2, count: 4 }
        );
        assert!(set.block().is_none());
        assert_eq!(
            set.accept(&cards[3]).unwrap(),
            Accepted::Added { have: 3, count: 4 }
        );
        assert_eq!(set.accept(&cards[1]).unwrap(), Accepted::Complete);
        assert_eq!(set.block().unwrap().as_slice(), &block[..]);
        // A card from another set is refused and dropped.
        let other = split_block(&block).unwrap();
        assert!(matches!(set.accept(&other[0]), Err(PaperError::Card(_))));
        // A damaged card fails its CRC.
        let mut bad = cards[1].clone();
        bad[100] ^= 1;
        assert!(set.accept(&bad).is_err());
    }

    #[test]
    fn class_2_is_16_cards_and_class_3_refused() {
        let block = vec![7u8; 16384];
        assert_eq!(split_block(&block).unwrap().len(), 16);
        assert!(split_block(&[0u8; 65536]).is_err());
        assert!(split_block(&[0u8; 100]).is_err());
    }

    #[test]
    fn share_card_groups_in_fours() {
        let t = share_card_text("askas1abcdefghijklmnop", 2, 5, 3);
        assert!(t.starts_with("SHARE 2 OF 5 — ANY 3 OPEN THE NOTE\n"));
        assert!(t.contains("aska s1ab cdef"));
    }
}
