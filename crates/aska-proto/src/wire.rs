//! Fixed-length encoders and decoders for every ADP/1 message (§4). No I/O here: callers read
//! exactly the number of bytes each constant names and hand the slice to a `decode_*` function.

use crate::*;

/// The relay's self-description (INFO response body, §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Info {
    pub max_ttl_hours: u16,
    /// Bit `c-1` set ⇒ size class `c` is served.
    pub classes_bitmap: u8,
    pub pow_base_difficulty: u8,
}

impl Info {
    pub fn serves(&self, class: u8) -> bool {
        (1..=8).contains(&class) && self.classes_bitmap >> (class - 1) & 1 == 1
    }
    /// Served classes in ascending order.
    pub fn classes(&self) -> Vec<u8> {
        (1u8..=8).filter(|c| self.serves(*c)).collect()
    }
}

/// PUT fixed fields (everything before the Block, §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PutFixed {
    pub class: u8,
    pub ttl_hours: u16,
    pub label: [u8; LABEL_LEN],
    pub challenge: [u8; CHALLENGE_LEN],
    pub nonce: [u8; NONCE_LEN],
}

impl PutFixed {
    /// A first attempt: all-zero challenge and nonce.
    pub fn first_attempt(class: u8, ttl_hours: u16, label: [u8; LABEL_LEN]) -> Self {
        PutFixed {
            class,
            ttl_hours,
            label,
            challenge: [0; CHALLENGE_LEN],
            nonce: [0; NONCE_LEN],
        }
    }
    pub fn is_first_attempt(&self) -> bool {
        self.challenge == [0; CHALLENGE_LEN]
    }
}

/// ST_POW_REQUIRED response body (§4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowRequired {
    pub challenge: [u8; CHALLENGE_LEN],
    pub difficulty: u8,
}

// ---- headers ----

pub fn encode_request_header(op: u8) -> [u8; HEADER_LEN] {
    [MAGIC[0], MAGIC[1], MAGIC[2], MAGIC[3], PROTO_VERSION, op]
}

pub fn encode_response_header(status: Status) -> [u8; HEADER_LEN] {
    [
        MAGIC[0],
        MAGIC[1],
        MAGIC[2],
        MAGIC[3],
        PROTO_VERSION,
        status as u8,
    ]
}

/// Validate magic and version of a 6-byte header; returns the sixth byte (op or status).
pub fn decode_header(h: &[u8]) -> Result<u8, ProtoError> {
    if h.len() < HEADER_LEN {
        return Err(ProtoError::Truncated);
    }
    if h[..4] != MAGIC {
        return Err(ProtoError::BadMagic);
    }
    if h[4] != PROTO_VERSION {
        return Err(ProtoError::BadVersion);
    }
    Ok(h[5])
}

pub fn decode_response_header(h: &[u8]) -> Result<Status, ProtoError> {
    let b = decode_header(h)?;
    Status::from_u8(b).ok_or(ProtoError::BadStatus(b))
}

// ---- INFO ----

pub fn encode_info_request() -> Vec<u8> {
    encode_request_header(OP_INFO).to_vec()
}

pub fn encode_info_response(info: &Info) -> Vec<u8> {
    let mut v = encode_response_header(Status::Ok).to_vec();
    v.extend_from_slice(&info.max_ttl_hours.to_be_bytes());
    v.push(info.classes_bitmap);
    v.push(info.pow_base_difficulty);
    v
}

pub fn decode_info_body(b: &[u8]) -> Result<Info, ProtoError> {
    if b.len() < INFO_BODY_LEN {
        return Err(ProtoError::Truncated);
    }
    Ok(Info {
        max_ttl_hours: u16::from_be_bytes([b[0], b[1]]),
        classes_bitmap: b[2],
        pow_base_difficulty: b[3],
    })
}

// ---- PUT ----

pub fn encode_put_fixed(p: &PutFixed) -> [u8; PUT_FIXED_LEN] {
    let mut out = [0u8; PUT_FIXED_LEN];
    out[0] = p.class;
    out[1..3].copy_from_slice(&p.ttl_hours.to_be_bytes());
    out[3..3 + LABEL_LEN].copy_from_slice(&p.label);
    out[3 + LABEL_LEN..3 + LABEL_LEN + CHALLENGE_LEN].copy_from_slice(&p.challenge);
    out[3 + LABEL_LEN + CHALLENGE_LEN..].copy_from_slice(&p.nonce);
    out
}

pub fn decode_put_fixed(b: &[u8]) -> Result<PutFixed, ProtoError> {
    if b.len() < PUT_FIXED_LEN {
        return Err(ProtoError::Truncated);
    }
    let mut label = [0u8; LABEL_LEN];
    let mut challenge = [0u8; CHALLENGE_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    label.copy_from_slice(&b[3..3 + LABEL_LEN]);
    challenge.copy_from_slice(&b[3 + LABEL_LEN..3 + LABEL_LEN + CHALLENGE_LEN]);
    nonce.copy_from_slice(&b[3 + LABEL_LEN + CHALLENGE_LEN..PUT_FIXED_LEN]);
    Ok(PutFixed {
        class: b[0],
        ttl_hours: u16::from_be_bytes([b[1], b[2]]),
        label,
        challenge,
        nonce,
    })
}

/// Whole PUT request: header ‖ fixed ‖ block. The Block length must match `p.class`.
pub fn encode_put_request(p: &PutFixed, block: &[u8]) -> Result<Vec<u8>, ProtoError> {
    if class_size(p.class) != Some(block.len()) {
        return Err(ProtoError::BadLength);
    }
    let mut v = Vec::with_capacity(HEADER_LEN + PUT_FIXED_LEN + block.len());
    v.extend_from_slice(&encode_request_header(OP_PUT));
    v.extend_from_slice(&encode_put_fixed(p));
    v.extend_from_slice(block);
    Ok(v)
}

pub fn encode_put_response(status: Status) -> Vec<u8> {
    encode_response_header(status).to_vec()
}

pub fn encode_pow_required_response(p: &PowRequired) -> Vec<u8> {
    let mut v = encode_response_header(Status::PowRequired).to_vec();
    v.extend_from_slice(&p.challenge);
    v.push(p.difficulty);
    v
}

pub fn decode_pow_required_body(b: &[u8]) -> Result<PowRequired, ProtoError> {
    if b.len() < POW_REQUIRED_BODY_LEN {
        return Err(ProtoError::Truncated);
    }
    let mut challenge = [0u8; CHALLENGE_LEN];
    challenge.copy_from_slice(&b[..CHALLENGE_LEN]);
    Ok(PowRequired {
        challenge,
        difficulty: b[CHALLENGE_LEN],
    })
}

// ---- GET_ALL ----

pub fn encode_get_all_request(class: u8) -> Vec<u8> {
    let mut v = encode_request_header(OP_GET_ALL).to_vec();
    v.push(class);
    v
}

/// `count(4)` that precedes the records.
pub fn encode_get_all_count(count: u32) -> Vec<u8> {
    let mut v = encode_response_header(Status::Ok).to_vec();
    v.extend_from_slice(&count.to_be_bytes());
    v
}

pub fn decode_get_all_count(b: &[u8]) -> Result<u32, ProtoError> {
    if b.len() < 4 {
        return Err(ProtoError::Truncated);
    }
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// One listing record: label ‖ block.
pub fn record_len(class: u8) -> Option<usize> {
    class_size(class).map(|s| LABEL_LEN + s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers() {
        assert_eq!(encode_request_header(OP_PUT), *b"ASKD\x01\x02");
        assert_eq!(decode_header(b"ASKD\x01\x03").unwrap(), 3);
        assert!(matches!(
            decode_header(b"XXXX\x01\x03"),
            Err(ProtoError::BadMagic)
        ));
        assert!(matches!(
            decode_header(b"ASKD\x02\x03"),
            Err(ProtoError::BadVersion)
        ));
        assert!(matches!(
            decode_header(b"ASKD\x01"),
            Err(ProtoError::Truncated)
        ));
        assert_eq!(
            decode_response_header(b"ASKD\x01\x07").unwrap(),
            Status::PowRequired
        );
        assert!(matches!(
            decode_response_header(b"ASKD\x01\x09"),
            Err(ProtoError::BadStatus(9))
        ));
    }

    #[test]
    fn info_roundtrip_matches_python_layout() {
        // Python: struct.pack(">HBB", 168, 0b111, 0)
        let info = Info {
            max_ttl_hours: 168,
            classes_bitmap: 0b111,
            pow_base_difficulty: 0,
        };
        let enc = encode_info_response(&info);
        assert_eq!(&enc[HEADER_LEN..], &[0x00, 0xA8, 0x07, 0x00]);
        assert_eq!(decode_info_body(&enc[HEADER_LEN..]).unwrap(), info);
        assert_eq!(info.classes(), vec![1, 2, 3]);
        assert!(!info.serves(4));
    }

    #[test]
    fn put_fixed_roundtrip_and_layout() {
        let p = PutFixed {
            class: 2,
            ttl_hours: 24,
            label: [0xAA; 32],
            challenge: [0xBB; 16],
            nonce: [0xCC; 8],
        };
        let enc = encode_put_fixed(&p);
        assert_eq!(enc.len(), 59);
        assert_eq!(enc[0], 2);
        assert_eq!(&enc[1..3], &[0, 24]);
        assert_eq!(&enc[3..35], &[0xAA; 32]);
        assert_eq!(&enc[35..51], &[0xBB; 16]);
        assert_eq!(&enc[51..59], &[0xCC; 8]);
        assert_eq!(decode_put_fixed(&enc).unwrap(), p);
        assert!(!p.is_first_attempt());
        assert!(PutFixed::first_attempt(1, 1, [0; 32]).is_first_attempt());
        assert!(matches!(
            encode_put_request(&p, &[0; 4096]),
            Err(ProtoError::BadLength)
        ));
        let req = encode_put_request(&p, &[0; 16384]).unwrap();
        assert_eq!(req.len(), 6 + 59 + 16384);
    }

    #[test]
    fn pow_required_and_get_all() {
        let pr = PowRequired {
            challenge: [1; 16],
            difficulty: 5,
        };
        let enc = encode_pow_required_response(&pr);
        assert_eq!(enc.len(), HEADER_LEN + 17);
        assert_eq!(decode_pow_required_body(&enc[HEADER_LEN..]).unwrap(), pr);
        assert_eq!(encode_get_all_request(3), b"ASKD\x01\x03\x03");
        let c = encode_get_all_count(7);
        assert_eq!(&c[HEADER_LEN..], &[0, 0, 0, 7]);
        assert_eq!(decode_get_all_count(&c[HEADER_LEN..]).unwrap(), 7);
        assert_eq!(record_len(1), Some(32 + 4096));
        assert_eq!(record_len(9), None);
        assert_eq!(class_of_len(65536), Some(3));
        assert_eq!(class_of_len(100), None);
    }
}
