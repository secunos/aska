//! Block Format v1 constants (§3).

pub const FORMAT_VERSION: u8 = 0x01;

pub const SALT_OFF: usize = 0;
pub const SALT_LEN: usize = 32;
pub const KEM_OFF: usize = 32;
pub const KEM_LEN: usize = 1120;
pub const N_SLOTS: usize = 4;
pub const HDR_NONCE_LEN: usize = 24;
pub const HDR_P_LEN: usize = 32;
pub const HDR_BODY_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
pub const HDR_LEN: usize = HDR_NONCE_LEN + HDR_P_LEN + HDR_BODY_LEN + TAG_LEN; // 88
pub const HDR_OFF: usize = KEM_OFF + KEM_LEN; // 1152
pub const RSV_OFF: usize = HDR_OFF + N_SLOTS * HDR_LEN; // 1504
pub const RSV_LEN: usize = 32;
pub const PAYLOAD_OFF: usize = RSV_OFF + RSV_LEN; // 1536
pub const PAYLOAD_GRANULE: usize = 256;
pub const INNER_HDR_LEN: usize = 1 + 1 + 4;

pub const FLAG_DISTRESS: u8 = 0x01;
pub const PTYPE_TEXT: u8 = 0x01;
pub const PTYPE_BINARY: u8 = 0x02;

pub const ARGON2_LEN: usize = 32;

/// Size class → total Block length (§3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SizeClass {
    C1 = 1,
    C2 = 2,
    C3 = 3,
}

impl SizeClass {
    pub const ALL: [SizeClass; 3] = [SizeClass::C1, SizeClass::C2, SizeClass::C3];

    /// Total Block length in bytes.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(self) -> usize {
        match self {
            SizeClass::C1 => 4096,
            SizeClass::C2 => 16384,
            SizeClass::C3 => 65536,
        }
    }

    pub fn payload_len(self) -> usize {
        self.len() - PAYLOAD_OFF
    }

    /// Largest single note this class can carry (§3).
    pub fn max_note_len(self) -> usize {
        self.payload_len() - HDR_P_LEN - INNER_HDR_LEN - TAG_LEN
    }

    pub fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(SizeClass::C1),
            2 => Some(SizeClass::C2),
            3 => Some(SizeClass::C3),
            _ => None,
        }
    }

    pub fn from_len(n: usize) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.len() == n)
    }
}

/// Info strings and associated data (§5.5). A v2 format changes the prefix.
pub const INFO_LABEL: &[u8] = b"aska/v1/label";
pub const INFO_SLOT_PREFIX: &[u8] = b"aska/v1/slot/p";
pub const INFO_UTC_HDR: &[u8] = b"aska/v1/utc/header";
pub const INFO_UTC_PAY: &[u8] = b"aska/v1/utc/payload";
pub const INFO_PAY_NONCE: &[u8] = b"aska/v1/payload-nonce";
pub const INFO_SHARE_VERIFY: &[u8] = b"aska/v1/share-verify";
pub const INFO_ROOT_FROM_KEM: &[u8] = b"aska/v1/root-from-kem";
/// Domain separator of the Receiving Key check (§7.5.3): SHA3-256 over the public key only.
pub const RK_CHECK_DOMAIN: &[u8] = b"aska/v1/rk-check";
/// Length of the Receiving Key check in bech32 characters (5 bits each → 60 bits).
pub const RK_CHECK_CHARS: usize = 12;
pub const AD_HEADER: &[u8] = b"aska/v1/header";
pub const AD_PAYLOAD: &[u8] = b"aska/v1/payload";

/// bech32m human-readable prefixes (§7.2).
pub const HRP_KEYCARD: &str = "aska";
pub const HRP_SHARE: &str = "askas";
pub const HRP_RXKEY: &str = "askar";
