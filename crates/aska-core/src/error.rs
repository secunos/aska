//! Error type. Deliberately coarse: an opener must not learn *why* a Block failed
//! beyond what it could infer anyway (§6.2, §8.4).

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid block length")]
    BadLength,
    #[error("slots do not fit in the size class")]
    TooLarge,
    #[error("invalid slot configuration")]
    BadSlots,
    #[error("no slot opens with this key")]
    NoSlot,
    #[error("block is malformed or tampered")]
    Malformed,
    #[error("invalid share")]
    BadShare,
    #[error("shares are inconsistent or insufficient")]
    ShareSet,
    #[error("share verification failed")]
    ShareVerify,
    #[error("invalid encoding")]
    Encoding,
    #[error("unsupported version")]
    Version,
    #[error("key derivation failed")]
    Kdf,
    #[error("randomness unavailable")]
    Rng,
}
