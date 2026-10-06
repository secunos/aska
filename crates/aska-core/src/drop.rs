//! Dead Drop client (Client Design §3 `drop`, ADP/1 §8): INFO / PUT with transparent
//! proof-of-work / GET_ALL, one isolated Tor circuit per request, posting to every relay in
//! the Key Card, and bucket retrieval with local label matching.
//!
//! Nothing here holds a secret: Blocks are ciphertext, labels are public, and the only
//! sensitive value — a circle's Tor client-auth key — is kept zeroising and never printed.

use crate::cancel::CancelToken;
use crate::encodings::{onion_address_to_pubkey, onion_pubkey_to_address, KeyCard};
use crate::rng::{OsRng, RandomSource};
use crate::tor::{connect_onion, TorConfig, TorError};
use aska_proto::client_sync as adp;
use aska_proto::{class_size, Info, ProtoError, Status, DEFAULT_PORT, LABEL_LEN};
use std::io::{Read, Write};
use zeroize::{Zeroize, Zeroizing};

/// A 32-byte secret kept on the heap behind a zeroising wrapper. Boxed on purpose: Rust
/// moves copy a struct's bytes, so an inline `Zeroizing<[u8; 32]>` inside a `Relay`, a job or
/// a `Session` leaves a plaintext copy behind at every move (found by the GUI memory gate);
/// a box moves as a pointer and its one heap copy is zeroised on drop.
pub type Secret32 = Box<Zeroizing<[u8; 32]>>;

/// Wrap a 32-byte secret (see [`Secret32`]).
pub fn secret32(bytes: [u8; 32]) -> Secret32 {
    Box::new(Zeroizing::new(bytes))
}

/// One relay as it appears in a Key Card (TLV 0x03 = onion public key; 0x06 = circle auth).
#[derive(Clone, PartialEq, Eq)]
pub struct Relay {
    pub pubkey: [u8; 32],
    pub port: u16,
    /// Circle client-authorisation private key (x25519), if the relay requires one.
    pub auth_key: Option<Secret32>,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Relay({}:{}, auth={})",
            self.onion(),
            self.port,
            self.auth_key.is_some()
        )
    }
}

impl Relay {
    pub fn from_onion(addr: &str) -> Result<Self, DropError> {
        let pubkey =
            onion_address_to_pubkey(addr).map_err(|_| DropError::Tor(TorError::NotOnion))?;
        Ok(Relay {
            pubkey,
            port: DEFAULT_PORT,
            auth_key: None,
        })
    }
    pub fn onion(&self) -> String {
        onion_pubkey_to_address(&self.pubkey)
    }
    /// Relays listed in a Key Card; the card's auth key (if any) applies to all of them.
    pub fn from_keycard(card: &KeyCard) -> Vec<Relay> {
        card.relays
            .iter()
            .map(|pk| Relay {
                pubkey: *pk,
                port: DEFAULT_PORT,
                auth_key: card.auth_key.map(secret32),
            })
            .collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DropError {
    #[error(transparent)]
    Tor(#[from] TorError),
    #[error(transparent)]
    Proto(#[from] ProtoError),
    #[error("relay answered {0:?}")]
    Status(Status),
    #[error("no relay configured")]
    NoRelay,
    #[error("cancelled")]
    Cancelled,
    #[error("the relay did not answer in time; try again on a fresh circuit")]
    Timeout,
    #[error("randomness unavailable")]
    Rng,
}

/// A byte stream to a relay. Boxed so tests can substitute a direct loopback connection.
pub trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

/// Opens one fresh connection to a relay. The production connector goes through Tor with a
/// new isolated circuit per call (§2.4); tests connect directly to an in-process relay.
/// Implementations register their socket with `cancel` so in-flight I/O can be aborted.
pub trait Connector: Send + Sync {
    fn connect(&self, relay: &Relay, cancel: &CancelToken) -> Result<Box<dyn Stream>, DropError>;
}

/// Production connector: SOCKS5 through the local Tor.
#[derive(Debug, Clone)]
pub struct TorConnector {
    pub cfg: TorConfig,
}

impl Connector for TorConnector {
    fn connect(&self, relay: &Relay, cancel: &CancelToken) -> Result<Box<dyn Stream>, DropError> {
        let s = connect_onion(&self.cfg, &relay.onion(), relay.port, cancel)?;
        Ok(Box::new(s))
    }
}

/// Outcome of posting one Block to one relay.
#[derive(Debug)]
pub struct PostResult {
    pub relay: Relay,
    pub result: Result<Status, DropError>,
}

impl PostResult {
    pub fn stored(&self) -> bool {
        matches!(self.result, Ok(Status::Ok))
    }
}

/// Outcome of a bucket fetch across relays and classes.
#[derive(Debug)]
pub struct FetchOutcome {
    /// The label that was searched for (lets the Session reject an outcome from a job built
    /// for earlier key material); `None` for a `fetch_all` outcome, which the Session matches
    /// itself with its receiving seed (DC-02 §2.4).
    pub label: Option<Secret32>,
    /// The matching Block, if any relay held it (`fetch` only).
    pub block: Option<Zeroizing<Vec<u8>>>,
    /// Every record seen (`fetch_all` only), in relay × class order.
    pub records: Vec<([u8; LABEL_LEN], Zeroizing<Vec<u8>>)>,
    /// Per relay×class: `Ok(records seen)` or the error.
    pub attempts: Vec<(Relay, u8, Result<usize, DropError>)>,
}

impl Drop for FetchOutcome {
    fn drop(&mut self) {
        // Record labels are plain arrays (the Blocks are `Zeroizing`); wipe them so that the
        // relay's copy of a Session's label does not stay in freed heap.
        for (l, _) in self.records.iter_mut() {
            l.zeroize();
        }
    }
}

impl FetchOutcome {
    /// True if at least one listing was received (so "not found" is meaningful).
    pub fn any_answered(&self) -> bool {
        self.attempts.iter().any(|(_, _, r)| r.is_ok())
    }
}

pub struct DropClient<'c> {
    pub connector: &'c dyn Connector,
    pub cancel: CancelToken,
}

impl std::fmt::Debug for DropClient<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DropClient({:?})", self.cancel)
    }
}

impl<'c> DropClient<'c> {
    pub fn new(connector: &'c dyn Connector, cancel: CancelToken) -> Self {
        DropClient { connector, cancel }
    }

    fn check_cancel(&self) -> Result<(), DropError> {
        if self.cancel.is_cancelled() {
            Err(DropError::Cancelled)
        } else {
            Ok(())
        }
    }

    /// Map an I/O failure to `Cancelled` when it was caused by cancellation, and a socket
    /// timeout (reported by the OS as `WouldBlock`) to `Timeout`.
    fn classify(&self, e: DropError) -> DropError {
        if self.cancel.is_cancelled() {
            return DropError::Cancelled;
        }
        match &e {
            DropError::Proto(ProtoError::Io(io))
                if matches!(
                    io.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                DropError::Timeout
            }
            _ => e,
        }
    }

    pub fn info(&self, relay: &Relay) -> Result<Info, DropError> {
        self.check_cancel()?;
        let mut s = self.connector.connect(relay, &self.cancel)?;
        adp::info(&mut s)
            .map_err(DropError::from)
            .map_err(|e| self.classify(e))
    }

    /// PUT with the PoW challenge handled transparently (a fresh isolated circuit for each
    /// retry). Returns the relay's final status; `Full` and errors mean "try another relay".
    pub fn put(
        &self,
        relay: &Relay,
        label: [u8; LABEL_LEN],
        block: &[u8],
        ttl_hours: u16,
    ) -> Result<Status, DropError> {
        self.check_cancel()?;
        let mut err: Option<DropError> = None;
        let st = adp::put_with_pow(
            || match self.connector.connect(relay, &self.cancel) {
                Ok(s) => Ok(s),
                Err(e) => {
                    let msg = e.to_string();
                    err = Some(e);
                    Err(std::io::Error::other(msg))
                }
            },
            label,
            block,
            ttl_hours,
        );
        match (st, err) {
            (Ok(s), _) => Ok(s),
            (Err(_), Some(e)) => Err(self.classify(e)),
            (Err(e), None) => Err(self.classify(e.into())),
        }
    }

    pub fn get_all(&self, relay: &Relay, class: u8) -> Result<Vec<aska_proto::Record>, DropError> {
        self.check_cancel()?;
        let mut s = self.connector.connect(relay, &self.cancel)?;
        adp::get_all(&mut s, class)
            .map_err(DropError::from)
            .map_err(|e| self.classify(e))
    }

    /// Post to every relay (CLI-12: two relays when the Key Card lists two).
    pub fn post_all(
        &self,
        relays: &[Relay],
        label: [u8; LABEL_LEN],
        block: &[u8],
        ttl_hours: u16,
    ) -> Vec<PostResult> {
        relays
            .iter()
            .map(|r| PostResult {
                relay: r.clone(),
                result: self.put(r, label, block, ttl_hours),
            })
            .collect()
    }

    /// Fetch the whole bucket of every class from every relay and match the label locally
    /// (§8: clients MUST NOT narrow a listing). The request pattern is fixed — every relay ×
    /// every class, regardless of where a match turns up — so that no relay can tell from the
    /// client's behaviour whether it, or another relay, held the Block.
    pub fn fetch(&self, relays: &[Relay], label: &[u8; LABEL_LEN], classes: &[u8]) -> FetchOutcome {
        let mut out = FetchOutcome {
            label: Some(secret32(*label)),
            block: None,
            records: Vec::new(),
            attempts: Vec::with_capacity(relays.len() * classes.len()),
        };
        for relay in relays {
            for &class in classes {
                if self.cancel.is_cancelled() {
                    out.attempts
                        .push((relay.clone(), class, Err(DropError::Cancelled)));
                    continue;
                }
                match self.get_all(relay, class) {
                    Ok(bucket) => {
                        let n = bucket.len();
                        // Constant work per record: compare every label; keep the first match.
                        // Every record's label is wiped afterwards — the bucket holds the
                        // relay's copy of L, which must not outlive the Session in freed heap
                        // (memory gate, M8 pre-review).
                        for (mut l, b) in bucket {
                            let hit = ct_eq(&l, label) && out.block.is_none();
                            let b = Zeroizing::new(b);
                            if hit {
                                out.block = Some(b);
                            } else {
                                drop(b);
                            }
                            l.zeroize();
                        }
                        out.attempts.push((relay.clone(), class, Ok(n)));
                    }
                    Err(e) => out.attempts.push((relay.clone(), class, Err(e))),
                }
            }
        }
        out
    }

    /// Fetch the whole bucket of every class from every relay and return every record, for a
    /// receiver that matches by decapsulation rather than by label (DC-02 §2.4). The request
    /// pattern is the same fixed relay × class sweep as `fetch`.
    pub fn fetch_all(&self, relays: &[Relay], classes: &[u8]) -> FetchOutcome {
        let mut out = FetchOutcome {
            label: None,
            block: None,
            records: Vec::new(),
            attempts: Vec::with_capacity(relays.len() * classes.len()),
        };
        for relay in relays {
            for &class in classes {
                if self.cancel.is_cancelled() {
                    out.attempts
                        .push((relay.clone(), class, Err(DropError::Cancelled)));
                    continue;
                }
                match self.get_all(relay, class) {
                    Ok(bucket) => {
                        out.attempts.push((relay.clone(), class, Ok(bucket.len())));
                        out.records
                            .extend(bucket.into_iter().map(|(l, b)| (l, Zeroizing::new(b))));
                    }
                    Err(e) => out.attempts.push((relay.clone(), class, Err(e))),
                }
            }
        }
        out
    }

    /// Decoy PUT: random bytes of a real class under a random label (§8, D-10).
    pub fn decoy_put(&self, relay: &Relay, class: u8, ttl_hours: u16) -> Result<Status, DropError> {
        let size = class_size(class).ok_or(DropError::Proto(ProtoError::BadClass))?;
        let label: [u8; 32] = OsRng.array().map_err(|_| DropError::Rng)?;
        let block = OsRng.bytes(size).map_err(|_| DropError::Rng)?;
        self.put(relay, label, &block, ttl_hours)
    }

    /// Decoy GET_ALL: fetch a bucket and discard it.
    pub fn decoy_get(&self, relay: &Relay, class: u8) -> Result<usize, DropError> {
        Ok(self.get_all(relay, class)?.len())
    }
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
