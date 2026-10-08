//! The `Session` (Client Design §2.3): the only owner of secrets. Two flows share one type:
//!
//! ```text
//! sender:   Idle → Composing → Sealed → (HandOver ⇄ Posted) → Closed
//! receiver: Idle → Collecting → Fetched → Opened → Closed
//! ```
//!
//! Every secret (root, passphrases, note text, Shares, opened plaintext) lives in a `LockedBuf`
//! while the Session is open, and is zeroised by `close()`, by `distress()`, by the idle
//! watchdog, or by drop. The front ends never receive owned copies of secrets except the
//! hand-over material (words, Key Card, Shares), which they display and then release.
//!
//! Network work never holds the Session: `post_job()` and `fetch_job()` hand out jobs that own
//! only public data (ciphertext, label, relays) plus a `CancelToken`, so a front end runs them
//! on a worker thread while `distress()` / `close()` / the watchdog stay available. `post()`
//! and `check_drops()` are the blocking conveniences for a command-line front end.
//!
//! Threading: `seal`, `open`, `add_key_material` and `close` scrub the calling thread's stack
//! after they finish, so they should run on the same thread (any thread with ≥ 512 KiB of
//! stack; every default is larger).

use crate::block::{open, region_len, seal, Slot};
use crate::cancel::CancelToken;
use crate::consts::{SizeClass, KEM_LEN, KEM_OFF, PTYPE_BINARY, PTYPE_TEXT};
use crate::cover::real_request_delay;
use crate::drop::{
    secret32, Connector, DropClient, DropError, FetchOutcome, PostResult, Relay, Secret32,
    TorConnector,
};
use crate::encodings::{share_decode, share_encode, KeyCard, ReceivingKey};
use crate::error::Error;
use crate::kdf::KdfProfile;
use crate::keys::Root;
use crate::rng::OsRng;
use crate::secret::{scrub_stack, LockState, LockedBuf};
use crate::shares::{combine, split, Share};
use crate::tor::{client_auth_add, TorConfig, TorError};
use crate::xwing;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Idle,
    Composing,
    Sealed,
    HandOver,
    Posted,
    Collecting,
    Fetched,
    Opened,
    Closed,
}

/// Protection level chosen by the sender (Client Design §5.2: Quick / Guarded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// The root travels whole (QR / 24 words).
    Quick,
    /// The root is split into `n` Shares of which `k` reconstruct it (2-of-3, 3-of-5).
    Guarded { k: u8, n: u8 },
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub tor: TorConfig,
    /// Relays for posting, and the receiver's fallback when the key material names none.
    pub relays: Vec<Relay>,
    /// Watchdog: the Session closes itself after this much inactivity (default 5 min).
    pub idle_timeout: Duration,
    /// Proceed even if secrets cannot be locked in RAM (the user accepted the doctor warning).
    /// With this false, every single secret buffer must lock or the operation fails.
    pub accept_unlocked_memory: bool,
    /// Real requests are delayed by a uniform random time in [0, this] (§6.5; default 90 s).
    pub request_delay_max: Duration,
    /// Size class for sealing; `None` = the smallest class the slots fit in.
    pub size_class: Option<SizeClass>,
    /// KDF profile for slots sealed by this Session.
    pub profile: KdfProfile,
    /// Profiles tried when opening (§6.2).
    pub open_profiles: Vec<KdfProfile>,
    /// TTL requested on PUT and written into Key Cards.
    pub ttl_hours: u16,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig {
            tor: TorConfig::default(),
            relays: Vec::new(),
            idle_timeout: Duration::from_secs(300),
            accept_unlocked_memory: false,
            request_delay_max: Duration::from_secs(90),
            size_class: None,
            profile: KdfProfile::DEFAULT,
            open_profiles: vec![KdfProfile::P1, KdfProfile::P2],
            ttl_hours: aska_proto::DEFAULT_TTL_HOURS,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("operation not allowed in state {0:?}")]
    WrongState(State),
    #[error("session expired (idle watchdog) and was closed")]
    Expired,
    #[error("cannot lock memory for secrets; accept the warning to proceed")]
    MemoryUnlocked,
    #[error("format: {0}")]
    Format(#[from] Error),
    #[error("dead drop: {0}")]
    Drop(#[from] DropError),
    #[error("a passphrase must not be empty")]
    EmptyPassphrase,
    #[error("no relay configured")]
    NoRelays,
    #[error("note does not fit any size class")]
    TooLarge,
    #[error("more Shares needed: have {have}, need {need}")]
    NeedShares { have: u8, need: u8 },
    #[error("that Share belongs to a different set; it was not kept")]
    ForeignShare,
    #[error("unrecognised key material")]
    BadKeyMaterial,
    #[error("input is not valid UTF-8 text")]
    NotText,
    #[error("client authorisation cannot be installed: {0}")]
    AuthUnavailable(String),
    #[error("client authorisation: {0}")]
    Auth(TorError),
    #[error("no relay answered")]
    NoRelayAnswered(DropError),
    #[error("no slot opened with that passphrase")]
    NoSlot,
    #[error("this job belongs to different key material")]
    StaleJob,
    #[error("not available when sealing for a receiving key: there is no key to hand over")]
    RecipientPath,
    #[error("not a Receiving Key (askar1…)")]
    BadReceivingKey,
    #[error("cancelled")]
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    Ready,
    NeedShares { have: u8, need: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenInfo {
    pub ptype: u8,
    pub len: usize,
    /// The slot carried the distress flag: key material has already been destroyed.
    pub distress: bool,
}

/// A decoy or distress slot waiting to be sealed.
struct PendingSlot {
    text: LockedBuf,
    passphrase: LockedBuf,
    distress: bool,
}

/// The idle watchdog's clock, shared between the Session and its detached jobs. Time spent
/// waiting on the network is not idleness: while a job is in flight the watchdog is
/// suspended, and when the job ends (however it ends) the clock is refreshed, so a slow Tor
/// fetch can never destroy the key material the user is waiting on.
struct Watchdog {
    last_activity: Instant,
    jobs_in_flight: u32,
}

type SharedWatchdog = Arc<std::sync::Mutex<Watchdog>>;

fn wd_lock(wd: &SharedWatchdog) -> std::sync::MutexGuard<'_, Watchdog> {
    wd.lock().unwrap_or_else(|e| e.into_inner())
}

/// Held by a job for its lifetime; see [`Watchdog`].
struct JobGuard(SharedWatchdog);

impl JobGuard {
    fn new(wd: &SharedWatchdog) -> Self {
        let mut w = wd_lock(wd);
        w.jobs_in_flight += 1;
        w.last_activity = Instant::now();
        JobGuard(wd.clone())
    }
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        let mut w = wd_lock(&self.0);
        w.jobs_in_flight = w.jobs_in_flight.saturating_sub(1);
        w.last_activity = Instant::now();
    }
}

/// Posting, detached from the Session: owns ciphertext, label, relays and a cancel token.
pub struct PostJob {
    block: Zeroizing<Vec<u8>>,
    label: Secret32,
    relays: Vec<Relay>,
    ttl_hours: u16,
    delay_max: Duration,
    connector: Arc<dyn Connector>,
    cancel: CancelToken,
    _guard: JobGuard,
}

impl std::fmt::Debug for PostJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PostJob({} relays)", self.relays.len())
    }
}

impl PostJob {
    /// Clone of the token; `cancel()` on it aborts the job wherever it is.
    pub fn cancel_token(&self) -> CancelToken {
        self.cancel.clone()
    }

    /// Wait the random request delay, then post to every relay. Blocking; run on a worker.
    pub fn run(self) -> Result<Vec<PostResult>, SessionError> {
        if !self
            .cancel
            .sleep(real_request_delay(self.delay_max, &mut OsRng))
        {
            return Err(SessionError::Cancelled);
        }
        let client = DropClient::new(self.connector.as_ref(), self.cancel.clone());
        let results = client.post_all(&self.relays, **self.label, &self.block, self.ttl_hours);
        // The label crossed this thread's stack by value: leave nothing behind (glibc keeps
        // finished threads' stacks mapped for reuse).
        scrub_stack();
        if self.cancel.is_cancelled() {
            return Err(SessionError::Cancelled);
        }
        Ok(results)
    }
}

/// Fetching, detached from the Session: owns label, relays, classes and a cancel token.
pub struct FetchJob {
    /// `None`: fetch everything; the Session matches by decapsulation (receiving seed).
    label: Option<Secret32>,
    relays: Vec<Relay>,
    classes: Vec<u8>,
    delay_max: Duration,
    connector: Arc<dyn Connector>,
    cancel: CancelToken,
    _guard: JobGuard,
}

impl std::fmt::Debug for FetchJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "FetchJob({} relays, classes {:?})",
            self.relays.len(),
            self.classes
        )
    }
}

impl FetchJob {
    pub fn cancel_token(&self) -> CancelToken {
        self.cancel.clone()
    }

    /// Wait the random request delay, then run the fixed relay×class pattern. Blocking.
    pub fn run(self) -> Result<FetchOutcome, SessionError> {
        if !self
            .cancel
            .sleep(real_request_delay(self.delay_max, &mut OsRng))
        {
            return Err(SessionError::Cancelled);
        }
        let client = DropClient::new(self.connector.as_ref(), self.cancel.clone());
        let out = match &self.label {
            Some(l) => client.fetch(&self.relays, l, &self.classes),
            None => client.fetch_all(&self.relays, &self.classes),
        };
        scrub_stack();
        if self.cancel.is_cancelled() {
            return Err(SessionError::Cancelled);
        }
        Ok(out)
    }
}

pub struct Session {
    cfg: SessionConfig,
    connector: Arc<dyn Connector>,
    state: State,
    watchdog: SharedWatchdog,
    // secrets
    root: Option<LockedBuf>,
    note: Option<(LockedBuf, u8)>,
    note_passphrase: Option<LockedBuf>,
    pending: Vec<PendingSlot>,
    shares: Vec<LockedBuf>,
    plaintext: Option<(LockedBuf, u8, bool)>,
    // non-secret working state
    block: Option<Zeroizing<Vec<u8>>>,
    /// Boxed so that moving the Session never leaves a copy of the label behind.
    label: Option<Secret32>,
    share_k: Option<u8>,
    key_relays: Vec<Relay>,
    key_class: Option<SizeClass>,
    /// Relays (by onion public key) whose client-auth key was installed this Tor session.
    installed_auth: HashSet<[u8; 32]>,
    // receiving-key path (DC-02)
    /// Sender: the Receiving Key to seal for; the Block then carries an X-Wing ciphertext.
    recipient: Option<Box<ReceivingKey>>,
    /// Sender: the Block was sealed for a receiving key — nothing to hand over (KEY-10).
    kem_sealed: bool,
    /// Receiver: the receiving seed; matching is by decapsulation, not by label.
    seed: Option<LockedBuf>,
    /// Receiver: the stand-ins of an unmatched seed bucket (a locked page holding zeros, the
    /// label of the all-zero root, a zero Block). Kept until the Session ends so that a miss
    /// ends with the same moves as a hit, which keeps its buffers (timing parity, DC-02 (c)).
    /// Nothing secret: the conditional copies never wrote into them.
    spent: Option<SpentStandIns>,
}

/// See `Session::spent`: a locked page, a label and a Block buffer, all non-secret.
type SpentStandIns = (LockedBuf, Secret32, Option<Zeroizing<Vec<u8>>>);

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Session({:?})", self.state)
    }
}

/// NFKC-normalise UTF-8 text held in a locked buffer into a new locked buffer.
fn nfkc_locked(input: &[u8], require_lock: bool) -> Result<LockedBuf, SessionError> {
    let text = std::str::from_utf8(input).map_err(|_| SessionError::NotText)?;
    // Two passes over the normalisation iterator — size first, then bytes straight into the
    // locked buffer through a 4-byte stack scratch — so no partial copy of a passphrase is
    // ever left in an unlocked, reallocated `String` (review finding C-5).
    let len: usize = text.nfkc().map(char::len_utf8).sum();
    let mut out = LockedBuf::try_with_capacity(len.max(1), require_lock)
        .map_err(|_| SessionError::MemoryUnlocked)?;
    let mut scratch = [0u8; 4];
    for c in text.nfkc() {
        let enc = c.encode_utf8(&mut scratch);
        out.extend_from_slice(enc.as_bytes());
    }
    scratch.zeroize();
    Ok(out)
}

/// Passphrases must carry some content: an empty or whitespace-only passphrase would create a
/// slot no receiver can reach, since every front end maps an empty entry to "no passphrase"
/// (review finding A-6; Block Format §5.3).
fn require_passphrase_content(p: &LockedBuf) -> Result<(), SessionError> {
    match std::str::from_utf8(p.as_slice()) {
        Ok(t) if !t.trim().is_empty() => Ok(()),
        _ => Err(SessionError::EmptyPassphrase),
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && a.ct_eq(b).into()
}

impl Session {
    /// Create a Session that reaches relays through the local Tor.
    pub fn new(cfg: SessionConfig) -> Result<Self, SessionError> {
        let connector: Arc<dyn Connector> = Arc::new(TorConnector {
            cfg: cfg.tor.clone(),
        });
        Self::with_connector(cfg, connector)
    }

    /// Create a Session with an explicit connector (tests; Qubes split mode later).
    pub fn with_connector(
        cfg: SessionConfig,
        connector: Arc<dyn Connector>,
    ) -> Result<Self, SessionError> {
        crate::platform::disable_core_dumps();
        // Probe: can this process lock memory at all?
        let probe = LockedBuf::with_capacity(32);
        if probe.lock_state() == LockState::Unlocked && !cfg.accept_unlocked_memory {
            return Err(SessionError::MemoryUnlocked);
        }
        Ok(Session {
            cfg,
            connector,
            state: State::Idle,
            watchdog: Arc::new(std::sync::Mutex::new(Watchdog {
                last_activity: Instant::now(),
                jobs_in_flight: 0,
            })),
            root: None,
            note: None,
            note_passphrase: None,
            pending: Vec::new(),
            shares: Vec::new(),
            plaintext: None,
            block: None,
            label: None,
            share_k: None,
            key_relays: Vec::new(),
            key_class: None,
            installed_auth: HashSet::new(),
            recipient: None,
            kem_sealed: false,
            seed: None,
            spent: None,
        })
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Time left before the watchdog closes the Session. While a post or fetch job is in
    /// flight this stays at the full timeout: waiting on the network is not idleness.
    pub fn remaining_idle(&self) -> Duration {
        let w = wd_lock(&self.watchdog);
        if w.jobs_in_flight > 0 {
            return self.cfg.idle_timeout;
        }
        self.cfg
            .idle_timeout
            .saturating_sub(w.last_activity.elapsed())
    }

    /// True while a detached job holds the Session's key material busy (front ends show
    /// "working" instead of the idle countdown).
    pub fn job_in_flight(&self) -> bool {
        wd_lock(&self.watchdog).jobs_in_flight > 0
    }

    /// Run the watchdog; front ends call this from a timer. Returns `Err(Expired)` once.
    pub fn tick(&mut self) -> Result<(), SessionError> {
        if self.state == State::Closed {
            return Ok(());
        }
        let expired = {
            let w = wd_lock(&self.watchdog);
            w.jobs_in_flight == 0 && w.last_activity.elapsed() >= self.cfg.idle_timeout
        };
        if expired {
            self.close();
            return Err(SessionError::Expired);
        }
        Ok(())
    }

    /// Count user attention as activity: the View screen calls this while a note is on
    /// screen so the idle watchdog (§2.3) does not end a Session the user is reading; the
    /// note's own auto-close countdown (§5.5) then decides when it ends.
    pub fn keep_alive(&mut self) -> Result<(), SessionError> {
        self.touch()
    }

    fn touch(&mut self) -> Result<(), SessionError> {
        self.tick()?;
        if self.state == State::Closed {
            return Err(SessionError::WrongState(State::Closed));
        }
        wd_lock(&self.watchdog).last_activity = Instant::now();
        Ok(())
    }

    fn require(&self, states: &[State]) -> Result<(), SessionError> {
        if states.contains(&self.state) {
            Ok(())
        } else {
            Err(SessionError::WrongState(self.state))
        }
    }

    /// A locked buffer holding `data`, honouring `accept_unlocked_memory`.
    fn lock(&self, data: &[u8]) -> Result<LockedBuf, SessionError> {
        LockedBuf::try_from_slice(data, !self.cfg.accept_unlocked_memory)
            .map_err(|_| SessionError::MemoryUnlocked)
    }

    /// Accept a buffer the front end allocated: it must be locked unless the user accepted.
    fn accept(&self, b: LockedBuf) -> Result<LockedBuf, SessionError> {
        if b.lock_state() == LockState::Unlocked && !self.cfg.accept_unlocked_memory {
            return Err(SessionError::MemoryUnlocked);
        }
        Ok(b)
    }

    fn root(&self) -> Result<Root, SessionError> {
        if self.kem_sealed {
            return Err(SessionError::RecipientPath);
        }
        let r = self
            .root
            .as_ref()
            .ok_or(SessionError::WrongState(self.state))?;
        Ok(Root::from_slice(r.as_slice()))
    }

    fn set_root(&mut self, root: &Root) -> Result<(), SessionError> {
        let buf = self.lock(root.as_bytes())?;
        if let Some(mut old) = self.root.replace(buf) {
            old.clear();
        }
        self.label = Some(secret32(crate::kdf::derive_label(root)));
        Ok(())
    }

    // ------------------------------------------------------------------ sender

    /// Seal the coming note for a Receiving Key (`askar1…`, DC-02): the Block will carry an
    /// X-Wing ciphertext and there will be nothing to hand over. Allowed before sealing.
    /// The key's relay hints become this Session's relays when none are configured.
    pub fn set_recipient(&mut self, askar: &str) -> Result<(), SessionError> {
        self.touch()?;
        self.require(&[State::Idle, State::Composing])?;
        let rk = ReceivingKey::decode(askar).map_err(|_| SessionError::BadReceivingKey)?;
        crate::xwing::validate_public_key(&rk.pk).map_err(|_| SessionError::BadReceivingKey)?;
        if self.cfg.relays.is_empty() && !rk.relays.is_empty() {
            self.cfg.relays = rk
                .relays
                .iter()
                .map(|pk| Relay {
                    pubkey: *pk,
                    port: aska_proto::DEFAULT_PORT,
                    auth_key: None,
                })
                .collect();
        }
        if self.cfg.size_class.is_none() {
            self.cfg.size_class = rk.size_class;
        }
        self.recipient = Some(Box::new(rk));
        Ok(())
    }

    /// The check (twelve characters, a hash of the public key) of the Receiving Key this Session
    /// seals for.
    pub fn recipient_check(&self) -> Option<String> {
        self.recipient.as_ref().map(|rk| rk.check())
    }

    /// True once the Block was sealed for a receiving key (no hand-over exists).
    pub fn sealed_for_recipient(&self) -> bool {
        self.kem_sealed
    }

    /// Replace the relays this Session posts to (Client Design §5.2: "if every relay is full
    /// or unreachable, the Block is kept in the Session and the user is offered another
    /// relay"). Allowed while there is a sealed Block that has not been posted yet, and before
    /// anything has been composed. On the receiving side these are the fallback for key
    /// material that names no relay (words, Shares), so they may change while collecting and
    /// between fetch attempts — a Key Card's own relays still take precedence.
    pub fn set_relays(&mut self, relays: Vec<Relay>) -> Result<(), SessionError> {
        self.touch()?;
        self.require(&[
            State::Idle,
            State::Composing,
            State::Sealed,
            State::HandOver,
            State::Collecting,
            State::Fetched,
        ])?;
        self.cfg.relays = relays;
        Ok(())
    }

    /// Start composing a note. `ptype` is `PTYPE_TEXT` or `PTYPE_BINARY`.
    pub fn compose(&mut self, note: &[u8], ptype: u8) -> Result<(), SessionError> {
        let buf = self.lock(note)?;
        self.compose_locked(buf, ptype)
    }

    /// Same, from a buffer the front end filled directly (an editor writing into locked
    /// memory, §3.1).
    pub fn compose_locked(&mut self, note: LockedBuf, ptype: u8) -> Result<(), SessionError> {
        self.touch()?;
        self.require(&[State::Idle, State::Composing])?;
        if ptype != PTYPE_TEXT && ptype != PTYPE_BINARY {
            return Err(SessionError::Format(Error::Malformed));
        }
        if region_len(note.len()) > SizeClass::C3.payload_len() {
            return Err(SessionError::TooLarge);
        }
        let note = self.accept(note)?;
        if let Some((mut old, _)) = self.note.replace((note, ptype)) {
            old.clear();
        }
        self.state = State::Composing;
        Ok(())
    }

    /// Protect the real note with a passphrase (optional; without one the slot is open).
    pub fn set_passphrase(&mut self, passphrase: Option<&str>) -> Result<(), SessionError> {
        let buf = match passphrase {
            Some(p) => Some(self.lock(p.as_bytes())?),
            None => None,
        };
        self.set_passphrase_locked(buf)
    }

    /// Same, from a locked buffer of UTF-8 (the in-app keypad writes here, §6.3).
    pub fn set_passphrase_locked(
        &mut self,
        passphrase: Option<LockedBuf>,
    ) -> Result<(), SessionError> {
        self.touch()?;
        self.require(&[State::Composing])?;
        let norm = match passphrase {
            Some(p) => {
                let p = self.accept(p)?;
                {
                    let n = nfkc_locked(p.as_slice(), !self.cfg.accept_unlocked_memory)?;
                    require_passphrase_content(&n)?;
                    Some(n)
                }
            }
            None => None,
        };
        if let Some(mut old) = std::mem::replace(&mut self.note_passphrase, norm) {
            old.clear();
        }
        Ok(())
    }

    /// Add a decoy slot: harmless text behind its own passphrase (D-07).
    pub fn add_decoy(&mut self, text: &str, passphrase: &str) -> Result<(), SessionError> {
        let t = self.lock(text.as_bytes())?;
        let p = self.lock(passphrase.as_bytes())?;
        self.add_decoy_locked(t, p)
    }

    pub fn add_decoy_locked(
        &mut self,
        text: LockedBuf,
        passphrase: LockedBuf,
    ) -> Result<(), SessionError> {
        self.touch()?;
        self.require(&[State::Composing])?;
        let text = self.accept(text)?;
        let passphrase = self.accept(passphrase)?;
        let passphrase = nfkc_locked(passphrase.as_slice(), !self.cfg.accept_unlocked_memory)?;
        require_passphrase_content(&passphrase)?;
        self.pending.push(PendingSlot {
            text,
            passphrase,
            distress: false,
        });
        Ok(())
    }

    /// Add the distress slot: the text shown, and the passphrase that destroys the receiver's
    /// key material when entered (§6.4). At most one.
    pub fn set_distress(&mut self, text: &str, passphrase: &str) -> Result<(), SessionError> {
        let t = self.lock(text.as_bytes())?;
        let p = self.lock(passphrase.as_bytes())?;
        self.set_distress_locked(t, p)
    }

    pub fn set_distress_locked(
        &mut self,
        text: LockedBuf,
        passphrase: LockedBuf,
    ) -> Result<(), SessionError> {
        self.touch()?;
        self.require(&[State::Composing])?;
        let text = self.accept(text)?;
        let passphrase = self.accept(passphrase)?;
        let passphrase = nfkc_locked(passphrase.as_slice(), !self.cfg.accept_unlocked_memory)?;
        require_passphrase_content(&passphrase)?;
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].distress {
                let mut p = self.pending.remove(i);
                p.text.clear();
                p.passphrase.clear();
            } else {
                i += 1;
            }
        }
        self.pending.push(PendingSlot {
            text,
            passphrase,
            distress: true,
        });
        Ok(())
    }

    /// Generate the root, seal the Block and (for Guarded) split the Shares.
    pub fn seal(&mut self, level: Level) -> Result<(), SessionError> {
        let r = self.seal_inner(level);
        scrub_stack();
        r
    }

    /// Not inlined on purpose: `scrub_stack` in the caller clears the frames *below* the
    /// caller's own, so the secret-handling body must live in a frame of its own. Inlining it
    /// would lift its temporaries (a moved `Root`, KDF buffers) into the caller's frame, where
    /// the scrub cannot reach them (found by the GUI memory gate in a release build).
    #[inline(never)]
    fn seal_inner(&mut self, level: Level) -> Result<(), SessionError> {
        self.touch()?;
        self.require(&[State::Composing])?;
        if let Level::Guarded { k, n } = level {
            if k < 2 || n < k {
                return Err(SessionError::Format(Error::BadShare));
            }
            if self.recipient.is_some() {
                return Err(SessionError::RecipientPath);
            }
        }
        let (note, ptype) = self
            .note
            .as_ref()
            .ok_or(SessionError::WrongState(self.state))?;

        // Slot copies are Zeroize-on-drop; the sealed Block is the only thing that survives.
        let mut slots: Vec<Slot> = Vec::with_capacity(1 + self.pending.len());
        slots.push(Slot {
            data: note.as_slice().to_vec(),
            ptype: *ptype,
            passphrase_nfkc: self.note_passphrase.as_ref().map(|p| p.as_slice().to_vec()),
            distress: false,
            profile: self.cfg.profile,
        });
        for p in &self.pending {
            slots.push(Slot {
                data: p.text.as_slice().to_vec(),
                ptype: PTYPE_TEXT,
                passphrase_nfkc: Some(p.passphrase.as_slice().to_vec()),
                distress: p.distress,
                profile: self.cfg.profile,
            });
        }
        let need: usize = slots.iter().map(|s| region_len(s.data.len())).sum();
        let class = match self.cfg.size_class {
            Some(c) if c.payload_len() >= need => c,
            Some(_) => return Err(SessionError::TooLarge),
            None => SizeClass::ALL
                .into_iter()
                .find(|c| c.payload_len() >= need)
                .ok_or(SessionError::TooLarge)?,
        };

        let (root, block) = match &self.recipient {
            None => {
                let root = Root::generate_mixed()?;
                let block = seal(&root, class, &slots, &mut OsRng, None, None)?;
                (root, block)
            }
            Some(rk) => {
                // DC-02 §2: the root comes from the X-Wing shared secret and the KEM region
                // carries the ciphertext (ML-KEM part ‖ Elligator2 representative).
                let (ss, region) = xwing::encapsulate(&rk.pk)?;
                let root = xwing::root_from_shared_secret(&ss);
                drop(ss);
                let block = seal(&root, class, &slots, &mut OsRng, None, Some(&region))?;
                (root, block)
            }
        };
        drop(slots);
        self.set_root(&root)?;
        self.block = Some(Zeroizing::new(block));
        self.key_class = Some(class);
        if self.recipient.is_some() {
            // KEY-10: the sender never holds a hand-over key; only the label is needed to post.
            if let Some(mut r) = self.root.take() {
                r.clear();
            }
            self.kem_sealed = true;
        }

        self.clear_shares();
        if let Level::Guarded { k, n } = level {
            let shares = split(&root, k, n, &mut OsRng)?;
            let mut locked = Vec::with_capacity(shares.len());
            for s in &shares {
                locked.push(self.lock(&s.to_bytes()[..])?);
            }
            self.shares = locked;
            self.share_k = Some(k);
        }
        // The note and passphrases are inside the Block now.
        if let Some((mut n, _)) = self.note.take() {
            n.clear();
        }
        if let Some(mut p) = self.note_passphrase.take() {
            p.clear();
        }
        for mut p in self.pending.drain(..) {
            p.text.clear();
            p.passphrase.clear();
        }
        self.state = State::Sealed;
        Ok(())
    }

    fn clear_shares(&mut self) {
        for mut s in self.shares.drain(..) {
            s.clear();
        }
        self.share_k = None;
    }

    fn mark_hand_over(&mut self) {
        if self.state == State::Sealed {
            self.state = State::HandOver;
        }
    }

    /// The 24 words (Quick level, or as an alternative to the Key Card). Also available on
    /// the receiving side once the key material is complete (`aska key words` re-encodes a
    /// Key Card or a set of Shares for a further hand-over).
    pub fn hand_over_words(&mut self) -> Result<Zeroizing<String>, SessionError> {
        self.touch()?;
        self.require(&[
            State::Sealed,
            State::HandOver,
            State::Posted,
            State::Collecting,
        ])?;
        let words = self.words_inner();
        scrub_stack();
        words
    }

    #[inline(never)]
    fn words_inner(&mut self) -> Result<Zeroizing<String>, SessionError> {
        let r = self.root()?;
        self.mark_hand_over();
        Ok(r.to_words())
    }

    /// The Key Card (root + relays + class + TTL + circle auth key) as bech32m text for a QR.
    /// On the receiving side the card names the relays the key material came with (or the
    /// configured fallback), so a re-encoded card points where the original did.
    pub fn hand_over_keycard(&mut self) -> Result<Zeroizing<String>, SessionError> {
        self.touch()?;
        self.require(&[
            State::Sealed,
            State::HandOver,
            State::Posted,
            State::Collecting,
        ])?;
        let text = self.keycard_inner();
        scrub_stack();
        text
    }

    #[inline(never)]
    fn keycard_inner(&mut self) -> Result<Zeroizing<String>, SessionError> {
        let r = self.root()?;
        let relays = if self.state == State::Collecting {
            self.receive_relays()
        } else {
            self.cfg.relays.clone()
        };
        let mut card = KeyCard::new(r);
        card.relays = relays.iter().map(|r| r.pubkey).collect();
        card.size_class = self.key_class;
        card.ttl_hours = Some(self.cfg.ttl_hours);
        // The Key Card carries ONE auth key (TLV 0x06) that applies to every listed relay, so
        // it is included only when every relay shares the same key.
        let first = relays.first().and_then(|r| r.auth_key.clone());
        if first.is_some()
            && relays
                .iter()
                .all(|r| r.auth_key.as_deref() == first.as_deref())
        {
            card.auth_key = first.map(|k| **k);
        }
        let text = card.encode()?;
        self.mark_hand_over();
        Ok(text)
    }

    /// The sealed Block and its label, for Qubes split mode (Client Design §8.2): the offline
    /// qube writes them to a file that a networked qube posts with `aska post`. Both are what
    /// the relay would see anyway — ciphertext and a one-way label — and reveal nothing about
    /// the root. Sealed, HandOver or Posted states only.
    pub fn sealed_block(&self) -> Result<([u8; 32], &[u8]), SessionError> {
        if !matches!(self.state, State::Sealed | State::HandOver | State::Posted) {
            return Err(SessionError::WrongState(self.state));
        }
        let block = self
            .block
            .as_ref()
            .ok_or(SessionError::WrongState(self.state))?;
        let label: [u8; 32] = ***self
            .label
            .as_ref()
            .ok_or(SessionError::WrongState(self.state))?;
        Ok((label, block.as_slice()))
    }

    /// Number of Shares produced (0 for Quick).
    pub fn share_count(&self) -> usize {
        self.shares.len()
    }

    /// Split key material that arrived whole (24 words or a Key Card) into fresh Shares —
    /// `aska share split`, the recovery drill of Client Design Table 3. Collecting state with
    /// complete key material only; replaces any Shares held.
    pub fn split_shares(&mut self, k: u8, n: u8) -> Result<(), SessionError> {
        self.touch()?;
        self.require(&[State::Collecting])?;
        if k < 2 || n < k {
            return Err(SessionError::Format(Error::BadShare));
        }
        let r = self.split_inner(k, n);
        scrub_stack();
        r
    }

    #[inline(never)]
    fn split_inner(&mut self, k: u8, n: u8) -> Result<(), SessionError> {
        let root = self.root()?;
        let shares = split(&root, k, n, &mut OsRng)?;
        let mut locked = Vec::with_capacity(shares.len());
        for s in &shares {
            locked.push(self.lock(&s.to_bytes()[..])?);
        }
        self.clear_shares();
        self.shares = locked;
        self.share_k = Some(k);
        Ok(())
    }

    /// One Share as `askas…` text — shown to one trustee at a time (§5.3).
    pub fn share_text(&mut self, i: usize) -> Result<Zeroizing<String>, SessionError> {
        self.touch()?;
        self.require(&[
            State::Sealed,
            State::HandOver,
            State::Posted,
            State::Collecting,
        ])?;
        let text = self.share_text_inner(i);
        scrub_stack();
        text
    }

    #[inline(never)]
    fn share_text_inner(&mut self, i: usize) -> Result<Zeroizing<String>, SessionError> {
        if self.kem_sealed {
            return Err(SessionError::RecipientPath);
        }
        let b = self
            .shares
            .get(i)
            .ok_or(SessionError::WrongState(self.state))?;
        let s = Share::from_bytes(b.as_slice())?;
        self.mark_hand_over();
        Ok(share_encode(&s)?)
    }

    /// Make sure every relay that needs client authorisation has it installed; drop relays
    /// that cannot be used here (Tails and Whonix, C-03). Errors before any network step when auth is
    /// required but impossible. This talks to the local control port (loopback, ≤ 15 s) while
    /// holding the Session; the Tor network is never touched here.
    fn prepare_relays(&mut self, relays: &[Relay]) -> Result<Vec<Relay>, SessionError> {
        let tails = crate::platform::control_port_filtered();
        let mut usable = Vec::with_capacity(relays.len());
        let mut skipped = 0;
        for r in relays {
            match &r.auth_key {
                None => usable.push(r.clone()),
                Some(_) if tails => skipped += 1,
                Some(k) => {
                    if self.cfg.tor.control.is_none() {
                        return Err(SessionError::AuthUnavailable(
                            "this relay needs a circle key but no Tor control port is configured"
                                .into(),
                        ));
                    }
                    if !self.installed_auth.contains(&r.pubkey) {
                        client_auth_add(&self.cfg.tor, &r.onion(), k)
                            .map_err(SessionError::Auth)?;
                        self.installed_auth.insert(r.pubkey);
                    }
                    usable.push(r.clone());
                }
            }
        }
        if usable.is_empty() {
            return Err(if skipped > 0 {
                SessionError::AuthUnavailable(
                    "every relay needs a circle key, which cannot be installed on Tails or Whonix (C-03)"
                        .into(),
                )
            } else {
                SessionError::NoRelays
            });
        }
        Ok(usable)
    }

    /// A posting job for a worker thread (see module docs).
    pub fn post_job(&mut self) -> Result<PostJob, SessionError> {
        self.touch()?;
        self.require(&[State::Sealed, State::HandOver, State::Posted])?;
        if self.cfg.relays.is_empty() {
            return Err(SessionError::NoRelays);
        }
        let relays = self.prepare_relays(&self.cfg.relays.clone())?;
        let block = self
            .block
            .as_ref()
            .ok_or(SessionError::WrongState(self.state))?;
        let label = self
            .label
            .clone()
            .ok_or(SessionError::WrongState(self.state))?;
        Ok(PostJob {
            block: block.clone(),
            label,
            relays,
            ttl_hours: self.cfg.ttl_hours,
            delay_max: self.cfg.request_delay_max,
            connector: self.connector.clone(),
            cancel: CancelToken::new(),
            _guard: JobGuard::new(&self.watchdog),
        })
    }

    /// Record a job's outcome: the Session is `Posted` once any relay stored the Block.
    pub fn record_post(&mut self, results: &[PostResult]) -> Result<(), SessionError> {
        self.touch()?;
        self.require(&[State::Sealed, State::HandOver, State::Posted])?;
        if results.iter().any(|r| r.stored()) {
            self.state = State::Posted;
        }
        Ok(())
    }

    /// Blocking convenience: `post_job().run()` + `record_post`.
    pub fn post(&mut self) -> Result<Vec<PostResult>, SessionError> {
        let r = self.post_inner();
        scrub_stack();
        r
    }

    #[inline(never)]
    fn post_inner(&mut self) -> Result<Vec<PostResult>, SessionError> {
        let job = self.post_job()?;
        let results = job.run()?;
        self.record_post(&results)?;
        Ok(results)
    }

    // ---------------------------------------------------------------- receiver

    /// Feed key material: 24 words, an `aska1…` Key Card, or an `askas1…` Share. Nothing is
    /// changed unless the input parses.
    pub fn add_key_material(&mut self, input: &str) -> Result<KeyStatus, SessionError> {
        let r = self.add_key_material_inner(input);
        scrub_stack();
        r
    }

    /// Not inlined on purpose: `scrub_stack` in the caller clears the frames *below* the
    /// caller's own, so the secret-handling body must live in a frame of its own. Inlining it
    /// would lift its temporaries (a moved `Root`, KDF buffers) into the caller's frame, where
    /// the scrub cannot reach them (found by the GUI memory gate in a release build).
    #[inline(never)]
    fn add_key_material_inner(&mut self, input: &str) -> Result<KeyStatus, SessionError> {
        self.touch()?;
        self.require(&[State::Idle, State::Collecting])?;
        let t = input.trim();
        // Prefix test without copying the secret: the HRP is ASCII and case-insensitive.
        let starts = |p: &str| {
            t.len() >= p.len()
                && t.as_bytes()[..p.len()]
                    .iter()
                    .zip(p.as_bytes())
                    .all(|(a, b)| a.eq_ignore_ascii_case(b))
        };

        if starts("askas1") {
            let s = share_decode(t)?;
            let bytes = s.to_bytes();
            if self.shares.iter().any(|b| ct_eq(b.as_slice(), &bytes[..])) {
                self.state = State::Collecting;
                return Ok(self.share_status());
            }
            // Set membership is decidable from the Share's own header (set_id, k, verify
            // tag): reject a stranger before it is kept, whatever k is.
            if let Some(first) = self.shares.first() {
                let f = Share::from_bytes(first.as_slice())?;
                if f.set_id != s.set_id || f.k != s.k || f.verify != s.verify {
                    return Err(SessionError::ForeignShare);
                }
            }
            let buf = self.lock(&bytes[..])?;
            self.shares.push(buf);
            self.share_k = Some(s.k);
            self.state = State::Collecting;
            if self.shares.len() >= s.k as usize {
                let parsed: Result<Vec<Share>, Error> = self
                    .shares
                    .iter()
                    .map(|b| Share::from_bytes(b.as_slice()))
                    .collect();
                match parsed.and_then(|p| combine(&p)) {
                    Ok(root) => {
                        self.set_root(&root)?;
                        self.clear_shares();
                        return Ok(KeyStatus::Ready);
                    }
                    Err(Error::ShareSet | Error::ShareVerify) => {
                        // Same header but the set does not reconstruct (an x collision or a
                        // forged Share): forget the newcomer and keep collecting.
                        if let Some(mut bad) = self.shares.pop() {
                            bad.clear();
                        }
                        return Err(SessionError::ForeignShare);
                    }
                    Err(e) => return Err(SessionError::Format(e)),
                }
            }
            return Ok(self.share_status());
        }
        if starts("aska1") {
            let card = KeyCard::decode(t)?;
            self.key_relays = Relay::from_keycard(&card);
            self.key_class = card.size_class;
            self.set_root(&card.root)?;
            self.state = State::Collecting;
            return Ok(KeyStatus::Ready);
        }
        if t.split_whitespace().count() == 24 {
            let root = Root::from_words(t)?;
            self.set_root(&root)?;
            self.state = State::Collecting;
            return Ok(KeyStatus::Ready);
        }
        Err(SessionError::BadKeyMaterial)
    }

    /// Receiver, receiving-key path (DC-02): take the 24-word receiving seed. Fetches then
    /// bring every Block of every class and the Session matches by decapsulation.
    pub fn add_receiving_seed(&mut self, words: &str) -> Result<(), SessionError> {
        let r = self.add_receiving_seed_inner(words);
        scrub_stack();
        r
    }

    #[inline(never)]
    fn add_receiving_seed_inner(&mut self, words: &str) -> Result<(), SessionError> {
        // The seed uses the root's word encoding (§7.1); it is a different key, kept apart.
        let seed = Root::from_words(words)?;
        self.add_receiving_seed_bytes_inner(seed.as_bytes())
    }

    /// `add_receiving_seed` for a seed held as bytes — one stored in the encrypted profile
    /// (RM-09) rather than typed as 24 words.
    pub fn add_receiving_seed_bytes(&mut self, seed: &[u8; 32]) -> Result<(), SessionError> {
        let r = self.add_receiving_seed_bytes_inner(seed);
        scrub_stack();
        r
    }

    #[inline(never)]
    fn add_receiving_seed_bytes_inner(&mut self, seed: &[u8; 32]) -> Result<(), SessionError> {
        self.touch()?;
        self.require(&[State::Idle, State::Collecting])?;
        let buf = self.lock(seed)?;
        if let Some(mut old) = self.seed.replace(buf) {
            old.clear();
        }
        if let Some(mut r) = self.root.take() {
            r.clear();
        }
        self.label = None;
        self.clear_shares();
        self.state = State::Collecting;
        Ok(())
    }

    /// True while this Session receives with a seed (no label until a Block matched).
    pub fn has_receiving_seed(&self) -> bool {
        self.seed.is_some()
    }

    /// DC-02 §2.4: decapsulate every record with the seed, derive its would-be label and
    /// compare in constant time. The same work is done whether or not a record matches, and
    /// wherever it sits: the matching record's root and Block are picked up with branch-free
    /// conditional copies, every record is wiped, and afterwards exactly one root is locked and
    /// one label derived — the found one, or an all-zero stand-in that is then discarded.
    /// (A GitHub runner measured the former hit-only `set_root` — a fresh locked page plus a
    /// label derivation, ~3–4 µs on a ~2.9 ms bucket — with 400 rounds; 6 Oct 2026.)
    #[inline(never)]
    fn match_records_with_seed<I>(&mut self, records: I) -> Result<bool, SessionError>
    where
        I: IntoIterator<Item = ([u8; 32], Zeroizing<Vec<u8>>)>,
    {
        use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
        let expanded = {
            let seed = self
                .seed
                .as_ref()
                .ok_or(SessionError::WrongState(self.state))?;
            let mut bytes = Zeroizing::new([0u8; xwing::SEED_LEN]);
            bytes.copy_from_slice(seed.as_slice());
            xwing::Expanded::from_seed(&bytes)
        };
        let mut found = Choice::from(0u8);
        let mut root_acc = Zeroizing::new([0u8; 32]);
        // One bucket is one size class, so every record has the length of the first; a record
        // of another length (a misbehaving relay) can never be taken. Lengths are public.
        let mut block_acc: Option<Zeroizing<Vec<u8>>> = None;
        for (mut l, b) in records {
            let Some(region) = b.get(KEM_OFF..KEM_OFF + KEM_LEN) else {
                l.zeroize();
                continue; // not a Block of any class
            };
            let region: &[u8; KEM_LEN] = region.try_into().expect("length checked");
            let ss = expanded.decapsulate(region);
            let root = xwing::root_from_shared_secret(&ss);
            let mut label = crate::kdf::derive_label(&root);
            let acc = block_acc.get_or_insert_with(|| Zeroizing::new(vec![0u8; b.len()]));
            let same_len = Choice::from((acc.len() == b.len()) as u8);
            let take = l[..].ct_eq(&label[..]) & !found & same_len;
            for (x, y) in root_acc.iter_mut().zip(root.as_bytes().iter()) {
                x.conditional_assign(y, take);
            }
            if acc.len() == b.len() {
                for (x, y) in acc.iter_mut().zip(b.iter()) {
                    x.conditional_assign(y, take);
                }
            }
            found |= take;
            // Candidate labels and the record's label are wiped either way (memory gate);
            // `b` (Zeroizing) is wiped when it drops here, for every record alike.
            label.zeroize();
            l.zeroize();
        }
        drop(expanded);
        // Identical finishing work on both outcomes.
        let candidate = Root::from_bytes(*root_acc);
        root_acc.zeroize();
        let buf = self.lock(candidate.as_bytes())?;
        let label = secret32(crate::kdf::derive_label(&candidate));
        drop(candidate);
        if bool::from(found) {
            if let Some(mut old) = self.root.replace(buf) {
                old.clear();
            }
            self.label = Some(label);
            self.block = block_acc;
            self.state = State::Fetched;
            Ok(true)
        } else {
            // Stored like a hit's buffers (released with the Session), not freed here.
            let _previous = self.spent.replace((buf, label, block_acc));
            Ok(false)
        }
    }

    /// Forget every piece of key material collected so far (wrong Shares, start over).
    pub fn clear_key_material(&mut self) -> Result<(), SessionError> {
        self.touch()?;
        self.require(&[State::Idle, State::Collecting])?;
        self.clear_shares();
        if let Some(mut r) = self.root.take() {
            r.clear();
        }
        if let Some(mut sd) = self.seed.take() {
            sd.clear();
        }
        self.label = None;
        self.key_relays.clear();
        self.key_class = None;
        self.state = State::Idle;
        Ok(())
    }

    fn share_status(&self) -> KeyStatus {
        KeyStatus::NeedShares {
            have: self.shares.len() as u8,
            need: self.share_k.unwrap_or(2),
        }
    }

    /// Relays this receiver will poll: from the Key Card if it named any, else the config.
    fn receive_relays(&self) -> Vec<Relay> {
        if self.key_relays.is_empty() {
            self.cfg.relays.clone()
        } else {
            self.key_relays.clone()
        }
    }

    /// A fetch job for a worker thread: the fixed relay×class pattern for this root's label.
    pub fn fetch_job(&mut self) -> Result<FetchJob, SessionError> {
        self.touch()?;
        self.require(&[State::Collecting, State::Fetched])?;
        let label = if self.seed.is_some() {
            None
        } else {
            Some(
                self.label
                    .clone()
                    .ok_or(SessionError::WrongState(self.state))?,
            )
        };
        let relays = self.receive_relays();
        if relays.is_empty() {
            return Err(SessionError::NoRelays);
        }
        let relays = self.prepare_relays(&relays)?;
        // The Key Card's class if it names one; otherwise the caller's `size_class` (the CLI's
        // `receive --class`, for words and Shares, which carry no class); otherwise all three.
        let classes: Vec<u8> = match self.key_class.or(self.cfg.size_class) {
            Some(c) => vec![c as u8],
            None => vec![1, 2, 3],
        };
        Ok(FetchJob {
            label,
            relays,
            classes,
            delay_max: self.cfg.request_delay_max,
            connector: self.connector.clone(),
            cancel: CancelToken::new(),
            _guard: JobGuard::new(&self.watchdog),
        })
    }

    /// Take a fetch outcome in. `Ok(true)` = the Block is here (state `Fetched`);
    /// `Ok(false)` = at least one relay answered and none had it; `Err` = no relay answered.
    pub fn accept_fetch(&mut self, outcome: FetchOutcome) -> Result<bool, SessionError> {
        // Matching (and, with a seed, decapsulation of every record) runs in the inner
        // function; the stack below it is scrubbed afterwards (review finding B-5).
        let r = self.accept_fetch_inner(outcome);
        scrub_stack();
        r
    }

    #[inline(never)]
    fn accept_fetch_inner(&mut self, mut outcome: FetchOutcome) -> Result<bool, SessionError> {
        self.touch()?;
        self.require(&[State::Collecting, State::Fetched])?;
        if self.seed.is_some() {
            if outcome.label.is_some() {
                return Err(SessionError::StaleJob);
            }
            let answered = outcome.any_answered();
            let records = std::mem::take(&mut outcome.records);
            if self.match_records_with_seed(records)? {
                return Ok(true);
            }
            if answered {
                return Ok(false);
            }
        } else {
            if self.label.as_deref() != outcome.label.as_deref() {
                return Err(SessionError::StaleJob);
            }
            if let Some(b) = outcome.block.take() {
                self.block = Some(b);
                self.state = State::Fetched;
                return Ok(true);
            }
            if outcome.any_answered() {
                return Ok(false);
            }
        }
        let first = std::mem::take(&mut outcome.attempts)
            .into_iter()
            .find_map(|(_, _, r)| r.err())
            .unwrap_or(DropError::NoRelay);
        Err(SessionError::NoRelayAnswered(first))
    }

    /// Match a bucket that arrived by other means — Qubes split mode, where a networked qube
    /// fetched the listing to a file and the offline qube that holds the key material does the
    /// label match (Client Design §8.2). Every record is compared in constant time and the
    /// whole bucket is consumed whatever the outcome, as `fetch` does over the network.
    /// `Ok(true)` = the Block is here (state `Fetched`); `Ok(false)` = not in this bucket.
    pub fn accept_bucket<I>(&mut self, records: I) -> Result<bool, SessionError>
    where
        I: IntoIterator<Item = ([u8; 32], Vec<u8>)>,
    {
        let r = self.accept_bucket_inner(records.into_iter().collect::<Vec<_>>());
        scrub_stack();
        r
    }

    #[inline(never)]
    fn accept_bucket_inner(
        &mut self,
        records: Vec<([u8; 32], Vec<u8>)>,
    ) -> Result<bool, SessionError> {
        self.touch()?;
        self.require(&[State::Collecting, State::Fetched])?;
        if self.seed.is_some() {
            return self
                .match_records_with_seed(records.into_iter().map(|(l, b)| (l, Zeroizing::new(b))));
        }
        let label = self
            .label
            .as_ref()
            .ok_or(SessionError::WrongState(self.state))?;
        let mut found: Option<Zeroizing<Vec<u8>>> = None;
        for (l, b) in records {
            let hit = ct_eq(&l, &***label);
            if hit && found.is_none() {
                found = Some(Zeroizing::new(b));
            }
        }
        match found {
            Some(b) => {
                self.block = Some(b);
                self.state = State::Fetched;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Blocking convenience: `fetch_job().run()` + `accept_fetch`.
    pub fn check_drops(&mut self) -> Result<bool, SessionError> {
        let r = self.check_drops_inner();
        scrub_stack();
        r
    }

    #[inline(never)]
    fn check_drops_inner(&mut self) -> Result<bool, SessionError> {
        let job = self.fetch_job()?;
        let out = job.run()?;
        self.accept_fetch(out)
    }

    /// Open the fetched Block. On a distress slot the key material is destroyed (§6.4).
    pub fn open(&mut self, passphrase: Option<&str>) -> Result<OpenInfo, SessionError> {
        let buf = match passphrase {
            Some(p) => Some(self.lock(p.as_bytes())?),
            None => None,
        };
        self.open_locked(buf)
    }

    /// Same, with the passphrase in a locked buffer from the in-app keypad (§6.3).
    pub fn open_locked(&mut self, passphrase: Option<LockedBuf>) -> Result<OpenInfo, SessionError> {
        let r = self.open_inner(passphrase);
        scrub_stack();
        r
    }

    /// Not inlined on purpose: `scrub_stack` in the caller clears the frames *below* the
    /// caller's own, so the secret-handling body must live in a frame of its own. Inlining it
    /// would lift its temporaries (a moved `Root`, KDF buffers) into the caller's frame, where
    /// the scrub cannot reach them (found by the GUI memory gate in a release build).
    #[inline(never)]
    fn open_inner(&mut self, passphrase: Option<LockedBuf>) -> Result<OpenInfo, SessionError> {
        self.touch()?;
        self.require(&[State::Fetched, State::Opened])?;
        let root = self.root()?;
        let block = self
            .block
            .as_ref()
            .ok_or(SessionError::WrongState(self.state))?;
        let pw = match passphrase {
            Some(p) => {
                let p = self.accept(p)?;
                Some(nfkc_locked(p.as_slice(), !self.cfg.accept_unlocked_memory)?)
            }
            None => None,
        };
        let result = open(
            block,
            &root,
            pw.as_ref().map(|p| p.as_slice()),
            &self.cfg.open_profiles,
        );
        drop(pw);
        drop(root);
        let mut opened = match result {
            Ok(o) => o,
            Err(Error::NoSlot) => return Err(SessionError::NoSlot),
            Err(e) => return Err(SessionError::Format(e)),
        };
        let distress = opened.distress;

        // Timing parity (§6.4) is approximate: both paths move the root into a fresh buffer
        // and destroy the old one, and both replace the Block copy and destroy the old one;
        // the distress path additionally drops the fresh buffers, which costs microseconds
        // against the hundreds of milliseconds of Argon2id that dominate every open.
        // On distress the real key material is destroyed: the root is replaced by fresh
        // random bytes (so a later `open` on this Session does the same Argon2id work and
        // fails with `NoSlot`, exactly as after a decoy — review finding A-2), the label,
        // relays, Shares and the receiving seed are cleared (review findings C-2/A-3: the
        // seed re-derives the root from a Block that is still on the relay). The Block is
        // public ciphertext and stays so that the follow-on behaviour is identical.
        let mut fresh = self.lock(&[0u8; 32])?;
        if let Some(mut old) = self.root.take() {
            if !distress {
                fresh.set(old.as_slice());
            } else {
                let rnd: [u8; 32] = {
                    use crate::rng::RandomSource;
                    OsRng.array().map_err(SessionError::Format)?
                };
                fresh.set(&rnd);
            }
            old.clear();
        }
        let block_copy = self.block.take().map(|b| Zeroizing::new(b.to_vec()));
        self.root = Some(fresh);
        self.block = block_copy;
        self.clear_shares();
        if distress {
            self.label = None;
            self.key_relays.clear();
            if let Some(mut seed) = self.seed.take() {
                seed.clear();
            }
        }

        let info = OpenInfo {
            ptype: opened.ptype,
            len: opened.data.len(),
            distress,
        };
        let text = self.lock(&opened.data)?;
        opened.data.zeroize();
        if let Some((mut old, _, _)) = self.plaintext.replace((text, opened.ptype, distress)) {
            old.clear();
        }
        self.state = State::Opened;
        Ok(info)
    }

    /// The opened note, for the View screen (read-only; lives in locked memory).
    pub fn plaintext(&self) -> Option<&[u8]> {
        self.plaintext.as_ref().map(|(b, _, _)| b.as_slice())
    }

    /// Destroy every secret and end the Session.
    pub fn close(&mut self) {
        if let Some(mut r) = self.root.take() {
            r.clear();
        }
        if let Some(mut sd) = self.seed.take() {
            sd.clear();
        }
        self.recipient = None;
        self.kem_sealed = false;
        if let Some((mut n, _)) = self.note.take() {
            n.clear();
        }
        if let Some(mut p) = self.note_passphrase.take() {
            p.clear();
        }
        for mut p in self.pending.drain(..) {
            p.text.clear();
            p.passphrase.clear();
        }
        self.clear_shares();
        if let Some((mut p, _, _)) = self.plaintext.take() {
            p.clear();
        }
        self.block = None;
        self.label = None;
        self.key_relays.clear();
        self.key_class = None;
        // Circle client-authorisation keys held in the configuration are secrets too; drop them
        // with everything else rather than leaving them until the Session is dropped (C-15).
        for r in self.cfg.relays.iter_mut() {
            r.auth_key = None;
        }
        self.state = State::Closed;
        scrub_stack();
    }

    /// User-triggered destruction (the panic action): identical to `close()`.
    pub fn distress(&mut self) {
        self.close();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}
