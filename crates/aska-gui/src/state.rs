//! Application state shared by the screens. The `Session` — the only owner of secrets — lives
//! here while a flow is on screen and is *moved* to a worker thread for the slow steps
//! (`Option::take`), then moved back. Everything else is presentation state or the settings
//! of §5.6, which live for this run of the application only (or in the encrypted profile the
//! user opened) — never in a plain file.

use aska_core::cover::{CoverLevel, CoverScheduler};
use aska_core::doctor::{Check, Finding, Severity};
use aska_core::drop::{Connector, Relay, Secret32, TorConnector};
use aska_core::session::{Session, SessionConfig};
use aska_core::tor::TorConfig;
use std::cell::RefCell;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

/// Which Tor the client talks to (Client Design §2.4; D-16 for the Tor Browser option).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorSource {
    System,
    TorBrowser,
}

impl TorSource {
    pub fn socks(self) -> SocketAddr {
        match self {
            TorSource::System => aska_core::platform::default_socks(),
            TorSource::TorBrowser => "127.0.0.1:9150".parse().expect("static"),
        }
    }
}

/// The footer's one-line Tor status, derived from the doctor findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorState {
    Checking,
    Ok,
    NoCircuit,
    Blocked,
    Down,
}

/// What the user knows about the profile they opened (never the file's contents).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileInfo {
    pub name: String,
    pub relays: usize,
    pub circle_key: bool,
    /// Receiving seeds the profile holds (RM-09); only their count is shown.
    pub seeds: usize,
}

pub struct App {
    pub tor_source: TorSource,
    pub findings: Vec<Finding>,
    pub tor_state: TorState,
    /// The user accepted the memory-lock warning for this session.
    pub accept_unlocked: bool,
    /// Relays typed on the Send/Receive/Settings screens or loaded from a profile.
    pub relays: Vec<Relay>,
    /// The live Session, when a flow is on screen. Network work runs as a `PostJob` /
    /// `FetchJob` on a worker while the Session stays here, so `close_session()`, distress
    /// and the idle watchdog remain available during a post or fetch (review finding C-1);
    /// only the short open step (Argon2id) borrows the Session on the worker.
    pub session: Option<Session>,
    /// Cancel token of the job in flight, if any: cancelled by `close_session()`/`shutdown()`.
    pub inflight: Option<aska_core::cancel::CancelToken>,
    /// Idle watchdog (§2.3, C-05).
    pub idle_timeout: Duration,
    /// Note auto-close on the View screen (§5.5, C-05).
    pub view_timeout: Duration,
    /// Cover traffic (§6.5, D-10) and its running scheduler.
    pub cover_level: CoverLevel,
    cover: Option<CoverScheduler>,
    /// The encrypted profile opened this run, if any (§5.6).
    pub profile: Option<ProfileInfo>,
    /// Where that profile lives, so the Receiving key screen can rewrite it in place when a
    /// seed is stored or removed (RM-09). Set together with `profile`.
    pub profile_path: Option<PathBuf>,
    /// The receiving seeds of the open profile, for this run (RM-09): the Receive screen
    /// offers them instead of the 24 words. Each is zeroised when dropped.
    pub profile_seeds: Vec<Secret32>,
    /// A network operation failed the way a blocked network fails (D-16) and nothing has
    /// succeeded since. Kept across doctor re-runs, which cannot see the condition without
    /// a control port; cleared by the next successful post or fetch or a change of Tor.
    blocked_observed: bool,
}

pub type Shared = Rc<RefCell<App>>;

impl App {
    pub fn new() -> Shared {
        Rc::new(RefCell::new(App {
            tor_source: TorSource::System,
            findings: Vec::new(),
            tor_state: TorState::Checking,
            accept_unlocked: false,
            relays: Vec::new(),
            session: None,
            inflight: None,
            idle_timeout: Duration::from_secs(300),
            view_timeout: Duration::from_secs(300),
            cover_level: CoverLevel::Modest,
            cover: None,
            profile: None,
            profile_path: None,
            profile_seeds: Vec::new(),
            blocked_observed: false,
        }))
    }

    /// A profile was created or opened: remember what it holds for this run.
    pub fn set_profile(&mut self, info: ProfileInfo, path: PathBuf, seeds: Vec<Secret32>) {
        self.profile = Some(ProfileInfo {
            seeds: seeds.len(),
            ..info
        });
        self.profile_path = Some(path);
        self.profile_seeds = seeds;
    }

    /// The open profile's seeds changed on disk (stored or removed): keep the run in step.
    pub fn set_profile_seeds(&mut self, seeds: Vec<Secret32>) {
        if let Some(p) = self.profile.as_mut() {
            p.seeds = seeds.len();
        }
        self.profile_seeds = seeds;
    }

    /// Forget the open profile: its name, path and seeds (the seeds are zeroised).
    pub fn forget_profile(&mut self) {
        self.profile = None;
        self.profile_path = None;
        self.profile_seeds.clear();
    }

    /// The stored seeds by the twelve-character check of the Receiving Key each yields (no
    /// relay hints: the check depends on the public key alone), in profile order.
    pub fn profile_seed_checks(&self) -> Vec<String> {
        self.profile_seeds
            .iter()
            .map(|s| aska_core::xwing::receiving_key_from_seed(s, &[], None, None).check())
            .collect()
    }

    pub fn tor_config(&self) -> TorConfig {
        TorConfig {
            socks: self.tor_source.socks(),
            ..TorConfig::default()
        }
    }

    pub fn connector(&self) -> Arc<dyn Connector> {
        Arc::new(TorConnector {
            cfg: self.tor_config(),
        })
    }

    pub fn session_config(&self, ttl_hours: u16, class: Option<u8>) -> SessionConfig {
        SessionConfig {
            tor: self.tor_config(),
            relays: self.relays.clone(),
            idle_timeout: self.idle_timeout,
            accept_unlocked_memory: self.accept_unlocked,
            size_class: class.and_then(aska_core::consts::SizeClass::from_u8),
            ttl_hours,
            ..SessionConfig::default()
        }
    }

    /// Network operations are refused while a Refuse-level finding stands (Table 4).
    pub fn network_refused(&self) -> bool {
        aska_core::doctor::refuses(&self.findings)
    }

    /// Derive the footer state from findings.
    pub fn apply_findings(&mut self, mut findings: Vec<Finding>) {
        // A doctor run without a control port cannot see a blocked network; keep what the
        // last failed operation told us until something succeeds (D-16).
        if self.blocked_observed && !findings.iter().any(|f| f.check == Check::TorNetwork) {
            findings.push(aska_core::doctor::blocked_network_finding());
        }
        self.tor_state = if findings
            .iter()
            .any(|f| f.check == Check::Tor && f.severity == Severity::Refuse)
        {
            TorState::Down
        } else if findings.iter().any(|f| f.check == Check::TorNetwork) {
            TorState::Blocked
        } else if findings
            .iter()
            .any(|f| f.check == Check::Tor && f.severity == Severity::Warn)
        {
            TorState::NoCircuit
        } else {
            TorState::Ok
        };
        self.findings = findings;
        self.restart_cover();
    }

    /// Drop a finding the user acknowledged (memory lock → also accept unlocked memory).
    pub fn acknowledge(&mut self, check: Check) {
        if check == Check::MemoryLock {
            self.accept_unlocked = true;
        }
        self.findings.retain(|f| f.check != check);
    }

    /// A post or fetch failed with the signature of a blocked network: raise the D-16 finding
    /// (an amber Home banner with the platform's direction) until something succeeds.
    pub fn note_blocked_network(&mut self) {
        self.blocked_observed = true;
        let mut f = self.findings.clone();
        f.retain(|x| x.check != Check::TorNetwork);
        self.apply_findings(f);
    }

    /// A post or fetch succeeded: the network is not blocking Tor (any more).
    pub fn note_network_ok(&mut self) {
        if !self.blocked_observed && !self.findings.iter().any(|f| f.check == Check::TorNetwork) {
            return;
        }
        self.blocked_observed = false;
        let mut f = self.findings.clone();
        f.retain(|x| x.check != Check::TorNetwork);
        self.apply_findings(f);
    }

    /// The user chose another Tor: what was observed through the old one no longer holds.
    pub fn set_tor_source(&mut self, source: TorSource) {
        if self.tor_source != source {
            self.tor_source = source;
            self.blocked_observed = false;
        }
    }

    /// Remember the relays for this run and keep the cover scheduler in step with them.
    pub fn set_relays(&mut self, relays: Vec<Relay>) {
        if self.relays != relays {
            self.relays = relays;
            self.restart_cover();
        }
    }

    pub fn set_cover_level(&mut self, level: CoverLevel) {
        if self.cover_level != level {
            self.cover_level = level;
            self.restart_cover();
        }
    }

    /// (Re)start cover traffic for the current relays, level and Tor; off while Tor is
    /// refused (decoys through a dead proxy would only be noise in the local log).
    pub fn restart_cover(&mut self) {
        if let Some(mut c) = self.cover.take() {
            c.stop();
        }
        if self.network_refused() || self.relays.is_empty() {
            return;
        }
        self.cover = CoverScheduler::start(self.connector(), self.relays.clone(), self.cover_level);
    }

    pub fn cover_running(&self) -> bool {
        self.cover.is_some()
    }

    /// Close and drop any live Session (idle expiry, Done, distress).
    pub fn close_session(&mut self) {
        if let Some(c) = self.inflight.take() {
            c.cancel();
        }
        if let Some(mut s) = self.session.take() {
            s.close();
        }
    }

    /// Everything that must stop when the window closes.
    pub fn shutdown(&mut self) {
        self.close_session();
        if let Some(mut c) = self.cover.take() {
            c.stop();
        }
    }
}
