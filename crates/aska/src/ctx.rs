//! Shared command context: Tor configuration, relays (from `--relay` and the encrypted
//! profile), the doctor gate every command passes through, and the hand-over display helpers.

use crate::files;
use crate::term::{self, Input};
use aska_core::doctor::{self, Check, DoctorConfig, Severity};
use aska_core::drop::Relay;
use aska_core::profile::open_profile;
use aska_core::qr;
use aska_core::session::{Session, SessionConfig};
use aska_core::tor::{ControlAuth, TorConfig};
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

/// Exit codes (Client Design §4 plus two the design leaves to the implementation).
pub mod exit {
    pub const OK: i32 = 0;
    /// Usage error, I/O error, or a state the design does not cover.
    pub const ERROR: i32 = 1;
    /// Success after the user (or `--yes`) acknowledged doctor warnings.
    pub const WARNED: i32 = 2;
    /// The user declined to continue.
    pub const USER_REFUSED: i32 = 3;
    /// Every relay unreachable or full.
    pub const RELAY: i32 = 4;
    /// Nothing found / nothing opened.
    pub const NOTHING: i32 = 5;
    /// The doctor refused: not through Tor, or a relay that is not a `.onion`.
    pub const DOCTOR_REFUSED: i32 = 6;
    /// Standard output was closed before the command finished (`aska verify | head -1`): stop
    /// quietly with the status a shell reports for a command ended by SIGPIPE (128 + 13).
    pub const PIPE: i32 = 141;
}

/// A command's failure, carrying the exit code and a line for stderr.
pub struct Fail(pub i32, pub String);

impl Fail {
    pub fn new(code: i32, msg: impl Into<String>) -> Self {
        Fail(code, msg.into())
    }
}

impl From<io::Error> for Fail {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::BrokenPipe {
            return Fail(exit::PIPE, String::new());
        }
        Fail(exit::ERROR, e.to_string())
    }
}

impl From<aska_core::session::SessionError> for Fail {
    fn from(e: aska_core::session::SessionError) -> Self {
        use aska_core::session::SessionError as E;
        let code = match e {
            E::NoRelayAnswered(_) | E::Drop(_) | E::NoRelays => exit::RELAY,
            E::NoSlot => exit::NOTHING,
            E::Expired => exit::USER_REFUSED,
            _ => exit::ERROR,
        };
        Fail(code, e.to_string())
    }
}

impl From<aska_core::Error> for Fail {
    fn from(e: aska_core::Error) -> Self {
        Fail(exit::ERROR, e.to_string())
    }
}

pub type CmdResult = Result<(), Fail>;

#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum QrStyle {
    /// Half-block characters with forced dark-on-light colours (default on a terminal).
    Half,
    /// `##` per module; works on any terminal or console.
    Ascii,
    /// Text only.
    None,
}

pub struct Ctx {
    pub tor: TorConfig,
    pub relays: Vec<Relay>,
    pub yes: bool,
    pub accept_unlocked: bool,
    pub fast: bool,
    pub qr: QrStyle,
    pub idle: Duration,
    pub scan_cmd: String,
    pub input: Input,
    /// Set once doctor warnings were acknowledged; turns exit 0 into exit 2.
    pub warned: bool,
}

/// Options shared by every command (globals on the command line).
pub struct Globals {
    pub socks: Option<String>,
    pub control: Option<String>,
    pub control_cookie: Option<PathBuf>,
    pub control_password: bool,
    pub profile: Option<PathBuf>,
    pub relays: Vec<String>,
    pub yes: bool,
    pub accept_unlocked_memory: bool,
    pub fast: bool,
    pub qr: Option<QrStyle>,
    pub idle: u64,
    pub scan_cmd: String,
    pub stdin: bool,
    /// Use Tor Browser's Tor (SOCKS 127.0.0.1:9150) instead of the system Tor.
    pub tor_browser: bool,
}

fn parse_loopback(s: &str, what: &str) -> Result<SocketAddr, Fail> {
    let a: SocketAddr = s
        .parse()
        .map_err(|_| Fail::new(exit::ERROR, format!("{what}: not a host:port address: {s}")))?;
    // On a Whonix Workstation the platform's Tor is the gateway qube (Client Design §8.2).
    let whonix_gateway = aska_core::platform::is_whonix()
        && a.ip() == std::net::IpAddr::from(aska_core::platform::WHONIX_GATEWAY);
    if !a.ip().is_loopback() && !whonix_gateway {
        return Err(Fail::new(
            exit::DOCTOR_REFUSED,
            format!("{what} must be on the loopback interface (127.0.0.1 or ::1), got {a}"),
        ));
    }
    Ok(a)
}

impl Ctx {
    pub fn build(g: Globals) -> Result<Self, Fail> {
        let mut input = Input::open(g.stdin)?;
        input.set_idle(Duration::from_secs(g.idle.max(30)));
        // Input buffers follow the same memory-lock rule as the Session's secrets (C-10).
        input.set_require_lock(!g.accept_unlocked_memory);
        // Tor Browser's Tor is a fine system Tor for Aska — and the one a user who had to
        // connect through a bridge already has running (D-16, option A).
        let default_socks = aska_core::platform::default_socks().to_string();
        let socks_str = if g.tor_browser {
            "127.0.0.1:9150"
        } else {
            g.socks.as_deref().unwrap_or(&default_socks)
        };
        let socks = parse_loopback(socks_str, "--socks")?;
        let control = g
            .control
            .as_deref()
            .map(|c| parse_loopback(c, "--control"))
            .transpose()?;
        let control_auth = if let Some(p) = g.control_cookie {
            ControlAuth::CookieFile(p)
        } else if g.control_password {
            let pw = input
                .read_hidden("Tor control-port password: ")?
                .ok_or_else(|| Fail::new(exit::ERROR, "no control password given"))?;
            ControlAuth::Password(Zeroizing::new(pw.as_str().to_owned()))
        } else {
            ControlAuth::None
        };
        let tor = TorConfig {
            socks,
            control,
            control_auth,
            ..TorConfig::default()
        };

        let mut relays = Vec::new();
        if let Some(path) = &g.profile {
            let bytes = files::read_profile(path)
                .map_err(|e| Fail::new(exit::ERROR, format!("{}: {e}", path.display())))?;
            let pw = input
                .read_hidden(&format!("Passphrase for profile {}: ", path.display()))?
                .ok_or_else(|| Fail::new(exit::ERROR, "no profile passphrase given"))?;
            let p = open_profile(&bytes, &pw).map_err(|_| {
                Fail::new(
                    exit::ERROR,
                    "profile did not open (wrong passphrase, or not a profile)",
                )
            })?;
            relays.extend(p.relays());
        }
        for r in &g.relays {
            let relay = Relay::from_onion(r).map_err(|_| {
                Fail::new(
                    exit::DOCTOR_REFUSED,
                    format!("only .onion relays are allowed; not a valid v3 onion address: {r}"),
                )
            })?;
            if !relays.iter().any(|x| x.pubkey == relay.pubkey) {
                relays.push(relay);
            }
        }

        let qr = g.qr.unwrap_or(if term::stdout_is_tty() && !g.stdin {
            QrStyle::Half
        } else {
            QrStyle::None
        });
        Ok(Ctx {
            tor,
            relays,
            yes: g.yes,
            accept_unlocked: g.accept_unlocked_memory,
            fast: g.fast,
            qr,
            idle: Duration::from_secs(g.idle.max(30)),
            scan_cmd: g.scan_cmd,
            input,
            warned: false,
        })
    }

    /// Session configuration for this invocation.
    pub fn session_config(&self, ttl_hours: u16, class: Option<u8>) -> SessionConfig {
        SessionConfig {
            tor: self.tor.clone(),
            relays: self.relays.clone(),
            idle_timeout: self.idle,
            accept_unlocked_memory: self.accept_unlocked,
            request_delay_max: if self.fast {
                Duration::ZERO
            } else {
                Duration::from_secs(90)
            },
            size_class: class.and_then(aska_core::consts::SizeClass::from_u8),
            ttl_hours,
            ..SessionConfig::default()
        }
    }

    pub fn new_session(&self, ttl_hours: u16, class: Option<u8>) -> Result<Session, Fail> {
        Session::new(self.session_config(ttl_hours, class)).map_err(|e| match e {
            aska_core::session::SessionError::MemoryUnlocked => Fail::new(
                exit::USER_REFUSED,
                "cannot lock memory for secrets; re-run and accept the warning, or pass --accept-unlocked-memory",
            ),
            e => e.into(),
        })
    }

    /// The doctor gate (Client Design §4: every command prints the relevant warnings before
    /// acting). `network` = this command will talk to Tor: refusals then stop it. Warnings need
    /// acknowledgement — `--yes`, or a `y` at the prompt; acknowledging the memory-lock warning
    /// also accepts unlocked memory for this invocation.
    pub fn doctor_gate(&mut self, network: bool) -> CmdResult {
        let findings = doctor::run(&DoctorConfig {
            tor: self.tor.clone(),
            relay_addresses: self.relays.iter().map(|r| r.onion()).collect(),
            probe_tor: network,
        });
        let mut warns = 0;
        let mut memlock = false;
        for f in &findings {
            let tag = match f.severity {
                Severity::Refuse => "REFUSE",
                Severity::Warn => "WARN",
                Severity::Info => "INFO",
            };
            if f.severity == Severity::Warn {
                warns += 1;
            }
            if f.check == Check::MemoryLock {
                memlock = true;
            }
            note!("[{tag}] {}{}", f.message, cli_hint_for(f));
        }
        if network && doctor::refuses(&findings) {
            return Err(Fail::new(
                exit::DOCTOR_REFUSED,
                "refusing network operations until the findings above are fixed",
            ));
        }
        if warns > 0 {
            let ok = if self.yes {
                true
            } else if !self.input.is_interactive() {
                return Err(Fail::new(
                    exit::USER_REFUSED,
                    "doctor warnings need acknowledging: pass --yes in non-interactive mode",
                ));
            } else {
                let a = self.input.read_line("Continue anyway? [y/N] ")?;
                matches!(
                    a.as_deref().map(|s| s.trim()),
                    Some("y") | Some("Y") | Some("yes")
                )
            };
            if !ok {
                return Err(Fail::new(
                    exit::USER_REFUSED,
                    "stopped at the doctor warnings",
                ));
            }
            self.warned = true;
            if memlock {
                self.accept_unlocked = true;
                self.input.set_require_lock(false);
            }
        }
        Ok(())
    }

    /// Exit code for a successful command.
    pub fn success_code(&self) -> i32 {
        if self.warned {
            exit::WARNED
        } else {
            exit::OK
        }
    }

    /// Render hand-over text: optional QR, then the text itself.
    pub fn render_material(&self, text: &str) -> Result<Zeroizing<String>, Fail> {
        // Pre-sized for the QR (≤ 180 rows × ≤ 200 bytes) plus the text (review finding C-9).
        let mut out = Zeroizing::new(String::with_capacity(text.len() + 40 * 1024));
        match self.qr {
            QrStyle::None => {}
            style => {
                let m = qr::encode(text)?;
                let r = match style {
                    QrStyle::Half => qr::render_half_block(&m, true),
                    _ => qr::render_ascii(&m),
                };
                out.push_str(&r);
                out.push('\n');
            }
        }
        out.push_str(text);
        out.push('\n');
        Ok(out)
    }

    /// Run the camera helper and return the first line it prints (the decoded QR text).
    pub fn scan(&mut self) -> Result<Zeroizing<String>, Fail> {
        note!(
            "Starting the camera helper ({}) — show the QR code to the camera …",
            self.scan_cmd
        );
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(&self.scan_cmd)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .map_err(|e| Fail::new(exit::ERROR, format!("camera helper failed to start: {e}")))?;
        let mut text = Zeroizing::new(String::from_utf8_lossy(&out.stdout).into_owned());
        let first: Zeroizing<String> =
            Zeroizing::new(text.lines().next().unwrap_or("").trim().to_string());
        use zeroize::Zeroize;
        text.zeroize();
        if first.is_empty() {
            return Err(Fail::new(
                exit::ERROR,
                "the camera helper returned nothing (is zbar-tools installed? see --scan-cmd)",
            ));
        }
        Ok(first)
    }

    /// Read a line of key material or a `scan` request; `Ok(None)` on an empty line / EOF.
    pub fn read_material(&mut self, prompt: &str) -> Result<Option<term::SecretLine>, Fail> {
        let line = self.input.read_line(prompt)?;
        match line {
            None => Ok(None),
            Some(l) if l.trim().is_empty() => Ok(None),
            Some(l) if l.trim() == "scan" && self.input.is_interactive() => {
                Ok(Some(term::SecretLine::from_text(&self.scan()?)?))
            }
            Some(l) => Ok(Some(l)),
        }
    }

    /// Write text to a user-named file (never overwriting), e.g. `--out-keycard`.
    pub fn write_named(&self, path: &Path, text: &str) -> Result<(), Fail> {
        use std::io::Write;
        let mut f = files::create_new(path)?;
        f.write_all(text.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        Ok(())
    }
}

/// Does this Dead Drop error look like a network that blocks Tor (D-16)? The local Tor was
/// reached, nothing beyond it answered.
pub fn looks_blocked(e: &aska_core::drop::DropError) -> bool {
    use aska_core::drop::DropError as D;
    match e {
        // An I/O timeout on an *established* relay stream is a slow or stalling relay, not a
        // blocked network (review finding C-12); only Tor's own verdicts count.
        D::Timeout => false,
        D::Tor(t) => aska_core::tor::looks_like_blocked_network(t),
        _ => false,
    }
}

/// The CLI's own last step for the D-16 finding (the GUI shows a button instead).
pub fn cli_hint_for(f: &aska_core::doctor::Finding) -> &'static str {
    if f.check == Check::TorNetwork {
        aska_core::tor::blocked_network_cli_hint()
    } else {
        ""
    }
}

/// The D-16 guidance line, printed once when every network attempt failed that way.
pub fn print_blocked_hint() {
    note!(
        "Every attempt failed the way a blocked network fails (Tor answered, nothing beyond it did). {}{}",
        aska_core::tor::blocked_network_guidance(),
        aska_core::tor::blocked_network_cli_hint()
    );
}

/// `24h`, `48h`, `7d`, or plain hours; 1..=168.
pub fn parse_ttl(s: &str) -> Result<u16, String> {
    let t = s.trim().to_ascii_lowercase();
    let (num, mult) = if let Some(h) = t.strip_suffix('h') {
        (h, 1u32)
    } else if let Some(d) = t.strip_suffix('d') {
        (d, 24u32)
    } else {
        (t.as_str(), 1u32)
    };
    let n: u32 = num
        .parse()
        .map_err(|_| format!("bad TTL {s:?}: use 1h, 6h, 24h, 48h, 72h or 7d"))?;
    let hours = n * mult;
    // Only the TTLs the clients offer and the decoy traffic imitates (`cover::TTL_CHOICES_HOURS`):
    // any other value would single the note out from the cover traffic on the relay (CLI-06).
    if !aska_core::cover::TTL_CHOICES_HOURS.contains(&(hours.min(u32::from(u16::MAX)) as u16)) {
        return Err(format!(
            "bad TTL {s:?}: use 1h, 6h, 24h, 48h, 72h or 7d (other values would mark the note among the cover traffic)"
        ));
    }
    Ok(hours as u16)
}

/// `2of3`, `3of5`, `2/3`.
pub fn parse_shares(s: &str) -> Result<(u8, u8), String> {
    let t = s.trim().to_ascii_lowercase();
    let parts: Vec<&str> = if t.contains("of") {
        t.split("of").collect()
    } else {
        t.split('/').collect()
    };
    if parts.len() != 2 {
        return Err(format!("bad threshold {s:?}: use e.g. 2of3 or 3of5"));
    }
    let k: u8 = parts[0]
        .trim()
        .parse()
        .map_err(|_| format!("bad threshold {s:?}"))?;
    let n: u8 = parts[1]
        .trim()
        .parse()
        .map_err(|_| format!("bad threshold {s:?}"))?;
    if k < 2 || n < k || n > 16 {
        return Err(format!(
            "threshold must satisfy 2 ≤ k ≤ n ≤ 16, got {k} of {n}"
        ));
    }
    Ok((k, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_and_threshold_parsing() {
        assert_eq!(parse_ttl("24h").unwrap(), 24);
        assert_eq!(parse_ttl("7d").unwrap(), 168);
        assert_eq!(parse_ttl("6").unwrap(), 6);
        assert_eq!(parse_ttl("3d").unwrap(), 72);
        // Only the cover-traffic TTL set (CLI-06, 1.1): 36 h was accepted by 1.0.x.
        assert!(parse_ttl("36").is_err());
        assert!(parse_ttl("2h").is_err());
        assert!(parse_ttl("8d").is_err());
        assert!(parse_ttl("0h").is_err());
        assert!(parse_ttl("soon").is_err());
        assert_eq!(parse_shares("2of3").unwrap(), (2, 3));
        assert_eq!(parse_shares("3/5").unwrap(), (3, 5));
        assert!(parse_shares("1of3").is_err());
        assert!(parse_shares("4of3").is_err());
        assert!(parse_shares("2of3of4").is_err());
    }
}
