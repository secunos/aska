//! Tor transport (Client Design §2.4): SOCKS5 with hostname addressing and per-request
//! circuit isolation, `.onion`-only destinations, loopback-only proxy, and the control-port
//! command that installs a circle client-authorisation key for the current Tor session.
//!
//! Networking is synchronous (`std::net`) so that no secret is ever captured by a future.
//! Every connection is registered with a `CancelToken`, so a front end can abort a request
//! that is stuck in a rendezvous.

use crate::cancel::{CancelToken, RegisteredStream};
use crate::encodings::onion_address_to_pubkey;
use crate::error::Error;
use crate::rng::{OsRng, RandomSource};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;
use zeroize::Zeroizing;

/// How the Tor proxy is reached.
#[derive(Clone, PartialEq, Eq)]
pub struct TorConfig {
    /// SOCKS5 port; MUST be a loopback address (127.0.0.0/8 or ::1).
    pub socks: SocketAddr,
    /// Control port, only needed for client-authorised relays (TLV 0x06). Loopback only.
    pub control: Option<SocketAddr>,
    /// How to authenticate to the control port.
    pub control_auth: ControlAuth,
    /// Connect + rendezvous timeout per request.
    pub connect_timeout: Duration,
    /// Read/write timeout on the established stream.
    pub io_timeout: Duration,
    /// Wall-clock bound for one whole request (connect + handshake + transfer), so a slow
    /// or dripping relay cannot hold a request open indefinitely. Default 10 minutes, which
    /// covers a full class-3 listing over a slow circuit.
    pub request_deadline: Duration,
}

impl std::fmt::Debug for TorConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TorConfig(socks={}, control={:?}, auth={}, connect={:?}, io={:?}, deadline={:?})",
            self.socks,
            self.control,
            match self.control_auth {
                ControlAuth::None => "none",
                ControlAuth::CookieFile(_) => "cookie",
                ControlAuth::Password(_) => "password(<redacted>)",
            },
            self.connect_timeout,
            self.io_timeout,
            self.request_deadline
        )
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum ControlAuth {
    /// No authentication configured on the control port.
    None,
    /// `CookieAuthentication 1`; the cookie file (default `/run/tor/control.authcookie`).
    CookieFile(std::path::PathBuf),
    /// `HashedControlPassword`; the clear-text password (zeroised on drop).
    Password(Zeroizing<String>),
}

impl std::fmt::Debug for ControlAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlAuth::None => f.write_str("None"),
            ControlAuth::CookieFile(p) => write!(f, "CookieFile({})", p.display()),
            ControlAuth::Password(_) => f.write_str("Password(<redacted>)"),
        }
    }
}

impl Default for TorConfig {
    fn default() -> Self {
        TorConfig {
            socks: crate::platform::default_socks(),
            control: None,
            control_auth: ControlAuth::CookieFile("/run/tor/control.authcookie".into()),
            // Tor itself gives up on an onion rendezvous after ~120 s; match it so that the
            // user sees Tor's verdict rather than ours.
            connect_timeout: Duration::from_secs(120),
            io_timeout: Duration::from_secs(60),
            request_deadline: Duration::from_secs(600),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TorError {
    #[error("proxy address is not loopback: {0}")]
    ProxyNotLoopback(SocketAddr),
    #[error("destination is not a valid .onion address")]
    NotOnion,
    #[error("Tor is not reachable at {0}: {1}")]
    Unreachable(SocketAddr, std::io::Error),
    #[error("SOCKS5 handshake failed")]
    Handshake,
    #[error("SOCKS5 connect refused (reply {0:#04x})")]
    ConnectRefused(u8),
    #[error("control port: {0}")]
    Control(String),
    #[error("cancelled")]
    Cancelled,
    #[error("timed out: {0}")]
    Timeout(&'static str),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("randomness unavailable")]
    Rng,
}

impl From<Error> for TorError {
    fn from(_: Error) -> Self {
        TorError::Rng
    }
}

/// The proxy must be on this machine (RLY-01) — or, on a Whonix Workstation only, the fixed
/// address of its Tor gateway qube, which is the platform's "local Tor" (Client Design §8.2).
fn require_loopback(a: SocketAddr) -> Result<(), TorError> {
    if a.ip().is_loopback()
        || (crate::platform::is_whonix()
            && a.ip() == std::net::IpAddr::from(crate::platform::WHONIX_GATEWAY))
    {
        Ok(())
    } else {
        Err(TorError::ProxyNotLoopback(a))
    }
}

/// Validate and normalise an onion address: lowercase host with the `.onion` suffix.
pub fn normalise_onion(addr: &str) -> Result<String, TorError> {
    let host = addr.trim().trim_end_matches('/').to_lowercase();
    onion_address_to_pubkey(&host).map_err(|_| TorError::NotOnion)?;
    Ok(host)
}

/// Random SOCKS5 username/password: Tor maps distinct credentials to distinct circuits
/// (`IsolateSOCKSAuth`, on by default), which is the per-request isolation of §2.4.
fn isolation_credentials() -> Result<(String, String), TorError> {
    let r: [u8; 16] = OsRng.array()?;
    Ok((
        data_encoding::HEXLOWER.encode(&r[..8]),
        data_encoding::HEXLOWER.encode(&r[8..]),
    ))
}

/// Open a fresh, isolated circuit to `onion:port` through the SOCKS5 proxy. The returned
/// stream is registered with `cancel` (so `cancel.cancel()` aborts it), unregisters itself on
/// drop, and enforces `cfg.request_deadline` for the whole request.
pub fn connect_onion(
    cfg: &TorConfig,
    onion: &str,
    port: u16,
    cancel: &CancelToken,
) -> Result<RegisteredStream, TorError> {
    require_loopback(cfg.socks)?;
    let host = normalise_onion(onion)?;
    if cancel.is_cancelled() {
        return Err(TorError::Cancelled);
    }
    let raw = TcpStream::connect_timeout(&cfg.socks, Duration::from_secs(5))
        .map_err(|e| TorError::Unreachable(cfg.socks, e))?;
    raw.set_nodelay(true)?;
    // During the handshake each read may take up to the rendezvous time.
    let mut s = RegisteredStream::new(raw, cancel, cfg.connect_timeout, cfg.request_deadline);

    let timed = |e: std::io::Error, phase: &'static str| -> TorError {
        match e.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                TorError::Timeout(phase)
            }
            _ => TorError::Io(e),
        }
    };

    // Method negotiation: offer username/password only (RFC 1929) to force isolation.
    s.write_all(&[0x05, 0x01, 0x02])?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r)
        .map_err(|e| timed(e, "Tor's SOCKS port did not answer"))?;
    if r != [0x05, 0x02] {
        return Err(TorError::Handshake);
    }
    let (user, pass) = isolation_credentials()?;
    let mut auth = vec![0x01, user.len() as u8];
    auth.extend_from_slice(user.as_bytes());
    auth.push(pass.len() as u8);
    auth.extend_from_slice(pass.as_bytes());
    s.write_all(&auth)?;
    s.read_exact(&mut r)
        .map_err(|e| timed(e, "Tor's SOCKS port did not answer"))?;
    if r[1] != 0x00 {
        return Err(TorError::Handshake);
    }

    // CONNECT with domain-name addressing (ATYP 3): Tor resolves the onion itself.
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req)?;
    let mut rep = [0u8; 4];
    s.read_exact(&mut rep).map_err(|e| {
        timed(
            e,
            "Tor could not reach the relay in time (rendezvous); try again on a fresh circuit",
        )
    })?;
    if rep[1] != 0x00 {
        return Err(if cancel.is_cancelled() {
            TorError::Cancelled
        } else {
            TorError::ConnectRefused(rep[1])
        });
    }
    let skip = match rep[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut n = [0u8; 1];
            s.read_exact(&mut n)?;
            n[0] as usize + 2
        }
        _ => return Err(TorError::Handshake),
    };
    let mut bnd = vec![0u8; skip];
    s.read_exact(&mut bnd)?;
    s.set_io_timeout(cfg.io_timeout);
    Ok(s)
}

/// Doctor probe: the proxy is loopback and answers a SOCKS5 method negotiation.
pub fn check_socks(cfg: &TorConfig) -> Result<(), TorError> {
    require_loopback(cfg.socks)?;
    let mut s = TcpStream::connect_timeout(&cfg.socks, Duration::from_secs(5))
        .map_err(|e| TorError::Unreachable(cfg.socks, e))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(&[0x05, 0x01, 0x02])?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r)?;
    if r == [0x05, 0x02] {
        Ok(())
    } else {
        Err(TorError::Handshake)
    }
}

// ---- control port ----

/// Longest control-port reply line we accept, and the most lines in one reply.
const MAX_CONTROL_LINE: usize = 4096;
const MAX_CONTROL_LINES: usize = 1024;

struct Control {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}

/// Quote a string for the control protocol (`\` and `"` escaped, in that order).
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\r' | '\n' => {}
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

impl Control {
    fn open(cfg: &TorConfig) -> Result<Self, TorError> {
        let addr = cfg
            .control
            .ok_or_else(|| TorError::Control("no control port configured".into()))?;
        require_loopback(addr)?;
        let s = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
            .map_err(|e| TorError::Unreachable(addr, e))?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        s.set_write_timeout(Some(Duration::from_secs(10)))?;
        let writer = s.try_clone()?;
        let mut c = Control {
            reader: BufReader::new(s),
            writer,
        };
        let line: Zeroizing<String> = Zeroizing::new(match &cfg.control_auth {
            ControlAuth::None => "AUTHENTICATE\r\n".to_string(),
            ControlAuth::CookieFile(p) => {
                let cookie = Zeroizing::new(std::fs::read(p).map_err(|e| {
                    TorError::Control(format!("cannot read cookie {}: {e}", p.display()))
                })?);
                format!(
                    "AUTHENTICATE {}\r\n",
                    data_encoding::HEXUPPER.encode(&cookie)
                )
            }
            ControlAuth::Password(pw) => format!("AUTHENTICATE {}\r\n", quote(pw)),
        });
        c.command(&line)?;
        Ok(c)
    }

    /// Send one command and read the whole reply (mid lines `xyz-`, data blocks `xyz+` up to
    /// a lone `.`, final line `xyz `). Success is any 2xx final code; anything else is an error
    /// carrying the final line.
    fn command(&mut self, line: &str) -> Result<Vec<String>, TorError> {
        self.writer.write_all(line.as_bytes())?;
        self.writer.flush()?;
        let mut lines = Vec::new();
        let mut in_data = false;
        loop {
            let mut raw = Vec::new();
            let n = self
                .reader
                .by_ref()
                .take(MAX_CONTROL_LINE as u64 + 1)
                .read_until(b'\n', &mut raw)?;
            if n == 0 {
                return Err(TorError::Control("connection closed".into()));
            }
            if raw.len() > MAX_CONTROL_LINE || lines.len() >= MAX_CONTROL_LINES {
                return Err(TorError::Control("reply too long".into()));
            }
            while matches!(raw.last(), Some(b'\r') | Some(b'\n')) {
                raw.pop();
            }
            if in_data {
                if raw == b"." {
                    in_data = false;
                }
                continue;
            }
            if raw.len() < 4 || !raw[..3].iter().all(u8::is_ascii_digit) {
                return Err(TorError::Control("malformed reply".into()));
            }
            let text = String::from_utf8_lossy(&raw).into_owned();
            match raw[3] {
                b'-' => lines.push(text),
                b'+' => {
                    lines.push(text);
                    in_data = true;
                }
                b' ' => {
                    let ok = raw[0] == b'2';
                    lines.push(text.clone());
                    return if ok {
                        Ok(lines)
                    } else {
                        Err(TorError::Control(text))
                    };
                }
                _ => return Err(TorError::Control("malformed reply".into())),
            }
        }
    }
}

/// Install a circle client-authorisation key for `onion` in the running Tor, for this Tor
/// session only (no `Permanent` flag, no `ClientName`; §2.4). Refused on Tails (C-03).
/// A key that was already installed is replaced (Tor answers `251`), which counts as success.
pub fn client_auth_add(
    cfg: &TorConfig,
    onion: &str,
    x25519_private: &[u8; 32],
) -> Result<(), TorError> {
    if crate::platform::control_port_filtered() {
        return Err(TorError::Control(
            "client-authorised relays are not supported on Tails or Whonix in v1 (C-03: the \
             control port is filtered there)"
                .into(),
        ));
    }
    let host = normalise_onion(onion)?;
    let bare = host.trim_end_matches(".onion");
    let key = Zeroizing::new(data_encoding::BASE64.encode(x25519_private));
    let mut c = Control::open(cfg)?;
    let cmd = Zeroizing::new(format!("ONION_CLIENT_AUTH_ADD {bare} x25519:{}\r\n", *key));
    c.command(&cmd)?;
    let _ = c.command("QUIT\r\n");
    Ok(())
}

/// The configuration with a control port filled in when none was given and the system Tor's
/// conventional one is usable from here: `127.0.0.1:9051` with the cookie at
/// `/run/tor/control.authcookie` **readable by this user** (Debian: member of `debian-tor`;
/// a torrc with `ControlPort 9051` and `CookieAuthentication 1`). Nothing is written and no
/// connection is made here — only a readable cookie file enables the later query. Skipped
/// where the control port is filtered (Tails, Whonix) and for a non-default SOCKS proxy such
/// as Tor Browser's (its control port and cookie live elsewhere).
pub fn with_discovered_control(cfg: &TorConfig) -> TorConfig {
    if cfg.control.is_some() || crate::platform::control_port_filtered() {
        return cfg.clone();
    }
    if cfg.socks != crate::platform::default_socks() {
        return cfg.clone();
    }
    let cookie = std::path::Path::new("/run/tor/control.authcookie");
    let readable = std::fs::File::open(cookie).is_ok();
    if !readable {
        return cfg.clone();
    }
    TorConfig {
        control: Some(SocketAddr::from(([127, 0, 0, 1], 9051))),
        control_auth: ControlAuth::CookieFile(cookie.to_path_buf()),
        ..cfg.clone()
    }
}

/// `GETINFO status/circuit-established` → true when Tor has built a circuit (doctor).
pub fn circuit_established(cfg: &TorConfig) -> Result<bool, TorError> {
    let mut c = Control::open(cfg)?;
    let lines = c.command("GETINFO status/circuit-established\r\n")?;
    let _ = c.command("QUIT\r\n");
    Ok(lines
        .iter()
        .any(|l| l.contains("status/circuit-established=1")))
}

/// Tor's bootstrap progress, 0–100, from `GETINFO status/bootstrap-phase` (D-16, option A).
/// `Ok(None)` when Tor answered but the line had no `PROGRESS=` (an old or unusual Tor).
/// A Tor that runs but stays below 100 for long is the signature of a network that blocks
/// it: the SOCKS port answers, every circuit attempt fails.
pub fn bootstrap_progress(cfg: &TorConfig) -> Result<Option<u8>, TorError> {
    let mut c = Control::open(cfg)?;
    let lines = c.command("GETINFO status/bootstrap-phase\r\n")?;
    let _ = c.command("QUIT\r\n");
    Ok(parse_bootstrap_progress(&lines))
}

/// `250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"` → 100.
pub fn parse_bootstrap_progress(lines: &[String]) -> Option<u8> {
    lines.iter().find_map(|l| {
        let i = l.find("PROGRESS=")?;
        let rest = &l[i + "PROGRESS=".len()..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse::<u8>().ok().map(|p| p.min(100))
    })
}

/// True if this failure is the kind a network that blocks Tor produces: the local Tor was
/// reached, but nothing beyond it answered (rendezvous timeout, SOCKS "unreachable" /
/// "general failure" replies). A refused loopback connection or a bad address is not.
pub fn looks_like_blocked_network(e: &TorError) -> bool {
    matches!(
        e,
        TorError::Timeout(_) | TorError::ConnectRefused(0x01) | TorError::ConnectRefused(0x04)
    )
}

/// What to do when the local network blocks Tor (D-16, option A: detect and direct). Aska
/// never configures Tor itself — it uses the system Tor and writes nothing — so the advice
/// names the platform's own connection tool, which knows how to connect through a bridge.
pub fn blocked_network_guidance() -> &'static str {
    if crate::platform::is_tails() {
        "If this network blocks Tor: open Tails' Tor Connection assistant, choose to connect \
         with a bridge, and try again once it reports connected."
    } else if crate::platform::is_whonix() {
        "If this network blocks Tor: run the Anon Connection Wizard in sys-whonix and choose \
         a bridge, then try again."
    } else {
        "If this network blocks Tor: connect Tor Browser through a bridge (its Settings → \
         Connection), keep it open, and let Aska use Tor Browser's Tor."
    }
}

/// The command-line form of the last step of [`blocked_network_guidance`]: how the CLI
/// selects Tor Browser's Tor. Empty on Tails and Whonix, where the platform tool is the
/// whole answer. The graphical client offers a button instead.
pub fn blocked_network_cli_hint() -> &'static str {
    if crate::platform::is_tails() || crate::platform::is_whonix() {
        ""
    } else {
        " (run aska with --tor-browser)"
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn discovered_control_never_overrides_or_leaves_loopback() {
        let explicit = super::TorConfig {
            control: Some("127.0.0.1:9999".parse().unwrap()),
            ..super::TorConfig::default()
        };
        assert_eq!(super::with_discovered_control(&explicit), explicit);
        let tb = super::TorConfig {
            socks: "127.0.0.1:9150".parse().unwrap(),
            ..super::TorConfig::default()
        };
        // A non-default SOCKS (Tor Browser) never gets the system Tor's control port.
        assert_eq!(super::with_discovered_control(&tb).control, None);
        let d = super::with_discovered_control(&super::TorConfig::default());
        if let Some(c) = d.control {
            assert!(c.ip().is_loopback());
            assert!(std::fs::File::open("/run/tor/control.authcookie").is_ok());
        }
    }

    use super::*;

    #[test]
    fn bootstrap_progress_parsing_and_block_signature() {
        let done = vec![
            "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\""
                .to_string(),
            "250 OK".to_string(),
        ];
        assert_eq!(parse_bootstrap_progress(&done), Some(100));
        let stuck = vec![
            "250-status/bootstrap-phase=WARN BOOTSTRAP PROGRESS=5 TAG=conn SUMMARY=\"Connecting to a relay\" WARNING=\"Connection refused\" REASON=CONNECTREFUSED COUNT=30 RECOMMENDATION=warn"
                .to_string(),
        ];
        assert_eq!(parse_bootstrap_progress(&stuck), Some(5));
        assert_eq!(parse_bootstrap_progress(&["250 OK".to_string()]), None);
        assert_eq!(
            parse_bootstrap_progress(&["PROGRESS=250".to_string()]),
            Some(100),
            "clamped"
        );
        assert!(looks_like_blocked_network(&TorError::Timeout("rendezvous")));
        assert!(looks_like_blocked_network(&TorError::ConnectRefused(0x04)));
        assert!(!looks_like_blocked_network(&TorError::NotOnion));
        assert!(!looks_like_blocked_network(&TorError::Handshake));
        assert!(blocked_network_guidance().contains("bridge"));
    }

    #[test]
    fn onion_validation() {
        assert!(
            normalise_onion("2GZYXA5IHM7NSGGFXNU52RCK2VV4RVMDLKIU3ZZUI5DU4XYCLEN53WID.onion/")
                .is_ok()
        );
        assert!(matches!(
            normalise_onion("example.com"),
            Err(TorError::NotOnion)
        ));
        assert!(matches!(
            normalise_onion("notreallyanonion.onion"),
            Err(TorError::NotOnion)
        ));
    }

    #[test]
    fn proxy_must_be_loopback() {
        let cfg = TorConfig {
            socks: "10.0.0.1:9050".parse().unwrap(),
            ..TorConfig::default()
        };
        assert!(matches!(
            check_socks(&cfg),
            Err(TorError::ProxyNotLoopback(_))
        ));
        assert!(matches!(
            connect_onion(
                &cfg,
                "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion",
                4567,
                &CancelToken::new()
            ),
            Err(TorError::ProxyNotLoopback(_))
        ));
    }

    #[test]
    fn credentials_differ_per_request() {
        let a = isolation_credentials().unwrap();
        let b = isolation_credentials().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.0.len(), 16);
    }

    #[test]
    fn quoting_and_redaction() {
        assert_eq!(quote(r#"a"b\c"#), r#""a\"b\\c""#);
        let cfg = TorConfig {
            control_auth: ControlAuth::Password(Zeroizing::new("hunter2".into())),
            ..TorConfig::default()
        };
        let d = format!("{cfg:?}");
        assert!(!d.contains("hunter2"));
        assert!(d.contains("redacted"));
    }

    /// A scripted control port exercising mid lines, a data block, 251 and a 5xx.
    #[test]
    fn control_parser() {
        use std::io::Write as _;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = [0u8; 256];
            let _ = std::io::Read::read(&mut s, &mut buf); // AUTHENTICATE
            s.write_all(b"250 OK\r\n").unwrap();
            let _ = std::io::Read::read(&mut s, &mut buf); // ONION_CLIENT_AUTH_ADD
            s.write_all(b"251 Client for onion existed and replaced\r\n")
                .unwrap();
            let _ = std::io::Read::read(&mut s, &mut buf); // GETINFO
            s.write_all(b"250+config-text=\r\nfoo bar\r\n.\r\n250-status/circuit-established=1\r\n250 OK\r\n")
                .unwrap();
            let _ = std::io::Read::read(&mut s, &mut buf);
            s.write_all(b"552 Unrecognized key\r\n").unwrap();
            let _ = std::io::Read::read(&mut s, &mut buf);
        });
        let cfg = TorConfig {
            control: Some(addr),
            control_auth: ControlAuth::None,
            ..TorConfig::default()
        };
        let mut c = Control::open(&cfg).unwrap();
        assert!(c.command("ONION_CLIENT_AUTH_ADD x y\r\n").is_ok());
        let lines = c.command("GETINFO x\r\n").unwrap();
        assert!(lines
            .iter()
            .any(|l| l.contains("status/circuit-established=1")));
        assert!(matches!(
            c.command("GETINFO bogus\r\n"),
            Err(TorError::Control(m)) if m.starts_with("552")
        ));
    }
}
