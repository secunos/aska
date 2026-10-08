//! Environment checks (Client Design §6.1, Table 4; CLI-09). Read-only probes that return
//! structured findings for the front ends to display. Only two findings refuse anything:
//! a Tor path that is not usable, and a relay address that is not a `.onion`.

use crate::platform;
use crate::secret::{LockState, LockedBuf};
use crate::tor::{self, TorConfig};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Check {
    Swap,
    MemoryLock,
    ScreenCapture,
    RemoteDesktop,
    Accessibility,
    Tor,
    /// Tor runs but cannot reach the Tor network — the signature of a blocking network (D-16).
    TorNetwork,
    RelayAddress,
    Fingerprint,
    CoreDumps,
    TailsPersistence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warn,
    /// Network operations are refused while this finding stands.
    Refuse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub check: Check,
    pub severity: Severity,
    /// User-facing text (English; localised by the front end, C-06).
    pub message: String,
}

/// What the doctor needs to know about the intended session.
#[derive(Debug, Clone)]
pub struct DoctorConfig {
    pub tor: TorConfig,
    /// Relay addresses the session intends to use (checked for `.onion` validity).
    pub relay_addresses: Vec<String>,
    /// Whether to probe the SOCKS port (costs one loopback connection).
    pub probe_tor: bool,
}

/// Run every check. Findings are ordered by severity, most serious first.
pub fn run(cfg: &DoctorConfig) -> Vec<Finding> {
    let mut f = Vec::new();

    if platform::swap_active() {
        f.push(Finding {
            check: Check::Swap,
            severity: Severity::Warn,
            message:
                "Swap is enabled — a note could be written to disk. Disable swap or use Tails."
                    .into(),
        });
    }

    let probe = LockedBuf::with_capacity(4096);
    let limit = platform::memlock_limit();
    if probe.lock_state() == LockState::Unlocked || limit.is_some_and(|l| l < 8 * 1024 * 1024) {
        f.push(Finding {
            check: Check::MemoryLock,
            severity: Severity::Warn,
            message: "Cannot lock memory — secrets may be swapped.".into(),
        });
    }

    if platform::session_type().as_deref() == Some("x11") {
        f.push(Finding {
            check: Check::ScreenCapture,
            severity: Severity::Warn,
            message: "X11 session: screenshots cannot be prevented. Prefer a Wayland session."
                .into(),
        });
    } else if platform::session_type().as_deref() == Some("wayland") {
        // No Wayland protocol lets a window exclude itself from capture; KDE Plasma 6.6+
        // offers it as a user action, which is the most Aska can point at (1.1 step 4).
        let v = platform::plasma_version();
        if platform::plasma_can_hide_window(v) {
            f.push(Finding {
                check: Check::ScreenCapture,
                severity: Severity::Info,
                message: "Plasma can hide this window from screenshots and recordings: title bar → More Actions → \"Hide from Screencast\" (a window rule makes it permanent). Aska cannot turn it on itself.".into(),
            });
        } else if v.is_some() {
            f.push(Finding {
                check: Check::ScreenCapture,
                severity: Severity::Info,
                message: "Plasma before 6.6 cannot hide a window from screen capture; capture can be detected, not blocked.".into(),
            });
        }
    }
    // Process probes compare the exact `comm` (the kernel truncates it to 15 bytes), so
    // "obsidian" does not trip the "obs" check. The PipeWire ScreenCast-portal and AT-SPI
    // client probes of Table 4 need D-Bus and are a documented gap until M5 (GUI) adds them.
    let procs = platform::process_names();
    let has = |names: &[&str]| procs.iter().any(|p| names.iter().any(|n| p == n));
    if has(&[
        "obs",
        "wf-recorder",
        "kooha",
        "gpu-screen-reco",
        "simplescreenrec",
        "recordmydesktop",
        "peek",
        "vokoscreenNG",
    ]) {
        f.push(Finding {
            check: Check::ScreenCapture,
            severity: Severity::Warn,
            message: "Screen is being shared or recorded.".into(),
        });
    }
    let ssh_x =
        std::env::var_os("SSH_CONNECTION").is_some() && std::env::var_os("DISPLAY").is_some();
    if ssh_x
        || has(&[
            "gnome-remote-de",
            "vino-server",
            "x11vnc",
            "xrdp",
            "krfb",
            "Xtigervnc",
            "Xvnc",
            "waypipe",
            "wayvnc",
        ])
    {
        f.push(Finding {
            check: Check::RemoteDesktop,
            severity: Severity::Warn,
            message: "A remote session is active.".into(),
        });
    }
    if has(&["orca"]) || std::env::var("GNOME_ACCESSIBILITY").as_deref() == Ok("1") {
        f.push(Finding {
            check: Check::Accessibility,
            severity: Severity::Warn,
            message: "An accessibility service could read notes.".into(),
        });
    }

    if cfg.probe_tor {
        match tor::check_socks(&cfg.tor) {
            Err(e) => f.push(Finding {
                check: Check::Tor,
                severity: Severity::Refuse,
                message: format!("Not connected through Tor — nothing will be sent. ({e})"),
            }),
            Ok(()) => {
                // With a control port we can also ask how far Tor got. Bootstrap stuck below
                // 100 % is what a network that blocks Tor looks like from here (D-16): the
                // SOCKS port answers, nothing beyond it does. Without a control port this
                // cannot be told apart from a slow start, so the same guidance is given at
                // the moment a request fails instead (`tor::looks_like_blocked_network`).
                let tor_cfg = tor::with_discovered_control(&cfg.tor);
                if tor_cfg.control.is_some() {
                    match tor::bootstrap_progress(&tor_cfg) {
                        Ok(Some(p)) if p < 100 => f.push(Finding {
                            check: Check::TorNetwork,
                            severity: Severity::Warn,
                            message: format!(
                                "Tor is running but has not reached the Tor network (bootstrap {p} %); \
                                 nothing can be sent or fetched until it does. {}",
                                tor::blocked_network_guidance()
                            ),
                        }),
                        _ => {
                            if let Ok(false) = tor::circuit_established(&tor_cfg) {
                                f.push(Finding {
                                    check: Check::Tor,
                                    severity: Severity::Warn,
                                    message: "Tor is running but has not built a circuit yet."
                                        .into(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    for a in &cfg.relay_addresses {
        if tor::normalise_onion(a).is_err() {
            f.push(Finding {
                check: Check::RelayAddress,
                severity: Severity::Refuse,
                message: "Only .onion relays are allowed.".into(),
            });
            break;
        }
    }

    // Only a release build (embedded key) with a signed hash list in reach can fail this; a
    // development build or a binary moved away from its SHA256SUMS is "unverifiable", not a
    // finding (`aska verify` says so in detail).
    if crate::fingerprint::check().verified() == Some(false) {
        f.push(Finding {
            check: Check::Fingerprint,
            severity: Severity::Warn,
            message: "This build does not match its signed release list — do not use it for \
                      anything real (see `aska verify`)."
                .into(),
        });
    }

    let cd = platform::disable_core_dumps();
    if !cd.rlimit_zero || !cd.non_dumpable {
        f.push(Finding {
            check: Check::CoreDumps,
            severity: Severity::Warn,
            message: "Crash dumps enabled — secrets could be written on a crash.".into(),
        });
    }

    if platform::tails_persistence_unlocked() {
        f.push(Finding {
            check: Check::TailsPersistence,
            severity: Severity::Info,
            message: "Persistent Storage is unlocked — remember nothing from Aska is saved there."
                .into(),
        });
    }

    f.sort_by_key(|x| std::cmp::Reverse(x.severity));
    f
}

/// True if any finding refuses network operations.
pub fn refuses(findings: &[Finding]) -> bool {
    findings.iter().any(|f| f.severity == Severity::Refuse)
}

/// The finding a front end records when an operation failed the way a blocked network
/// fails — the local Tor answered, nothing beyond it did (`tor::looks_like_blocked_network`).
/// Without a control port this is the only way the condition can be told (D-16, option A);
/// the graphical client shows it as the same amber banner the doctor would have raised.
pub fn blocked_network_finding() -> Finding {
    Finding {
        check: Check::TorNetwork,
        severity: Severity::Warn,
        message: format!(
            "Every attempt failed the way a blocked network fails: Tor answered, nothing beyond \
             it did. {}",
            tor::blocked_network_guidance()
        ),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn blocked_network_finding_is_the_tor_network_warning_with_the_direction() {
        let f = super::blocked_network_finding();
        assert_eq!(f.check, super::Check::TorNetwork);
        assert_eq!(f.severity, super::Severity::Warn);
        assert!(f.message.contains("blocked network"));
        assert!(f.message.contains("bridge"));
        // Front-end neutral: the CLI appends its own flag hint, the GUI shows a button.
        assert!(!f.message.contains("--tor-browser"));
    }

    use super::*;

    #[test]
    fn non_onion_relay_refuses_and_probe_off_runs() {
        let cfg = DoctorConfig {
            tor: TorConfig::default(),
            relay_addresses: vec!["example.com".into()],
            probe_tor: false,
        };
        let f = run(&cfg);
        assert!(refuses(&f));
        assert_eq!(f[0].check, Check::RelayAddress);
        let cfg = DoctorConfig {
            relay_addresses: vec![],
            ..cfg
        };
        let f = run(&cfg);
        assert!(!f.iter().any(|x| x.check == Check::RelayAddress));
    }

    #[test]
    fn unreachable_tor_refuses() {
        let cfg = DoctorConfig {
            tor: TorConfig {
                socks: "127.0.0.1:1".parse().unwrap(),
                ..TorConfig::default()
            },
            relay_addresses: vec![],
            probe_tor: true,
        };
        let f = run(&cfg);
        assert!(f
            .iter()
            .any(|x| x.check == Check::Tor && x.severity == Severity::Refuse));
    }
}
