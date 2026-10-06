//! Process-level settings and host detection used by the Session and the doctor.
#![allow(unsafe_code)]

use std::path::Path;

/// Outcome of `disable_core_dumps`, reported by the doctor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreDumpState {
    pub rlimit_zero: bool,
    pub non_dumpable: bool,
}

/// Set `RLIMIT_CORE` to 0 and clear the dumpable flag (Client Design §3.1). Idempotent.
pub fn disable_core_dumps() -> CoreDumpState {
    let lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: pointer to a fully initialised rlimit that outlives the call.
    let rlimit_zero = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) } == 0;
    // SAFETY: integer arguments only.
    let non_dumpable = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0;
    CoreDumpState {
        rlimit_zero,
        non_dumpable,
    }
}

/// Current soft `RLIMIT_MEMLOCK` in bytes (`None` = unlimited or unknown).
pub fn memlock_limit() -> Option<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: out-pointer to a valid rlimit.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) } != 0 {
        return None;
    }
    if lim.rlim_cur == libc::RLIM_INFINITY {
        None
    } else {
        Some(lim.rlim_cur)
    }
}

/// True on Tails (the amnesic live system), detected by its version file or os-release.
pub fn is_tails() -> bool {
    if Path::new("/etc/amnesia/version").exists() {
        return true;
    }
    std::fs::read_to_string("/etc/os-release")
        .map(|s| s.lines().any(|l| l == "ID=tails" || l == "NAME=\"Tails\""))
        .unwrap_or(false)
}

/// True on Whonix (Workstation or Gateway), where Tor and its connection wizard live in
/// `sys-whonix`; detected by its version file, marker directory or os-release.
pub fn is_whonix() -> bool {
    if Path::new("/etc/whonix_version").exists() || Path::new("/usr/share/whonix").exists() {
        return true;
    }
    std::fs::read_to_string("/etc/os-release")
        .map(|s| {
            s.lines()
                .any(|l| l == "ID=whonix" || l.starts_with("NAME=\"Whonix"))
        })
        .unwrap_or(false)
}

/// Whonix's fixed internal address of the Tor gateway (`sys-whonix`), as seen from a
/// Workstation: the only non-loopback SOCKS proxy the client accepts, and only on Whonix.
pub const WHONIX_GATEWAY: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 152, 152, 10);

/// Platforms where the Tor control port is filtered (Tails' and Whonix's onion-grater), so
/// `ONION_CLIENT_AUTH_ADD` cannot be issued: circle-authorised relays are unusable (C-03).
pub fn control_port_filtered() -> bool {
    is_tails() || is_whonix()
}

/// The system Tor's SOCKS address for this platform: loopback 9050 everywhere except a
/// Whonix Workstation, whose Tor runs in the gateway qube.
pub fn default_socks() -> std::net::SocketAddr {
    if is_whonix() {
        std::net::SocketAddr::new(WHONIX_GATEWAY.into(), 9050)
    } else {
        "127.0.0.1:9050".parse().expect("static")
    }
}

/// True when Tails' Persistent Storage is unlocked (informational doctor finding).
pub fn tails_persistence_unlocked() -> bool {
    is_tails() && Path::new("/live/persistence/TailsData_unlocked").exists()
}

/// Session type as reported by the desktop: "wayland", "x11", "tty" or None.
pub fn session_type() -> Option<String> {
    if let Ok(t) = std::env::var("XDG_SESSION_TYPE") {
        return Some(t);
    }
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        return Some("wayland".into());
    }
    if std::env::var_os("DISPLAY").is_some() {
        return Some("x11".into());
    }
    None
}

/// Whether swap is active: any entry in `/proc/swaps` or a zram block device.
pub fn swap_active() -> bool {
    let swaps = std::fs::read_to_string("/proc/swaps").unwrap_or_default();
    if swaps.lines().skip(1).any(|l| !l.trim().is_empty()) {
        return true;
    }
    std::fs::read_dir("/sys/block")
        .map(|d| {
            d.flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with("zram"))
        })
        .unwrap_or(false)
}

/// Names (comm) of all running processes, for the doctor's process probes.
pub fn process_names() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(d) = std::fs::read_dir("/proc") {
        for e in d.flatten() {
            let name = e.file_name();
            if !name.to_string_lossy().chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            if let Ok(comm) = std::fs::read_to_string(e.path().join("comm")) {
                out.push(comm.trim().to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_dumps_and_limits() {
        let s = disable_core_dumps();
        assert!(s.rlimit_zero);
        assert!(s.non_dumpable);
        let _ = memlock_limit();
        let _ = swap_active();
        assert!(!process_names().is_empty());
        let _ = session_type();
        let _ = is_tails();
    }
}
