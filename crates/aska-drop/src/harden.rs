//! Process hardening at start (§5.1, RLY-06): lock all current and future memory against
//! swapping, forbid core dumps, and mark the process non-dumpable so `/proc/<pid>/mem` and
//! ptrace from an unprivileged user are refused. This is the only module in the workspace
//! that uses `unsafe`; each call is a single libc syscall wrapper with no pointer arguments.
//!
//! Why the lock limit is checked up front: with `mlockall(MCL_CURRENT | MCL_FUTURE)` every page
//! the process ever maps must fit inside `RLIMIT_MEMLOCK`, and an allocation that would exceed
//! it is refused by the kernel. The release build aborts on a refused allocation, so a relay
//! started under a lock limit smaller than its configured store runs fine while the store is
//! small and then dies — under a client, hours later — the first time it grows past the limit.
//! (Field incident 2026-09-29: default 8 MiB limit, SIGABRT at the first full listing.) The
//! relay therefore refuses to start unless the hard limit is unlimited or comfortably above
//! the store's worst case.
#![allow(unsafe_code)]

use crate::store::Config;
use aska_proto::class_size;

/// Memory the relay needs beyond the Blocks themselves: the static binary, two worker-thread
/// stacks (fully resident under `MCL_FUTURE`), the runtime, per-record bookkeeping and slack.
pub const RUNTIME_HEADROOM_BYTES: u64 = 64 * 1024 * 1024;

/// Per-record bookkeeping beyond the Block: label, deadline, digest, map slot, `Arc` header.
const RECORD_OVERHEAD_BYTES: u64 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardenError {
    /// `mlockall` failed — usually `RLIMIT_MEMLOCK` is too low (run under the systemd unit,
    /// which sets `LimitMEMLOCK=infinity`, or as root).
    MemoryLock(i32),
    /// The hard `RLIMIT_MEMLOCK` is finite and smaller than the configured store needs.
    MemoryLimitTooSmall {
        limit: u64,
        required: u64,
    },
    CoreDump(i32),
    Dumpable(i32),
}

impl std::fmt::Display for HardenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HardenError::MemoryLock(e) => write!(
                f,
                "mlockall failed (errno {e}); raise RLIMIT_MEMLOCK (systemd: LimitMEMLOCK=infinity) \
                 or run with --insecure-no-mlock for development only"
            ),
            HardenError::MemoryLimitTooSmall { limit, required } => write!(
                f,
                "RLIMIT_MEMLOCK is {} MiB but the configured store needs at least {} MiB locked; \
                 set LimitMEMLOCK=infinity in the systemd unit (or lower --cap-1/2/3), otherwise \
                 the relay would abort the first time the store grows past the limit",
                limit / (1024 * 1024),
                required.div_ceil(1024 * 1024)
            ),
            HardenError::CoreDump(e) => write!(f, "setrlimit(RLIMIT_CORE, 0) failed (errno {e})"),
            HardenError::Dumpable(e) => write!(f, "prctl(PR_SET_DUMPABLE, 0) failed (errno {e})"),
        }
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Worst-case bytes the relay must be able to lock for this configuration: every class at its
/// cap plus bookkeeping, plus the fixed runtime headroom. Listings add nothing — they share the
/// stored Blocks (`store::Block`).
pub fn required_locked_bytes(cfg: &Config) -> u64 {
    let blocks: u64 = (1u8..=3)
        .map(|c| {
            let cap = cfg.caps[c as usize - 1] as u64;
            cap * (class_size(c).unwrap_or(0) as u64 + RECORD_OVERHEAD_BYTES)
        })
        .sum();
    blocks + RUNTIME_HEADROOM_BYTES
}

/// `rlim_t` is `u64` on the targets we ship but not everywhere.
#[allow(clippy::unnecessary_cast)]
fn rlim(v: libc::rlim_t) -> u64 {
    v as u64
}

fn memlock_rlimit() -> Option<libc::rlimit> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: out-pointer to a valid rlimit.
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) } == 0 {
        Some(lim)
    } else {
        None
    }
}

/// True if the process holds `CAP_IPC_LOCK` in its effective set: the kernel then does not
/// apply `RLIMIT_MEMLOCK` to it at all (root running the relay by hand). Read from
/// `/proc/self/status`; unreadable means "assume not", which errs towards the clear refusal.
fn has_cap_ipc_lock() -> bool {
    const CAP_IPC_LOCK: u32 = 14;
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|st| {
            st.lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
        })
        .is_some_and(|caps| caps & (1u64 << CAP_IPC_LOCK) != 0)
}

/// Refuse to run under a hard lock limit that cannot hold the configured store. A limit that
/// cannot be read is treated as unlimited (`mlockall` below still decides whether locking works
/// at all), and a process exempt from the limit (`CAP_IPC_LOCK`) passes.
pub fn check_memlock_limit(cfg: &Config) -> Result<(), HardenError> {
    let Some(lim) = memlock_rlimit() else {
        return Ok(());
    };
    if lim.rlim_max == libc::RLIM_INFINITY || has_cap_ipc_lock() {
        return Ok(());
    }
    let required = required_locked_bytes(cfg);
    if rlim(lim.rlim_max) < required {
        return Err(HardenError::MemoryLimitTooSmall {
            limit: rlim(lim.rlim_max),
            required,
        });
    }
    Ok(())
}

/// Disable core dumps and make the process non-dumpable. Always required.
pub fn no_core_dumps() -> Result<(), HardenError> {
    let lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: passes a pointer to a fully initialised rlimit that outlives the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) } != 0 {
        return Err(HardenError::CoreDump(errno()));
    }
    // SAFETY: prctl with integer arguments only.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(HardenError::Dumpable(errno()));
    }
    Ok(())
}

/// Keep the allocator's locked footprint proportional to what is actually stored.
///
/// glibc gives each thread that allocates its own arena, reserved as a 64 MiB mapping; under
/// `MCL_FUTURE` a mapping is made resident and locked in full the moment it is created, so a
/// handful of arenas would pin hundreds of megabytes of zeros. One arena, grown with `brk` in
/// small steps, locks only what the store holds. Must run before any worker thread exists.
/// A no-op on other C libraries.
fn single_malloc_arena() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: mallopt with integer arguments only.
    unsafe {
        libc::mallopt(libc::M_ARENA_MAX, 1);
    }
}

/// Lock all current and future pages in RAM. Tries to raise the soft `RLIMIT_MEMLOCK` to the
/// hard limit first so that a unit with `LimitMEMLOCK=infinity` works without further setup.
pub fn lock_memory() -> Result<(), HardenError> {
    single_malloc_arena();
    if let Some(mut lim) = memlock_rlimit() {
        if lim.rlim_cur < lim.rlim_max {
            lim.rlim_cur = lim.rlim_max;
            // SAFETY: pointer to a valid rlimit; failure is tolerated (mlockall below decides).
            unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &lim) };
        }
    }
    // SAFETY: integer flags only.
    if unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) } != 0 {
        return Err(HardenError::MemoryLock(errno()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_bytes_follow_the_caps() {
        let d = required_locked_bytes(&Config::default());
        // 2000×4 KiB + 800×16 KiB + 200×64 KiB ≈ 33 MiB of Blocks, plus overhead and headroom.
        assert!(d > 33 * 1024 * 1024 + RUNTIME_HEADROOM_BYTES);
        assert!(d < 40 * 1024 * 1024 + RUNTIME_HEADROOM_BYTES);
        let empty = Config {
            caps: [0, 0, 0],
            ..Config::default()
        };
        assert_eq!(required_locked_bytes(&empty), RUNTIME_HEADROOM_BYTES);
        let big = Config {
            caps: [200_000, 0, 0],
            ..Config::default()
        };
        assert!(required_locked_bytes(&big) > 800 * 1024 * 1024);
    }

    #[test]
    fn default_limit_of_8_mib_is_refused() {
        // The incident configuration: a stock unit without LimitMEMLOCK gives 8 MiB.
        let err = HardenError::MemoryLimitTooSmall {
            limit: 8 * 1024 * 1024,
            required: required_locked_bytes(&Config::default()),
        };
        let msg = err.to_string();
        assert!(msg.contains("8 MiB"), "{msg}");
        assert!(msg.contains("LimitMEMLOCK=infinity"), "{msg}");
    }
}
