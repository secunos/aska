//! Cover traffic (Client Design §6.5, D-10): decoy PUTs and GET_ALLs on a Poisson schedule
//! while the application is open, plus the random delay applied to real requests so that they
//! fall inside the same process. There is no background service: the scheduler is a thread
//! owned by the front end and stops when the application closes.

use crate::cancel::CancelToken;
use crate::drop::{Connector, DropClient, Relay};
use crate::rng::{OsRng, RandomSource};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverLevel {
    Off,
    /// Roughly four to eight decoy requests per relay per day of uptime (default).
    Modest,
    /// Roughly hourly.
    High,
}

impl CoverLevel {
    /// Mean interval between decoy requests for one relay.
    pub fn mean_interval(self) -> Option<Duration> {
        match self {
            CoverLevel::Off => None,
            CoverLevel::Modest => Some(Duration::from_secs(4 * 3600)),
            CoverLevel::High => Some(Duration::from_secs(3600)),
        }
    }
}

/// Uniform in [0, 1) from the CSPRNG (53 bits).
fn unit(rng: &mut impl RandomSource) -> f64 {
    let b: [u8; 8] = rng.array().unwrap_or([0x80; 8]);
    (u64::from_be_bytes(b) >> 11) as f64 / (1u64 << 53) as f64
}

/// Exponential inter-arrival time with the given mean (a Poisson process).
pub fn poisson_interval(mean: Duration, rng: &mut impl RandomSource) -> Duration {
    let u = unit(rng).max(f64::MIN_POSITIVE);
    Duration::from_secs_f64(-u.ln() * mean.as_secs_f64())
}

/// Random delay for a real request, uniform in [0, max] (default max 90 s).
pub fn real_request_delay(max: Duration, rng: &mut impl RandomSource) -> Duration {
    Duration::from_secs_f64(unit(rng) * max.as_secs_f64())
}

/// Size class for a decoy, drawn with the same distribution real use is expected to have
/// (mostly small notes): 70 % class 1, 20 % class 2, 10 % class 3.
pub fn decoy_class(rng: &mut impl RandomSource) -> u8 {
    match unit(rng) {
        u if u < 0.7 => 1,
        u if u < 0.9 => 2,
        _ => 3,
    }
}

/// TTLs a real post may carry (the client's choices; the CLI default is 24 h). A decoy's TTL
/// is drawn from the same set, weighted towards the default, so the relay cannot tell decoy
/// PUTs from real ones by their TTL or by the deadline it stores (review finding C-3; CLI-06).
pub const TTL_CHOICES_HOURS: [u16; 6] = [1, 6, 24, 48, 72, 168];

/// Decoy TTL: one of the real choices; 24 h half of the time, the others equally likely.
pub fn decoy_ttl(rng: &mut impl RandomSource) -> u16 {
    let u = unit(rng);
    if u < 0.5 {
        24
    } else {
        let others = [1u16, 6, 48, 72, 168];
        others[(((u - 0.5) * 2.0) * others.len() as f64) as usize % others.len()]
    }
}

/// A running cover-traffic scheduler. `stop()` (or drop) cancels in-flight decoys through
/// their sockets and returns promptly; it never waits for a Tor rendezvous to finish.
pub struct CoverScheduler {
    cancel: CancelToken,
    handle: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for CoverScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CoverScheduler({:?})", self.cancel)
    }
}

impl CoverScheduler {
    /// Start issuing decoys to `relays` through `connector` at `level`. Returns `None` for
    /// `CoverLevel::Off` or an empty relay list.
    pub fn start(
        connector: Arc<dyn Connector>,
        relays: Vec<Relay>,
        level: CoverLevel,
    ) -> Option<Self> {
        let mean = level.mean_interval()?;
        if relays.is_empty() {
            return None;
        }
        let cancel = CancelToken::new();
        let c2 = cancel.clone();
        let handle = std::thread::Builder::new()
            .name("aska-cover".into())
            .spawn(move || run(connector, relays, mean, c2))
            .ok()?;
        Some(CoverScheduler {
            cancel,
            handle: Some(handle),
        })
    }

    pub fn stop(&mut self) {
        self.cancel.cancel();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for CoverScheduler {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run(connector: Arc<dyn Connector>, relays: Vec<Relay>, mean: Duration, cancel: CancelToken) {
    use std::sync::atomic::{AtomicBool, Ordering};
    let mut rng = OsRng;
    // Independent Poisson clock per relay, and at most one in-flight decoy per relay.
    let mut next: Vec<Instant> = relays
        .iter()
        .map(|_| Instant::now() + poisson_interval(mean, &mut rng))
        .collect();
    let busy: Vec<Arc<AtomicBool>> = relays
        .iter()
        .map(|_| Arc::new(AtomicBool::new(false)))
        .collect();
    while cancel.sleep(Duration::from_millis(500)) {
        let now = Instant::now();
        for (i, relay) in relays.iter().enumerate() {
            if now < next[i] {
                continue;
            }
            next[i] = now + poisson_interval(mean, &mut rng);
            if busy[i].swap(true, Ordering::SeqCst) {
                continue; // the previous decoy to this relay is still in flight
            }
            let class = decoy_class(&mut rng);
            let ttl = decoy_ttl(&mut rng);
            let put = unit(&mut rng) < 0.5;
            // Each decoy runs on its own short-lived thread so a slow circuit never delays
            // the schedule or the shutdown; the shared token aborts it on stop().
            let (connector, relay, cancel, flag) = (
                connector.clone(),
                relay.clone(),
                cancel.clone(),
                busy[i].clone(),
            );
            let spawned = std::thread::Builder::new()
                .name("aska-decoy".into())
                .spawn(move || {
                    let client = DropClient::new(connector.as_ref(), cancel);
                    // Results are deliberately ignored: a decoy has no outcome to report.
                    if put {
                        let _ = client.decoy_put(&relay, class, ttl);
                    } else {
                        let _ = client.decoy_get(&relay, class);
                    }
                    flag.store(false, Ordering::SeqCst);
                });
            if spawned.is_err() {
                busy[i].store(false, Ordering::SeqCst);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::TestRng;

    #[test]
    fn poisson_mean_is_right() {
        let mut rng = TestRng::new(b"cover");
        let mean = Duration::from_secs(3600);
        let n = 20_000;
        let total: f64 = (0..n)
            .map(|_| poisson_interval(mean, &mut rng).as_secs_f64())
            .sum();
        let avg = total / n as f64;
        assert!((avg - 3600.0).abs() < 100.0, "avg {avg}");
    }

    #[test]
    fn distributions_in_range() {
        let mut rng = TestRng::new(b"c2");
        let mut counts = [0usize; 4];
        for _ in 0..10_000 {
            counts[decoy_class(&mut rng) as usize] += 1;
            let t = decoy_ttl(&mut rng);
            assert!(TTL_CHOICES_HOURS.contains(&t));
            let d = real_request_delay(Duration::from_secs(90), &mut rng);
            assert!(d <= Duration::from_secs(90));
        }
        assert!(counts[1] > 6500 && counts[1] < 7500, "{counts:?}");
        assert!(counts[3] > 700 && counts[3] < 1300, "{counts:?}");
        assert_eq!(CoverLevel::Off.mean_interval(), None);
    }
}
