//! The RAM-only store (§5): per-class maps from label to `(block, deadline, digest)`,
//! monotonic deadlines, expire-only TTL, caps, idempotent duplicates, adaptive PoW policy
//! and CSPRNG-randomised listing. Nothing here touches a clock that can be mapped to a calendar
//! instant, and nothing here can be asked about one label.

use aska_proto::{
    class_size, Status, CHALLENGE_LEN, CHALLENGE_TTL_SECS, DEFAULT_CAPS, DEFAULT_MAX_TTL_HOURS,
    LABEL_LEN, MAX_TTL_HOURS_CEILING,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

pub type Label = [u8; LABEL_LEN];
pub type Challenge = [u8; CHALLENGE_LEN];

/// A fixed-size map key that wipes itself when its slot is dropped. `HashMap::retain` and
/// `remove` drop the key in place, so an expired label or a spent challenge is overwritten
/// with zeros in the table rather than left readable in locked RAM until the slot is reused
/// (finding of the ADP/1 draft 0.3 re-issue). The table's bytes themselves move unwiped when
/// it grows; that residual is documented in ADP/1 §5.1.
#[derive(Clone, PartialEq, Eq, Hash)]
struct WipedKey<const N: usize>([u8; N]);

impl<const N: usize> Drop for WipedKey<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> std::borrow::Borrow<[u8; N]> for WipedKey<N> {
    fn borrow(&self) -> &[u8; N] {
        &self.0
    }
}
/// A stored Block. Shared between the store and any listing that is being written out, so a
/// GET_ALL never copies the bucket (§4.4): the relay's peak memory stays at one copy of each
/// Block however many listings are in flight. The bytes are zeroised when the last holder —
/// the store on expiry, or the last in-flight listing — drops them.
pub type Block = Arc<Zeroizing<Vec<u8>>>;

struct Entry {
    block: Block,
    deadline: Instant,
    /// SHA-256 of the Block, for the idempotent-duplicate rule; wiped with the entry.
    digest: Zeroizing<[u8; 32]>,
}

/// Relay policy: the complete configuration surface (§9.3, Table 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Per-class Block caps for classes 1..=3; 0 = class not served.
    pub caps: [usize; 3],
    /// 1..=168.
    pub max_ttl_hours: u16,
    /// Base PoW difficulty in bits; adaptive bits are added on top (§6.2).
    pub pow_base_difficulty: u8,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            caps: DEFAULT_CAPS,
            max_ttl_hours: DEFAULT_MAX_TTL_HOURS,
            pow_base_difficulty: 0,
        }
    }
}

impl Config {
    /// Clamp to the specification's hard limits.
    pub fn validated(mut self) -> Self {
        self.max_ttl_hours = self.max_ttl_hours.clamp(1, MAX_TTL_HOURS_CEILING);
        self
    }
}

pub struct Store {
    cfg: Config,
    data: [HashMap<WipedKey<LABEL_LEN>, Entry>; 3],
    challenges: HashMap<WipedKey<CHALLENGE_LEN>, Instant>,
    /// Test hook: an offset added to the monotonic clock (never set in production).
    clock_offset: Duration,
}

impl Store {
    pub fn new(cfg: Config) -> Self {
        Store {
            cfg: cfg.validated(),
            data: [HashMap::new(), HashMap::new(), HashMap::new()],
            challenges: HashMap::new(),
            clock_offset: Duration::ZERO,
        }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    fn now(&self) -> Instant {
        Instant::now() + self.clock_offset
    }

    /// Advance the store's notion of "now" (tests only; expiry is monotonic so this is the only
    /// way to exercise it without waiting).
    pub fn advance_clock(&mut self, by: Duration) {
        self.clock_offset += by;
    }

    pub fn serves(&self, class: u8) -> bool {
        (1..=3).contains(&class) && self.cfg.caps[class as usize - 1] > 0
    }

    /// Bit `c-1` set ⇒ class `c` served (INFO, §4.2).
    pub fn classes_bitmap(&self) -> u8 {
        (1u8..=3)
            .filter(|c| self.serves(*c))
            .fold(0, |acc, c| acc | 1 << (c - 1))
    }

    /// Delete every entry whose deadline has passed, and every stale challenge (§5.2).
    pub fn expire(&mut self) {
        let now = self.now();
        for d in self.data.iter_mut() {
            d.retain(|_, e| e.deadline > now);
        }
        self.challenges.retain(|_, t| *t > now);
    }

    /// Adaptive difficulty (§6.2): base, +1 bit per 12.5 % of capacity used above 50 %, max +4.
    /// Integer arithmetic; identical to the reference's `int((fill - 0.5) / 0.125) + 1`.
    pub fn difficulty_for(&self, class: u8) -> u8 {
        if !self.serves(class) {
            return self.cfg.pow_base_difficulty;
        }
        let n = self.data[class as usize - 1].len();
        let cap = self.cfg.caps[class as usize - 1].max(1);
        let extra = if 2 * n < cap {
            0
        } else {
            ((8 * n - 4 * cap) / cap + 1).min(4)
        };
        self.cfg.pow_base_difficulty.saturating_add(extra as u8)
    }

    pub fn new_challenge(&mut self) -> Challenge {
        let mut ch = [0u8; CHALLENGE_LEN];
        // A failed CSPRNG read leaves an all-zero challenge, which the protocol reserves for
        // "no challenge"; refusing it is the safe failure.
        if getrandom::getrandom(&mut ch).is_err() || ch == [0u8; CHALLENGE_LEN] {
            return [0u8; CHALLENGE_LEN];
        }
        let deadline = self.now() + Duration::from_secs(CHALLENGE_TTL_SECS);
        self.challenges.insert(WipedKey(ch), deadline);
        ch
    }

    /// Single use: true iff the challenge was outstanding and unexpired; it is removed either way.
    pub fn consume_challenge(&mut self, ch: &Challenge) -> bool {
        let now = self.now();
        match self.challenges.remove(ch) {
            Some(t) => t > now,
            None => false,
        }
    }

    /// Store a Block (§4.3, §5). The caller has already handled proof-of-work. The body arrives
    /// in a zeroising buffer so that a refused or duplicate Block is wiped when it is dropped.
    pub fn put(
        &mut self,
        class: u8,
        ttl_hours: u16,
        label: Label,
        block: Zeroizing<Vec<u8>>,
    ) -> Status {
        self.expire();
        if !self.serves(class) {
            return Status::BadClass;
        }
        if ttl_hours == 0 || ttl_hours > self.cfg.max_ttl_hours {
            return Status::BadTtl;
        }
        if class_size(class) != Some(block.len()) {
            return Status::BadLength;
        }
        let digest: Zeroizing<[u8; 32]> = Zeroizing::new(Sha256::digest(block.as_slice()).into());
        let cap = self.cfg.caps[class as usize - 1];
        let deadline = self.now() + Duration::from_secs(u64::from(ttl_hours) * 3600);
        let d = &mut self.data[class as usize - 1];
        if let Some(e) = d.get(&label) {
            return if e.digest == digest {
                Status::Ok // idempotent retry (P-04)
            } else {
                Status::Duplicate
            };
        }
        if d.len() >= cap {
            return Status::Full;
        }
        d.insert(
            WipedKey(label),
            Entry {
                block: Arc::new(block),
                deadline,
                digest,
            },
        );
        Status::Ok
    }

    /// Every live `(label, block)` of a class in an order freshly randomised with a CSPRNG (§4.4).
    /// The Blocks are shared handles, not copies: a listing of a full class-3 bucket costs the
    /// relay 200 × 8 bytes, not 200 × 64 KiB. (Under `mlockall(MCL_FUTURE)` every allocation
    /// must fit in `RLIMIT_MEMLOCK`, so the old full copy was the first thing to fail on a
    /// relay whose lock limit was too small — see `harden::check_memlock_limit`.)
    pub fn get_all(&mut self, class: u8) -> Option<Vec<(Label, Block)>> {
        self.expire();
        if !self.serves(class) {
            return None;
        }
        let mut items: Vec<(Label, Block)> = self.data[class as usize - 1]
            .iter()
            .map(|(l, e)| (l.0, Arc::clone(&e.block)))
            .collect();
        // Fisher–Yates with unbiased CSPRNG indices (HashMap iteration order is already
        // unpredictable, but the specification requires an explicit CSPRNG shuffle).
        let mut i = items.len();
        while i > 1 {
            let j = rand_below(i);
            i -= 1;
            items.swap(i, j);
        }
        Some(items)
    }

    /// Live Blocks per class (for tests and the INFO-free health model; never exposed on the wire).
    pub fn counts(&mut self) -> [usize; 3] {
        self.expire();
        [self.data[0].len(), self.data[1].len(), self.data[2].len()]
    }

    #[cfg(test)]
    pub(crate) fn outstanding_challenges(&self) -> usize {
        self.challenges.len()
    }
}

/// Uniform integer in `0..n` by rejection sampling over the CSPRNG.
fn rand_below(n: usize) -> usize {
    debug_assert!(n > 0);
    let n64 = n as u64;
    let zone = u64::MAX - (u64::MAX % n64);
    loop {
        let mut b = [0u8; 8];
        if getrandom::getrandom(&mut b).is_err() {
            // Fall back to index 0: still a valid permutation step; a broken CSPRNG on the host
            // is an operator problem, not a reason to abort a listing.
            return 0;
        }
        let v = u64::from_be_bytes(b);
        if v < zone {
            return (v % n64) as usize;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(cap1: usize) -> Config {
        Config {
            caps: [cap1, 800, 200],
            ..Config::default()
        }
    }

    fn rnd<const N: usize>() -> [u8; N] {
        let mut b = [0u8; N];
        getrandom::getrandom(&mut b).unwrap();
        b
    }
    fn rblock(class: u8) -> Zeroizing<Vec<u8>> {
        let mut v = vec![0u8; class_size(class).unwrap()];
        getrandom::getrandom(&mut v).unwrap();
        Zeroizing::new(v)
    }

    #[test]
    fn put_get_duplicate_full_ttl() {
        let mut s = Store::new(cfg(4));
        let (l0, b0) = (rnd::<32>(), rblock(1));
        assert_eq!(s.put(1, 1, l0, b0.clone()), Status::Ok);
        assert_eq!(s.put(1, 1, l0, b0.clone()), Status::Ok); // idempotent
        assert_eq!(s.put(1, 1, l0, rblock(1)), Status::Duplicate);
        assert_eq!(s.put(1, 0, rnd(), rblock(1)), Status::BadTtl);
        assert_eq!(s.put(1, 169, rnd(), rblock(1)), Status::BadTtl);
        assert_eq!(s.put(4, 1, rnd(), rblock(1)), Status::BadClass);
        assert_eq!(s.put(2, 1, rnd(), rblock(1)), Status::BadLength);
        for _ in 0..3 {
            assert_eq!(s.put(1, 1, rnd(), rblock(1)), Status::Ok);
        }
        assert_eq!(s.put(1, 1, rnd(), rblock(1)), Status::Full);
        assert_eq!(s.counts(), [4, 0, 0]);
        let got = s.get_all(1).unwrap();
        assert_eq!(got.len(), 4);
        assert!(got.iter().any(|(l, b)| *l == l0 && ***b == *b0));
        assert!(s.get_all(4).is_none());
    }

    #[test]
    fn expiry_is_monotonic_and_exact() {
        let mut s = Store::new(cfg(10));
        s.put(1, 1, rnd(), rblock(1));
        s.put(1, 2, rnd(), rblock(1));
        s.advance_clock(Duration::from_secs(3600 - 1));
        assert_eq!(s.counts(), [2, 0, 0]);
        s.advance_clock(Duration::from_secs(1));
        assert_eq!(s.counts(), [1, 0, 0]);
        s.advance_clock(Duration::from_secs(3600));
        assert_eq!(s.counts(), [0, 0, 0]);
    }

    #[test]
    fn difficulty_schedule_matches_reference() {
        // reference: fill<0.5 → 0; then int((fill-0.5)/0.125)+1 capped at 4
        let mut s = Store::new(cfg(8));
        let expect = [0, 0, 0, 0, 1, 2, 3, 4, 4];
        for (n, e) in expect.iter().enumerate() {
            assert_eq!(s.difficulty_for(1), *e, "n={n}");
            if n < 8 {
                s.put(1, 1, rnd(), rblock(1));
            }
        }
        // selftest scenario of the reference: cap 4, 3 stored → 3 bits
        let mut s = Store::new(cfg(4));
        for _ in 0..3 {
            s.put(1, 1, rnd(), rblock(1));
        }
        assert_eq!(s.difficulty_for(1), 3);
        // base adds
        let mut s = Store::new(Config {
            pow_base_difficulty: 8,
            ..cfg(4)
        });
        assert_eq!(s.difficulty_for(1), 8);
        s.put(1, 1, rnd(), rblock(1));
        s.put(1, 1, rnd(), rblock(1));
        assert_eq!(s.difficulty_for(1), 9);
    }

    #[test]
    fn challenges_single_use_and_expire() {
        let mut s = Store::new(cfg(4));
        let c = s.new_challenge();
        assert_ne!(c, [0; 16]);
        assert!(s.consume_challenge(&c));
        assert!(!s.consume_challenge(&c));
        let c2 = s.new_challenge();
        s.advance_clock(Duration::from_secs(121));
        assert!(!s.consume_challenge(&c2));
        let c3 = s.new_challenge();
        assert_eq!(s.outstanding_challenges(), 1);
        s.advance_clock(Duration::from_secs(121));
        s.expire();
        assert_eq!(s.outstanding_challenges(), 0);
        assert!(!s.consume_challenge(&c3));
    }

    #[test]
    fn listing_order_is_randomised() {
        let mut s = Store::new(cfg(100));
        for _ in 0..12 {
            s.put(1, 1, rnd(), rblock(1));
        }
        let orders: Vec<Vec<Label>> = (0..5)
            .map(|_| s.get_all(1).unwrap().into_iter().map(|(l, _)| l).collect())
            .collect();
        assert!(orders.iter().any(|o| *o != orders[0]));
    }

    #[test]
    fn config_validation_and_bitmap() {
        let c = Config {
            max_ttl_hours: 500,
            ..Config::default()
        }
        .validated();
        assert_eq!(c.max_ttl_hours, 168);
        let c = Config {
            max_ttl_hours: 0,
            ..Config::default()
        }
        .validated();
        assert_eq!(c.max_ttl_hours, 1);
        let s = Store::new(Config {
            caps: [10, 0, 5],
            ..Config::default()
        });
        assert_eq!(s.classes_bitmap(), 0b101);
        assert!(!s.serves(2));
    }

    #[test]
    fn rand_below_in_range() {
        for n in [1usize, 2, 3, 7, 1000] {
            for _ in 0..200 {
                assert!(rand_below(n) < n);
            }
        }
    }
}
