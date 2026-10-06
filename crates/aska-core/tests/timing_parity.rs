//! Timing parity of the distress path (Client Design §5.5, §6.4; Prototype Plan M5 gate):
//! opening a decoy slot and opening a distress slot must take indistinguishable time. The
//! two paths share every expensive step (Argon2id, four header trials, the payload AEAD); the
//! distress path additionally destroys the key material, which must stay lost in the noise.
//!
//! Method: one Block with a decoy slot and a distress slot; `N` opens of each on fresh
//! Sessions, interleaved so drift affects both equally; a two-sided Mann–Whitney U test on
//! the durations. The gate passes when the two samples are not distinguishable at p < 0.01.
//! Argon2id dominates each open, so this is slow: it is `#[ignore]` by default and run by
//! `scripts/timing-parity.sh` (release build) and CI.

use aska_core::consts::PTYPE_TEXT;
use aska_core::kdf::KdfProfile;
use aska_core::session::{KeyStatus, Level, Session, SessionConfig};
use std::time::{Duration, Instant};

const N: usize = 150;

fn cfg() -> SessionConfig {
    SessionConfig {
        accept_unlocked_memory: true,
        request_delay_max: Duration::ZERO,
        profile: KdfProfile::P2,
        open_profiles: vec![KdfProfile::P2],
        ..SessionConfig::default()
    }
}

/// Two-sided Mann–Whitney U, normal approximation with tie correction; returns the p-value.
fn mann_whitney_p(a: &[f64], b: &[f64]) -> f64 {
    let (n1, n2) = (a.len() as f64, b.len() as f64);
    let mut all: Vec<(f64, u8)> = a
        .iter()
        .map(|&x| (x, 0))
        .chain(b.iter().map(|&x| (x, 1)))
        .collect();
    all.sort_by(|x, y| x.0.partial_cmp(&y.0).unwrap());
    // Average ranks for ties.
    let mut ranks = vec![0f64; all.len()];
    let mut tie_term = 0f64;
    let mut i = 0;
    while i < all.len() {
        let mut j = i;
        while j + 1 < all.len() && all[j + 1].0 == all[i].0 {
            j += 1;
        }
        let r = (i + j) as f64 / 2.0 + 1.0;
        for rk in &mut ranks[i..=j] {
            *rk = r;
        }
        let t = (j - i + 1) as f64;
        tie_term += t * t * t - t;
        i = j + 1;
    }
    let r1: f64 = all
        .iter()
        .zip(&ranks)
        .filter(|((_, g), _)| *g == 0)
        .map(|(_, r)| r)
        .sum();
    let u = r1 - n1 * (n1 + 1.0) / 2.0;
    let n = n1 + n2;
    let mu = n1 * n2 / 2.0;
    let sigma = (n1 * n2 / 12.0 * ((n + 1.0) - tie_term / (n * (n - 1.0)))).sqrt();
    if sigma == 0.0 {
        return 1.0;
    }
    let z = ((u - mu).abs() - 0.5).max(0.0) / sigma;
    2.0 * (1.0 - normal_cdf(z))
}

fn normal_cdf(z: f64) -> f64 {
    // Abramowitz–Stegun 7.1.26 via erf.
    let t = 1.0 / (1.0 + 0.3275911 * z / 2f64.sqrt());
    let x = z / 2f64.sqrt();
    let poly = t
        * (0.254829592
            + t * (-0.284496736 + t * (1.421413741 + t * (-1.453152027 + t * 1.061405429))));
    let erf = 1.0 - poly * (-x * x).exp();
    0.5 * (1.0 + erf)
}

fn median(v: &[f64]) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    s[s.len() / 2]
}

#[test]
#[ignore = "slow (Argon2id × 2N); run by scripts/timing-parity.sh"]
fn decoy_and_distress_opens_are_indistinguishable_in_time() {
    // One Block: real slot open, decoy behind "south", distress behind "help".
    let mut s = Session::new(cfg()).unwrap();
    s.compose(b"meet 14 nov, north gate", PTYPE_TEXT).unwrap();
    s.add_decoy("buy milk", "south").unwrap();
    s.set_distress("buy milk", "help").unwrap();
    s.seal(Level::Quick).unwrap();
    let words = s.hand_over_words().unwrap();
    let (label, block) = s.sealed_block().unwrap();
    let block = block.to_vec();

    let time_open = |pass: &str| -> f64 {
        let mut r = Session::new(cfg()).unwrap();
        assert_eq!(r.add_key_material(&words).unwrap(), KeyStatus::Ready);
        assert!(r.accept_bucket([(label, block.clone())]).unwrap());
        let t = Instant::now();
        let info = r.open(Some(pass)).unwrap();
        let dt = t.elapsed().as_secs_f64();
        assert_eq!(r.plaintext().unwrap(), b"buy milk");
        // The distress path has done its work already; nothing else may differ.
        let _ = info.distress;
        r.close();
        dt
    };

    let (mut decoy, mut distress) = (Vec::with_capacity(N), Vec::with_capacity(N));
    for i in 0..N {
        // Alternate the order each round so slow-then-fast drift cannot favour one side.
        if i % 2 == 0 {
            decoy.push(time_open("south"));
            distress.push(time_open("help"));
        } else {
            distress.push(time_open("help"));
            decoy.push(time_open("south"));
        }
    }
    let p = mann_whitney_p(&decoy, &distress);
    eprintln!(
        "timing parity: N={N} median decoy {:.1} ms, median distress {:.1} ms, p = {p:.3}",
        median(&decoy) * 1e3,
        median(&distress) * 1e3
    );
    assert!(
        p >= 0.01,
        "decoy and distress opens are distinguishable (p = {p:.4}): decoy {:?} distress {:?}",
        decoy,
        distress
    );
}

#[test]
fn mann_whitney_sanity() {
    let a: Vec<f64> = (0..30).map(|i| 1.0 + (i % 7) as f64 * 0.01).collect();
    let b: Vec<f64> = (0..30).map(|i| 1.0 + ((i + 3) % 7) as f64 * 0.01).collect();
    assert!(mann_whitney_p(&a, &b) > 0.5);
    let c: Vec<f64> = (0..30).map(|i| 2.0 + (i % 7) as f64 * 0.01).collect();
    assert!(mann_whitney_p(&a, &c) < 0.001);
}

/// DC-02 gate (c): receiving-side matching by decapsulation does the same work for every
/// Block, whether or not one matches. ONE seed is matched against two buckets that differ in a
/// single record: the hit bucket holds 20 random Blocks plus the KEM Block sealed for that
/// seed, the miss bucket the same 20 plus a random Block in its place. The two timings must be
/// indistinguishable.
///
/// (Until 6 Oct 2026 the miss side used a second seed. Decapsulation time varies by a few
/// microseconds from key to key — public-key-dependent, the same for every record of one
/// receiver, so it reveals nothing about which record matched — but over 21 records two random
/// keys can differ by tens of microseconds, and the old test failed whenever it drew such a
/// pair: it compared two keys, not a hit with a miss. Observed on a GitHub runner.)
#[test]
#[ignore = "slow; run by scripts/timing-parity.sh"]
fn seed_matching_time_does_not_depend_on_a_match() {
    use aska_core::rng::{OsRng, RandomSource};
    let words = aska_core::xwing::new_seed_words().unwrap();
    let rk = aska_core::xwing::receiving_key_from_words(&words, &[], None, None).unwrap();
    let askar = rk.encode().unwrap();
    let mut s = Session::new(cfg()).unwrap();
    s.set_recipient(&askar).unwrap();
    s.compose(b"kem block", PTYPE_TEXT).unwrap();
    s.seal(Level::Quick).unwrap();
    let (label, block) = s.sealed_block().unwrap();
    let block = block.to_vec();
    let mut miss_bucket: Vec<([u8; 32], Vec<u8>)> = (0..20)
        .map(|_| (OsRng.array().unwrap(), OsRng.bytes(block.len()).unwrap()))
        .collect();
    let mut hit_bucket = miss_bucket.clone();
    hit_bucket.insert(10, (label, block.clone()));
    miss_bucket.insert(
        10,
        (OsRng.array().unwrap(), OsRng.bytes(block.len()).unwrap()),
    );

    let time_match = |bucket: &Vec<([u8; 32], Vec<u8>)>, expect: bool| -> f64 {
        let mut r = Session::new(cfg()).unwrap();
        r.add_receiving_seed(&words).unwrap();
        let t = Instant::now();
        let matched = r.accept_bucket(bucket.iter().cloned()).unwrap();
        let dt = t.elapsed().as_secs_f64();
        assert_eq!(matched, expect);
        r.close();
        dt
    };
    let n = 400; // ~3 ms per round; enough rounds to see a 20 µs effect through CI noise
    let (mut hit, mut miss) = (Vec::with_capacity(n), Vec::with_capacity(n));
    for i in 0..n {
        if i % 2 == 0 {
            hit.push(time_match(&hit_bucket, true));
            miss.push(time_match(&miss_bucket, false));
        } else {
            miss.push(time_match(&miss_bucket, false));
            hit.push(time_match(&hit_bucket, true));
        }
    }
    let p = mann_whitney_p(&hit, &miss);
    eprintln!(
        "matching parity: 21 Blocks × {n}; median hit {:.2} ms, median miss {:.2} ms, p = {p:.3}",
        median(&hit) * 1e3,
        median(&miss) * 1e3
    );
    assert!(p >= 0.01, "matching time depends on the match (p = {p:.4})");
}
