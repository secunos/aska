//! Min-entropy estimate and health tests on raw 8-bit samples (DC-04 §4.3 steps 2–3).
//!
//! The estimate is the smaller of two figures — the most-common-value estimate (−log₂ of an
//! upper confidence bound on the largest probability, the direct min-entropy estimate) and the
//! collision entropy (−log₂ of an upper confidence bound on Σpᵢ²; it bounds min-entropy from
//! above, so it only tightens the figure when a flat-looking distribution hides structure) —
//! then **halved** as a margin for correlation between neighbouring samples and frames, then
//! **capped at 4 bits** per 8-bit sample. It is a heuristic, as every entropy estimate is; the
//! margin and the cap are the design's answer, and the raw figures are kept in the [`Report`]
//! so an expert can judge.
//!
//! The health tests are the two continuous tests of NIST SP 800-90B §4.4 — repetition count
//! and adaptive proportion — with cutoffs derived from the estimate at a false-alarm rate of
//! 2⁻²⁰.

use crate::PaperError;

/// Fewest samples for an estimate.
pub const MIN_SAMPLES: usize = 16_384;
/// Cap on the estimate (bits per 8-bit sample).
pub const CAP_BITS: f64 = 4.0;
/// Below this the source is refused.
pub const FLOOR_BITS: f64 = 0.25;
/// Adaptive-proportion window.
pub const APT_WINDOW: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Report {
    pub samples: usize,
    /// Most-common-value estimate before margin and cap.
    pub mcv_bits: f64,
    /// Collision estimate before margin and cap.
    pub collision_bits: f64,
    /// The figure used: min(mcv, collision) / 2, capped.
    pub bits_per_sample: f64,
    pub cap_applied: bool,
}

/// Estimate the min-entropy per sample.
pub fn min_entropy(samples: &[u8]) -> Result<Report, PaperError> {
    let n = samples.len();
    if n < MIN_SAMPLES {
        return Err(PaperError::Entropy(format!(
            "only {n} samples; at least {MIN_SAMPLES} are needed for an estimate"
        )));
    }
    let mut counts = [0u64; 256];
    for &s in samples {
        counts[s as usize] += 1;
    }
    let nf = n as f64;
    let z = 2.576; // 99 % one-sided-ish bound as in SP 800-90B
    let max = *counts.iter().max().expect("256 entries") as f64;
    let p_hat = max / nf;
    let p_u = (p_hat + z * (p_hat * (1.0 - p_hat) / nf).sqrt()).min(1.0);
    let mcv_bits = -p_u.log2();
    let coll: f64 = counts
        .iter()
        .map(|&c| (c as f64) * (c as f64 - 1.0))
        .sum::<f64>()
        / (nf * (nf - 1.0));
    let coll_u = (coll + z * (coll * (1.0 - coll) / nf).sqrt()).min(1.0);
    let collision_bits = -coll_u.log2();
    let raw = mcv_bits.min(collision_bits) / 2.0;
    let cap_applied = raw > CAP_BITS;
    let bits = raw.min(CAP_BITS);
    if bits < FLOOR_BITS {
        return Err(PaperError::Entropy(format!(
            "the source gives about {bits:.2} bits per sample after the margin; it is not usable — \
             cover the lens or point the camera at a textured, moving scene"
        )));
    }
    Ok(Report {
        samples: n,
        mcv_bits,
        collision_bits,
        bits_per_sample: bits,
        cap_applied,
    })
}

/// Repetition-count cutoff for an assumed entropy `h` per sample at α = 2⁻²⁰: C = 1 + ⌈20/h⌉.
pub fn rct_cutoff(h: f64) -> usize {
    1 + (20.0 / h).ceil() as usize
}

/// Adaptive-proportion cutoff: the smallest C such that P(Binomial(W, 2⁻ʰ) ≥ C) ≤ 2⁻²⁰.
pub fn apt_cutoff(h: f64) -> usize {
    let w = APT_WINDOW as f64;
    let p = 2f64.powf(-h);
    // Cumulative binomial via log-space pmf.
    let ln_choose = |n: f64, k: f64| ln_gamma(n + 1.0) - ln_gamma(k + 1.0) - ln_gamma(n - k + 1.0);
    let mut cum = 0.0f64;
    let target = 1.0 - 2f64.powi(-20);
    for k in 0..=APT_WINDOW {
        let kf = k as f64;
        let lp = ln_choose(w, kf) + kf * p.ln() + (w - kf) * (1.0 - p).ln();
        cum += lp.exp();
        if cum >= target {
            return k + 1;
        }
    }
    APT_WINDOW + 1
}

/// Lanczos approximation of ln Γ(x), x > 0.
fn ln_gamma(x: f64) -> f64 {
    const G: f64 = 7.0;
    const C: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if x < 0.5 {
        return (std::f64::consts::PI / (std::f64::consts::PI * x).sin()).ln() - ln_gamma(1.0 - x);
    }
    let x = x - 1.0;
    let mut a = C[0];
    let t = x + G + 0.5;
    for (i, &c) in C.iter().enumerate().skip(1) {
        a += c / (x + i as f64);
    }
    0.5 * (2.0 * std::f64::consts::PI).ln() + (x + 0.5) * t.ln() - t + a.ln()
}

/// The two continuous health tests over the whole raw stream.
pub fn health_tests(samples: &[u8], h: f64) -> Result<(), PaperError> {
    let rct = rct_cutoff(h);
    let mut run = 1usize;
    for w in samples.windows(2) {
        if w[0] == w[1] {
            run += 1;
            if run >= rct {
                return Err(PaperError::Entropy(format!(
                    "repetition-count test failed: a value repeated {run} times (cutoff {rct}) — \
                     the source is stuck"
                )));
            }
        } else {
            run = 1;
        }
    }
    let apt = apt_cutoff(h);
    for window in samples.chunks(APT_WINDOW) {
        if window.len() < APT_WINDOW {
            break;
        }
        let first = window[0];
        let count = window.iter().filter(|&&s| s == first).count();
        if count >= apt {
            return Err(PaperError::Entropy(format!(
                "adaptive-proportion test failed: a value filled {count} of {APT_WINDOW} samples \
                 (cutoff {apt}) — the source is biased"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cutoffs_are_sane() {
        assert_eq!(rct_cutoff(1.0), 21);
        assert_eq!(rct_cutoff(4.0), 6);
        // Exact binomial figures for W = 512, α = 2⁻²⁰ (checked with exact rational
        // arithmetic): h = 1 → 311, h = 2 → 177, h = 4 → 62.
        assert_eq!(apt_cutoff(1.0), 311);
        assert_eq!(apt_cutoff(2.0), 177);
        assert_eq!(apt_cutoff(4.0), 62);
        assert!((ln_gamma(5.0) - 24f64.ln()).abs() < 1e-9);
    }

    #[test]
    fn full_entropy_is_near_the_cap_and_constant_is_refused() {
        let mut v = vec![0u8; 65536];
        getrandom::getrandom(&mut v).unwrap();
        let r = min_entropy(&v).unwrap();
        // With 65 536 samples over 256 values the confidence bound on the most common value
        // keeps the MCV figure near 7.5 bits, so the halved estimate lands just under the cap.
        assert!(
            r.bits_per_sample >= 3.5 && r.bits_per_sample <= CAP_BITS,
            "{r:?}"
        );
        assert!(
            r.mcv_bits > 7.0 && r.collision_bits > 7.5 && !r.cap_applied,
            "{r:?}"
        );
        health_tests(&v, r.bits_per_sample).unwrap();
        assert!(min_entropy(&[7u8; 65536]).is_err());
        assert!(min_entropy(&v[..1000]).is_err());
    }

    #[test]
    fn a_biased_source_is_estimated_low() {
        // Two values, 90/10: min-entropy 0.152 bits; after the margin ≈ 0.07 → refused.
        let v: Vec<u8> = (0..65536u32)
            .map(|i| if i % 10 == 0 { 1 } else { 0 })
            .collect();
        assert!(min_entropy(&v).is_err());
        // 16 equiprobable values: 4 bits (both figures) → halved to 2 (no cap).
        let v: Vec<u8> = (0..65536u32).map(|i| ((i * 7919) % 16) as u8).collect();
        let r = min_entropy(&v).unwrap();
        assert!((1.9..=2.0).contains(&r.bits_per_sample), "{r:?}");
    }
}
