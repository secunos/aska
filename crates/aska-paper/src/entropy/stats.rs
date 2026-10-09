//! Statistical tests on a finished booklet's pad digits (DC-04 §4.3 step 7): frequency,
//! serial (pairs), adjacent repeats and longest run — rejection at p < 10⁻³. These catch gross
//! faults (a stuck source, a broken mixer); they are the last line, not the first.

use crate::PaperError;

/// χ² critical value, 9 degrees of freedom, p = 0.001.
const CHI2_9: f64 = 27.877;
/// χ² critical value, 99 degrees of freedom, p = 0.001.
const CHI2_99: f64 = 148.230;
/// Two-sided normal critical value for p = 0.001.
const Z: f64 = 3.291;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DigitStats {
    pub digits: usize,
    pub chi2_frequency: f64,
    /// `None` when fewer than 2 000 digits (the pair test needs them).
    pub chi2_serial: Option<f64>,
    pub repeats_z: f64,
    pub longest_run: usize,
}

/// Run every test on ASCII digits; `Err` names the first failure.
pub fn test_digits(digits: &[u8]) -> Result<DigitStats, PaperError> {
    let n = digits.len();
    if n < 200 {
        return Err(PaperError::Entropy("too few digits to test".into()));
    }
    let mut freq = [0f64; 10];
    let mut pairs = [0f64; 100];
    let mut repeats = 0usize;
    let mut longest = 1usize;
    let mut run = 1usize;
    let mut prev: Option<u8> = None;
    for &b in digits {
        let d = b.wrapping_sub(b'0');
        if d > 9 {
            return Err(PaperError::Digits("not a digit"));
        }
        freq[d as usize] += 1.0;
        if let Some(p) = prev {
            pairs[(p * 10 + d) as usize] += 1.0;
            if p == d {
                repeats += 1;
                run += 1;
                longest = longest.max(run);
            } else {
                run = 1;
            }
        }
        prev = Some(d);
    }
    let nf = n as f64;
    let e = nf / 10.0;
    let chi2_frequency: f64 = freq.iter().map(|&o| (o - e) * (o - e) / e).sum();
    let chi2_serial = if n >= 2_000 {
        let ep = (nf - 1.0) / 100.0;
        Some(pairs.iter().map(|&o| (o - ep) * (o - ep) / ep).sum::<f64>())
    } else {
        None
    };
    let m = nf - 1.0;
    let repeats_z = (repeats as f64 - 0.1 * m) / (m * 0.1 * 0.9).sqrt();
    let stats = DigitStats {
        digits: n,
        chi2_frequency,
        chi2_serial,
        repeats_z,
        longest_run: longest,
    };
    if chi2_frequency > CHI2_9 {
        return Err(PaperError::Entropy(format!(
            "digit frequencies are not uniform (χ² = {chi2_frequency:.1})"
        )));
    }
    if let Some(s) = chi2_serial {
        if s > CHI2_99 {
            return Err(PaperError::Entropy(format!(
                "digit pairs are not uniform (χ² = {s:.1})"
            )));
        }
    }
    if repeats_z.abs() > Z {
        return Err(PaperError::Entropy(format!(
            "adjacent repeats are off (z = {repeats_z:.2})"
        )));
    }
    let max_run = (nf.log10().floor() as usize) + 4;
    if longest > max_run {
        return Err(PaperError::Entropy(format!(
            "a digit repeated {longest} times in a row (limit {max_run})"
        )));
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_digits_pass_and_patterns_fail() {
        let mut bytes = vec![0u8; 20_000];
        getrandom::getrandom(&mut bytes).unwrap();
        let digits: Vec<u8> = bytes
            .iter()
            .filter(|&&b| b < 250)
            .map(|&b| b'0' + b % 10)
            .collect();
        let s = test_digits(&digits).unwrap();
        assert!(s.chi2_serial.is_some());
        // Counter pattern: pairs are far from uniform.
        let seq: Vec<u8> = (0..5_000u32).map(|i| b'0' + (i % 10) as u8).collect();
        assert!(test_digits(&seq).is_err());
        // A long run.
        let mut d = digits.clone();
        for b in d[100..110].iter_mut() {
            *b = b'7';
        }
        assert!(test_digits(&d).is_err());
        assert!(test_digits(&digits[..100]).is_err());
    }
}
