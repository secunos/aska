//! The checkerboard (DC-04 §3.1, Table 1): a fixed, public, prefix-free code from a 37-symbol
//! alphabet (26 letters, space, ten digits) to decimal digits. Seven frequent letters take one
//! digit (0–6); the digits 7, 8 and 9 begin two-digit codes.
//!
//! The table is public — the security is in the pad — but the *text* and its digits are
//! secret, so both live in [`LockedBuf`]s and the lookups index fixed tables rather than
//! branching on secret values.

use crate::{LockedBuf, PaperError};

/// Single-digit symbols: index = code.
pub const ROW0: &[u8; 7] = b"ETAOINS";
/// Codes 70–79.
pub const ROW7: &[u8; 10] = b"RHLDCUMFPG";
/// Codes 80–89 (89 is the space).
pub const ROW8: &[u8; 10] = b"WYBVKXJQZ ";
/// Codes 90–99: the digits 0–9.
pub const ROW9: &[u8; 10] = b"0123456789";

/// Code of an alphabet symbol: `(first digit, second digit or 0xFF)`, or `None`.
/// Built from the four rows, so the table above is the single source of truth.
fn code_of(sym: u8) -> Option<(u8, u8)> {
    // A 128-entry table indexed by the ASCII byte; built once.
    static TABLE: std::sync::OnceLock<[(u8, u8); 128]> = std::sync::OnceLock::new();
    let t = TABLE.get_or_init(|| {
        let mut t = [(0xFFu8, 0xFFu8); 128];
        for (i, &c) in ROW0.iter().enumerate() {
            t[c as usize] = (i as u8, 0xFF);
        }
        for (row, syms) in [(7u8, ROW7), (8u8, ROW8), (9u8, ROW9)] {
            for (i, &c) in syms.iter().enumerate() {
                t[c as usize] = (row, i as u8);
            }
        }
        t
    });
    if sym >= 128 {
        return None;
    }
    let e = t[sym as usize];
    if e.0 == 0xFF {
        None
    } else {
        Some(e)
    }
}

/// Symbol of a code: `row` 0 with `col` 0–6, or rows 7–9 with `col` 0–9.
fn symbol_of(row: u8, col: u8) -> Option<u8> {
    match (row, col) {
        (0, 0..=6) => Some(ROW0[col as usize]),
        (7, 0..=9) => Some(ROW7[col as usize]),
        (8, 0..=9) => Some(ROW8[col as usize]),
        (9, 0..=9) => Some(ROW9[col as usize]),
        _ => None,
    }
}

/// Normalise one character of user text to alphabet symbols (DC-04 §3.1): NFKC is applied by
/// the caller on the whole string; here: upper case, the Nordic letters as AA/AE/OE, other
/// accented Latin letters to their base letter, anything else refused.
fn normalise_char(c: char, out: &mut Vec<u8>) -> Result<(), PaperError> {
    match c {
        'a'..='z' => out.push(c.to_ascii_uppercase() as u8),
        'A'..='Z' | '0'..='9' | ' ' => out.push(c as u8),
        '\n' | '\t' | '\r' => out.push(b' '),
        'å' | 'Å' => out.extend_from_slice(b"AA"),
        'ä' | 'Ä' | 'æ' | 'Æ' => out.extend_from_slice(b"AE"),
        'ö' | 'Ö' | 'ø' | 'Ø' => out.extend_from_slice(b"OE"),
        'ß' => out.extend_from_slice(b"SS"),
        'à' | 'á' | 'â' | 'ã' | 'À' | 'Á' | 'Â' | 'Ã' => out.push(b'A'),
        'ç' | 'Ç' => out.push(b'C'),
        'è' | 'é' | 'ê' | 'ë' | 'È' | 'É' | 'Ê' | 'Ë' => out.push(b'E'),
        'ì' | 'í' | 'î' | 'ï' | 'Ì' | 'Í' | 'Î' | 'Ï' => out.push(b'I'),
        'ñ' | 'Ñ' => out.push(b'N'),
        'ò' | 'ó' | 'ô' | 'õ' | 'Ò' | 'Ó' | 'Ô' | 'Õ' => out.push(b'O'),
        'ù' | 'ú' | 'û' | 'ü' | 'Ù' | 'Ú' | 'Û' | 'Ü' => out.push(b'U'),
        'ý' | 'ÿ' | 'Ý' => out.push(b'Y'),
        other => return Err(PaperError::Alphabet(other)),
    }
    Ok(())
}

/// Normalise text to alphabet symbols: NFKC, upper case, transliteration (§3.1). Runs of
/// whitespace become one space; leading and trailing spaces are dropped. Punctuation is refused
/// with the offending character so the client can say which.
pub fn normalise(text: &str) -> Result<LockedBuf, PaperError> {
    use zeroize::Zeroize;
    let mut syms: Vec<u8> = Vec::with_capacity(text.len() * 2);
    use unicode_normalization::UnicodeNormalization;
    for c in text.nfkc() {
        if let Err(e) = normalise_char(c, &mut syms) {
            syms.zeroize();
            return Err(e);
        }
    }
    // Collapse spaces and trim.
    let mut out = LockedBuf::with_capacity(syms.len().max(1));
    let mut prev_space = true;
    for &b in &syms {
        if b == b' ' {
            if !prev_space {
                out.extend_from_slice(b" ");
            }
            prev_space = true;
        } else {
            out.extend_from_slice(&[b]);
            prev_space = false;
        }
    }
    syms.zeroize();
    let n = out.len();
    if n > 0 && out.as_slice()[n - 1] == b' ' {
        out.truncate(n - 1);
    }
    Ok(out)
}

/// Encode normalised symbols (output of [`normalise`]) as checkerboard digits.
pub fn to_digits(symbols: &[u8]) -> Result<LockedBuf, PaperError> {
    let mut out = LockedBuf::with_capacity(symbols.len() * 2 + 1);
    for &s in symbols {
        let (a, b) = code_of(s).ok_or(PaperError::Alphabet(s as char))?;
        out.extend_from_slice(&[b'0' + a]);
        if b != 0xFF {
            out.extend_from_slice(&[b'0' + b]);
        }
    }
    Ok(out)
}

/// Text → digits in one step.
pub fn encode(text: &str) -> Result<LockedBuf, PaperError> {
    let mut syms = normalise(text)?;
    let d = to_digits(syms.as_slice());
    syms.clear();
    d
}

/// Decode checkerboard digits (ASCII) back to symbols. A dangling prefix digit at the end is
/// an error (`Digits`), as is anything that is not a digit.
pub fn from_digits(digits: &[u8]) -> Result<LockedBuf, PaperError> {
    if !crate::all_digits(digits) {
        return Err(PaperError::Digits("not a digit"));
    }
    let mut out = LockedBuf::with_capacity(digits.len().max(1));
    let mut i = 0;
    while i < digits.len() {
        let d = digits[i] - b'0';
        if d <= 6 {
            out.extend_from_slice(&[symbol_of(0, d).expect("row 0")]);
            i += 1;
        } else {
            if i + 1 >= digits.len() {
                out.clear();
                return Err(PaperError::Digits("a two-digit code is cut short"));
            }
            let e = digits[i + 1] - b'0';
            out.extend_from_slice(&[symbol_of(d, e).expect("rows 7-9")]);
            i += 2;
        }
    }
    Ok(out)
}

/// Digits needed for a text, without producing them (for "will it fit?" prompts).
pub fn digit_count(symbols: &[u8]) -> usize {
    symbols
        .iter()
        .map(|&s| match code_of(s) {
            Some((_, 0xFF)) => 1,
            Some(_) => 2,
            None => 0,
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_has_37_symbols_and_is_prefix_free() {
        let mut seen = std::collections::HashSet::new();
        for &c in ROW0.iter().chain(ROW7).chain(ROW8).chain(ROW9) {
            assert!(seen.insert(c), "duplicate symbol {}", c as char);
        }
        assert_eq!(seen.len(), 37);
        // Single digits are 0–6 only; 7, 8, 9 never stand alone.
        for s in seen {
            let (a, b) = code_of(s).unwrap();
            if b == 0xFF {
                assert!(a <= 6);
            } else {
                assert!(a >= 7);
            }
        }
    }

    #[test]
    fn worked_example_from_dc04() {
        let d = encode("MEET 14 NOV NORTH GATE").unwrap();
        assert_eq!(d.as_slice(), b"760018991948953838953701718979210");
        let back = from_digits(d.as_slice()).unwrap();
        assert_eq!(back.as_slice(), b"MEET 14 NOV NORTH GATE");
    }

    #[test]
    fn round_trip_every_symbol() {
        let all = "ETAOINSRHLDCUMFPGWYBVKXJQZ 0123456789";
        let d = encode(all).unwrap();
        assert_eq!(
            from_digits(d.as_slice()).unwrap().as_slice(),
            all.as_bytes()
        );
    }

    #[test]
    fn normalisation_rules() {
        assert_eq!(
            normalise("  Två   öl,  tack").unwrap_err().to_string(),
            "not in the paper alphabet: ','"
        );
        let n = normalise("  Två   öl  tack\n").unwrap();
        assert_eq!(n.as_slice(), b"TVAA OEL TACK");
        assert_eq!(normalise("Ångström").unwrap().as_slice(), b"AANGSTROEM");
        assert!(matches!(normalise("a.b"), Err(PaperError::Alphabet('.'))));
    }

    #[test]
    fn dangling_prefix_is_an_error() {
        assert!(from_digits(b"7").is_err());
        assert!(from_digits(b"07").is_err());
        assert!(from_digits(b"0x").is_err());
        assert_eq!(from_digits(b"").unwrap().len(), 0);
    }
}
