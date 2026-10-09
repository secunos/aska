//! Modulo-10 one-time pad arithmetic (DC-04 §3.2). Inputs and outputs are ASCII digits in
//! locked memory. The pad is used from its first digit; the caller decides what to do with the
//! page afterwards (destroy it — the page is the only record of which digits were spent).

use crate::{all_digits, LockedBuf, PaperError};

/// cᵢ = (mᵢ + kᵢ) mod 10. Errors if the message is longer than the pad or not digits.
pub fn encipher(message: &[u8], pad: &[u8]) -> Result<LockedBuf, PaperError> {
    combine(message, pad, |m, k| (m + k) % 10)
}

/// mᵢ = (cᵢ − kᵢ) mod 10.
pub fn decipher(cipher: &[u8], pad: &[u8]) -> Result<LockedBuf, PaperError> {
    combine(cipher, pad, |c, k| (c + 10 - k) % 10)
}

fn combine(a: &[u8], pad: &[u8], f: impl Fn(u8, u8) -> u8) -> Result<LockedBuf, PaperError> {
    if !all_digits(a) || !all_digits(pad) {
        return Err(PaperError::Digits("not a digit"));
    }
    if a.len() > pad.len() {
        return Err(PaperError::TooLong {
            need: a.len(),
            have: pad.len(),
        });
    }
    let mut out = LockedBuf::with_capacity(a.len().max(1));
    for (&x, &k) in a.iter().zip(pad) {
        out.extend_from_slice(&[b'0' + f(x - b'0', k - b'0')]);
    }
    Ok(out)
}

/// The pad that turns `cipher` into `innocent` — a cover pad (DC-04 §3.7): k′ = c − m′ mod 10.
/// Both must have the same length.
pub fn cover_pad(cipher: &[u8], innocent: &[u8]) -> Result<LockedBuf, PaperError> {
    if cipher.len() != innocent.len() {
        return Err(PaperError::TooLong {
            need: innocent.len(),
            have: cipher.len(),
        });
    }
    decipher(cipher, innocent)
}

/// Pad a digit string with the space code (89) towards `len` digits (device-path length
/// hiding, DC-04 Q-5). Only whole `89` pairs are added, so the result has `len` or `len − 1`
/// digits and always decodes; the decoder's caller trims the trailing spaces.
pub fn pad_with_spaces(message: &[u8], len: usize) -> Result<LockedBuf, PaperError> {
    if !all_digits(message) {
        return Err(PaperError::Digits("not a digit"));
    }
    if message.len() > len {
        return Err(PaperError::TooLong {
            need: message.len(),
            have: len,
        });
    }
    let mut out = LockedBuf::with_capacity(len.max(1));
    out.extend_from_slice(message);
    while out.len() + 2 <= len {
        out.extend_from_slice(b"89");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dc04_example() {
        let m = b"760018991948953838953701718979210";
        let pad = b"279749132099457148372454626642375951480946439196613631751385";
        let c = encipher(m, pad).unwrap();
        assert_eq!(c.as_slice(), b"939757023937300976225155334511585");
        assert_eq!(decipher(c.as_slice(), pad).unwrap().as_slice(), m);
    }

    #[test]
    fn cover_pad_decrypts_to_the_innocent_text() {
        let c = b"939757023937300976225155334511585";
        let inn = crate::checkerboard::encode("SEE YOU ON SUNDAY LOVE").unwrap();
        let k2 = cover_pad(c, inn.as_slice()).unwrap();
        assert_eq!(k2.as_slice(), b"339969996458052019778837255898755");
        let m2 = decipher(c, k2.as_slice()).unwrap();
        assert_eq!(
            crate::checkerboard::from_digits(m2.as_slice())
                .unwrap()
                .as_slice(),
            b"SEE YOU ON SUNDAY LOVE"
        );
    }

    #[test]
    fn length_and_digit_checks() {
        assert!(matches!(
            encipher(b"123", b"12"),
            Err(PaperError::TooLong { need: 3, have: 2 })
        ));
        assert!(encipher(b"1a", b"12").is_err());
        assert!(encipher(b"12", b"1x").is_err());
        let p = pad_with_spaces(b"12", 7).unwrap();
        assert_eq!(p.as_slice(), b"128989");
    }
}
