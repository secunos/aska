//! QR encoding for hand-over (Client Design Table 2, `qr`): the module matrix and two terminal
//! renderings — half-block characters for legibility and plain ASCII as the fallback the
//! Prototype Plan asks for (M4 risk: terminal QR legibility). Decoding from camera frames
//! arrives with the graphical client (M5); the CLI reads scans from a helper process.
//!
//! Everything here is derived from key material — a Key Card QR *is* the key — so the matrix
//! and every rendered string are zeroised on drop. What the terminal emulator keeps of what it
//! displayed is outside this process (Client Design §7); the CLI uses the alternate screen and
//! clears it, which is the most a process can do.

use crate::error::Error;
use qrcode::{EcLevel, QrCode};
use zeroize::{Zeroize, Zeroizing};

/// A QR symbol as a square grid of modules (`1` = dark).
pub struct QrMatrix {
    size: usize,
    modules: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for QrMatrix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QrMatrix({}×{}, <redacted>)", self.size, self.size)
    }
}

impl QrMatrix {
    pub fn size(&self) -> usize {
        self.size
    }

    /// Dark module at (x, y)? Out-of-range is light (the quiet zone).
    pub fn dark(&self, x: isize, y: isize) -> bool {
        if x < 0 || y < 0 || x as usize >= self.size || y as usize >= self.size {
            return false;
        }
        self.modules[y as usize * self.size + x as usize] == 1
    }
}

/// Modules of quiet zone drawn around the symbol. The standard asks for four; two is what
/// every common terminal scanner copes with and keeps the symbol on screen.
pub const QUIET: isize = 2;

/// Encode text as a QR symbol (error correction M). Bech32m strings and BIP-39 words are
/// case-insensitive on decode, so they are upper-cased first: that lets the encoder use the
/// alphanumeric mode, which is about 40 % smaller than byte mode and scans more reliably.
pub fn encode(text: &str) -> Result<QrMatrix, Error> {
    let mut upper: Zeroizing<String> = Zeroizing::new(text.trim().to_ascii_uppercase());
    if upper.is_empty() {
        return Err(Error::Encoding);
    }
    let code = QrCode::with_error_correction_level(upper.as_bytes(), EcLevel::M)
        .map_err(|_| Error::Encoding)?;
    upper.zeroize();
    let size = code.width();
    let mut modules = Zeroizing::new(Vec::with_capacity(size * size));
    for c in code.to_colors() {
        modules.push(u8::from(c == qrcode::Color::Dark));
    }
    Ok(QrMatrix { size, modules })
}

/// Half-block rendering: two module rows per text line, dark-on-light forced with ANSI colours
/// so the symbol scans on any terminal theme. `ansi = false` gives the bare block characters
/// (for a light terminal or a file the user explicitly asked for).
pub fn render_half_block(m: &QrMatrix, ansi: bool) -> Zeroizing<String> {
    let (on, off) = if ansi {
        ("\x1b[30;107m", "\x1b[0m")
    } else {
        ("", "")
    };
    let n = m.size as isize;
    let mut out = Zeroizing::new(String::new());
    let mut y = -QUIET;
    while y < n + QUIET {
        out.push_str(on);
        for x in -QUIET..n + QUIET {
            let top = m.dark(x, y);
            let bottom = m.dark(x, y + 1);
            out.push(match (top, bottom) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        out.push_str(off);
        out.push('\n');
        y += 2;
    }
    out
}

/// ASCII rendering: two characters per module, `##` dark and spaces light, so the aspect ratio
/// is roughly square in a monospace font. Works everywhere, including over a serial console.
pub fn render_ascii(m: &QrMatrix) -> Zeroizing<String> {
    let n = m.size as isize;
    let mut out = Zeroizing::new(String::new());
    for y in -QUIET..n + QUIET {
        for x in -QUIET..n + QUIET {
            out.push_str(if m.dark(x, y) { "##" } else { "  " });
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_keycard_sized_text_and_renders_both_ways() {
        // A class-1 Key Card with one relay is about 130 bech32 characters.
        let text = format!("aska1{}", "q".repeat(125));
        let m = encode(&text).unwrap();
        assert!(m.size >= 21 && m.size % 4 == 1, "size {}", m.size);
        // Finder pattern corner is dark; quiet zone is light.
        assert!(m.dark(0, 0) && m.dark(6, 6));
        assert!(!m.dark(-1, 0) && !m.dark(m.size as isize, 0));
        let hb = render_half_block(&m, false);
        let lines = hb.lines().count();
        assert_eq!(lines, (m.size + 2 * QUIET as usize).div_ceil(2));
        let ascii = render_ascii(&m);
        assert_eq!(ascii.lines().count(), m.size + 2 * QUIET as usize);
        assert!(ascii.contains("##"));
    }

    #[test]
    fn words_upper_cased_fit_alphanumeric_mode() {
        let words = "abandon ".repeat(23) + "about";
        let m = encode(&words).unwrap();
        // 24 words ≈ 150 chars; alphanumeric mode at EC-M fits version ≤ 8 (49 modules).
        assert!(m.size <= 49, "size {}", m.size);
    }

    #[test]
    fn empty_input_is_an_error() {
        assert!(encode("   ").is_err());
    }
}
