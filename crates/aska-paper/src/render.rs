//! Page rendering (DC-04 §8.1): a one-bit raster drawn from an embedded 5×7 bitmap font, so no
//! font engine, glyph cache or toolkit ever sees a pad digit. The raster lives in a
//! [`LockedBuf`] and is wiped on drop; the clients hand it to a printer (step 4) or show it
//! row by row for hand copying.
//!
//! Layout (A4 portrait): header with set code, page, label and checksum; the rules line; the
//! pad rows with index and check digit; the hand-tag key rows; the device-tag keys; then the
//! page's QR (numeric mode, error correction M) centred below, as large as the remaining height
//! allows (at most five pixels per module).

use crate::entropy::Label;
use crate::page::{Page, KEYS_PER_ROW};
use crate::LockedBuf;
use aska_core::qr::{self, QrMatrix};

/// Glyph columns and rows of the font.
pub const GLYPH_W: usize = 5;
pub const GLYPH_H: usize = 7;
/// Advance (glyph plus one blank column), in font units.
pub const ADVANCE: usize = 6;

/// 5×7 glyphs, one byte per row (low five bits, MSB = left column).
fn glyph(c: u8) -> [u8; GLYPH_H] {
    match c {
        b'0' => [0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E],
        b'1' => [0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E],
        b'2' => [0x0E, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1F],
        b'3' => [0x1F, 0x02, 0x04, 0x02, 0x01, 0x11, 0x0E],
        b'4' => [0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02],
        b'5' => [0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E],
        b'6' => [0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E],
        b'7' => [0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
        b'8' => [0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E],
        b'9' => [0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C],
        b'A' => [0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11],
        b'B' => [0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E],
        b'C' => [0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E],
        b'D' => [0x1C, 0x12, 0x11, 0x11, 0x11, 0x12, 0x1C],
        b'E' => [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F],
        b'F' => [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10],
        b'G' => [0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0F],
        b'H' => [0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11],
        b'I' => [0x0E, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E],
        b'J' => [0x07, 0x02, 0x02, 0x02, 0x02, 0x12, 0x0C],
        b'K' => [0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11],
        b'L' => [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F],
        b'M' => [0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11],
        b'N' => [0x11, 0x11, 0x19, 0x15, 0x13, 0x11, 0x11],
        b'O' => [0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E],
        b'P' => [0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10],
        b'Q' => [0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D],
        b'R' => [0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11],
        b'S' => [0x0F, 0x10, 0x10, 0x0E, 0x01, 0x01, 0x1E],
        b'T' => [0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        b'U' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E],
        b'V' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04],
        b'W' => [0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0A],
        b'X' => [0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11],
        b'Y' => [0x11, 0x11, 0x11, 0x0A, 0x04, 0x04, 0x04],
        b'Z' => [0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F],
        b'-' => [0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00],
        b'.' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x0C],
        b':' => [0x00, 0x0C, 0x0C, 0x00, 0x0C, 0x0C, 0x00],
        b'/' => [0x01, 0x01, 0x02, 0x04, 0x08, 0x10, 0x10],
        b'(' => [0x02, 0x04, 0x08, 0x08, 0x08, 0x04, 0x02],
        b')' => [0x08, 0x04, 0x02, 0x02, 0x02, 0x04, 0x08],
        b'*' => [0x00, 0x04, 0x15, 0x0E, 0x15, 0x04, 0x00],
        b'?' => [0x0E, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04],
        _ => [0x00; GLYPH_H], // space and anything unknown
    }
}

/// A one-bit raster, `1` = black, rows padded to whole bytes, in locked memory.
pub struct Raster {
    width: usize,
    height: usize,
    stride: usize,
    bits: LockedBuf,
}

impl std::fmt::Debug for Raster {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Raster({}×{}, <pixels redacted>)",
            self.width, self.height
        )
    }
}

impl Raster {
    pub fn new(width: usize, height: usize) -> Self {
        let stride = width.div_ceil(8);
        let mut bits = LockedBuf::with_capacity(stride * height);
        // LockedBuf is zero-filled; set the length.
        bits.extend_from_slice(&vec![0u8; stride * height]);
        Raster {
            width,
            height,
            stride,
            bits,
        }
    }

    pub fn width(&self) -> usize {
        self.width
    }
    pub fn height(&self) -> usize {
        self.height
    }
    pub fn stride(&self) -> usize {
        self.stride
    }
    /// Packed rows, MSB = leftmost pixel (the PBM P4 / PWG 1-bit layout).
    pub fn rows(&self) -> &[u8] {
        self.bits.as_slice()
    }

    #[inline]
    pub fn set(&mut self, x: usize, y: usize) {
        if x < self.width && y < self.height {
            self.bits.as_mut_slice()[y * self.stride + x / 8] |= 0x80 >> (x % 8);
        }
    }

    pub fn get(&self, x: usize, y: usize) -> bool {
        x < self.width
            && y < self.height
            && self.bits.as_slice()[y * self.stride + x / 8] & (0x80 >> (x % 8)) != 0
    }

    pub fn fill_rect(&mut self, x: usize, y: usize, w: usize, h: usize) {
        for yy in y..y + h {
            for xx in x..x + w {
                self.set(xx, yy);
            }
        }
    }

    /// Draw ASCII text with the bitmap font at `scale` pixels per font unit. Lower-case is
    /// drawn as upper-case. Returns the x position after the text.
    pub fn text(&mut self, x: usize, y: usize, scale: usize, s: &[u8]) -> usize {
        let mut cx = x;
        for &c in s {
            let g = glyph(c.to_ascii_uppercase());
            for (row, bits) in g.iter().enumerate() {
                for col in 0..GLYPH_W {
                    if bits & (0x10 >> col) != 0 {
                        self.fill_rect(cx + col * scale, y + row * scale, scale, scale);
                    }
                }
            }
            cx += ADVANCE * scale;
        }
        cx
    }

    /// Draw a QR symbol with `module` pixels per module and a four-module quiet zone (white).
    pub fn qr(&mut self, x: usize, y: usize, module: usize, m: &QrMatrix) {
        let n = m.size() as isize;
        for yy in 0..n {
            for xx in 0..n {
                if m.dark(xx, yy) {
                    self.fill_rect(
                        x + xx as usize * module,
                        y + yy as usize * module,
                        module,
                        module,
                    );
                }
            }
        }
    }

    /// The raster as a binary PBM (P4) image, in locked memory.
    pub fn to_pbm(&self) -> LockedBuf {
        let header = format!("P4\n{} {}\n", self.width, self.height);
        let mut out = LockedBuf::with_capacity(header.len() + self.bits.len());
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(self.bits.as_slice());
        out
    }

    /// Wipe now (also on drop).
    pub fn clear(&mut self) {
        self.bits.clear();
    }
}

/// Paper sizes in pixels at `dpi`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Paper {
    A4,
    Letter,
}

impl Paper {
    pub fn pixels(self, dpi: u32) -> (usize, usize) {
        let (w_in, h_in) = match self {
            Paper::A4 => (8.2677, 11.6929),
            Paper::Letter => (8.5, 11.0),
        };
        (
            (w_in * dpi as f64).round() as usize,
            (h_in * dpi as f64).round() as usize,
        )
    }
}

/// Rendering options.
#[derive(Debug, Clone, Copy)]
pub struct RenderOptions {
    pub dpi: u32,
    pub paper: Paper,
    /// Pixels per font unit (2 at 150 dpi gives 10 × 14 px glyphs, about 1.7 mm high).
    pub scale: usize,
    pub margin: usize,
}

impl Default for RenderOptions {
    fn default() -> Self {
        RenderOptions {
            dpi: 150,
            paper: Paper::A4,
            scale: 2,
            margin: 60,
        }
    }
}

/// The rules line printed on every page (DC-04 §3.6).
pub const RULES: &[u8] =
    b"USE ONCE - WRITE ON GLASS - NEVER PHOTOGRAPH - DISSOLVE AND STIR AFTER USE";

/// Render one pad page.
pub fn render_page(
    page: &Page,
    label: Label,
    opts: &RenderOptions,
) -> Result<Raster, crate::PaperError> {
    let (w, h) = opts.paper.pixels(opts.dpi);
    let mut r = Raster::new(w, h);
    let sc = opts.scale;
    let line = GLYPH_H * sc + 6 * sc / 2 + 2; // line height
    let mut y = opts.margin;
    let x0 = opts.margin;
    let spec = page.spec();
    let sum = page.checksum();

    // Header: SET 7342  PAGE A 03  N 400  PHYSICAL  CHECK 556377
    let mut head = Vec::with_capacity(80);
    head.extend_from_slice(
        format!(
            "SET {:04}  PAGE {} {:02}  N {}  ",
            spec.set_code,
            spec.direction.letter(),
            spec.number,
            spec.pad_len
        )
        .as_bytes(),
    );
    head.extend_from_slice(label.as_str().as_bytes());
    head.extend_from_slice(b"  CHECK ");
    head.extend_from_slice(&sum);
    r.text(x0, y, sc + 1, &head); // one size larger
    y += GLYPH_H * (sc + 1) + 8;
    r.text(x0, y, sc, RULES);
    y += line + line / 2;

    // Pad rows: "01  27974 91320 ... 51385  2"
    r.text(x0, y, sc, b"PAD");
    y += line;
    let mut buf = Vec::with_capacity(80);
    for (i, row, check) in page.pad_rows() {
        buf.clear();
        buf.extend_from_slice(format!("{i:02}  ").as_bytes());
        for (gi, g) in row.chunks(5).enumerate() {
            if gi > 0 {
                buf.push(b' ');
            }
            buf.extend_from_slice(g);
        }
        buf.extend_from_slice(format!("  {check}").as_bytes());
        r.text(x0, y, sc, &buf);
        y += line;
    }
    y += line / 2;

    // Hand-tag keys
    let krows = page.key_rows();
    if !krows.is_empty() {
        r.text(x0, y, sc, b"HAND TAG KEYS  A0 A1 ...  THEN B");
        y += line;
        for (first, row, check) in krows {
            buf.clear();
            if first == usize::MAX {
                buf.extend_from_slice(b"B     ");
            } else {
                buf.extend_from_slice(format!("A{first:03}  ").as_bytes());
            }
            for (gi, g) in row.chunks(crate::handtag::KEY_DIGITS).enumerate() {
                if gi > 0 {
                    buf.push(b' ');
                }
                buf.extend_from_slice(g);
            }
            if first != usize::MAX {
                // pad short last row so the check digit aligns
                let missing = KEYS_PER_ROW - row.len() / crate::handtag::KEY_DIGITS;
                for _ in 0..missing {
                    buf.extend_from_slice(b"     ");
                }
            }
            buf.extend_from_slice(format!("  {check}").as_bytes());
            r.text(x0, y, sc, &buf);
            y += line;
        }
        y += line / 2;
    }

    // Device-tag keys
    let c = page.canonical();
    let end = c.len();
    buf.clear();
    buf.extend_from_slice(b"DEVICE TAG KEYS  R ");
    buf.extend_from_slice(&c[end - 38..end - 19]);
    buf.extend_from_slice(b"  S ");
    buf.extend_from_slice(&c[end - 19..]);
    r.text(x0, y, sc, &buf);
    y += line + line / 2;
    use zeroize::Zeroize;
    buf.zeroize();

    // QR below, centred, as large as fits (max 5 px/module), quiet zone 4 modules.
    let payload = page.qr_payload();
    let text = std::str::from_utf8(payload.as_slice()).expect("digits");
    let matrix = qr::encode(text).map_err(|_| crate::PaperError::Page("QR too large"))?;
    let n = matrix.size() + 8;
    let avail_h = h.saturating_sub(y + opts.margin);
    let avail_w = w - 2 * opts.margin;
    let module = (avail_h.min(avail_w) / n).clamp(1, 5);
    if module < 2 {
        return Err(crate::PaperError::Page("page too small for its QR"));
    }
    let qx = (w - n * module) / 2 + 4 * module;
    let qy = y + 4 * module;
    r.qr(qx, qy, module, &matrix);
    Ok(r)
}

/// Rows of a page as plain text lines for the terminal or the hand-copy view (no header).
pub fn page_rows_text(page: &Page) -> Vec<LockedBuf> {
    let mut out = Vec::new();
    for (i, row, check) in page.pad_rows() {
        let mut l = LockedBuf::with_capacity(80);
        l.extend_from_slice(format!("{i:02}  ").as_bytes());
        for (gi, g) in row.chunks(5).enumerate() {
            if gi > 0 {
                l.extend_from_slice(b" ");
            }
            l.extend_from_slice(g);
        }
        l.extend_from_slice(format!("  {check}").as_bytes());
        out.push(l);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::{Direction, PageSpec};

    fn page(n: usize, hand: bool) -> Page {
        let spec = PageSpec {
            set_code: 7342,
            direction: Direction::A,
            number: 3,
            pad_len: n,
            hand_tag: hand,
        };
        let pad: Vec<u8> = (0..n).map(|i| b'0' + ((i * 7 + 3) % 10) as u8).collect();
        let keys: Vec<u8> = if hand {
            (0..n / 2 + 2)
                .flat_map(|i| format!("{:04}", (i * 97 + 11) % 9973).into_bytes())
                .collect()
        } else {
            Vec::new()
        };
        Page::assemble(
            spec,
            &pad,
            &keys,
            1_231_961_752_939_033_616,
            1_450_779_715_753_509_526,
        )
        .unwrap()
    }

    #[test]
    fn font_glyphs_are_distinct_for_digits() {
        let mut seen = std::collections::HashSet::new();
        for d in b'0'..=b'9' {
            assert!(seen.insert(glyph(d)));
        }
        assert_eq!(glyph(b' '), [0u8; 7]);
    }

    #[test]
    fn text_draws_pixels_and_qr_round_trips() {
        let mut r = Raster::new(100, 20);
        let end = r.text(2, 2, 1, b"A1");
        assert_eq!(end, 2 + 2 * ADVANCE);
        assert!(r.get(2 + 1, 2)); // top of the A
        assert!(!r.get(0, 0));
        let pbm = r.to_pbm();
        assert!(pbm.as_slice().starts_with(b"P4\n100 20\n"));
    }

    #[test]
    fn every_page_size_renders_on_a4_and_letter_and_the_qr_decodes() {
        for n in crate::page::PAD_LENGTHS {
            for hand in [true, false] {
                let p = page(n, hand);
                for paper in [Paper::A4, Paper::Letter] {
                    let opts = RenderOptions {
                        paper,
                        ..RenderOptions::default()
                    };
                    let r = render_page(&p, Label::Physical, &opts).unwrap();
                    assert_eq!(r.width(), paper.pixels(150).0);
                    let dark: usize = r.rows().iter().map(|b| b.count_ones() as usize).sum();
                    assert!(dark > 5000, "n={n} hand={hand} {paper:?}");
                }
                // Decode the rendered QR with the project's own decoder (greyscale raster).
                let opts = RenderOptions::default();
                let r = render_page(&p, Label::Seeded, &opts).unwrap();
                let (w, h) = (r.width(), r.height());
                let mut luma = vec![255u8; w * h];
                for y in 0..h {
                    for x in 0..w {
                        if r.get(x, y) {
                            luma[y * w + x] = 0;
                        }
                    }
                }
                let text = aska_scan::decode_luma(w, h, &luma).expect("QR decodes");
                let q = Page::parse_with_checksum(text.as_bytes()).unwrap();
                assert_eq!(q.canonical(), p.canonical());
            }
        }
    }

    #[test]
    fn rows_text_matches_pad_rows() {
        let p = page(200, false);
        let rows = page_rows_text(&p);
        assert_eq!(rows.len(), 4);
        assert!(rows[0].as_slice().starts_with(b"01  "));
    }
}
