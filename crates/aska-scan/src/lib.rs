//! In-process QR scanning for Aska (Client Design C-04, built in 1.1): frames come straight
//! from the camera into this process, are reduced to greyscale, searched for a QR code and
//! wiped — no helper process, no file, no frame leaving the process. The decoded text (a Key
//! Card, a Share or a Receiving Key) is returned in zeroising memory.
//!
//! Camera access is Video4Linux2 through `libc` alone (`v4l2` module): it works wherever the
//! user may read the device — Debian and Ubuntu (user in the `video` group), Tails, and a
//! Qubes qube with the camera attached. The desktop portal route (PipeWire) is not used: it
//! only adds value for sandboxed packaging, which Aska does not ship, and would add a C
//! library and generated bindings to every build. Cameras that offer only compressed formats
//! (MJPEG) are not read here; the clients then fall back to the external `zbarcam` helper.

pub mod v4l2;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

/// A greyscale frame handed to a preview callback: `w × h` bytes, row-major.
pub struct Preview {
    pub width: u32,
    pub height: u32,
    pub luma: Zeroizing<Vec<u8>>,
}

#[derive(Debug)]
pub enum ScanError {
    /// No `/dev/video*` device, or none that could be opened and read.
    NoCamera(String),
    /// Nothing decoded before the deadline.
    Timeout,
    /// The caller cancelled.
    Cancelled,
    Io(std::io::Error),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::NoCamera(why) => write!(f, "no usable camera: {why}"),
            ScanError::Timeout => write!(f, "no QR code seen before the time ran out"),
            ScanError::Cancelled => write!(f, "scan cancelled"),
            ScanError::Io(e) => write!(f, "camera error: {e}"),
        }
    }
}

impl std::error::Error for ScanError {}

impl From<std::io::Error> for ScanError {
    fn from(e: std::io::Error) -> Self {
        ScanError::Io(e)
    }
}

pub struct ScanOptions {
    /// A specific device; `None` tries `/dev/video*` in order.
    pub device: Option<PathBuf>,
    /// Give up after this long without a decode.
    pub timeout: Duration,
    /// Set by the caller to stop early.
    pub cancel: Arc<AtomicBool>,
    /// Longest side of the preview frames (0 = no preview).
    pub preview_size: u32,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            device: None,
            timeout: Duration::from_secs(90),
            cancel: Arc::new(AtomicBool::new(false)),
            preview_size: 0,
        }
    }
}

/// Open the camera and return the first QR code it sees. `on_preview` receives a downscaled
/// greyscale copy of frames as they arrive (for a viewfinder); it runs on the calling thread.
pub fn scan(
    opts: &ScanOptions,
    mut on_preview: impl FnMut(Preview),
) -> Result<Zeroizing<String>, ScanError> {
    let cam = open_any(opts.device.as_deref())?;
    let (w, h, fourcc) = (cam.width() as usize, cam.height() as usize, cam.fourcc());
    let deadline = Instant::now() + opts.timeout;
    let mut luma: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; w * h]);
    loop {
        if opts.cancel.load(Ordering::Relaxed) {
            return Err(ScanError::Cancelled);
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(ScanError::Timeout);
        }
        let wait = (deadline - now).min(Duration::from_millis(250));
        let Some(frame) = cam.next_frame(wait)? else {
            continue;
        };
        if !luma_into(fourcc, w, h, frame.data(), &mut luma) {
            continue; // a short frame; wait for the next
        }
        drop(frame);
        if opts.preview_size > 0 {
            on_preview(downscale(w, h, &luma, opts.preview_size));
        }
        if let Some(text) = decode_luma(w, h, &luma) {
            luma.zeroize();
            return Ok(text);
        }
    }
}

fn open_any(device: Option<&Path>) -> Result<v4l2::Camera, ScanError> {
    let candidates: Vec<PathBuf> = match device {
        Some(d) => vec![d.to_path_buf()],
        None => v4l2::devices(),
    };
    if candidates.is_empty() {
        return Err(ScanError::NoCamera("no /dev/video device".into()));
    }
    let mut last = String::new();
    for c in &candidates {
        match v4l2::Camera::open(c) {
            Ok(cam) => return Ok(cam),
            Err(e) => last = format!("{}: {e}", c.display()),
        }
    }
    Err(ScanError::NoCamera(last))
}

/// Extract 8-bit luma from a raw frame into `out` (`w × h`). `false` if the frame is too short.
pub fn luma_into(fourcc: u32, w: usize, h: usize, data: &[u8], out: &mut [u8]) -> bool {
    let n = w * h;
    if out.len() < n {
        return false;
    }
    match fourcc {
        v4l2::FOURCC_YUYV => {
            if data.len() < n * 2 {
                return false;
            }
            for (o, px) in out[..n].iter_mut().zip(data.chunks_exact(2)) {
                *o = px[0];
            }
        }
        v4l2::FOURCC_GREY | v4l2::FOURCC_NV12 | v4l2::FOURCC_YU12 => {
            if data.len() < n {
                return false;
            }
            out[..n].copy_from_slice(&data[..n]);
        }
        v4l2::FOURCC_RGB3 | v4l2::FOURCC_BGR3 => {
            if data.len() < n * 3 {
                return false;
            }
            let (ri, bi) = if fourcc == v4l2::FOURCC_RGB3 {
                (0, 2)
            } else {
                (2, 0)
            };
            for (o, px) in out[..n].iter_mut().zip(data.chunks_exact(3)) {
                let (r, g, b) = (px[ri] as u32, px[1] as u32, px[bi] as u32);
                *o = ((r * 77 + g * 150 + b * 29) >> 8) as u8;
            }
        }
        _ => return false,
    }
    true
}

/// Find and decode one QR code in a greyscale image. The first grid that decodes wins.
pub fn decode_luma(w: usize, h: usize, luma: &[u8]) -> Option<Zeroizing<String>> {
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| luma[y * w + x]);
    let grids = img.detect_grids();
    for g in grids {
        if let Ok((_meta, text)) = g.decode() {
            // rqrr hands back a plain String; move it into zeroising memory and let the
            // original be dropped (its heap is freed unwiped — a residual the GUI memory gate
            // tracks; the core wipes its own copy as usual).
            let out = Zeroizing::new(text.trim().to_string());
            if !out.is_empty() {
                return Some(out);
            }
        }
    }
    None
}

/// Nearest-neighbour downscale so the longest side is `max_side`.
pub fn downscale(w: usize, h: usize, luma: &[u8], max_side: u32) -> Preview {
    let max_side = max_side.max(1) as usize;
    let scale = (w.max(h)).div_ceil(max_side).max(1);
    let (pw, ph) = (w.div_ceil(scale), h.div_ceil(scale));
    let mut out = Zeroizing::new(vec![0u8; pw * ph]);
    for y in 0..ph {
        for x in 0..pw {
            out[y * pw + x] = luma[(y * scale).min(h - 1) * w + (x * scale).min(w - 1)];
        }
    }
    Preview {
        width: pw as u32,
        height: ph as u32,
        luma: out,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qrcode::{EcLevel, QrCode};

    /// Render `text` as a QR code into a synthetic camera frame: `scale` pixels per module,
    /// a quiet zone, placed at (`ox`, `oy`) in a `w × h` grey background, with `noise`
    /// (0–255) of pseudo-random speckle so the decoder is not handed a perfect bitmap.
    fn frame(
        text: &str,
        w: usize,
        h: usize,
        scale: usize,
        ox: usize,
        oy: usize,
        noise: u8,
    ) -> Vec<u8> {
        let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M).unwrap();
        let n = code.width();
        let mut img = vec![0x90u8; w * h];
        let mut seed = 0x9e37_79b9u32;
        for (i, px) in img.iter_mut().enumerate() {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            let _ = i;
            let d = (seed % (noise as u32 + 1)) as u8;
            *px = px.wrapping_sub(d / 2);
        }
        let quiet = 4 * scale;
        for y in 0..n * scale + 2 * quiet {
            for x in 0..n * scale + 2 * quiet {
                let (px, py) = (ox + x, oy + y);
                if px >= w || py >= h {
                    continue;
                }
                let inside =
                    x >= quiet && y >= quiet && x < quiet + n * scale && y < quiet + n * scale;
                let dark = inside
                    && code[((x - quiet) / scale, (y - quiet) / scale)] == qrcode::Color::Dark;
                let base: u8 = if dark { 20 } else { 235 };
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                let d = (seed % (noise as u32 + 1)) as u8;
                img[py * w + px] = if dark { base + d / 2 } else { base - d / 2 };
            }
        }
        img
    }

    #[test]
    fn decodes_key_card_sized_codes_from_a_noisy_frame() {
        // A Key Card with two relays is ~380 characters of bech32m; a Share ~80; a Receiving
        // Key with hints ~2 400 (QR version 40 holds 2 953 bytes at EC-L, 2 331 at EC-M).
        let bech = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        let card: String = std::iter::once("aska1")
            .chain(std::iter::repeat_n(bech, 12))
            .collect();
        let share: String = std::iter::once("askas1")
            .chain(std::iter::repeat_n(bech, 3))
            .collect();
        for (text, scale) in [(share.as_str(), 6), (card.as_str(), 4)] {
            let img = frame(text, 640, 480, scale, 40, 30, 40);
            let got = decode_luma(640, 480, &img).expect("decoded");
            assert_eq!(got.as_str(), text);
        }
        // Upper-case alphanumeric mode (what the clients' QR renderer uses).
        let upper = card.to_uppercase();
        let img = frame(&upper, 640, 480, 4, 20, 20, 30);
        assert_eq!(decode_luma(640, 480, &img).unwrap().as_str(), upper);
        // A receiving key: large; rendered at 2 px per module in a 1280×960 frame.
        let rk: String = std::iter::once("askar1")
            .chain(std::iter::repeat_n(bech, 70))
            .collect::<String>()
            .to_uppercase();
        let img = frame(&rk, 1280, 960, 2, 100, 60, 10);
        assert_eq!(decode_luma(1280, 960, &img).unwrap().as_str(), rk);
    }

    #[test]
    fn no_code_means_none_and_luma_extraction_handles_each_format() {
        let blank = vec![0x80u8; 320 * 240];
        assert!(decode_luma(320, 240, &blank).is_none());
        let (w, h) = (4usize, 2usize);
        let mut out = vec![0u8; w * h];
        // YUYV: Y0 U Y1 V …
        let mut yuyv = Vec::new();
        for i in 0..w * h / 2 {
            yuyv.extend_from_slice(&[(2 * i) as u8 * 10, 128, (2 * i + 1) as u8 * 10, 128]);
        }
        assert!(luma_into(v4l2::FOURCC_YUYV, w, h, &yuyv, &mut out));
        assert_eq!(out, (0..8).map(|i| i * 10).collect::<Vec<u8>>());
        let grey: Vec<u8> = (0..8).map(|i| 255 - i).collect();
        assert!(luma_into(v4l2::FOURCC_GREY, w, h, &grey, &mut out));
        assert_eq!(out, grey);
        let mut nv12 = grey.clone();
        nv12.extend_from_slice(&[128; 4]);
        assert!(luma_into(v4l2::FOURCC_NV12, w, h, &nv12, &mut out));
        assert_eq!(out, grey);
        let rgb: Vec<u8> = (0..8).flat_map(|_| [255u8, 255, 255]).collect();
        assert!(luma_into(v4l2::FOURCC_RGB3, w, h, &rgb, &mut out));
        assert!(out.iter().all(|&v| v >= 254));
        // Short frames are rejected, unknown formats too.
        assert!(!luma_into(v4l2::FOURCC_YUYV, w, h, &yuyv[..5], &mut out));
        assert!(!luma_into(v4l2::fourcc(b"MJPG"), w, h, &grey, &mut out));
        // Downscale keeps the aspect and the longest side.
        let p = downscale(640, 480, &vec![7u8; 640 * 480], 160);
        assert_eq!((p.width, p.height), (160, 120));
        assert!(p.luma.iter().all(|&v| v == 7));
    }
}
