//! The camera as a raw source (DC-04 §4.2): the least-significant bits of the luma plane,
//! through the 1.1.0 Video4Linux2 capture layer. With the lens covered the bits are sensor
//! dark noise; pointed at a textured, moving scene they are scene plus noise. Eight pixel LSBs
//! (taken at a stride, so a frame's samples spread over the sensor) make one 8-bit sample.
//!
//! Frames never leave the capture layer except as these bits: the luma buffer is zeroising and
//! the kernel buffers are blanked by `aska-scan` when the camera closes.

use super::RawSource;
use crate::PaperError;
use aska_scan::v4l2::Camera;
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

/// Pixel stride between sampled LSBs.
pub const STRIDE: usize = 8;
/// Frames the estimate must span before a booklet may be finished.
pub const MIN_FRAMES: usize = 60;

pub struct CameraSource {
    cam: Camera,
    luma: Zeroizing<Vec<u8>>,
    frames: usize,
    name: String,
}

impl CameraSource {
    /// Open `device`, or the first usable `/dev/video*`.
    pub fn open(device: Option<&Path>) -> Result<Self, PaperError> {
        let candidates = match device {
            Some(d) => vec![d.to_path_buf()],
            None => aska_scan::v4l2::devices(),
        };
        if candidates.is_empty() {
            return Err(PaperError::Entropy("no camera device".into()));
        }
        let mut last = String::new();
        for c in &candidates {
            match Camera::open(c) {
                Ok(cam) => {
                    let n = cam.width() as usize * cam.height() as usize;
                    return Ok(CameraSource {
                        cam,
                        luma: Zeroizing::new(vec![0u8; n]),
                        frames: 0,
                        name: format!("camera {}", c.display()),
                    });
                }
                Err(e) => last = format!("{}: {e}", c.display()),
            }
        }
        Err(PaperError::Entropy(format!("no usable camera: {last}")))
    }

    pub fn frames(&self) -> usize {
        self.frames
    }

    /// Samples one frame yields.
    pub fn samples_per_frame(&self) -> usize {
        self.luma.len() / STRIDE / 8
    }
}

impl RawSource for CameraSource {
    fn pull(&mut self, out: &mut [u8]) -> Result<usize, PaperError> {
        let (w, h, fourcc) = (
            self.cam.width() as usize,
            self.cam.height() as usize,
            self.cam.fourcc(),
        );
        let frame = match self.cam.next_frame(Duration::from_millis(500)) {
            Ok(Some(f)) => f,
            Ok(None) => return Ok(0),
            Err(e) => return Err(PaperError::Entropy(format!("camera: {e}"))),
        };
        if !aska_scan::luma_into(fourcc, w, h, frame.data(), &mut self.luma) {
            return Ok(0);
        }
        drop(frame);
        self.frames += 1;
        let mut n = 0usize;
        let mut acc = 0u8;
        let mut nbits = 0;
        for px in self.luma.iter().step_by(STRIDE) {
            acc = (acc << 1) | (px & 1);
            nbits += 1;
            if nbits == 8 {
                if n >= out.len() {
                    break;
                }
                out[n] = acc;
                n += 1;
                acc = 0;
                nbits = 0;
            }
        }
        for b in self.luma.iter_mut() {
            *b = 0;
        }
        Ok(n)
    }

    fn spread_enough(&self) -> bool {
        self.frames >= MIN_FRAMES
    }

    fn describe(&self) -> String {
        format!(
            "{} ({}×{}, {} frames, stride {STRIDE})",
            self.name,
            self.cam.width(),
            self.cam.height(),
            self.frames
        )
    }
}
