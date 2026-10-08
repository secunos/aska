//! A minimal Video4Linux2 capture layer: open a `/dev/videoN` device, pick a raw pixel format,
//! map a few kernel buffers and dequeue frames. Written against the stable V4L2 user-space ABI
//! (`linux/videodev2.h`) with `libc` only — no C library, no generated bindings — so it adds
//! nothing to the build machine's requirements. The structure sizes and `ioctl` request
//! numbers below are the authoritative ones (checked by `tests::abi_matches_the_kernel_headers`
//! against the values a C compiler produces from the headers).
//!
//! Only what the scanner needs is implemented: single-planar video capture over `mmap`
//! streaming. Every `unsafe` is one `libc` call with a pointer to a local or to a mapping
//! this module owns.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::time::Duration;

// ---------------------------------------------------------------- constants (videodev2.h)

pub const BUF_TYPE_VIDEO_CAPTURE: u32 = 1;
pub const MEMORY_MMAP: u32 = 1;
pub const FIELD_ANY: u32 = 0;
pub const CAP_VIDEO_CAPTURE: u32 = 0x0000_0001;
pub const CAP_STREAMING: u32 = 0x0400_0000;

/// Four-character codes of the raw formats the luma extractor understands, in order of
/// preference: packed YUYV (what nearly every UVC webcam offers at 640×480), 8-bit grey, the
/// planar YUV families (luma plane first), then packed RGB/BGR.
pub const FOURCC_YUYV: u32 = fourcc(b"YUYV");
pub const FOURCC_GREY: u32 = fourcc(b"GREY");
pub const FOURCC_NV12: u32 = fourcc(b"NV12");
pub const FOURCC_YU12: u32 = fourcc(b"YU12");
pub const FOURCC_RGB3: u32 = fourcc(b"RGB3");
pub const FOURCC_BGR3: u32 = fourcc(b"BGR3");
pub const PREFERRED_FORMATS: [u32; 6] = [
    FOURCC_YUYV,
    FOURCC_GREY,
    FOURCC_NV12,
    FOURCC_YU12,
    FOURCC_RGB3,
    FOURCC_BGR3,
];

pub const fn fourcc(c: &[u8; 4]) -> u32 {
    (c[0] as u32) | (c[1] as u32) << 8 | (c[2] as u32) << 16 | (c[3] as u32) << 24
}

// `_IOC(dir, 'V', nr, size)` as the kernel encodes it on every Linux architecture Aska
// supports (x86-64 and aarch64 share the generic layout).
const IOC_WRITE: u64 = 1;
const IOC_READ: u64 = 2;
const fn ioc(dir: u64, nr: u64, size: u64) -> u64 {
    dir << 30 | size << 16 | (b'V' as u64) << 8 | nr
}
const VIDIOC_QUERYCAP: u64 = ioc(IOC_READ, 0, 104);
const VIDIOC_ENUM_FMT: u64 = ioc(IOC_READ | IOC_WRITE, 2, 64);
const VIDIOC_S_FMT: u64 = ioc(IOC_READ | IOC_WRITE, 5, 208);
const VIDIOC_REQBUFS: u64 = ioc(IOC_READ | IOC_WRITE, 8, 20);
const VIDIOC_QUERYBUF: u64 = ioc(IOC_READ | IOC_WRITE, 9, 88);
const VIDIOC_QBUF: u64 = ioc(IOC_READ | IOC_WRITE, 15, 88);
const VIDIOC_DQBUF: u64 = ioc(IOC_READ | IOC_WRITE, 17, 88);
const VIDIOC_STREAMON: u64 = ioc(IOC_WRITE, 18, 4);
const VIDIOC_STREAMOFF: u64 = ioc(IOC_WRITE, 19, 4);

// ---------------------------------------------------------------- structures (x86-64/aarch64)

#[repr(C)]
struct Capability {
    driver: [u8; 16],
    card: [u8; 32],
    bus_info: [u8; 32],
    version: u32,
    capabilities: u32,
    device_caps: u32,
    reserved: [u32; 3],
}

#[repr(C)]
struct FmtDesc {
    index: u32,
    type_: u32,
    flags: u32,
    description: [u8; 32],
    pixelformat: u32,
    mbus_code: u32,
    reserved: [u32; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PixFormat {
    width: u32,
    height: u32,
    pixelformat: u32,
    field: u32,
    bytesperline: u32,
    sizeimage: u32,
    colorspace: u32,
    priv_: u32,
    flags: u32,
    ycbcr_enc: u32,
    quantization: u32,
    xfer_func: u32,
}

/// `struct v4l2_format`: the type, 4 bytes of padding (the union is 8-aligned), then a
/// 200-byte union of which only the single-planar `pix` member is used.
#[repr(C)]
struct Format {
    type_: u32,
    _pad: u32,
    pix: PixFormat,
    _rest: [u8; 200 - 48],
}

#[repr(C)]
struct RequestBuffers {
    count: u32,
    type_: u32,
    memory: u32,
    capabilities: u32,
    flags: u8,
    reserved: [u8; 3],
}

#[repr(C)]
struct Timecode {
    type_: u32,
    flags: u32,
    frames: u8,
    seconds: u8,
    minutes: u8,
    hours: u8,
    userbits: [u8; 4],
}

#[repr(C)]
struct Buffer {
    index: u32,
    type_: u32,
    bytesused: u32,
    flags: u32,
    field: u32,
    timestamp: libc::timeval,
    timecode: Timecode,
    sequence: u32,
    memory: u32,
    /// The `m` union: `offset` for MMAP buffers (the other members are wider; 8 bytes).
    m: u64,
    length: u32,
    reserved2: u32,
    request_fd: i32,
}

fn zeroed<T>() -> T {
    // SAFETY: every structure above is plain data for which all-zero is a valid value.
    unsafe { std::mem::zeroed() }
}

fn ioctl<T>(fd: RawFd, req: u64, arg: &mut T) -> io::Result<()> {
    loop {
        // SAFETY: `arg` is a valid, exclusively borrowed structure of the size the request
        // encodes; the kernel reads/writes within it.
        let r = unsafe { libc::ioctl(fd, req as _, arg as *mut T) };
        if r == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

// ---------------------------------------------------------------- the device

struct Mapping {
    ptr: *mut libc::c_void,
    len: usize,
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // The buffer held frames of the key material; blank it before giving the pages back.
        // SAFETY: ptr/len are the mapping made in `Camera::open`.
        unsafe {
            std::ptr::write_bytes(self.ptr.cast::<u8>(), 0, self.len);
            libc::munmap(self.ptr, self.len);
        }
    }
}

/// An open, streaming capture device.
pub struct Camera {
    fd: OwnedFd,
    maps: Vec<Mapping>,
    width: u32,
    height: u32,
    fourcc: u32,
    streaming: bool,
}

/// One dequeued frame: the bytes of a kernel buffer, requeued when dropped.
pub struct Frame<'a> {
    cam: &'a Camera,
    index: u32,
    used: usize,
}

impl Frame<'_> {
    pub fn data(&self) -> &[u8] {
        let m = &self.cam.maps[self.index as usize];
        // SAFETY: the mapping is valid for `len` bytes while `cam` lives; `used <= len`.
        unsafe { std::slice::from_raw_parts(m.ptr.cast::<u8>(), self.used.min(m.len)) }
    }
}

impl Drop for Frame<'_> {
    fn drop(&mut self) {
        let _ = self.cam.queue(self.index);
    }
}

impl Camera {
    /// Open `path` (e.g. `/dev/video0`), choose the first of `PREFERRED_FORMATS` the device
    /// offers, ask for about 640×480 (the driver may adjust), map four buffers and start
    /// streaming.
    pub fn open(path: &Path) -> io::Result<Camera> {
        let c = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path"))?;
        // SAFETY: a NUL-terminated path; flags are plain constants.
        let raw = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a descriptor we just opened and own.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let r = fd.as_raw_fd();

        let mut cap: Capability = zeroed();
        ioctl(r, VIDIOC_QUERYCAP, &mut cap)?;
        let caps = if cap.device_caps != 0 {
            cap.device_caps
        } else {
            cap.capabilities
        };
        if caps & CAP_VIDEO_CAPTURE == 0 || caps & CAP_STREAMING == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "not a streaming video capture device",
            ));
        }

        // Formats the device offers, in its order; pick our most preferred among them.
        let mut offered = Vec::new();
        for index in 0..64u32 {
            let mut d: FmtDesc = zeroed();
            d.index = index;
            d.type_ = BUF_TYPE_VIDEO_CAPTURE;
            match ioctl(r, VIDIOC_ENUM_FMT, &mut d) {
                Ok(()) => offered.push(d.pixelformat),
                Err(_) => break,
            }
        }
        let Some(&fourcc) = PREFERRED_FORMATS.iter().find(|f| offered.contains(f)) else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the camera offers no raw format this scanner reads (only compressed ones)",
            ));
        };

        let mut fmt: Format = zeroed();
        fmt.type_ = BUF_TYPE_VIDEO_CAPTURE;
        fmt.pix.width = 640;
        fmt.pix.height = 480;
        fmt.pix.pixelformat = fourcc;
        fmt.pix.field = FIELD_ANY;
        ioctl(r, VIDIOC_S_FMT, &mut fmt)?;
        if fmt.pix.pixelformat != fourcc || fmt.pix.width == 0 || fmt.pix.height == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the camera did not accept a raw format",
            ));
        }
        let (width, height) = (fmt.pix.width, fmt.pix.height);

        let mut req: RequestBuffers = zeroed();
        req.count = 4;
        req.type_ = BUF_TYPE_VIDEO_CAPTURE;
        req.memory = MEMORY_MMAP;
        ioctl(r, VIDIOC_REQBUFS, &mut req)?;
        if req.count < 2 {
            return Err(io::Error::other("too few capture buffers"));
        }
        let mut maps = Vec::with_capacity(req.count as usize);
        for index in 0..req.count {
            let mut b: Buffer = zeroed();
            b.index = index;
            b.type_ = BUF_TYPE_VIDEO_CAPTURE;
            b.memory = MEMORY_MMAP;
            ioctl(r, VIDIOC_QUERYBUF, &mut b)?;
            let len = b.length as usize;
            let offset = (b.m & 0xffff_ffff) as libc::off_t;
            // SAFETY: mapping a device buffer the driver described; checked for failure.
            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    r,
                    offset,
                )
            };
            if ptr == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            // Frames of key material must never reach a core dump.
            // SAFETY: advice on a mapping we own.
            unsafe { libc::madvise(ptr, len, libc::MADV_DONTDUMP) };
            maps.push(Mapping { ptr, len });
        }
        let mut cam = Camera {
            fd,
            maps,
            width,
            height,
            fourcc,
            streaming: false,
        };
        for i in 0..cam.maps.len() as u32 {
            cam.queue(i)?;
        }
        let mut t = BUF_TYPE_VIDEO_CAPTURE;
        ioctl(cam.fd.as_raw_fd(), VIDIOC_STREAMON, &mut t)?;
        cam.streaming = true;
        Ok(cam)
    }

    pub fn width(&self) -> u32 {
        self.width
    }
    pub fn height(&self) -> u32 {
        self.height
    }
    pub fn fourcc(&self) -> u32 {
        self.fourcc
    }

    fn queue(&self, index: u32) -> io::Result<()> {
        let mut b: Buffer = zeroed();
        b.index = index;
        b.type_ = BUF_TYPE_VIDEO_CAPTURE;
        b.memory = MEMORY_MMAP;
        ioctl(self.fd.as_raw_fd(), VIDIOC_QBUF, &mut b)
    }

    /// The next frame, waiting at most `timeout`; `Ok(None)` when none arrived in time.
    pub fn next_frame(&self, timeout: Duration) -> io::Result<Option<Frame<'_>>> {
        let mut p = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: one pollfd, count 1.
        let n = unsafe { libc::poll(&mut p, 1, ms) };
        if n < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::Interrupted {
                Ok(None)
            } else {
                Err(e)
            };
        }
        if n == 0 {
            return Ok(None);
        }
        let mut b: Buffer = zeroed();
        b.type_ = BUF_TYPE_VIDEO_CAPTURE;
        b.memory = MEMORY_MMAP;
        match ioctl(self.fd.as_raw_fd(), VIDIOC_DQBUF, &mut b) {
            Ok(()) => Ok(Some(Frame {
                cam: self,
                index: b.index,
                used: b.bytesused as usize,
            })),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl Drop for Camera {
    fn drop(&mut self) {
        if self.streaming {
            let mut t = BUF_TYPE_VIDEO_CAPTURE;
            let _ = ioctl(self.fd.as_raw_fd(), VIDIOC_STREAMOFF, &mut t);
        }
        // Mappings are blanked and unmapped by their own Drop, before the descriptor closes.
    }
}

/// Capture devices present: `/dev/video*`, lowest number first.
pub fn devices() -> Vec<std::path::PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir("/dev")
        .map(|d| {
            d.filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                        n.starts_with("video") && n[5..].chars().all(|c| c.is_ascii_digit())
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values a C compiler produces from `linux/videodev2.h` on x86-64 (recorded when
    /// this module was written; the V4L2 user-space ABI is frozen).
    #[test]
    fn abi_matches_the_kernel_headers() {
        assert_eq!(std::mem::size_of::<Capability>(), 104);
        assert_eq!(std::mem::size_of::<FmtDesc>(), 64);
        assert_eq!(std::mem::size_of::<PixFormat>(), 48);
        assert_eq!(std::mem::size_of::<Format>(), 208);
        assert_eq!(std::mem::size_of::<RequestBuffers>(), 20);
        assert_eq!(std::mem::size_of::<Buffer>(), 88);
        assert_eq!(std::mem::offset_of!(Buffer, m), 64);
        assert_eq!(std::mem::offset_of!(Buffer, length), 72);
        assert_eq!(std::mem::offset_of!(Buffer, bytesused), 8);
        assert_eq!(std::mem::offset_of!(Format, pix), 8);
        assert_eq!(std::mem::offset_of!(FmtDesc, pixelformat), 44);
        assert_eq!(VIDIOC_QUERYCAP, 0x8068_5600);
        assert_eq!(VIDIOC_ENUM_FMT, 0xc040_5602);
        assert_eq!(VIDIOC_S_FMT, 0xc0d0_5605);
        assert_eq!(VIDIOC_REQBUFS, 0xc014_5608);
        assert_eq!(VIDIOC_QUERYBUF, 0xc058_5609);
        assert_eq!(VIDIOC_QBUF, 0xc058_560f);
        assert_eq!(VIDIOC_DQBUF, 0xc058_5611);
        assert_eq!(VIDIOC_STREAMON, 0x4004_5612);
        assert_eq!(VIDIOC_STREAMOFF, 0x4004_5613);
        assert_eq!(FOURCC_YUYV, 0x5659_5559);
        assert_eq!(FOURCC_NV12, 0x3231_564e);
        assert_eq!(FOURCC_GREY, 0x5945_5247);
        assert_eq!(FOURCC_YU12, 0x3231_5559);
        assert_eq!(FOURCC_RGB3, 0x3342_4752);
        assert_eq!(FOURCC_BGR3, 0x3352_4742);
        assert_eq!(CAP_VIDEO_CAPTURE, 0x1);
        assert_eq!(CAP_STREAMING, 0x0400_0000);
    }

    #[test]
    fn a_missing_device_is_an_error_not_a_panic() {
        assert!(Camera::open(Path::new("/dev/video-none")).is_err());
        let _ = devices();
    }
}
