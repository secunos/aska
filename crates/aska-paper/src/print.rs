//! Printing (DC-04 §5.2): the checks a client makes before a pad page goes to a printer, the
//! IPP client that talks to the local CUPS over its domain socket, and the PostScript that
//! carries a page raster.
//!
//! Rules enforced here, not in the clients: a pad is printed only when the **spool directory
//! is on volatile storage** (tmpfs or ramfs — the job file would otherwise sit on disk after
//! the job is "deleted"), and only to a printer whose **device URI is `usb://`** (a network
//! printer receives the job in clear and may keep it; `cups-pdf:` and `file:` would write a
//! file). The job name is a fixed word. The job travels as PostScript built in locked memory
//! from the raster — through the socket, never through a temporary file.
//!
//! What this cannot prevent and the clients must say: CUPS's `page_log`/`error_log` and the
//! printer's own job counter still record that a job of so many pages was printed.

use crate::render::Raster;
use crate::{LockedBuf, PaperError};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// The spool directory CUPS uses by default (`RequestRoot` in cups-files.conf).
pub const SPOOL_DIR: &str = "/var/spool/cups";
/// The local CUPS domain socket.
pub const CUPS_SOCKET: &str = "/run/cups/cups.sock";
/// Every job carries this name and nothing else.
pub const JOB_NAME: &str = "Document";

/// Why a pad page may not be printed here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The spool is on persistent storage (or could not be examined: the reason).
    SpoolPersistent(String),
    /// The chosen printer is not a locally attached USB printer: its device URI's scheme.
    NotUsb(String),
    /// No printer of that name.
    NoSuchPrinter(String),
    /// CUPS could not be reached.
    NoCups(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::SpoolPersistent(why) => write!(
                f,
                "the print spool ({SPOOL_DIR}) is not on volatile storage ({why}) — a printed pad would be kept on disk; print on an amnesic system or copy the page by hand"
            ),
            Refusal::NotUsb(scheme) => write!(
                f,
                "the printer is reached over `{scheme}`, not USB — the job would travel over the network or into a file; pads go only to a locally attached printer"
            ),
            Refusal::NoSuchPrinter(n) => write!(f, "no printer named {n:?}"),
            Refusal::NoCups(e) => write!(f, "{e}"),
        }
    }
}

/// Is the spool directory on tmpfs or ramfs? Decided from the mount table (`/proc/self/mounts`):
/// the longest mount point that is a prefix of the path decides, so a bind mount or a tmpfs
/// mounted exactly on the spool directory is recognised.
pub fn spool_is_volatile() -> Result<(), Refusal> {
    spool_is_volatile_at(SPOOL_DIR)
}

pub fn spool_is_volatile_at(path: &str) -> Result<(), Refusal> {
    let mounts = std::fs::read_to_string("/proc/self/mounts")
        .map_err(|e| Refusal::SpoolPersistent(format!("cannot read the mount table: {e}")))?;
    if !std::path::Path::new(path).is_dir() {
        return Err(Refusal::SpoolPersistent(format!("{path} does not exist")));
    }
    match fs_type_of(&mounts, path) {
        Some(ty) if ty == "tmpfs" || ty == "ramfs" => Ok(()),
        Some(ty) => Err(Refusal::SpoolPersistent(format!("filesystem type {ty}"))),
        None => Err(Refusal::SpoolPersistent("no mount point found".into())),
    }
}

/// The filesystem type of the mount holding `path`, from a mount table in `/proc/mounts` form.
fn fs_type_of(mounts: &str, path: &str) -> Option<String> {
    let mut best: Option<(usize, String)> = None;
    for line in mounts.lines() {
        let mut f = line.split(' ');
        let (Some(_dev), Some(mp), Some(ty)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        let mp = mp.replace("\\040", " ");
        let is_prefix = mp == "/"
            || path == mp
            || (path.starts_with(&mp) && path.as_bytes().get(mp.len()) == Some(&b'/'));
        if is_prefix && best.as_ref().is_none_or(|(l, _)| mp.len() >= *l) {
            best = Some((mp.len(), ty.to_string()));
        }
    }
    best.map(|(_, t)| t)
}

/// A printer as CUPS lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Printer {
    pub name: String,
    pub device_uri: String,
    /// IPP printer-state: 3 idle, 4 processing, 5 stopped.
    pub state: u32,
}

impl Printer {
    /// Scheme of the device URI (`usb`, `ipp`, `socket`, `cups-pdf`, …).
    pub fn scheme(&self) -> &str {
        self.device_uri.split(':').next().unwrap_or("")
    }

    pub fn is_usb(&self) -> bool {
        self.scheme() == "usb"
    }
}

/// Check a printer for pad printing: USB only.
pub fn check_printer(p: &Printer) -> Result<(), Refusal> {
    if p.is_usb() {
        Ok(())
    } else {
        Err(Refusal::NotUsb(p.scheme().to_string()))
    }
}

// ---------------------------------------------------------------------------------------------
// IPP

const OP_PRINT_JOB: u16 = 0x0002;
const OP_CUPS_GET_PRINTERS: u16 = 0x4002;
const TAG_OPERATION: u8 = 0x01;
const TAG_PRINTER: u8 = 0x04;
const TAG_END: u8 = 0x03;
const TAG_INTEGER: u8 = 0x21;
const TAG_ENUM: u8 = 0x23;
const TAG_NAME: u8 = 0x42;
const TAG_KEYWORD: u8 = 0x44;
const TAG_URI: u8 = 0x45;
const TAG_CHARSET: u8 = 0x47;
const TAG_LANGUAGE: u8 = 0x48;
const TAG_MIME: u8 = 0x49;

fn attr(buf: &mut Vec<u8>, tag: u8, name: &str, value: &[u8]) {
    buf.push(tag);
    buf.extend_from_slice(&(name.len() as u16).to_be_bytes());
    buf.extend_from_slice(name.as_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buf.extend_from_slice(value);
}

fn request_head(op: u16, printer_uri: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(256);
    b.extend_from_slice(&[0x02, 0x00]); // IPP/2.0
    b.extend_from_slice(&op.to_be_bytes());
    b.extend_from_slice(&1u32.to_be_bytes()); // request-id
    b.push(TAG_OPERATION);
    attr(&mut b, TAG_CHARSET, "attributes-charset", b"utf-8");
    attr(&mut b, TAG_LANGUAGE, "attributes-natural-language", b"en");
    attr(&mut b, TAG_URI, "printer-uri", printer_uri.as_bytes());
    attr(&mut b, TAG_NAME, "requesting-user-name", b"aska");
    b
}

/// One decoded attribute.
struct Attr {
    group: u8,
    tag: u8,
    name: String,
    value: Vec<u8>,
}

fn parse_response(body: &[u8]) -> Result<(u16, Vec<Attr>), PaperError> {
    if body.len() < 8 {
        return Err(PaperError::Print("short IPP response".into()));
    }
    let status = u16::from_be_bytes([body[2], body[3]]);
    let mut attrs = Vec::new();
    let mut i = 8;
    let mut group = 0u8;
    let mut last_name = String::new();
    while i < body.len() {
        let tag = body[i];
        i += 1;
        if tag == TAG_END {
            break;
        }
        if tag < 0x10 {
            group = tag;
            continue;
        }
        if i + 2 > body.len() {
            break;
        }
        let nl = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        i += 2;
        if i + nl > body.len() {
            break;
        }
        let name = if nl == 0 {
            last_name.clone()
        } else {
            String::from_utf8_lossy(&body[i..i + nl]).into_owned()
        };
        i += nl;
        if i + 2 > body.len() {
            break;
        }
        let vl = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        i += 2;
        if i + vl > body.len() {
            break;
        }
        let value = body[i..i + vl].to_vec();
        i += vl;
        last_name = name.clone();
        attrs.push(Attr {
            group,
            tag,
            name,
            value,
        });
    }
    Ok((status, attrs))
}

/// POST an IPP request (plus optional document data) to CUPS over its socket; return the body.
fn post(path: &str, ipp: &[u8], document: Option<&[u8]>) -> Result<Vec<u8>, PaperError> {
    let mut s = UnixStream::connect(CUPS_SOCKET)
        .map_err(|e| PaperError::Print(format!("cannot reach {CUPS_SOCKET}: {e}")))?;
    s.set_read_timeout(Some(Duration::from_secs(30))).ok();
    s.set_write_timeout(Some(Duration::from_secs(30))).ok();
    let len = ipp.len() + document.map_or(0, <[u8]>::len);
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/ipp\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n"
    );
    s.write_all(head.as_bytes()).map_err(io_err)?;
    s.write_all(ipp).map_err(io_err)?;
    if let Some(d) = document {
        s.write_all(d).map_err(io_err)?;
    }
    s.flush().map_err(io_err)?;
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).map_err(io_err)?;
    let sep = find(&resp, b"\r\n\r\n")
        .ok_or_else(|| PaperError::Print("malformed HTTP response".into()))?;
    let headers = String::from_utf8_lossy(&resp[..sep]).to_ascii_lowercase();
    if !headers.starts_with("http/1.1 200") && !headers.starts_with("http/1.0 200") {
        let line = headers.lines().next().unwrap_or("").to_string();
        return Err(PaperError::Print(format!("print system answered: {line}")));
    }
    let body = &resp[sep + 4..];
    if headers.contains("transfer-encoding: chunked") {
        Ok(dechunk(body))
    } else {
        Ok(body.to_vec())
    }
}

fn io_err(e: std::io::Error) -> PaperError {
    PaperError::Print(format!("print system: {e}"))
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(nl) = find(b, b"\r\n") {
        let size_str = String::from_utf8_lossy(&b[..nl]);
        let size = usize::from_str_radix(size_str.trim().split(';').next().unwrap_or("0"), 16)
            .unwrap_or(0);
        b = &b[nl + 2..];
        if size == 0 || b.len() < size {
            break;
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size..];
        if b.starts_with(b"\r\n") {
            b = &b[2..];
        }
    }
    out
}

/// The printers CUPS knows, with their device URIs.
pub fn list_printers() -> Result<Vec<Printer>, Refusal> {
    let mut req = request_head(OP_CUPS_GET_PRINTERS, "ipp://localhost/");
    attr(
        &mut req,
        TAG_KEYWORD,
        "requested-attributes",
        b"printer-name",
    );
    attr(&mut req, TAG_KEYWORD, "", b"device-uri");
    attr(&mut req, TAG_KEYWORD, "", b"printer-state");
    req.push(TAG_END);
    let body = post("/", &req, None).map_err(|e| Refusal::NoCups(e.to_string()))?;
    let (status, attrs) = parse_response(&body).map_err(|e| Refusal::NoCups(e.to_string()))?;
    if status == 0x0406 {
        return Ok(Vec::new()); // not-found: no printers
    }
    if status > 0x00ff {
        return Err(Refusal::NoCups(format!("IPP status 0x{status:04x}")));
    }
    let mut out = Vec::new();
    let mut cur: Option<Printer> = None;
    for a in attrs.into_iter().filter(|a| a.group == TAG_PRINTER) {
        if a.name == "printer-name" {
            if let Some(p) = cur.take() {
                out.push(p);
            }
            cur = Some(Printer {
                name: String::from_utf8_lossy(&a.value).into_owned(),
                device_uri: String::new(),
                state: 0,
            });
        } else if let Some(p) = cur.as_mut() {
            match a.name.as_str() {
                "device-uri" => p.device_uri = String::from_utf8_lossy(&a.value).into_owned(),
                "printer-state"
                    if (a.tag == TAG_ENUM || a.tag == TAG_INTEGER) && a.value.len() == 4 =>
                {
                    p.state = u32::from_be_bytes([a.value[0], a.value[1], a.value[2], a.value[3]]);
                }
                _ => {}
            }
        }
    }
    if let Some(p) = cur.take() {
        out.push(p);
    }
    Ok(out)
}

/// Find a printer by name.
pub fn find_printer(name: &str) -> Result<Printer, Refusal> {
    list_printers()?
        .into_iter()
        .find(|p| p.name == name)
        .ok_or_else(|| Refusal::NoSuchPrinter(name.to_string()))
}

/// Submit a PostScript document to `printer`. Returns the job id. Performs **no** policy
/// check — callers use [`pad_print_checks`] first for pad material.
pub fn print_postscript(printer: &Printer, document: &[u8]) -> Result<u32, PaperError> {
    let uri = format!("ipp://localhost/printers/{}", printer.name);
    let mut req = request_head(OP_PRINT_JOB, &uri);
    attr(&mut req, TAG_NAME, "job-name", JOB_NAME.as_bytes());
    attr(
        &mut req,
        TAG_MIME,
        "document-format",
        b"application/postscript",
    );
    req.push(TAG_END);
    let body = post(&format!("/printers/{}", printer.name), &req, Some(document))?;
    let (status, attrs) = parse_response(&body)?;
    if status > 0x00ff {
        return Err(PaperError::Print(format!(
            "the print system refused the job (IPP status 0x{status:04x})"
        )));
    }
    let id = attrs
        .iter()
        .find(|a| a.name == "job-id" && a.value.len() == 4)
        .map(|a| u32::from_be_bytes([a.value[0], a.value[1], a.value[2], a.value[3]]))
        .unwrap_or(0);
    Ok(id)
}

/// Every check a pad page needs before printing: volatile spool, USB printer.
pub fn pad_print_checks(printer: &Printer) -> Result<(), Refusal> {
    spool_is_volatile()?;
    check_printer(printer)
}

// ---------------------------------------------------------------------------------------------
// PostScript

/// PostScript (Level 2) carrying one or more page rasters as `imagemask`s at `dpi`, in locked
/// memory. The hex data doubles the raster's size; an A4 page at 150 dpi is about 550 KB.
pub fn postscript(pages: &[&Raster], dpi: u32) -> LockedBuf {
    let total: usize = pages
        .iter()
        .map(|r| r.rows().len() * 2 + r.rows().len() / 40 + 512)
        .sum();
    let mut out = LockedBuf::with_capacity(total + 256);
    out.extend_from_slice(b"%!PS-Adobe-3.0\n");
    out.extend_from_slice(format!("%%Pages: {}\n%%EndComments\n", pages.len()).as_bytes());
    for (i, r) in pages.iter().enumerate() {
        let (w, h) = (r.width(), r.height());
        let pw = w as f64 * 72.0 / dpi as f64;
        let ph = h as f64 * 72.0 / dpi as f64;
        out.extend_from_slice(
            format!(
                "%%Page: {n} {n}\n<< /PageSize [{pw:.2} {ph:.2}] >> setpagedevice\ngsave\n{pw:.2} {ph:.2} scale\n{w} {h} true [{w} 0 0 -{h} 0 {h}] currentfile /ASCIIHexDecode filter imagemask\n",
                n = i + 1
            )
            .as_bytes(),
        );
        // Hex of the packed rows; 1 bits paint (imagemask with polarity true).
        let mut line = [0u8; 80];
        let mut col = 0;
        for &b in r.rows() {
            line[col] = HEX[(b >> 4) as usize];
            line[col + 1] = HEX[(b & 15) as usize];
            col += 2;
            if col == 80 {
                out.extend_from_slice(&line);
                out.extend_from_slice(b"\n");
                col = 0;
            }
        }
        if col > 0 {
            out.extend_from_slice(&line[..col]);
            out.extend_from_slice(b"\n");
        }
        out.extend_from_slice(b">\ngrestore\nshowpage\n");
    }
    out.extend_from_slice(b"%%EOF\n");
    out
}

const HEX: &[u8; 16] = b"0123456789abcdef";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spool_check_recognises_tmpfs_and_disk() {
        let table = "rootfs / ext4 rw 0 0\ntmpfs /dev/shm tmpfs rw 0 0\ntmpfs /var/spool/cups tmpfs rw 0 0\nnone /var/spool/cups\\040x ramfs rw 0 0\n/dev/sda1 /var ext4 rw 0 0\n";
        assert_eq!(
            fs_type_of(table, "/var/spool/cups").as_deref(),
            Some("tmpfs")
        );
        assert_eq!(
            fs_type_of(table, "/var/spool/cups x").as_deref(),
            Some("ramfs")
        );
        assert_eq!(
            fs_type_of(table, "/var/spool/cupsd").as_deref(),
            Some("ext4")
        ); // not a prefix match
        assert_eq!(fs_type_of(table, "/var/log").as_deref(), Some("ext4"));
        assert_eq!(fs_type_of(table, "/etc").as_deref(), Some("ext4"));
        // The live system: /dev/shm is tmpfs; / is not; a missing directory is refused.
        assert!(spool_is_volatile_at("/dev/shm").is_ok());
        assert!(matches!(
            spool_is_volatile_at("/"),
            Err(Refusal::SpoolPersistent(_))
        ));
        assert!(matches!(
            spool_is_volatile_at("/no/such/dir"),
            Err(Refusal::SpoolPersistent(_))
        ));
    }

    #[test]
    fn printer_policy() {
        let usb = Printer {
            name: "p".into(),
            device_uri: "usb://Brother/HL-L2350DW?serial=X".into(),
            state: 3,
        };
        let net = Printer {
            name: "n".into(),
            device_uri: "ipp://192.0.2.1/ipp/print".into(),
            state: 3,
        };
        let pdf = Printer {
            name: "f".into(),
            device_uri: "cups-pdf:/".into(),
            state: 3,
        };
        assert!(check_printer(&usb).is_ok());
        assert_eq!(check_printer(&net), Err(Refusal::NotUsb("ipp".into())));
        assert_eq!(check_printer(&pdf), Err(Refusal::NotUsb("cups-pdf".into())));
    }

    #[test]
    fn ipp_request_and_response_coding() {
        let mut req = request_head(OP_PRINT_JOB, "ipp://localhost/printers/x");
        attr(&mut req, TAG_NAME, "job-name", JOB_NAME.as_bytes());
        req.push(TAG_END);
        assert_eq!(&req[..2], &[2, 0]);
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), OP_PRINT_JOB);
        assert_eq!(req[8], TAG_OPERATION);
        // A hand-built response: status 0x0000, one printer with two attributes (and an
        // additional value with an empty name).
        let mut resp = vec![2, 0, 0, 0, 0, 0, 0, 1, TAG_OPERATION];
        attr(&mut resp, TAG_CHARSET, "attributes-charset", b"utf-8");
        resp.push(TAG_PRINTER);
        attr(&mut resp, TAG_NAME, "printer-name", b"lp0");
        attr(&mut resp, TAG_URI, "device-uri", b"usb://X/Y");
        resp.push(TAG_ENUM);
        resp.extend_from_slice(&13u16.to_be_bytes());
        resp.extend_from_slice(b"printer-state");
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&3u32.to_be_bytes());
        attr(&mut resp, TAG_KEYWORD, "", b"second-value");
        resp.push(TAG_END);
        let (status, attrs) = parse_response(&resp).unwrap();
        assert_eq!(status, 0);
        assert_eq!(attrs.len(), 5);
        assert_eq!(attrs[4].name, "printer-state"); // additional value inherits the name
        assert!(attrs
            .iter()
            .any(|a| a.group == TAG_PRINTER && a.name == "device-uri"));
        // Chunked decoding.
        let chunked = b"4\r\nabcd\r\n2\r\nef\r\n0\r\n\r\n";
        assert_eq!(dechunk(chunked), b"abcdef");
    }

    #[test]
    fn postscript_shape() {
        let mut r = Raster::new(16, 2);
        r.set(0, 0);
        r.set(15, 1);
        let ps = postscript(&[&r, &r], 150);
        let s = std::str::from_utf8(ps.as_slice()).unwrap();
        assert!(s.starts_with("%!PS-Adobe-3.0\n%%Pages: 2\n"));
        assert!(s.contains(
            "16 2 true [16 0 0 -2 0 2] currentfile /ASCIIHexDecode filter imagemask\n80000001\n>\n"
        ));
        assert_eq!(s.matches("showpage").count(), 2);
        assert!(s.ends_with("%%EOF\n"));
    }

    /// End to end through a real PostScript interpreter when one is installed (Ghostscript in
    /// CI): a rendered page → PostScript → raster → the page QR decodes with the project's own
    /// decoder. Skipped silently where `gs` is absent.
    #[test]
    fn postscript_renders_and_the_page_qr_decodes_through_ghostscript() {
        if std::process::Command::new("gs")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("gs not installed; skipping");
            return;
        }
        use crate::page::{Direction, Page, PageSpec};
        use crate::render::{render_page, RenderOptions};
        let spec = PageSpec {
            set_code: 7342,
            direction: Direction::A,
            number: 3,
            pad_len: 200,
            hand_tag: false,
        };
        let pad: Vec<u8> = (0..200).map(|i| b'0' + ((i * 7 + 3) % 10) as u8).collect();
        let page = Page::assemble(
            spec,
            &pad,
            &[],
            1_231_961_752_939_033_616,
            1_450_779_715_753_509_526,
        )
        .unwrap();
        let opts = RenderOptions::default();
        let raster = render_page(&page, crate::entropy::Label::Seeded, &opts).unwrap();
        let ps = postscript(&[&raster], opts.dpi);
        let (w, h) = (raster.width(), raster.height());
        let mut gs = std::process::Command::new("gs")
            .args([
                "-q",
                "-dNOPAUSE",
                "-dBATCH",
                "-dSAFER",
                "-sDEVICE=pgmraw",
                &format!("-r{}", opts.dpi),
                &format!("-g{w}x{h}"),
                "-sOutputFile=-",
                "-",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        {
            let mut stdin = gs.stdin.take().unwrap();
            stdin.write_all(ps.as_slice()).unwrap();
        }
        let out = gs.wait_with_output().unwrap();
        assert!(out.status.success());
        // The raster is the last w*h bytes of the PGM (the header carries a comment line).
        let data = &out.stdout;
        assert!(data.len() >= w * h);
        let luma = &data[data.len() - w * h..];
        // Top-left header pixel of the page is white; some pixel of the QR is black.
        assert_eq!(luma[0], 255);
        let decoded = aska_scan::decode_luma(w, h, luma).expect("the printed page's QR decodes");
        let back = Page::parse_with_checksum(decoded.as_bytes()).unwrap();
        assert_eq!(back.canonical(), page.canonical());
    }
}
