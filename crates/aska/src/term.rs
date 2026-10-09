//! Terminal I/O for the CLI. Everything the user types or sees that is secret passes through
//! here: passphrases with echo off, key material lines, the hand-over screens and the note
//! viewer on the alternate screen (cleared on exit), and single keypresses with a timeout so
//! the Session's idle watchdog can be mirrored on screen.
//!
//! Two input modes (Client Design §4): interactive, through `/dev/tty` so prompts work even
//! when stdin carries data; and `--stdin`, where every input is a line of standard input in a
//! documented order and no prompt is ever printed. Secrets never come from `argv` or the
//! environment. The only `unsafe` in this crate is the termios and poll calls below, each a
//! single libc call with a pointer to a local it outlives, and the `dup(0)` that gives
//! `--stdin` mode an unbuffered descriptor of its own.
//!
//! **No input buffer outlives the line it belongs to** (pre-review C-10, fixed in 1.1): bytes
//! are read one at a time with `read(2)` straight into a fixed-capacity `LockedBuf` (pinned,
//! excluded from dumps, zeroised on drop), never through `BufReader` or `io::Stdin`'s own
//! 8 KiB buffer, which would keep every passphrase and every Key Card typed for the life of
//! the process. A line longer than `LINE_CAP` bytes, or a note longer than `NOTE_CAP`, is an
//! error rather than a reallocation.
#![allow(unsafe_code)]

use aska_core::secret::LockedBuf;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::time::{Duration, Instant};
use zeroize::Zeroize;
use zeroize::Zeroizing;

/// Longest line accepted at any prompt (a Receiving Key with eight relay hints is ~2 400
/// characters; a Key Card at most 1 023).
pub const LINE_CAP: usize = 8 * 1024;
/// Longest note accepted from the editor (the largest Block holds less than this).
pub const NOTE_CAP: usize = 64 * 1024;

/// One line of input, UTF-8, in locked memory. Derefs to `str` so callers treat it as text;
/// zeroised when dropped.
pub struct SecretLine(LockedBuf);

impl SecretLine {
    /// Copy text (e.g. a camera helper's output) into locked memory.
    pub fn from_text(text: &str) -> io::Result<Self> {
        if text.len() > LINE_CAP {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("input longer than {LINE_CAP} bytes"),
            ));
        }
        let buf = LockedBuf::try_from_slice(text.as_bytes(), false).map_err(lock_error)?;
        Ok(SecretLine(buf))
    }

    pub fn as_str(&self) -> &str {
        // Validated UTF-8 at construction; the buffer is never mutated afterwards.
        std::str::from_utf8(self.0.as_slice()).unwrap_or("")
    }
}

impl std::ops::Deref for SecretLine {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl Zeroize for SecretLine {
    fn zeroize(&mut self) {
        self.0.clear();
    }
}

/// Read one line (without the newline) byte by byte into a locked buffer of `cap` bytes.
/// `Ok(None)` at EOF before any byte. `require_lock` refuses a buffer that could not be pinned.
fn read_line_locked<R: Read>(
    r: &mut R,
    cap: usize,
    require_lock: bool,
) -> io::Result<Option<LockedBuf>> {
    let mut buf = LockedBuf::try_with_capacity(cap, require_lock).map_err(lock_error)?;
    let mut byte = [0u8; 1];
    let mut any = false;
    loop {
        let n = match r.read(&mut byte) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            break;
        }
        any = true;
        if byte[0] == b'\n' {
            break;
        }
        if buf.len() == cap {
            byte.zeroize();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("input line longer than {cap} bytes"),
            ));
        }
        buf.extend_from_slice(&byte);
    }
    byte.zeroize();
    if !any {
        return Ok(None);
    }
    // Strip a trailing CR (CRLF input); the LF was never stored.
    while buf.as_slice().last() == Some(&b'\r') {
        buf.truncate(buf.len() - 1);
    }
    Ok(Some(buf))
}

fn lock_error(e: aska_core::secret::LockError) -> io::Error {
    io::Error::new(
        io::ErrorKind::OutOfMemory,
        format!(
            "{e} for the input; re-run and accept the memory warning, or pass --accept-unlocked-memory"
        ),
    )
}

fn to_line(buf: LockedBuf) -> io::Result<SecretLine> {
    if std::str::from_utf8(buf.as_slice()).is_err() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input is not UTF-8",
        ));
    }
    Ok(SecretLine(buf))
}

/// Restores the terminal attributes it was created from, even on early return or panic.
struct TermiosGuard {
    fd: i32,
    saved: libc::termios,
}

impl TermiosGuard {
    fn new(fd: i32) -> io::Result<Self> {
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        // SAFETY: fd is an open tty; pointer to a local that outlives the call.
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(TermiosGuard { fd, saved })
    }

    fn apply(&self, f: impl FnOnce(&mut libc::termios)) -> io::Result<()> {
        let mut t = self.saved;
        f(&mut t);
        // SAFETY: as above.
        if unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for TermiosGuard {
    fn drop(&mut self) {
        // SAFETY: restoring attributes we read from this fd.
        unsafe { libc::tcsetattr(self.fd, libc::TCSAFLUSH, &self.saved) };
    }
}

/// Wait up to `timeout` for the fd to become readable. `Ok(true)` = readable.
fn poll_readable(fd: i32, timeout: Duration) -> io::Result<bool> {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: one pollfd, count 1.
    let r = unsafe { libc::poll(&mut p, 1, ms) };
    if r < 0 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::Interrupted {
            return Ok(false);
        }
        return Err(e);
    }
    Ok(r > 0)
}

/// The interactive terminal (`/dev/tty`), or the `--stdin` line protocol.
pub enum Input {
    Tty(Tty),
    /// An unbuffered duplicate of descriptor 0 (never `io::stdin()`, which buffers 8 KiB).
    Stdin(Stdin),
}

pub struct Stdin {
    fd: File,
    require_lock: bool,
}

pub struct Tty {
    dev: File,
    /// Idle deadline at prompts (review finding C-13): a prompt left unanswered for this
    /// long ends the command, so key material and passphrases do not sit in memory while the
    /// user is away. `None` = no limit.
    idle: Option<Duration>,
    require_lock: bool,
}

impl Tty {
    /// Wait for input at a prompt; `Err(TimedOut)` when the idle deadline passes first.
    fn await_input(&self) -> io::Result<()> {
        if let Some(d) = self.idle {
            if !poll_readable(self.dev.as_raw_fd(), d)? {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "no input at the prompt within the idle time — session ended, nothing kept",
                ));
            }
        }
        Ok(())
    }
}

impl Input {
    /// `--stdin` if asked; otherwise `/dev/tty`, which fails when there is no terminal at all.
    pub fn open(stdin_mode: bool) -> io::Result<Self> {
        if stdin_mode {
            // SAFETY: dup(0) returns a fresh descriptor we own exclusively (or -1).
            let fd = unsafe { libc::dup(0) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fd is a valid descriptor owned by nobody else.
            let fd = unsafe { File::from_raw_fd(fd) };
            return Ok(Input::Stdin(Stdin {
                fd,
                require_lock: false,
            }));
        }
        let dev = File::options()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    "no interactive terminal (run from a terminal, or use --stdin for scripting)",
                )
            })?;
        Ok(Input::Tty(Tty {
            dev,
            idle: None,
            require_lock: false,
        }))
    }

    /// Whether input buffers must be pinned in RAM (set from the memory-lock decision: the
    /// doctor's warning acknowledged, or `--accept-unlocked-memory`, makes this false).
    pub fn set_require_lock(&mut self, require: bool) {
        match self {
            Input::Tty(t) => t.require_lock = require,
            Input::Stdin(s) => s.require_lock = require,
        }
    }

    /// Set the idle deadline for prompts (the Session's idle timeout; CLI `--idle`).
    pub fn set_idle(&mut self, idle: Duration) {
        if let Input::Tty(t) = self {
            t.idle = Some(idle);
        }
    }

    pub fn is_interactive(&self) -> bool {
        matches!(self, Input::Tty(_))
    }

    /// One raw line from the current source into a locked buffer of `cap` bytes.
    fn raw_line(&mut self, cap: usize) -> io::Result<Option<LockedBuf>> {
        match self {
            Input::Tty(t) => {
                t.await_input()?;
                read_line_locked(&mut t.dev, cap, t.require_lock)
            }
            Input::Stdin(s) => read_line_locked(&mut s.fd, cap, s.require_lock),
        }
    }

    /// Prompt and read one line with echo. In `--stdin` mode the prompt is not printed.
    pub fn read_line(&mut self, prompt: &str) -> io::Result<Option<SecretLine>> {
        if let Input::Tty(t) = self {
            t.dev.write_all(prompt.as_bytes())?;
            t.dev.flush()?;
        }
        self.raw_line(LINE_CAP)?.map(to_line).transpose()
    }

    /// Prompt and read one line with echo OFF (passphrases). The newline is echoed so the
    /// cursor moves on. In `--stdin` mode this is an ordinary line.
    pub fn read_hidden(&mut self, prompt: &str) -> io::Result<Option<SecretLine>> {
        match self {
            Input::Tty(t) => {
                t.dev.write_all(prompt.as_bytes())?;
                t.dev.flush()?;
                let g = TermiosGuard::new(t.dev.as_raw_fd())?;
                g.apply(|a| a.c_lflag &= !libc::ECHO)?;
                let r = t
                    .await_input()
                    .and_then(|()| read_line_locked(&mut t.dev, LINE_CAP, t.require_lock));
                drop(g);
                t.dev.write_all(b"\n")?;
                r?.map(to_line).transpose()
            }
            Input::Stdin(_) => self.read_line(""),
        }
    }

    /// Read lines until EOF or a line that is a single `.`; returns them joined with `\n` in
    /// one locked buffer. In `--stdin` mode the terminator is EOF only (a note may legitimately
    /// contain a `.`).
    pub fn read_text_block(&mut self, prompt: &str) -> io::Result<LockedBuf> {
        let require = match self {
            Input::Tty(t) => t.require_lock,
            Input::Stdin(s) => s.require_lock,
        };
        let mut out = LockedBuf::try_with_capacity(NOTE_CAP, require).map_err(lock_error)?;
        if let Input::Tty(t) = self {
            t.dev.write_all(prompt.as_bytes())?;
            t.dev.flush()?;
        }
        loop {
            let Some(line) = self.raw_line(LINE_CAP)? else {
                break;
            };
            if self.is_interactive() && line.as_slice() == b"." {
                break;
            }
            let extra = line.len() + usize::from(!out.is_empty());
            if out.len() + extra > NOTE_CAP {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("the note is longer than {NOTE_CAP} bytes"),
                ));
            }
            if !out.is_empty() {
                out.extend_from_slice(b"\n");
            }
            out.extend_from_slice(line.as_slice());
        }
        Ok(out)
    }

    /// Wait for a keypress, at most `timeout`. `Ok(true)` = a key was pressed. Raw mode, no
    /// echo; the byte read is discarded. In `--stdin` mode returns at once without waiting.
    pub fn wait_key(&mut self, timeout: Duration) -> io::Result<bool> {
        let Input::Tty(t) = self else {
            return Ok(true);
        };
        let fd = t.dev.as_raw_fd();
        let g = TermiosGuard::new(fd)?;
        g.apply(|a| {
            a.c_lflag &= !(libc::ICANON | libc::ECHO);
            a.c_cc[libc::VMIN] = 1;
            a.c_cc[libc::VTIME] = 0;
        })?;
        let pressed = poll_readable(fd, timeout)?;
        if pressed {
            let mut b = [0u8; 8];
            let _ = t.dev.read(&mut b);
        }
        Ok(pressed)
    }

    /// Keyboard timing as seed material (paper mode, DC-04 §4.2): raw mode, no echo; records
    /// the microsecond interval between successive keys until Enter is pressed after at least
    /// `min_keys` keys. The keys themselves are discarded — only the timing is kept. Not
    /// available in `--stdin` mode.
    pub fn read_timed_keys(&mut self, prompt: &str, min_keys: usize) -> io::Result<Vec<u32>> {
        let Input::Tty(t) = self else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "keyboard timing needs an interactive terminal",
            ));
        };
        t.dev.write_all(prompt.as_bytes())?;
        t.dev.flush()?;
        let fd = t.dev.as_raw_fd();
        let g = TermiosGuard::new(fd)?;
        g.apply(|a| {
            a.c_lflag &= !(libc::ICANON | libc::ECHO);
            a.c_cc[libc::VMIN] = 1;
            a.c_cc[libc::VTIME] = 0;
        })?;
        let mut intervals = Vec::with_capacity(min_keys + 16);
        let mut last = Instant::now();
        loop {
            t.await_input()?;
            let mut b = [0u8; 1];
            if t.dev.read(&mut b)? == 0 {
                break;
            }
            let now = Instant::now();
            let us = now
                .duration_since(last)
                .as_micros()
                .min(u128::from(u32::MAX)) as u32;
            last = now;
            if b[0] == b'\r' || b[0] == b'\n' {
                if intervals.len() >= min_keys {
                    break;
                }
                continue;
            }
            intervals.push(us);
            b.zeroize();
            if intervals.len() % 32 == 0 {
                t.dev.write_all(b".")?;
                t.dev.flush()?;
            }
        }
        t.dev.write_all(b"\n")?;
        Ok(intervals)
    }

    /// Write to the terminal (or stdout in `--stdin` mode).
    pub fn write(&mut self, s: &str) -> io::Result<()> {
        match self {
            Input::Tty(t) => {
                t.dev.write_all(s.as_bytes())?;
                t.dev.flush()
            }
            Input::Stdin(_) => {
                let mut o = io::stdout().lock();
                o.write_all(s.as_bytes())?;
                o.flush()
            }
        }
    }

    /// Show `body` on the alternate screen with a countdown line, until a key is pressed or
    /// `total` elapses; the screen is cleared afterwards whatever happens. `footer` is the
    /// sentence before the countdown ("Press any key to …"). In `--stdin` mode the body is
    /// printed once to stdout and the call returns.
    pub fn show_timed(&mut self, body: &str, footer: &str, total: Duration) -> io::Result<()> {
        if !self.is_interactive() {
            self.write(body)?;
            return self.write("\n");
        }
        self.write(ALT_ENTER)?;
        let r = self.timed_loop(body, footer, total);
        // Clear both the alternate screen and, after switching back, the cursor line, so no
        // remnant of the hand-over or the note is left on the visible screen.
        let left = self.write(ALT_LEAVE);
        r.and(left)
    }

    fn timed_loop(&mut self, body: &str, footer: &str, total: Duration) -> io::Result<()> {
        let start = Instant::now();
        // The frame is assembled once into a pre-sized zeroising buffer; each tick rewrites
        // only the countdown digits in place (review finding C-9: a `format!` per second left
        // prefixes of the body in freed heap memory).
        let head = "\x1b[H\x1b[2J";
        let mid = "\n\n";
        let tail = " — closes in ";
        let mut frame = Zeroizing::new(String::with_capacity(
            head.len() + body.len() + mid.len() + footer.len() + tail.len() + 6,
        ));
        frame.push_str(head);
        frame.push_str(body);
        frame.push_str(mid);
        frame.push_str(footer);
        frame.push_str(tail);
        let digits_at = frame.len();
        frame.push_str("00:00\n");
        loop {
            let left = total.saturating_sub(start.elapsed());
            let secs = left.as_secs();
            let d = [
                b'0' + ((secs / 60) / 10 % 10) as u8,
                b'0' + ((secs / 60) % 10) as u8,
                b':',
                b'0' + ((secs % 60) / 10) as u8,
                b'0' + ((secs % 60) % 10) as u8,
            ];
            // Same-length ASCII replacement: no reallocation, the buffer stays where it is.
            frame.replace_range(
                digits_at..digits_at + 5,
                std::str::from_utf8(&d).expect("ascii"),
            );
            self.write(&frame)?;
            if left.is_zero() {
                return Ok(());
            }
            let step = left.min(Duration::from_secs(1));
            if self.wait_key(step)? {
                return Ok(());
            }
        }
    }
}

const ALT_ENTER: &str = "\x1b[?1049h\x1b[H\x1b[2J";
const ALT_LEAVE: &str = "\x1b[2J\x1b[H\x1b[?1049l\x1b[2K\r";

/// Is standard output a terminal? (Decides whether a QR is drawn by default.)
pub fn stdout_is_tty() -> bool {
    // SAFETY: isatty on a well-known fd.
    unsafe { libc::isatty(1) == 1 }
}

/// Format 24 words as six numbered lines of four, for reading aloud.
pub fn words_block(words: &str) -> Zeroizing<String> {
    // Pre-sized and built without `join`/`format!` temporaries, so no partial copy of the
    // words is left in freed heap memory (review finding C-8).
    let mut out = Zeroizing::new(String::with_capacity(words.len() + 8 * 12));
    for (i, chunk) in words
        .split_whitespace()
        .collect::<Vec<_>>()
        .chunks(4)
        .enumerate()
    {
        use std::fmt::Write as _;
        let _ = write!(out, "  {:>2}. ", i * 4 + 1);
        for (k, w) in chunk.iter().enumerate() {
            if k > 0 {
                out.push_str("  ");
            }
            out.push_str(w);
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_read_unbuffered_into_locked_memory() {
        let data = b"first\nsecond line\r\n\nrest of\nnote.\n";
        let mut cur = &data[..];
        let l = read_line_locked(&mut cur, LINE_CAP, false)
            .unwrap()
            .unwrap();
        assert_eq!(l.as_slice(), b"first");
        assert!(l.capacity() >= LINE_CAP, "{}", l.capacity());
        let l = read_line_locked(&mut cur, LINE_CAP, false)
            .unwrap()
            .unwrap();
        assert_eq!(l.as_slice(), b"second line");
        let l = read_line_locked(&mut cur, LINE_CAP, false)
            .unwrap()
            .unwrap();
        assert_eq!(l.as_slice(), b"");
        // The reader consumed exactly the lines read: nothing is buffered ahead.
        assert_eq!(cur, b"rest of\nnote.\n");
        // A line at the cap is refused instead of growing.
        let long = [b'a'; 20];
        let mut c = &long[..];
        assert!(read_line_locked(&mut c, 16, false).is_err());
        // Non-UTF-8 is refused.
        let mut c = &b"\xff\xfe\n"[..];
        assert!(to_line(read_line_locked(&mut c, 16, false).unwrap().unwrap()).is_err());
        // EOF before any byte is None; a final line without a newline is a line.
        let mut c = &b""[..];
        assert!(read_line_locked(&mut c, 16, false).unwrap().is_none());
        let mut c = &b"tail"[..];
        assert_eq!(
            read_line_locked(&mut c, 16, false)
                .unwrap()
                .unwrap()
                .as_slice(),
            b"tail"
        );
    }

    #[test]
    fn stdin_mode_has_no_terminator_and_wait_key_returns_at_once() {
        let mut inp = Input::open(true).unwrap();
        assert!(inp.wait_key(Duration::from_secs(1)).unwrap());
        assert!(!inp.is_interactive());
    }

    #[test]
    fn words_are_laid_out_four_per_line() {
        let w = (1..=24)
            .map(|i| format!("w{i}"))
            .collect::<Vec<_>>()
            .join(" ");
        let b = words_block(&w);
        assert_eq!(b.lines().count(), 6);
        assert!(b.starts_with("   1. w1  w2  w3  w4"));
        assert!(b.contains("  21. w21  w22  w23  w24"));
    }
}
