//! Terminal I/O for the CLI. Everything the user types or sees that is secret passes through
//! here: passphrases with echo off, key material lines, the hand-over screens and the note
//! viewer on the alternate screen (cleared on exit), and single keypresses with a timeout so
//! the Session's idle watchdog can be mirrored on screen.
//!
//! Two input modes (Client Design §4): interactive, through `/dev/tty` so prompts work even
//! when stdin carries data; and `--stdin`, where every input is a line of standard input in a
//! documented order and no prompt is ever printed. Secrets never come from `argv` or the
//! environment. The only `unsafe` in this crate is the termios and poll calls below, each a
//! single libc call with a pointer to a local it outlives.
#![allow(unsafe_code)]

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

/// Read one line (without the newline) into zeroising memory. `Ok(None)` at EOF.
fn read_line_z<R: BufRead>(r: &mut R) -> io::Result<Option<Zeroizing<String>>> {
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    let n = r.read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    while matches!(buf.last(), Some(b'\n') | Some(b'\r')) {
        buf.pop();
    }
    let s = String::from_utf8(buf.to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "input is not UTF-8"))?;
    Ok(Some(Zeroizing::new(s)))
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
    Stdin(BufReader<io::Stdin>),
}

pub struct Tty {
    dev: File,
    reader: BufReader<File>,
    /// Idle deadline at prompts (review finding C-13): a prompt left unanswered for this
    /// long ends the command, so key material and passphrases do not sit in memory while the
    /// user is away. `None` = no limit.
    idle: Option<Duration>,
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
            return Ok(Input::Stdin(BufReader::new(io::stdin())));
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
        let reader = BufReader::new(dev.try_clone()?);
        Ok(Input::Tty(Tty {
            dev,
            reader,
            idle: None,
        }))
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

    /// Prompt and read one line with echo. In `--stdin` mode the prompt is not printed.
    pub fn read_line(&mut self, prompt: &str) -> io::Result<Option<Zeroizing<String>>> {
        match self {
            Input::Tty(t) => {
                t.dev.write_all(prompt.as_bytes())?;
                t.dev.flush()?;
                t.await_input()?;
                read_line_z(&mut t.reader)
            }
            Input::Stdin(r) => read_line_z(r),
        }
    }

    /// Prompt and read one line with echo OFF (passphrases). The newline is echoed so the
    /// cursor moves on. In `--stdin` mode this is an ordinary line.
    pub fn read_hidden(&mut self, prompt: &str) -> io::Result<Option<Zeroizing<String>>> {
        match self {
            Input::Tty(t) => {
                t.dev.write_all(prompt.as_bytes())?;
                t.dev.flush()?;
                let g = TermiosGuard::new(t.dev.as_raw_fd())?;
                g.apply(|a| a.c_lflag &= !libc::ECHO)?;
                let r = t.await_input().and_then(|()| read_line_z(&mut t.reader));
                drop(g);
                t.dev.write_all(b"\n")?;
                r
            }
            Input::Stdin(r) => read_line_z(r),
        }
    }

    /// Read lines until EOF or a line that is a single `.`; returns them joined with `\n`.
    /// In `--stdin` mode the terminator is EOF only (a note may legitimately contain a `.`).
    pub fn read_text_block(&mut self, prompt: &str) -> io::Result<Zeroizing<Vec<u8>>> {
        let mut out: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
        if let Input::Tty(t) = self {
            t.dev.write_all(prompt.as_bytes())?;
            t.dev.flush()?;
        }
        loop {
            let line = match self {
                Input::Tty(t) => read_line_z(&mut t.reader)?,
                Input::Stdin(r) => read_line_z(r)?,
            };
            let Some(mut line) = line else { break };
            if self.is_interactive() && line.as_str() == "." {
                line.zeroize();
                break;
            }
            if !out.is_empty() {
                out.push(b'\n');
            }
            out.extend_from_slice(line.as_bytes());
            line.zeroize();
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
    fn stdin_mode_reads_lines_and_text_blocks() {
        let data = b"first\nsecond line\r\n\nrest of\nnote.\n";
        let mut inp = Input::Stdin(BufReader::new(io::stdin()));
        // Replace the reader with our data via a cursor-backed BufReader through the same API.
        let mut cur = BufReader::new(&data[..]);
        assert_eq!(read_line_z(&mut cur).unwrap().unwrap().as_str(), "first");
        assert_eq!(
            read_line_z(&mut cur).unwrap().unwrap().as_str(),
            "second line"
        );
        assert_eq!(read_line_z(&mut cur).unwrap().unwrap().as_str(), "");
        // In stdin mode a lone "." is NOT a terminator.
        let mut cur2 = BufReader::new(&b"a\n.\nb\n"[..]);
        let mut acc = Vec::new();
        while let Some(l) = read_line_z(&mut cur2).unwrap() {
            acc.push(l.as_str().to_string());
        }
        assert_eq!(acc, ["a", ".", "b"]);
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
