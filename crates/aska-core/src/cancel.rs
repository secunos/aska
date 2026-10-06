//! Cancellation and per-request deadlines for network work.
//!
//! A `CancelToken` is shared between a front end and a job (post, fetch, cover traffic):
//! cancelling sets a flag, wakes any interruptible sleep, and shuts down every socket
//! currently registered, so a request blocked in a Tor rendezvous or a slow read returns at
//! once. The panic action (`Session::distress`) therefore never waits on the network.
//!
//! `RegisteredStream` wraps a connection: it registers on creation, unregisters on drop (so
//! no descriptor outlives the request), and enforces a wall-clock deadline for the whole
//! request on top of the per-read socket timeout — a relay dripping one byte per minute
//! cannot hold a fetch open for hours.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Inner {
    cancelled: AtomicBool,
    next_id: AtomicU64,
    sockets: Mutex<Vec<(u64, TcpStream)>>,
    wake: Condvar,
    lock: Mutex<()>,
}

#[derive(Clone, Default)]
pub struct CancelToken(Arc<Inner>);

impl std::fmt::Debug for CancelToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CancelToken(cancelled={})", self.is_cancelled())
    }
}

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::SeqCst)
    }

    /// Cancel: flag (under the sleep lock, so no wakeup is lost), shut down registered
    /// sockets, wake sleepers. Idempotent.
    pub fn cancel(&self) {
        {
            let _g = self.0.lock.lock().unwrap_or_else(|e| e.into_inner());
            self.0.cancelled.store(true, Ordering::SeqCst);
        }
        if let Ok(mut socks) = self.0.sockets.lock() {
            for (_, s) in socks.drain(..) {
                let _ = s.shutdown(Shutdown::Both);
            }
        }
        self.0.wake.notify_all();
    }

    /// Register a socket so that `cancel()` can interrupt I/O on it. Returns the id to pass
    /// to `unregister` when the request is over (`RegisteredStream` does this on drop).
    pub fn register(&self, s: &TcpStream) -> u64 {
        let id = self.0.next_id.fetch_add(1, Ordering::SeqCst);
        if let Ok(c) = s.try_clone() {
            if let Ok(mut socks) = self.0.sockets.lock() {
                socks.push((id, c));
            }
        }
        if self.is_cancelled() {
            let _ = s.shutdown(Shutdown::Both);
        }
        id
    }

    pub fn unregister(&self, id: u64) {
        if let Ok(mut socks) = self.0.sockets.lock() {
            socks.retain(|(i, _)| *i != id);
        }
    }

    /// Number of sockets currently registered (tests).
    pub fn registered(&self) -> usize {
        self.0.sockets.lock().map(|s| s.len()).unwrap_or(0)
    }

    /// Sleep for `d` unless cancelled first. Returns `true` if the full time elapsed.
    pub fn sleep(&self, d: Duration) -> bool {
        let deadline = Instant::now() + d;
        let Ok(mut g) = self.0.lock.lock() else {
            return !self.is_cancelled();
        };
        while !self.is_cancelled() {
            let now = Instant::now();
            if now >= deadline {
                return true;
            }
            match self.0.wake.wait_timeout(g, deadline - now) {
                Ok((ng, _)) => g = ng,
                Err(_) => return !self.is_cancelled(),
            }
        }
        false
    }
}

/// A connection registered with a token for the lifetime of one request, with a wall-clock
/// deadline for the whole request. Reads shorten the socket timeout to whatever is left.
pub struct RegisteredStream {
    inner: TcpStream,
    token: CancelToken,
    id: u64,
    deadline: Instant,
    io_timeout: Duration,
}

impl std::fmt::Debug for RegisteredStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RegisteredStream(id={})", self.id)
    }
}

impl RegisteredStream {
    /// `io_timeout` bounds each read; `deadline` bounds the whole request.
    pub fn new(
        inner: TcpStream,
        token: &CancelToken,
        io_timeout: Duration,
        deadline: Duration,
    ) -> Self {
        let id = token.register(&inner);
        RegisteredStream {
            inner,
            token: token.clone(),
            id,
            deadline: Instant::now() + deadline,
            io_timeout,
        }
    }

    /// Change the per-read timeout (the handshake uses the rendezvous timeout, the transfer
    /// the shorter I/O timeout).
    pub fn set_io_timeout(&mut self, t: Duration) {
        self.io_timeout = t;
    }

    fn arm(&self) -> std::io::Result<()> {
        if self.token.is_cancelled() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled",
            ));
        }
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "request deadline exceeded",
            ));
        }
        let t = left.min(self.io_timeout);
        self.inner.set_read_timeout(Some(t))?;
        self.inner.set_write_timeout(Some(t))
    }
}

impl Read for RegisteredStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.arm()?;
        self.inner.read(buf)
    }
}

impl Write for RegisteredStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.arm()?;
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl Drop for RegisteredStream {
    fn drop(&mut self) {
        self.token.unregister(self.id);
        let _ = self.inner.shutdown(Shutdown::Both);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_interrupts_sleep_and_sockets() {
        let t = CancelToken::new();
        assert!(t.sleep(Duration::from_millis(20)));
        let t2 = t.clone();
        let h = std::thread::spawn(move || t2.sleep(Duration::from_secs(10)));
        std::thread::sleep(Duration::from_millis(50));
        t.cancel();
        assert!(!h.join().unwrap());
        assert!(t.is_cancelled());

        // a blocked read on a registered socket returns after cancel
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let s = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (_srv, _) = l.accept().unwrap();
        let t = CancelToken::new();
        let mut s = RegisteredStream::new(s, &t, Duration::from_secs(30), Duration::from_secs(30));
        assert_eq!(t.registered(), 1);
        let t2 = t.clone();
        let h = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            t2.cancel();
        });
        let mut b = [0u8; 1];
        let r = s.read(&mut b).unwrap_or(0);
        assert_eq!(r, 0, "read must end with EOF/error after cancel");
        h.join().unwrap();
        drop(s);
        assert_eq!(t.registered(), 0, "unregistered on drop");
    }

    #[test]
    fn cancel_races_with_sleep_start() {
        // cancel() issued just before/while sleep() begins must never leave the sleeper
        // waiting for the full duration (lost-wakeup check, repeated).
        for _ in 0..50 {
            let t = CancelToken::new();
            let t2 = t.clone();
            let h = std::thread::spawn(move || {
                let t0 = Instant::now();
                let full = t2.sleep(Duration::from_secs(5));
                (full, t0.elapsed())
            });
            t.cancel();
            let (full, el) = h.join().unwrap();
            assert!(!full);
            assert!(el < Duration::from_secs(1), "sleeper waited {el:?}");
        }
    }

    #[test]
    fn request_deadline_bounds_a_dripping_peer() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut srv, _) = l.accept().unwrap();
            // one byte every 100 ms, forever
            loop {
                std::thread::sleep(Duration::from_millis(100));
                if srv.write_all(&[1]).is_err() {
                    break;
                }
            }
        });
        let t = CancelToken::new();
        let s = TcpStream::connect(addr).unwrap();
        let mut s =
            RegisteredStream::new(s, &t, Duration::from_secs(5), Duration::from_millis(600));
        let t0 = Instant::now();
        let mut buf = [0u8; 64];
        let r = s.read_exact(&mut buf);
        assert!(r.is_err(), "must give up at the deadline");
        assert!(t0.elapsed() < Duration::from_secs(3));
        // unregistered sockets no longer count
        drop(s);
        assert_eq!(t.registered(), 0);
    }
}
