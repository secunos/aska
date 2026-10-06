//! Shared test plumbing: an in-process Rust relay on a runtime thread, a connector that
//! dials it directly, and a minimal SOCKS5 server that behaves like Tor's SOCKS port.
#![allow(dead_code)]

use aska_core::cancel::{CancelToken, RegisteredStream};
use aska_core::drop::{Connector, DropError, Relay, Stream};
use aska_drop::{serve, Config, SharedStore, Store};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// A relay running on its own tokio runtime thread.
pub struct LocalRelay {
    pub addr: SocketAddr,
    pub store: SharedStore,
    _rt: tokio::runtime::Runtime,
}

pub fn start_relay(cfg: Config) -> LocalRelay {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let store: SharedStore = Arc::new(Mutex::new(Store::new(cfg)));
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let s2 = store.clone();
    rt.spawn(async move { serve(listener, s2, Duration::from_secs(30)).await });
    LocalRelay {
        addr,
        store,
        _rt: rt,
    }
}

/// Connects straight to a loopback relay, ignoring the relay's onion identity.
#[derive(Debug, Clone)]
pub struct DirectConnector {
    pub addr: SocketAddr,
}

impl Connector for DirectConnector {
    fn connect(&self, _relay: &Relay, cancel: &CancelToken) -> Result<Box<dyn Stream>, DropError> {
        let s = TcpStream::connect(self.addr)
            .map_err(|e| DropError::Tor(aska_core::tor::TorError::Unreachable(self.addr, e)))?;
        Ok(Box::new(RegisteredStream::new(
            s,
            cancel,
            Duration::from_secs(30),
            Duration::from_secs(60),
        )))
    }
}

/// A syntactically valid v3 onion for tests (the relay's identity is never checked locally).
pub fn test_relay() -> Relay {
    Relay::from_onion("2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion").unwrap()
}

/// Minimal SOCKS5 server: username/password method, CONNECT with a domain name that must end
/// in `.onion`, forwarded to `target`. Records the usernames it sees.
pub struct FakeSocks {
    pub addr: SocketAddr,
    pub usernames: Arc<Mutex<Vec<String>>>,
    pub hosts: Arc<Mutex<Vec<String>>>,
}

pub fn start_fake_socks(target: SocketAddr) -> FakeSocks {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let usernames = Arc::new(Mutex::new(Vec::new()));
    let hosts = Arc::new(Mutex::new(Vec::new()));
    let (u2, h2) = (usernames.clone(), hosts.clone());
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let (u, h) = (u2.clone(), h2.clone());
            std::thread::spawn(move || serve_socks(conn, target, u, h));
        }
    });
    FakeSocks {
        addr,
        usernames,
        hosts,
    }
}

fn serve_socks(
    mut c: TcpStream,
    target: SocketAddr,
    users: Arc<Mutex<Vec<String>>>,
    hosts: Arc<Mutex<Vec<String>>>,
) {
    let mut h = [0u8; 2];
    if c.read_exact(&mut h).is_err() || h[0] != 5 {
        return;
    }
    let mut methods = vec![0u8; h[1] as usize];
    c.read_exact(&mut methods).unwrap();
    if !methods.contains(&2) {
        let _ = c.write_all(&[5, 0xff]);
        return;
    }
    c.write_all(&[5, 2]).unwrap();
    let mut v = [0u8; 2];
    c.read_exact(&mut v).unwrap();
    let mut user = vec![0u8; v[1] as usize];
    c.read_exact(&mut user).unwrap();
    let mut pl = [0u8; 1];
    c.read_exact(&mut pl).unwrap();
    let mut pass = vec![0u8; pl[0] as usize];
    c.read_exact(&mut pass).unwrap();
    users.lock().unwrap().push(String::from_utf8(user).unwrap());
    c.write_all(&[1, 0]).unwrap();
    let mut req = [0u8; 4];
    c.read_exact(&mut req).unwrap();
    if req[1] != 1 || req[3] != 3 {
        let _ = c.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]);
        return;
    }
    let mut n = [0u8; 1];
    c.read_exact(&mut n).unwrap();
    let mut host = vec![0u8; n[0] as usize];
    c.read_exact(&mut host).unwrap();
    let mut port = [0u8; 2];
    c.read_exact(&mut port).unwrap();
    let host = String::from_utf8(host).unwrap();
    if !host.ends_with(".onion") {
        let _ = c.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]);
        return;
    }
    hosts.lock().unwrap().push(host);
    let Ok(mut t) = TcpStream::connect(target) else {
        let _ = c.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
        return;
    };
    c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
    let mut c2 = c.try_clone().unwrap();
    let mut t2 = t.try_clone().unwrap();
    let a = std::thread::spawn(move || {
        let _ = std::io::copy(&mut c2, &mut t2);
        let _ = t2.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut t, &mut c);
    let _ = c.shutdown(std::net::Shutdown::Write);
    let _ = a.join();
}

/// A scripted Tor control port that accepts every command (AUTHENTICATE, ONION_CLIENT_AUTH_ADD,
/// GETINFO, QUIT) with a 2xx reply, for exercising the client-auth path without Tor.
pub fn start_fake_control() -> SocketAddr {
    start_fake_control_with_bootstrap(None)
}

/// As `start_fake_control`, but answering `GETINFO status/bootstrap-phase` with the given
/// progress (a Tor stuck below 100 % is what a blocking network looks like).
pub fn start_fake_control_with_bootstrap(progress: Option<u8>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut reader = std::io::BufReader::new(conn.try_clone().unwrap());
                let mut w = conn;
                loop {
                    let mut line = String::new();
                    if std::io::BufRead::read_line(&mut reader, &mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let bootstrap = progress.map(|p| {
                        format!(
                            "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS={p} TAG=x SUMMARY=\"x\"\r\n250 OK\r\n"
                        )
                    });
                    let reply: &[u8] = if line.starts_with("GETINFO status/circuit-established") {
                        b"250-status/circuit-established=1\r\n250 OK\r\n"
                    } else if line.starts_with("GETINFO status/bootstrap-phase") {
                        bootstrap
                            .as_deref()
                            .map(str::as_bytes)
                            .unwrap_or(b"250 OK\r\n")
                    } else if line.starts_with("ONION_CLIENT_AUTH_ADD") {
                        b"251 Client for onion existed and replaced\r\n"
                    } else {
                        b"250 OK\r\n"
                    };
                    if w.write_all(reply).is_err() || line.starts_with("QUIT") {
                        break;
                    }
                }
            });
        }
    });
    addr
}
