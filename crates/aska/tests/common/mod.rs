//! Test plumbing for the CLI: an in-process relay, a fake Tor SOCKS port that forwards every
//! `.onion` CONNECT to it (copied from aska-core's tests), and a runner for the `aska` binary.
#![allow(dead_code)]

use aska_drop::{serve, Config, SharedStore, Store};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Any valid v3 onion address; the fake SOCKS port ignores it.
pub const ONION: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

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

/// Minimal SOCKS5 server: username/password method, CONNECT with a domain name that must end
/// in `.onion`, forwarded to `target`. Records the usernames it sees.
pub struct FakeSocks {
    pub addr: SocketAddr,
    pub usernames: Arc<Mutex<Vec<String>>>,
    pub hosts: Arc<Mutex<Vec<String>>>,
}

pub fn start_fake_socks(target: SocketAddr) -> FakeSocks {
    start_fake_socks_opt(target, false)
}

/// A SOCKS port whose Tor cannot reach anything: every CONNECT is answered "host
/// unreachable" (0x04), as Tor does when no circuit can be built (D-16 blocked network).
pub fn start_fake_socks_blocked() -> FakeSocks {
    start_fake_socks_opt("127.0.0.1:9".parse().unwrap(), true)
}

fn start_fake_socks_opt(target: SocketAddr, blocked: bool) -> FakeSocks {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let usernames = Arc::new(Mutex::new(Vec::new()));
    let hosts = Arc::new(Mutex::new(Vec::new()));
    let (u2, h2) = (usernames.clone(), hosts.clone());
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let (u, h) = (u2.clone(), h2.clone());
            std::thread::spawn(move || serve_socks(conn, target, u, h, blocked));
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
    blocked: bool,
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
    if blocked {
        let _ = c.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]);
        return;
    }
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

/// A relay plus a SOCKS port in front of it, and a scratch directory.
pub struct Bench {
    pub relay: LocalRelay,
    pub socks: FakeSocks,
    pub dir: PathBuf,
}

impl Bench {
    pub fn new(name: &str) -> Self {
        let relay = start_relay(Config::default());
        let socks = start_fake_socks(relay.addr);
        let dir = std::env::temp_dir().join(format!("aska-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Bench { relay, socks, dir }
    }

    /// Run `aska` with the bench's SOCKS port, `--stdin --yes --fast --idle 600` and the given
    /// args, feeding `stdin`. HOME and XDG dirs point into the scratch dir so any stray write
    /// would be visible there.
    pub fn aska(&self, args: &[&str], stdin: &str) -> Out {
        self.aska_in(&self.dir, args, stdin)
    }

    pub fn aska_in(&self, cwd: &Path, args: &[&str], stdin: &str) -> Out {
        self.aska_env(cwd, args, stdin, &[])
    }

    /// As `aska_in`, with extra environment variables (doctor trigger tests).
    pub fn aska_env(&self, cwd: &Path, args: &[&str], stdin: &str, env: &[(&str, &str)]) -> Out {
        self.run(cwd, args, stdin, env, Stdio::piped())
    }

    /// As `aska`, with standard output connected to a pipe whose reading end is already
    /// closed — every write to stdout fails with `EPIPE`, deterministically (`aska … | head`
    /// after `head` has gone). `Out::stdout` is then always empty.
    pub fn aska_closed_stdout(&self, args: &[&str], stdin: &str) -> Out {
        use std::os::fd::{FromRawFd, OwnedFd};
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `pipe` fills both descriptors on success; each is owned exactly once below.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe()");
        let (reader, writer) =
            unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        drop(reader);
        self.run(&self.dir, args, stdin, &[], Stdio::from(writer))
    }

    fn run(
        &self,
        cwd: &Path,
        args: &[&str],
        stdin: &str,
        env: &[(&str, &str)],
        stdout: Stdio,
    ) -> Out {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_aska"));
        cmd.current_dir(cwd)
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            // Test-specific variables last, so a test may override PATH (stub programs).
            .envs(env.iter().copied())
            .env("HOME", &self.dir)
            .env("XDG_CONFIG_HOME", self.dir.join("xdg-config"))
            .env("XDG_DATA_HOME", self.dir.join("xdg-data"))
            .env("XDG_CACHE_HOME", self.dir.join("xdg-cache"))
            .env("TMPDIR", self.dir.join("tmp"))
            .arg("--socks")
            .arg(self.socks.addr.to_string())
            .args([
                "--stdin",
                "--yes",
                "--fast",
                "--idle",
                "600",
                "--accept-unlocked-memory",
            ])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(stdout)
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        // Drop the parent's copies of the stdout pipe (in `aska_closed_stdout`) so the child
        // holds the only writer.
        drop(cmd);
        {
            let mut si = child.stdin.take().unwrap();
            // A command that refuses before reading stdin (doctor refusals) may have exited
            // already; the resulting broken pipe is not a test failure.
            let _ = si.write_all(stdin.as_bytes());
        }
        let o = child.wait_with_output().unwrap();
        Out {
            code: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        }
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

pub struct Out {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Out {
    /// The value after `KEY ` on the first stdout line starting with it.
    pub fn field(&self, key: &str) -> Option<String> {
        let p = format!("{key} ");
        self.stdout
            .lines()
            .find_map(|l| l.strip_prefix(&p).map(|v| v.trim().to_string()))
    }

    pub fn fields(&self, key: &str) -> Vec<String> {
        let p = format!("{key} ");
        self.stdout
            .lines()
            .filter_map(|l| l.strip_prefix(&p).map(|v| v.trim().to_string()))
            .collect()
    }

    pub fn ok(&self) -> bool {
        self.code == 0 || self.code == 2
    }

    pub fn dump(&self) -> String {
        format!(
            "exit {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            self.code, self.stdout, self.stderr
        )
    }
}
