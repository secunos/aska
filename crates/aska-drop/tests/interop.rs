//! Bidirectional interoperability with the Python reference (M2 gate):
//!  * the reference client's scenario passes against the Rust relay;
//!  * the Rust client's scenario passes against the reference relay;
//!  * the malformed-request corpus is answered with identical status bytes by both relays.
//!
//! Needs `python3` on PATH (the reference relay uses only the standard library). If it is
//! missing the tests print a notice and pass vacuously, so `cargo test` stays green on a
//! machine without Python — CI and the VM gate must have it.

mod common;

use aska_drop::Config;
use aska_proto::*;
use common::*;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

fn reference_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../reference")
}

fn python() -> Option<&'static str> {
    for p in ["python3", "python"] {
        if Command::new(p)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return Some(p);
        }
    }
    eprintln!("interop: python3 not found — skipping");
    None
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Start the reference relay as a child process and wait until it accepts connections.
struct PyRelay {
    child: std::process::Child,
    addr: std::net::SocketAddr,
}

impl PyRelay {
    async fn start(py: &str, extra: &[&str]) -> Self {
        let port = free_port();
        let child = Command::new(py)
            .arg(reference_dir().join("aska_drop.py"))
            .args(["serve", "--port", &port.to_string()])
            .args(extra)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn reference relay");
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let mut child = child;
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return PyRelay { child, addr };
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("reference relay did not start");
    }
}

impl Drop for PyRelay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
async fn python_client_against_rust_relay() {
    let Some(py) = python() else { return };
    let relay = start_relay(small_cfg(), Duration::from_secs(30)).await;
    let port = relay.addr.port().to_string();
    // The relay runs on this test's runtime, so the blocking child must not occupy its thread.
    let out = tokio::task::spawn_blocking(move || {
        Command::new(py)
            .arg(reference_dir().join("aska_drop.py"))
            .args([
                "remote-test",
                "--host",
                "127.0.0.1",
                "--port",
                &port,
                "--socks",
                "none",
            ])
            .output()
            .expect("run reference client")
    })
    .await
    .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("REMOTE TEST OK"),
        "reference client failed:\n{stdout}\n{stderr}"
    );
    assert_eq!(relay.store.lock().unwrap().counts(), [4, 0, 0]);
    relay.task.abort();
}

#[tokio::test]
async fn rust_client_against_python_relay() {
    let Some(py) = python() else { return };
    let relay = PyRelay::start(py, &["--cap-1", "4"]).await;
    let c = client(relay.addr);

    let info = c.info().await.unwrap();
    assert_eq!(info.max_ttl_hours, 168);
    assert_eq!(info.classes(), vec![1, 2, 3]);

    let labels: Vec<[u8; 32]> = (0..3).map(|_| rnd()).collect();
    let blocks: Vec<Vec<u8>> = (0..3).map(|_| rblock(1)).collect();
    for (l, b) in labels.iter().zip(&blocks) {
        assert_eq!(c.put(*l, b, 1).await.unwrap(), Status::Ok);
    }
    assert_eq!(c.put(labels[0], &blocks[0], 1).await.unwrap(), Status::Ok);
    assert_eq!(
        c.put(labels[0], &rblock(1), 1).await.unwrap(),
        Status::Duplicate
    );
    assert_eq!(c.put(rnd(), &rblock(1), 0).await.unwrap(), Status::BadTtl);
    assert_eq!(c.put(rnd(), &rblock(1), 169).await.unwrap(), Status::BadTtl);
    let mut got = c.get_all(1).await.unwrap();
    got.sort();
    let mut want: Vec<([u8; 32], Vec<u8>)> = labels.iter().cloned().zip(blocks.clone()).collect();
    want.sort();
    assert_eq!(got, want);
    // PoW path against the Python relay (3/4 full → 3 bits)
    assert_eq!(c.put(rnd(), &rblock(1), 1).await.unwrap(), Status::Ok);
    assert_eq!(c.put(rnd(), &rblock(1), 1).await.unwrap(), Status::Full);
    assert_eq!(c.get_all(1).await.unwrap().len(), 4);
    assert!(c.get_all(3).await.unwrap().is_empty());
}

#[tokio::test]
async fn malformed_corpus_identical_on_both_relays() {
    let Some(py) = python() else { return };
    let rust = start_relay(Config::default(), Duration::from_secs(30)).await;
    let pyr = PyRelay::start(py, &[]).await;
    let (cr, cp) = (client(rust.addr), client(pyr.addr));
    for (name, payload, want) in malformed_corpus() {
        let a = cr.raw_status(&payload).await.unwrap();
        let b = cp.raw_status(&payload).await.unwrap();
        assert_eq!(a, want as u8, "rust relay: {name}");
        assert_eq!(b, want as u8, "python relay: {name}");
    }
    rust.task.abort();
}
