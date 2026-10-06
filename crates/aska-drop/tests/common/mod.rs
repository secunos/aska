//! Shared helpers for the relay's integration and interop tests.
#![allow(dead_code)]

use aska_drop::{serve, Config, SharedStore, Store};
use aska_proto::client::TcpClient;
use aska_proto::*;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

pub struct Relay {
    pub addr: SocketAddr,
    pub store: SharedStore,
    pub task: JoinHandle<()>,
}

/// Start an in-process relay on a random loopback port.
pub async fn start_relay(cfg: Config, read_timeout: Duration) -> Relay {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let store: SharedStore = Arc::new(Mutex::new(Store::new(cfg)));
    let s2 = store.clone();
    let task = tokio::spawn(async move { serve(listener, s2, read_timeout).await });
    Relay { addr, store, task }
}

pub fn small_cfg() -> Config {
    Config {
        caps: [4, 800, 200],
        ..Config::default()
    }
}

pub fn client(addr: SocketAddr) -> TcpClient {
    TcpClient::new(addr)
}

pub fn rnd<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).unwrap();
    b
}

pub fn rblock(class: u8) -> Vec<u8> {
    let mut v = vec![0u8; class_size(class).unwrap()];
    getrandom::getrandom(&mut v).unwrap();
    v
}

/// The malformed-request corpus: (name, bytes, expected status). Both relays must answer each
/// item with exactly this status byte (M2 gate: "rejected identically").
pub fn malformed_corpus() -> Vec<(&'static str, Vec<u8>, Status)> {
    let put_fixed = |class: u8, ttl: u16| {
        encode_put_fixed(&PutFixed::first_attempt(class, ttl, [0u8; 32])).to_vec()
    };
    let put = |class: u8, ttl: u16, block: &[u8]| {
        let mut v = encode_request_header(OP_PUT).to_vec();
        v.extend_from_slice(&put_fixed(class, ttl));
        v.extend_from_slice(block);
        v
    };
    vec![
        ("bad magic", b"XXXX\x01\x01".to_vec(), Status::BadRequest),
        ("bad version", b"ASKD\x02\x01".to_vec(), Status::BadRequest),
        (
            "unknown op 0x09",
            b"ASKD\x01\x09".to_vec(),
            Status::BadRequest,
        ),
        (
            "unknown op 0x00",
            b"ASKD\x01\x00".to_vec(),
            Status::BadRequest,
        ),
        ("empty request", Vec::new(), Status::BadRequest),
        ("truncated header", b"ASK".to_vec(), Status::BadRequest),
        ("magic only", b"ASKD".to_vec(), Status::BadRequest),
        (
            "PUT truncated fixed fields",
            [b"ASKD\x01\x02".as_slice(), &[1u8, 0, 24]].concat(),
            Status::BadRequest,
        ),
        ("PUT class 0", put(0, 24, &[]), Status::BadClass),
        ("PUT class 9", put(9, 24, &[]), Status::BadClass),
        (
            "PUT truncated block",
            put(1, 24, &[0u8; 100]),
            Status::BadLength,
        ),
        ("PUT ttl 0", put(1, 0, &[0u8; 4096]), Status::BadTtl),
        ("PUT ttl 169", put(1, 169, &[0u8; 4096]), Status::BadTtl),
        ("PUT ttl 65535", put(1, 65535, &[0u8; 4096]), Status::BadTtl),
        ("PUT class 2 block ok", put(2, 1, &[7u8; 16384]), Status::Ok),
        (
            "PUT trailing garbage ignored",
            [put(1, 1, &[3u8; 4096]).as_slice(), &[9u8; 40]].concat(),
            Status::Ok,
        ),
        (
            "GET_ALL missing class",
            b"ASKD\x01\x03".to_vec(),
            Status::BadClass,
        ),
        (
            "GET_ALL class 0",
            b"ASKD\x01\x03\x00".to_vec(),
            Status::BadClass,
        ),
        (
            "GET_ALL class 4",
            b"ASKD\x01\x03\x04".to_vec(),
            Status::BadClass,
        ),
        (
            "GET_ALL class 255",
            b"ASKD\x01\x03\xff".to_vec(),
            Status::BadClass,
        ),
        (
            "GET_ALL class 3 ok",
            b"ASKD\x01\x03\x03".to_vec(),
            Status::Ok,
        ),
        (
            "INFO with trailing bytes",
            b"ASKD\x01\x01zzzz".to_vec(),
            Status::Ok,
        ),
    ]
}
