//! Relay behaviour over real loopback TCP with the Rust client (mirrors the reference's
//! `selftest` and `test_drop.py`, plus the PoW edge cases and the timeout path).

mod common;

use aska_drop::Config;
use aska_proto::client::{put_once, PutOutcome};
use aska_proto::*;
use common::*;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

#[tokio::test]
async fn selftest_scenario() {
    let relay = start_relay(small_cfg(), Duration::from_secs(30)).await;
    let c = client(relay.addr);

    let info = c.info().await.unwrap();
    assert_eq!(info.max_ttl_hours, 168);
    assert_eq!(info.classes(), vec![1, 2, 3]);
    assert_eq!(info.pow_base_difficulty, 0);

    let labels: Vec<[u8; 32]> = (0..3).map(|_| rnd()).collect();
    let blocks: Vec<Vec<u8>> = (0..3).map(|_| rblock(1)).collect();
    for (l, b) in labels.iter().zip(&blocks) {
        assert_eq!(c.put(*l, b, 1).await.unwrap(), Status::Ok);
    }
    assert_eq!(c.put(labels[0], &blocks[0], 1).await.unwrap(), Status::Ok); // idempotent
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

    // 3/4 = 75 % → +3 bits; the fourth PUT goes through the challenge path transparently
    assert_eq!(relay.store.lock().unwrap().difficulty_for(1), 3);
    assert_eq!(c.put(rnd(), &rblock(1), 1).await.unwrap(), Status::Ok);
    assert_eq!(c.put(rnd(), &rblock(1), 1).await.unwrap(), Status::Full);

    // expiry: advance the store's clock past the 1-hour TTL
    relay
        .store
        .lock()
        .unwrap()
        .advance_clock(Duration::from_secs(2 * 3600));
    assert!(c.get_all(1).await.unwrap().is_empty());
    assert_eq!(c.put(rnd(), &rblock(1), 1).await.unwrap(), Status::Ok);
    relay.task.abort();
}

/// A nonce that provably does NOT solve the puzzle (low difficulties verify by chance often).
fn non_solution(challenge: &[u8; 16], label: &[u8; 32], difficulty: u8) -> [u8; 8] {
    let mut n: u64 = u64::MAX;
    loop {
        let nonce = n.to_be_bytes();
        if !pow_check(challenge, label, &nonce, difficulty) {
            return nonce;
        }
        n -= 1;
    }
}

#[tokio::test]
async fn pow_edge_cases() {
    let relay = start_relay(small_cfg(), Duration::from_secs(30)).await;
    let c = client(relay.addr);
    for _ in 0..3 {
        assert_eq!(c.put(rnd(), &rblock(1), 1).await.unwrap(), Status::Ok);
    }
    let label: [u8; 32] = rnd();
    let block = rblock(1);
    // first attempt → challenge
    let mut s = TcpStream::connect(relay.addr).await.unwrap();
    let first = PutFixed::first_attempt(1, 1, label);
    let PutOutcome::PowRequired(p) = put_once(&mut s, &first, &block).await.unwrap() else {
        panic!("expected a challenge");
    };
    assert_eq!(p.difficulty, 3);
    drop(s);

    // wrong nonce → POW_INVALID, and the challenge is consumed by that attempt
    let mut bad = first;
    bad.challenge = p.challenge;
    bad.nonce = non_solution(&p.challenge, &label, p.difficulty);
    let mut s = TcpStream::connect(relay.addr).await.unwrap();
    assert_eq!(
        put_once(&mut s, &bad, &block).await.unwrap(),
        PutOutcome::Status(Status::PowInvalid)
    );
    drop(s);
    let mut good = first;
    good.challenge = p.challenge;
    good.nonce = pow_solve(&p.challenge, &label, p.difficulty);
    let mut s = TcpStream::connect(relay.addr).await.unwrap();
    assert_eq!(
        put_once(&mut s, &good, &block).await.unwrap(),
        PutOutcome::Status(Status::PowInvalid),
        "single use: a consumed challenge must not verify even with a correct nonce"
    );
    drop(s);

    // unknown challenge → POW_INVALID
    let mut unknown = first;
    unknown.challenge = rnd();
    unknown.nonce = pow_solve(&unknown.challenge, &label, 3);
    let mut s = TcpStream::connect(relay.addr).await.unwrap();
    assert_eq!(
        put_once(&mut s, &unknown, &block).await.unwrap(),
        PutOutcome::Status(Status::PowInvalid)
    );
    drop(s);

    // expired challenge → POW_INVALID
    let mut s = TcpStream::connect(relay.addr).await.unwrap();
    let PutOutcome::PowRequired(p2) = put_once(&mut s, &first, &block).await.unwrap() else {
        panic!()
    };
    drop(s);
    relay
        .store
        .lock()
        .unwrap()
        .advance_clock(Duration::from_secs(121));
    let mut late = first;
    late.challenge = p2.challenge;
    late.nonce = pow_solve(&p2.challenge, &label, p2.difficulty);
    let mut s = TcpStream::connect(relay.addr).await.unwrap();
    assert_eq!(
        put_once(&mut s, &late, &block).await.unwrap(),
        PutOutcome::Status(Status::PowInvalid)
    );
    drop(s);

    // solution for one label does not carry to another label (fresh challenge, wrong label)
    let mut s = TcpStream::connect(relay.addr).await.unwrap();
    let PutOutcome::PowRequired(p3) = put_once(&mut s, &first, &block).await.unwrap() else {
        panic!()
    };
    drop(s);
    let other_label: [u8; 32] = rnd();
    let mut moved = PutFixed::first_attempt(1, 1, other_label);
    moved.challenge = p3.challenge;
    moved.nonce = pow_solve(&p3.challenge, &label, p3.difficulty); // solved for `label`
    let mut s = TcpStream::connect(relay.addr).await.unwrap();
    let r = put_once(&mut s, &moved, &block).await.unwrap();
    // At 3 bits the wrong-label hash verifies by chance one time in eight, so compute the
    // expected verdict locally instead of assuming it: the relay must agree with pow_check.
    let verifies_anyway = pow_check(&p3.challenge, &other_label, &moved.nonce, p3.difficulty);
    let expected = if verifies_anyway {
        Status::Ok
    } else {
        Status::PowInvalid
    };
    assert_eq!(r, PutOutcome::Status(expected));
    drop(s);

    // the full client flow still works: one free slot unless the chance store above took it
    let stored = relay.store.lock().unwrap().counts()[0];
    let want = if stored < 4 { Status::Ok } else { Status::Full };
    assert_eq!(c.put(rnd(), &rblock(1), 1).await.unwrap(), want);
    relay.task.abort();
}

#[tokio::test]
async fn malformed_corpus_rejected_as_specified() {
    let relay = start_relay(small_cfg(), Duration::from_secs(30)).await;
    let c = client(relay.addr);
    for (name, payload, want) in malformed_corpus() {
        let got = c.raw_status(&payload).await.unwrap();
        assert_eq!(got, want as u8, "{name}");
    }
    relay.task.abort();
}

#[tokio::test]
async fn slow_client_is_answered_bad_request_after_timeout() {
    let relay = start_relay(small_cfg(), Duration::from_millis(300)).await;
    let mut s = TcpStream::connect(relay.addr).await.unwrap();
    s.write_all(b"ASK").await.unwrap(); // stall after 3 bytes
    let t0 = std::time::Instant::now();
    let mut h = [0u8; 6];
    tokio::io::AsyncReadExt::read_exact(&mut s, &mut h)
        .await
        .unwrap();
    assert!(t0.elapsed() >= Duration::from_millis(250));
    assert_eq!(h[5], Status::BadRequest as u8);
    relay.task.abort();
}

#[tokio::test]
async fn listing_is_randomised_and_classes_independent() {
    let relay = start_relay(Config::default(), Duration::from_secs(30)).await;
    let c = client(relay.addr);
    for _ in 0..12 {
        assert_eq!(c.put(rnd(), &rblock(1), 24).await.unwrap(), Status::Ok);
    }
    for _ in 0..2 {
        assert_eq!(c.put(rnd(), &rblock(3), 24).await.unwrap(), Status::Ok);
    }
    let orders: Vec<Vec<[u8; 32]>> = {
        let mut v = Vec::new();
        for _ in 0..5 {
            v.push(
                c.get_all(1)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|(l, _)| l)
                    .collect(),
            );
        }
        v
    };
    assert!(orders.iter().any(|o| *o != orders[0]));
    assert_eq!(c.get_all(2).await.unwrap().len(), 0);
    assert_eq!(c.get_all(3).await.unwrap().len(), 2);
    relay.task.abort();
}

#[tokio::test]
async fn concurrent_puts_and_gets() {
    let relay = start_relay(Config::default(), Duration::from_secs(30)).await;
    let addr = relay.addr;
    let mut tasks = Vec::new();
    for _ in 0..64 {
        tasks.push(tokio::spawn(async move {
            let c = client(addr);
            assert_eq!(c.put(rnd(), &rblock(2), 24).await.unwrap(), Status::Ok);
            c.get_all(2).await.unwrap().len()
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(client(addr).get_all(2).await.unwrap().len(), 64);
    assert_eq!(relay.store.lock().unwrap().counts(), [0, 64, 0]);
    relay.task.abort();
}

#[tokio::test]
async fn unserved_class_reports_bad_class_and_info_bitmap() {
    let relay = start_relay(
        Config {
            caps: [10, 0, 10],
            max_ttl_hours: 48,
            pow_base_difficulty: 2,
        },
        Duration::from_secs(30),
    )
    .await;
    let c = client(relay.addr);
    let info = c.info().await.unwrap();
    assert_eq!(info.classes(), vec![1, 3]);
    assert_eq!(info.max_ttl_hours, 48);
    assert_eq!(info.pow_base_difficulty, 2);
    assert_eq!(c.put(rnd(), &rblock(2), 1).await.unwrap(), Status::BadClass);
    assert_eq!(c.put(rnd(), &rblock(1), 49).await.unwrap(), Status::BadTtl);
    // base difficulty 2 → every PUT goes through PoW, transparently
    assert_eq!(c.put(rnd(), &rblock(1), 48).await.unwrap(), Status::Ok);
    assert!(matches!(
        c.get_all(2).await.unwrap_err(),
        ProtoError::Status(Status::BadClass)
    ));
    relay.task.abort();
}
