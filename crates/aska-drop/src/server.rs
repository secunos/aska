//! The connection handler and accept loop (§4). One request per connection; fixed-length reads;
//! a 30-second timeout per read and per write; one Block buffer per connection; no logging.
//!
//! The handler mirrors `reference/aska_drop.py::handle_connection` decision for decision so that
//! the malformed-request corpus is answered identically (M2 gate).

use crate::store::Store;
use aska_proto::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;

pub type SharedStore = Arc<Mutex<Store>>;

/// Upper bound on simultaneously open connections: bounds per-connection Block buffers
/// (256 × 64 KiB = 16 MiB worst case). Tor's rendezvous limits sit well below this.
pub const MAX_CONNECTIONS: usize = 256;
/// Timer-driven expiry interval (§5.2 "MAY run on a timer") so memory stays flat when idle.
pub const EXPIRY_TICK_SECS: u64 = 60;
/// One overall deadline per connection, on top of the per-call read/write timeout: a reader
/// that paces its reads just under the per-write timeout could otherwise hold a connection
/// slot for records × timeout (review finding D-1). A full class-3 listing (400 × 64 KiB
/// = 25 MiB) over a slow Tor circuit finishes well inside this.
pub const CONNECTION_BUDGET_SECS: u64 = 300;

fn lock(store: &SharedStore) -> std::sync::MutexGuard<'_, Store> {
    // A poisoned mutex means a panic while holding the lock; the store is plain data and is
    // still consistent, so continue rather than take the relay down.
    store.lock().unwrap_or_else(|e| e.into_inner())
}

async fn read_exact_timed<S: AsyncRead + Unpin>(s: &mut S, buf: &mut [u8], t: Duration) -> bool {
    matches!(timeout(t, s.read_exact(buf)).await, Ok(Ok(_)))
}

async fn write_timed<S: AsyncWrite + Unpin>(s: &mut S, data: &[u8], t: Duration) -> bool {
    matches!(timeout(t, s.write_all(data)).await, Ok(Ok(())))
}

/// PoW gate (§6.2) followed by the store's PUT rules (§4.3), under one lock acquisition.
fn put_policy(store: &SharedStore, p: &PutFixed, block: Vec<u8>) -> Vec<u8> {
    let mut s = lock(store);
    let difficulty = s.difficulty_for(p.class);
    if difficulty > 0 {
        if p.is_first_attempt() {
            let challenge = s.new_challenge();
            return encode_pow_required_response(&PowRequired {
                challenge,
                difficulty,
            });
        }
        if !s.consume_challenge(&p.challenge)
            || !pow_check(&p.challenge, &p.label, &p.nonce, difficulty)
        {
            return encode_put_response(Status::PowInvalid);
        }
    }
    encode_put_response(s.put(p.class, p.ttl_hours, p.label, block))
}

/// Serve exactly one request on `stream`, then return (the caller drops the stream, which
/// closes it). Never returns an error: a misbehaving client gets a status or silence.
pub async fn handle_connection<S: AsyncRead + AsyncWrite + Unpin>(
    store: &SharedStore,
    mut stream: S,
    read_timeout: Duration,
) {
    let t = read_timeout;
    let mut hdr = [0u8; HEADER_LEN];
    if !read_exact_timed(&mut stream, &mut hdr, t).await {
        write_timed(&mut stream, &encode_response_header(Status::BadRequest), t).await;
        return;
    }
    let op = match decode_header(&hdr) {
        Ok(op) => op,
        Err(_) => {
            write_timed(&mut stream, &encode_response_header(Status::BadRequest), t).await;
            return;
        }
    };
    match op {
        OP_INFO => {
            let info = {
                let s = lock(store);
                Info {
                    max_ttl_hours: s.config().max_ttl_hours,
                    classes_bitmap: s.classes_bitmap(),
                    pow_base_difficulty: s.config().pow_base_difficulty,
                }
            };
            write_timed(&mut stream, &encode_info_response(&info), t).await;
        }
        OP_PUT => {
            let mut fixed = [0u8; PUT_FIXED_LEN];
            if !read_exact_timed(&mut stream, &mut fixed, t).await {
                write_timed(&mut stream, &encode_response_header(Status::BadRequest), t).await;
                return;
            }
            let Ok(p) = decode_put_fixed(&fixed) else {
                write_timed(&mut stream, &encode_response_header(Status::BadRequest), t).await;
                return;
            };
            let Some(size) = class_size(p.class) else {
                write_timed(&mut stream, &encode_response_header(Status::BadClass), t).await;
                return;
            };
            // Read the whole Block before validating anything else (§4.3: rejection time must
            // not depend on content). The buffer is reserved fallibly: the release build aborts
            // on an allocation failure, and under `mlockall(MCL_FUTURE)` an allocation can be
            // refused when RLIMIT_MEMLOCK is exhausted, so a relay that is out of lockable
            // memory answers FULL for this Block rather than dying under every client.
            let mut block = Vec::new();
            if block.try_reserve_exact(size).is_err() {
                write_timed(&mut stream, &encode_response_header(Status::Full), t).await;
                return;
            }
            block.resize(size, 0);
            if !read_exact_timed(&mut stream, &mut block, t).await {
                write_timed(&mut stream, &encode_response_header(Status::BadLength), t).await;
                return;
            }
            let response = put_policy(store, &p, block);
            write_timed(&mut stream, &response, t).await;
        }
        OP_GET_ALL => {
            let mut c = [0u8; 1];
            if !read_exact_timed(&mut stream, &mut c, t).await {
                write_timed(&mut stream, &encode_response_header(Status::BadClass), t).await;
                return;
            }
            let items = lock(store).get_all(c[0]);
            let Some(items) = items else {
                write_timed(&mut stream, &encode_response_header(Status::BadClass), t).await;
                return;
            };
            if !write_timed(&mut stream, &encode_get_all_count(items.len() as u32), t).await {
                return;
            }
            for (label, block) in &items {
                if !write_timed(&mut stream, label, t).await
                    || !write_timed(&mut stream, block.as_slice(), t).await
                {
                    return;
                }
            }
        }
        _ => {
            write_timed(&mut stream, &encode_response_header(Status::BadRequest), t).await;
        }
    }
    let _ = timeout(t, stream.shutdown()).await;
}

/// Accept loop. Runs until the task is cancelled (the expiry ticker is aborted with it).
pub async fn serve(listener: TcpListener, store: SharedStore, read_timeout: Duration) {
    let limiter = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let ticker_store = store.clone();
    // Aborted when `serve` is dropped (cancelled), since the accept loop below never returns.
    let _ticker = AbortOnDrop(tokio::spawn(async move {
        let mut iv = tokio::time::interval(Duration::from_secs(EXPIRY_TICK_SECS));
        loop {
            iv.tick().await;
            lock(&ticker_store).expire();
        }
    }));
    loop {
        let Ok((stream, _peer)) = listener.accept().await else {
            // Transient accept errors (EMFILE, ECONNABORTED): back off briefly, never log.
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        // Shed load instead of queueing: when every slot is taken the new stream is dropped
        // at once (Tor's circuit is closed), so a saturated relay cannot pile up waiters
        // (review finding D-1).
        let Ok(permit) = limiter.clone().try_acquire_owned() else {
            drop(stream);
            continue;
        };
        let store = store.clone();
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            let _ = timeout(
                Duration::from_secs(CONNECTION_BUDGET_SECS),
                handle_connection(&store, stream, read_timeout),
            )
            .await;
            drop(permit);
        });
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}
