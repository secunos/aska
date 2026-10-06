//! One ADP/1 request over any async byte stream (feature `client`).
//!
//! Transport is the caller's business: at M3 `aska-core` hands in a stream that was opened
//! through Tor's SOCKS5 port with per-request isolation; the relay's tests hand in a plain
//! loopback TCP stream. Every function performs exactly one request and leaves the stream at
//! end-of-response; the caller drops it (the relay closes its side anyway, §4.1).

use crate::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Result of one PUT attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    Status(Status),
    PowRequired(PowRequired),
}

async fn read_status<S: AsyncRead + Unpin>(s: &mut S) -> Result<Status, ProtoError> {
    let mut h = [0u8; HEADER_LEN];
    s.read_exact(&mut h).await?;
    decode_response_header(&h)
}

/// INFO.
pub async fn info<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) -> Result<Info, ProtoError> {
    s.write_all(&encode_info_request()).await?;
    let st = read_status(s).await?;
    if st != Status::Ok {
        return Err(ProtoError::Status(st));
    }
    let mut b = [0u8; INFO_BODY_LEN];
    s.read_exact(&mut b).await?;
    decode_info_body(&b)
}

/// One PUT attempt with the given fixed fields (first attempt or PoW retry).
pub async fn put_once<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    fixed: &PutFixed,
    block: &[u8],
) -> Result<PutOutcome, ProtoError> {
    s.write_all(&encode_put_request(fixed, block)?).await?;
    let st = read_status(s).await?;
    if st == Status::PowRequired {
        let mut b = [0u8; POW_REQUIRED_BODY_LEN];
        s.read_exact(&mut b).await?;
        return Ok(PutOutcome::PowRequired(decode_pow_required_body(&b)?));
    }
    Ok(PutOutcome::Status(st))
}

/// GET_ALL: every live record of a class, in the relay's (randomised) order.
pub async fn get_all<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    class: u8,
) -> Result<Vec<Record>, ProtoError> {
    let size = class_size(class).ok_or(ProtoError::BadClass)?;
    s.write_all(&encode_get_all_request(class)).await?;
    let st = read_status(s).await?;
    if st != Status::Ok {
        return Err(ProtoError::Status(st));
    }
    let mut c = [0u8; 4];
    s.read_exact(&mut c).await?;
    let n = decode_get_all_count(&c)?;
    if n > max_listing_records(class).ok_or(ProtoError::BadClass)? {
        return Err(ProtoError::ListingTooLarge(n));
    }
    let n = n as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let mut label = [0u8; LABEL_LEN];
        s.read_exact(&mut label).await?;
        let mut block = vec![0u8; size];
        s.read_exact(&mut block).await?;
        out.push((label, block));
    }
    Ok(out)
}

/// Full PUT flow over a connection factory: first attempt, then at most one PoW retry on a
/// fresh connection (§4.3). `connect` is called once per attempt.
pub async fn put_with_pow<S, F, Fut>(
    mut connect: F,
    label: [u8; LABEL_LEN],
    block: &[u8],
    ttl_hours: u16,
) -> Result<Status, ProtoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::io::Result<S>>,
{
    let class = class_of_len(block.len()).ok_or(ProtoError::BadLength)?;
    let mut fixed = PutFixed::first_attempt(class, ttl_hours, label);
    // First attempt, then at most two solved submissions (a solved retry can be answered
    // PowInvalid if the 120 s challenge window elapsed during a slow Tor circuit, in which
    // case one fresh challenge is requested and solved). At most four connections in all.
    let mut solved = false;
    let mut submissions = 0;
    for _ in 0..4 {
        if submissions >= 2 {
            break;
        }
        let mut s = connect().await?;
        match put_once(&mut s, &fixed, block).await? {
            PutOutcome::Status(Status::PowInvalid) if solved => {
                fixed = PutFixed::first_attempt(class, ttl_hours, label);
                solved = false;
                submissions += 1;
            }
            PutOutcome::Status(st) => return Ok(st),
            PutOutcome::PowRequired(p) => {
                if solved {
                    // a second challenge after a solved one: the relay is misbehaving
                    return Err(ProtoError::PowRetryExhausted);
                }
                if p.difficulty > MAX_POW_DIFFICULTY {
                    return Err(ProtoError::PowTooHard(p.difficulty));
                }
                fixed.challenge = p.challenge;
                fixed.nonce = pow_solve(&p.challenge, &label, p.difficulty);
                solved = true;
            }
        }
    }
    Err(ProtoError::PowRetryExhausted)
}

/// Convenience client over plain TCP (tests and operator tooling only — production clients
/// connect through Tor, §8).
pub struct TcpClient {
    pub addr: std::net::SocketAddr,
}

impl TcpClient {
    pub fn new(addr: std::net::SocketAddr) -> Self {
        TcpClient { addr }
    }
    async fn connect(&self) -> std::io::Result<tokio::net::TcpStream> {
        tokio::net::TcpStream::connect(self.addr).await
    }
    pub async fn info(&self) -> Result<Info, ProtoError> {
        let mut s = self.connect().await?;
        info(&mut s).await
    }
    pub async fn put(
        &self,
        label: [u8; LABEL_LEN],
        block: &[u8],
        ttl_hours: u16,
    ) -> Result<Status, ProtoError> {
        put_with_pow(|| self.connect(), label, block, ttl_hours).await
    }
    pub async fn get_all(&self, class: u8) -> Result<Vec<Record>, ProtoError> {
        let mut s = self.connect().await?;
        get_all(&mut s, class).await
    }
    /// Send raw bytes, half-close, and return the status byte of the reply (malformed-request tests).
    pub async fn raw_status(&self, payload: &[u8]) -> Result<u8, ProtoError> {
        let mut s = self.connect().await?;
        s.write_all(payload).await?;
        s.shutdown().await?;
        let mut h = [0u8; HEADER_LEN];
        s.read_exact(&mut h).await?;
        decode_header(&h)
    }
}
