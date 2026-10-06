//! One ADP/1 request over any blocking byte stream (`std::io::Read + Write`).
//!
//! This is the transport-agnostic half used by `aska-core`'s Dead Drop client, which keeps
//! its networking synchronous on purpose: secrets then never sit in a future's captured state
//! (Client Design §3.1), and the front ends simply run a request on a worker thread.
//! Semantics are identical to the async `client` module.

use crate::*;
use std::io::{Read, Write};

/// Result of one PUT attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    Status(Status),
    PowRequired(PowRequired),
}

fn read_status<S: Read>(s: &mut S) -> Result<Status, ProtoError> {
    let mut h = [0u8; HEADER_LEN];
    s.read_exact(&mut h)?;
    decode_response_header(&h)
}

/// INFO.
pub fn info<S: Read + Write>(s: &mut S) -> Result<Info, ProtoError> {
    s.write_all(&encode_info_request())?;
    s.flush()?;
    let st = read_status(s)?;
    if st != Status::Ok {
        return Err(ProtoError::Status(st));
    }
    let mut b = [0u8; INFO_BODY_LEN];
    s.read_exact(&mut b)?;
    decode_info_body(&b)
}

/// One PUT attempt with the given fixed fields (first attempt or PoW retry).
pub fn put_once<S: Read + Write>(
    s: &mut S,
    fixed: &PutFixed,
    block: &[u8],
) -> Result<PutOutcome, ProtoError> {
    s.write_all(&encode_put_request(fixed, block)?)?;
    s.flush()?;
    let st = read_status(s)?;
    if st == Status::PowRequired {
        let mut b = [0u8; POW_REQUIRED_BODY_LEN];
        s.read_exact(&mut b)?;
        return Ok(PutOutcome::PowRequired(decode_pow_required_body(&b)?));
    }
    Ok(PutOutcome::Status(st))
}

/// GET_ALL: every live record of a class, in the relay's (randomised) order.
pub fn get_all<S: Read + Write>(s: &mut S, class: u8) -> Result<Vec<Record>, ProtoError> {
    let size = class_size(class).ok_or(ProtoError::BadClass)?;
    s.write_all(&encode_get_all_request(class))?;
    s.flush()?;
    let st = read_status(s)?;
    if st != Status::Ok {
        return Err(ProtoError::Status(st));
    }
    let mut c = [0u8; 4];
    s.read_exact(&mut c)?;
    let n = decode_get_all_count(&c)?;
    if n > max_listing_records(class).ok_or(ProtoError::BadClass)? {
        return Err(ProtoError::ListingTooLarge(n));
    }
    let n = n as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let mut label = [0u8; LABEL_LEN];
        s.read_exact(&mut label)?;
        let mut block = vec![0u8; size];
        s.read_exact(&mut block)?;
        out.push((label, block));
    }
    Ok(out)
}

/// Full PUT flow over a connection factory: first attempt, then at most one PoW retry on a
/// fresh connection (§4.3). `connect` is called once per attempt.
pub fn put_with_pow<S, F>(
    mut connect: F,
    label: [u8; LABEL_LEN],
    block: &[u8],
    ttl_hours: u16,
) -> Result<Status, ProtoError>
where
    S: Read + Write,
    F: FnMut() -> std::io::Result<S>,
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
        let mut s = connect()?;
        match put_once(&mut s, &fixed, block)? {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A scripted relay: replies with the canned bytes regardless of the request.
    struct Scripted {
        reply: std::io::Cursor<Vec<u8>>,
        sent: Vec<u8>,
    }
    impl Read for Scripted {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            self.reply.read(b)
        }
    }
    impl Write for Scripted {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.sent.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    fn scripted(reply: Vec<u8>) -> Scripted {
        Scripted {
            reply: std::io::Cursor::new(reply),
            sent: Vec::new(),
        }
    }

    #[test]
    fn hostile_listing_count_is_rejected_before_allocating() {
        let mut s = scripted(encode_get_all_count(u32::MAX));
        assert!(matches!(
            get_all(&mut s, 3),
            Err(ProtoError::ListingTooLarge(u32::MAX))
        ));
        let mut s = scripted(encode_get_all_count(MAX_LISTING_RECORDS[0] + 1));
        assert!(matches!(
            get_all(&mut s, 1),
            Err(ProtoError::ListingTooLarge(_))
        ));
        // class 3 has the tightest cap
        let mut s = scripted(encode_get_all_count(401));
        assert!(matches!(
            get_all(&mut s, 3),
            Err(ProtoError::ListingTooLarge(401))
        ));
        // an honest empty listing still works
        let mut s = scripted(encode_get_all_count(0));
        assert!(get_all(&mut s, 1).unwrap().is_empty());
    }

    #[test]
    fn absurd_pow_difficulty_is_refused_without_solving() {
        let reply = encode_pow_required_response(&PowRequired {
            challenge: [1; 16],
            difficulty: 64,
        });
        let r = put_with_pow(|| Ok(scripted(reply.clone())), [0; 32], &[0; 4096], 1);
        assert!(matches!(r, Err(ProtoError::PowTooHard(64))));
    }

    /// PowRequired → (solved) PowInvalid because the challenge expired → fresh PowRequired
    /// → (solved) Ok: the stale-challenge recovery completes.
    #[test]
    fn stale_challenge_is_recovered_once() {
        let challenge = encode_pow_required_response(&PowRequired {
            challenge: [2; 16],
            difficulty: 2,
        });
        let invalid = encode_put_response(Status::PowInvalid);
        let ok = encode_put_response(Status::Ok);
        let replies = std::cell::RefCell::new(vec![ok, challenge.clone(), invalid, challenge]);
        let r = put_with_pow(
            || Ok(scripted(replies.borrow_mut().pop().unwrap())),
            [0; 32],
            &[0; 4096],
            1,
        );
        assert_eq!(r.unwrap(), Status::Ok);
        assert!(replies.borrow().is_empty(), "exactly four connections");
    }

    #[test]
    fn endless_challenges_end_in_a_distinct_error() {
        let reply = encode_pow_required_response(&PowRequired {
            challenge: [1; 16],
            difficulty: 1,
        });
        let r = put_with_pow(|| Ok(scripted(reply.clone())), [0; 32], &[0; 4096], 1);
        assert!(matches!(r, Err(ProtoError::PowRetryExhausted)));
    }
}
