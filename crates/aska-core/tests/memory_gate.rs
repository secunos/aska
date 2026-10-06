//! M3 memory gate (Client Design §10, Prototype Plan M3): after a full send-and-receive the
//! Sessions are closed, and the process's own writable memory is scanned for the note's
//! plaintext marker and for the root R. Neither may be found.
//!
//! The needles are kept XOR-masked in this test so that the search itself never holds them
//! contiguously; comparison unmasks byte by byte.

mod common;

use aska_core::consts::PTYPE_BINARY;
use aska_core::kdf::KdfProfile;
use aska_core::keys::Root;
use aska_core::rng::{OsRng, RandomSource};
use aska_core::session::{Level, Session, SessionConfig};
use aska_drop::Config;
use common::*;
use std::sync::Arc;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

/// A needle kept XOR-masked so the search never holds the secret contiguously.
struct Masked {
    masked: Vec<u8>,
    mask: Vec<u8>,
    name: &'static str,
}

impl Masked {
    fn new(name: &'static str, plain: &[u8]) -> Self {
        assert!(plain.len() >= 16, "needle too short to be meaningful");
        let mut mask = vec![0u8; plain.len()];
        OsRng.fill(&mut mask).unwrap();
        let masked = plain.iter().zip(&mask).map(|(p, m)| p ^ m).collect();
        Masked { masked, mask, name }
    }
    fn len(&self) -> usize {
        self.masked.len()
    }
    fn matches_at(&self, hay: &[u8], pos: usize) -> bool {
        if pos + self.len() > hay.len() {
            return false;
        }
        (0..self.len()).all(|i| hay[pos + i] == self.masked[i] ^ self.mask[i])
    }
    fn count_in(&self, hay: &[u8]) -> usize {
        (0..hay.len().saturating_sub(self.len() - 1))
            .filter(|&p| self.matches_at(hay, p))
            .count()
    }
}

/// Every writable mapping of this process: heap, stacks, anonymous memory, data segments.
fn writable_regions() -> Vec<(usize, usize, String)> {
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let mut out = Vec::new();
    for line in maps.lines() {
        let mut parts = line.split_whitespace();
        let range = parts.next().unwrap();
        let perms = parts.next().unwrap();
        let path = parts.nth(3).unwrap_or("").to_string();
        if !perms.starts_with("rw") || path == "[vvar]" || path == "[vsyscall]" {
            continue;
        }
        let (a, b) = range.split_once('-').unwrap();
        let a = usize::from_str_radix(a, 16).unwrap();
        let b = usize::from_str_radix(b, 16).unwrap();
        out.push((a, b, path));
    }
    out
}

/// Read our own memory with `process_vm_readv`, which does not need `/proc/self/mem`
/// permissions (the process is non-dumpable after the Session ran).
fn read_region(start: usize, len: usize, buf: &mut Vec<u8>) -> bool {
    buf.clear();
    buf.resize(len, 0);
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: start as *mut libc::c_void,
        iov_len: len,
    };
    // SAFETY: both iovecs describe valid buffers/ranges for the duration of the call.
    let n = unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) };
    if n < 0 {
        return false;
    }
    buf.truncate(n as usize);
    true
}

/// Count occurrences of each needle. With `ASKA_GATE_DEBUG=1` each hit's mapping and offset
/// is printed, which is how a leak is located.
fn scan(needles: &[&Masked]) -> Vec<usize> {
    let debug = std::env::var_os("ASKA_GATE_DEBUG").is_some();
    let mut buf = Vec::new();
    let mut hits = vec![0usize; needles.len()];
    for (a, b, path) in writable_regions() {
        let mut off = a;
        while off < b {
            let len = (b - off).min(8 << 20);
            if read_region(off, len, &mut buf) {
                for (i, n) in needles.iter().enumerate() {
                    let c = n.count_in(&buf);
                    if c > 0 && debug {
                        for p in 0..buf.len() {
                            if n.matches_at(&buf, p) {
                                eprintln!(
                                    "needle {i}: {path} region {a:#x}-{b:#x} at +{:#x}",
                                    off - a + p
                                );
                            }
                        }
                    }
                    hits[i] += c;
                }
            }
            off += len;
        }
    }
    hits
}

/// The whole send-and-receive flow, in its own frame so that the outer test can scrub the
/// stack below itself before scanning. Returns only masked needles: the note marker, the
/// root R, the 24 words (head and tail), the passphrase, one Share, and the circle auth key.
#[inline(never)]
fn run_flow(relay: &LocalRelay) -> Vec<Masked> {
    let conn = Arc::new(DirectConnector { addr: relay.addr });
    let control = start_fake_control();
    let mut auth_relay = test_relay();
    let auth_key: [u8; 32] = OsRng.array().unwrap();
    auth_relay.auth_key = Some(aska_core::drop::secret32(auth_key));
    let cfg = SessionConfig {
        tor: aska_core::tor::TorConfig {
            control: Some(control),
            control_auth: aska_core::tor::ControlAuth::None,
            ..aska_core::tor::TorConfig::default()
        },
        relays: vec![auth_relay],
        accept_unlocked_memory: true,
        request_delay_max: Duration::ZERO,
        profile: KdfProfile::P2,
        open_profiles: vec![KdfProfile::P2],
        ..SessionConfig::default()
    };
    let mut needles = Vec::new();
    needles.push(Masked::new("auth key", &auth_key));

    // A note whose middle 32 bytes are a random marker; a long random passphrase.
    let mut marker: [u8; 32] = OsRng.array().unwrap();
    needles.push(Masked::new("note marker", &marker));
    let mut note = Zeroizing::new(vec![b'n'; 200]);
    note[100..132].copy_from_slice(&marker);
    let pw_bytes: [u8; 24] = OsRng.array().unwrap();
    let mut passphrase = Zeroizing::new(data_encoding::HEXLOWER.encode(&pw_bytes)); // 48 chars
    needles.push(Masked::new("passphrase", passphrase.as_bytes()));

    let mut s = Session::with_connector(cfg.clone(), conn.clone()).unwrap();
    s.compose(&note, PTYPE_BINARY).unwrap();
    s.set_passphrase(Some(&passphrase)).unwrap();
    s.add_decoy("decoy text", "pw").unwrap();
    s.seal(Level::Guarded { k: 2, n: 3 }).unwrap();
    let words = s.hand_over_words().unwrap();
    let card = s.hand_over_keycard().unwrap();
    let share0 = s.share_text(0).unwrap();
    let share1 = s.share_text(1).unwrap();
    assert!(s.post().unwrap()[0].stored(), "post through the auth path");
    s.close();
    drop(s);

    needles.push(Masked::new("words (head)", &words.as_bytes()[..40]));
    needles.push(Masked::new(
        "words (tail)",
        &words.as_bytes()[words.len() - 40..],
    ));
    {
        let sh = aska_core::encodings::share_decode(&share0).unwrap();
        needles.push(Masked::new("share 0 bytes", &sh.to_bytes()[..]));
        let r = Root::from_words(&words).unwrap();
        needles.push(Masked::new("root", r.as_bytes()));
        // Not the label: the relay runs in this process and legitimately holds it as a store
        // key. The GUI memory gate (scripts/memory-gate-gui.sh, relay out of process) checks
        // that the client keeps no copy of the label either.
    }

    // Receiver 1: Key Card (carries the auth key) → fetch → open real + decoy.
    let mut recv = Session::with_connector(cfg.clone(), conn.clone()).unwrap();
    recv.add_key_material(&card).unwrap();
    drop(card);
    assert!(recv.check_drops().unwrap());
    recv.open(Some(&passphrase)).unwrap();
    assert_eq!(&recv.plaintext().unwrap()[100..132], &marker[..]);
    recv.open(Some("pw")).unwrap();
    // while open, the marker is (correctly) present in locked memory — sanity check the scan
    {
        recv.open(Some(&passphrase)).unwrap();
        let hits = scan(&needles.iter().collect::<Vec<_>>());
        assert!(
            hits[1] >= 1,
            "sanity: marker visible while the Session is open"
        );
    }
    recv.close();
    drop(recv);

    // Receiver 2: two Shares.
    let mut recv2 = Session::with_connector(cfg, conn).unwrap();
    recv2.add_key_material(&share1).unwrap();
    recv2.add_key_material(&share0).unwrap();
    drop(share0);
    drop(share1);
    assert!(recv2.check_drops().unwrap());
    recv2.open(Some(&passphrase)).unwrap();
    recv2.close();
    drop(recv2);

    drop(words);
    drop(note);
    marker.zeroize();
    passphrase.zeroize();
    std::hint::black_box(&marker);
    needles
}

#[test]
fn no_secret_survives_session_close() {
    let relay = start_relay(Config::default());
    let needles = run_flow(&relay);
    // What a front end does after closing a Session: the core's stack scrub, then carry on.
    aska_core::secret::scrub_stack();
    let refs: Vec<&Masked> = needles.iter().collect();
    let hits = scan(&refs);
    let mut failures = Vec::new();
    for (n, h) in needles.iter().zip(&hits) {
        if *h > 0 {
            failures.push(format!("{} found {} time(s)", n.name, h));
        }
    }
    assert!(failures.is_empty(), "secrets survived close: {failures:?}");
}

/// The receiving-key path (DC-02): sender seals for a Receiving Key, receiver matches with the
/// seed and opens; afterwards neither the seed, the expanded X-Wing private keys, the shared
/// secret nor the note may remain. The public key is public and is not a needle.
#[inline(never)]
fn run_kem_flow(relay: &LocalRelay) -> Vec<Masked> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let conn = Arc::new(DirectConnector { addr: relay.addr });
    let cfg = SessionConfig {
        relays: vec![test_relay()],
        accept_unlocked_memory: true,
        request_delay_max: Duration::ZERO,
        profile: KdfProfile::P2,
        open_profiles: vec![KdfProfile::P2],
        ..SessionConfig::default()
    };
    let mut needles = Vec::new();
    let words = aska_core::xwing::new_seed_words().unwrap();
    // Seed bytes and the X-Wing expansion (SHAKE256(seed, 96): ML-KEM d‖z, then sk_X).
    let seed = Root::from_words(&words).unwrap();
    needles.push(Masked::new("receiving seed", seed.as_bytes()));
    let mut expanded = Zeroizing::new([0u8; 96]);
    {
        let mut h = sha3::Shake256::default();
        h.update(seed.as_bytes());
        h.finalize_xof().read(&mut expanded[..]);
    }
    needles.push(Masked::new("ML-KEM d‖z", &expanded[..64]));
    needles.push(Masked::new("X25519 sk", &expanded[64..]));
    drop(expanded);
    needles.push(Masked::new("seed words (head)", &words.as_bytes()[..40]));
    let rk = aska_core::xwing::receiving_key_from_words(&words, &[test_relay().pubkey], None, None)
        .unwrap();
    let askar = rk.encode().unwrap();

    let mut marker: [u8; 32] = OsRng.array().unwrap();
    needles.push(Masked::new("note marker", &marker));
    let mut note = Zeroizing::new(vec![b'k'; 200]);
    note[100..132].copy_from_slice(&marker);

    let mut s = Session::with_connector(cfg.clone(), conn.clone()).unwrap();
    s.set_recipient(&askar).unwrap();
    s.compose(&note, PTYPE_BINARY).unwrap();
    s.seal(Level::Quick).unwrap();
    let (label, block) = s.sealed_block().unwrap();
    // The root of a KEM Block is a needle too (derived from the shared secret; never shown).
    let mut root_copy = [0u8; 32];
    {
        // Recover R exactly as the receiver will, outside the Session, for the needle only.
        let e = aska_core::xwing::Expanded::from_seed(seed.as_bytes());
        let region: [u8; aska_core::consts::KEM_LEN] = block
            [aska_core::consts::KEM_OFF..aska_core::consts::KEM_OFF + aska_core::consts::KEM_LEN]
            .try_into()
            .unwrap();
        let ss = e.decapsulate(&region);
        needles.push(Masked::new("shared secret", &ss[..]));
        root_copy.copy_from_slice(aska_core::xwing::root_from_shared_secret(&ss).as_bytes());
        assert_eq!(
            aska_core::kdf::derive_label(&Root::from_bytes(root_copy)),
            label
        );
    }
    needles.push(Masked::new("root R", &root_copy));
    root_copy.zeroize();
    assert!(s.post().unwrap()[0].stored());
    s.close();
    drop(s);

    let mut r = Session::with_connector(cfg, conn).unwrap();
    r.add_receiving_seed(&words).unwrap();
    assert!(r.check_drops().unwrap());
    r.open(None).unwrap();
    assert_eq!(&r.plaintext().unwrap()[100..132], &marker[..]);
    r.close();
    drop(r);
    drop(words);
    drop(seed);
    note.zeroize();
    marker.zeroize();
    std::hint::black_box(&marker);
    needles
}

#[test]
fn no_receiving_key_secret_survives_session_close() {
    let relay = start_relay(Config::default());
    let needles = run_kem_flow(&relay);
    aska_core::secret::scrub_stack();
    let refs: Vec<&Masked> = needles.iter().collect();
    let hits = scan(&refs);
    let mut failures = Vec::new();
    for (n, h) in needles.iter().zip(&hits) {
        if *h > 0 {
            failures.push(format!("{} found {} time(s)", n.name, h));
        }
    }
    assert!(
        failures.is_empty(),
        "receiving-key secrets survived close: {failures:?}"
    );
}
