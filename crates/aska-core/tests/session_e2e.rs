//! End-to-end through the Session against an in-process relay (M3 gate, local half):
//! Level 1 (Quick) with decoy and distress slots, Level 2 (Guarded) via Shares, Key Card
//! relays, the PoW path, the idle watchdog, and state-machine refusals.

mod common;

use aska_core::cancel::CancelToken;
use aska_core::consts::{PTYPE_BINARY, PTYPE_TEXT};
use aska_core::drop::DropClient;
use aska_core::kdf::KdfProfile;
use aska_core::session::{KeyStatus, Level, Session, SessionConfig, SessionError, State};
use aska_drop::Config;
use common::*;
use std::sync::Arc;
use std::time::Duration;

fn cfg(relay: &LocalRelay) -> (SessionConfig, Arc<DirectConnector>) {
    let c = SessionConfig {
        relays: vec![test_relay()],
        accept_unlocked_memory: true,
        request_delay_max: Duration::ZERO,
        profile: KdfProfile::P2, // 64 MiB keeps the tests quick; P1 is exercised by the vectors
        open_profiles: vec![KdfProfile::P2, KdfProfile::P1],
        ..SessionConfig::default()
    };
    (c, Arc::new(DirectConnector { addr: relay.addr }))
}

#[test]
fn level1_quick_with_decoy_and_distress() {
    let relay = start_relay(Config::default());
    let (c, conn) = cfg(&relay);

    // sender
    let mut s = Session::with_connector(c.clone(), conn.clone()).unwrap();
    s.compose(b"meet 14 nov, north gate", PTYPE_TEXT).unwrap();
    s.set_passphrase(None).unwrap();
    s.add_decoy("buy milk", "south").unwrap();
    s.set_distress("nothing here", "help").unwrap();
    s.seal(Level::Quick).unwrap();
    assert_eq!(s.state(), State::Sealed);
    assert_eq!(s.share_count(), 0);
    let words = s.hand_over_words().unwrap();
    assert_eq!(words.split(' ').count(), 24);
    let card = s.hand_over_keycard().unwrap();
    assert!(card.starts_with("aska1"));
    assert_eq!(s.state(), State::HandOver);
    let results = s.post().unwrap();
    assert!(results.iter().all(|r| r.stored()), "{results:?}");
    assert_eq!(s.state(), State::Posted);
    s.close();
    assert_eq!(s.state(), State::Closed);
    assert!(matches!(
        s.post(),
        Err(SessionError::WrongState(State::Closed))
    ));
    assert_eq!(relay.store.lock().unwrap().counts()[0], 1);

    // receiver with the words: real note, then the decoy
    let mut r = Session::with_connector(c.clone(), conn.clone()).unwrap();
    assert_eq!(r.add_key_material(&words).unwrap(), KeyStatus::Ready);
    assert!(r.check_drops().unwrap());
    assert_eq!(r.state(), State::Fetched);
    let info = r.open(None).unwrap();
    assert!(!info.distress);
    assert_eq!(r.plaintext().unwrap(), b"meet 14 nov, north gate");
    let info = r.open(Some("south")).unwrap();
    assert!(!info.distress);
    assert_eq!(r.plaintext().unwrap(), b"buy milk");
    assert!(matches!(r.open(Some("wrong")), Err(SessionError::NoSlot)));
    // key material survives ordinary opens
    assert_eq!(r.plaintext().unwrap(), b"buy milk");
    r.close();

    // receiver with the Key Card, entering the distress passphrase
    let mut d = Session::with_connector(
        SessionConfig {
            relays: vec![],
            ..c.clone()
        },
        conn.clone(),
    )
    .unwrap();
    assert_eq!(d.add_key_material(&card).unwrap(), KeyStatus::Ready);
    assert!(d.check_drops().unwrap());
    let info = d.open(Some("help")).unwrap();
    assert!(info.distress);
    assert_eq!(d.plaintext().unwrap(), b"nothing here");
    // the root is gone — replaced by random bytes, so a further open does the same work
    // and fails exactly as it would after a decoy open (review finding A-2)
    assert!(matches!(d.open(None), Err(SessionError::NoSlot)));
    assert!(matches!(d.open(Some("south")), Err(SessionError::NoSlot)));
    d.close();
}

#[test]
fn level2_guarded_shares() {
    let relay = start_relay(Config::default());
    let (c, conn) = cfg(&relay);
    let mut s = Session::with_connector(c.clone(), conn.clone()).unwrap();
    let secret = vec![0xA5u8; 3000];
    s.compose(&secret, PTYPE_BINARY).unwrap();
    s.seal(Level::Guarded { k: 2, n: 3 }).unwrap();
    assert_eq!(s.share_count(), 3);
    let shares: Vec<String> = (0..3)
        .map(|i| s.share_text(i).unwrap().to_string())
        .collect();
    assert!(shares.iter().all(|t| t.starts_with("askas1")));
    assert!(s.share_text(3).is_err());
    assert!(s.post().unwrap().iter().all(|r| r.stored()));
    s.close();

    let mut r = Session::with_connector(c.clone(), conn.clone()).unwrap();
    assert_eq!(
        r.add_key_material(&shares[2]).unwrap(),
        KeyStatus::NeedShares { have: 1, need: 2 }
    );
    // the same Share twice does not count twice
    assert_eq!(
        r.add_key_material(&shares[2]).unwrap(),
        KeyStatus::NeedShares { have: 1, need: 2 }
    );
    assert_eq!(r.add_key_material(&shares[0]).unwrap(), KeyStatus::Ready);
    assert!(r.check_drops().unwrap());
    let info = r.open(None).unwrap();
    assert_eq!(info.ptype, PTYPE_BINARY);
    assert_eq!(r.plaintext().unwrap(), &secret[..]);
    r.close();
}

#[test]
fn pow_path_and_not_found() {
    // cap 4 → three pre-filled Blocks put the class at 75 % and the post must solve a puzzle
    let relay = start_relay(Config {
        caps: [4, 800, 200],
        ..Config::default()
    });
    let (c, conn) = cfg(&relay);
    let client = DropClient::new(conn.as_ref(), CancelToken::new());
    for _ in 0..3 {
        client.decoy_put(&test_relay(), 1, 1).unwrap();
    }
    assert_eq!(relay.store.lock().unwrap().difficulty_for(1), 3);
    let mut s = Session::with_connector(c.clone(), conn.clone()).unwrap();
    s.compose(b"x", PTYPE_TEXT).unwrap();
    s.seal(Level::Quick).unwrap();
    let words = s.hand_over_words().unwrap();
    assert!(s.post().unwrap()[0].stored());
    // a second post is idempotent (identical re-PUT → Ok)
    assert!(s.post().unwrap()[0].stored());

    // a receiver with a root that was never posted finds nothing
    let mut r = Session::with_connector(c.clone(), conn.clone()).unwrap();
    let other = aska_core::keys::Root::generate_mixed().unwrap().to_words();
    r.add_key_material(&other).unwrap();
    assert!(!r.check_drops().unwrap());
    assert_eq!(r.state(), State::Collecting);
    assert!(matches!(r.open(None), Err(SessionError::WrongState(_))));
    // and the real one finds the Block
    let mut r2 = Session::with_connector(c, conn).unwrap();
    r2.add_key_material(&words).unwrap();
    assert!(r2.check_drops().unwrap());
    assert_eq!(r2.open(None).unwrap().len, 1);
}

#[test]
fn watchdog_and_state_errors() {
    let relay = start_relay(Config::default());
    let (mut c, conn) = cfg(&relay);
    c.idle_timeout = Duration::from_millis(300);
    let mut s = Session::with_connector(c.clone(), conn.clone()).unwrap();
    s.compose(b"note", PTYPE_TEXT).unwrap();
    assert!(s.remaining_idle() <= Duration::from_millis(300));
    std::thread::sleep(Duration::from_millis(400));
    assert!(matches!(s.tick(), Err(SessionError::Expired)));
    assert_eq!(s.state(), State::Closed);
    assert!(s.tick().is_ok());

    let mut s = Session::with_connector(c.clone(), conn.clone()).unwrap();
    assert!(matches!(
        s.seal(Level::Quick),
        Err(SessionError::WrongState(State::Idle))
    ));
    assert!(matches!(s.compose(b"x", 9), Err(SessionError::Format(_))));
    assert!(matches!(
        s.compose(&vec![0u8; 70_000], PTYPE_BINARY),
        Err(SessionError::TooLarge)
    ));
    assert!(matches!(
        s.add_key_material("not key material"),
        Err(SessionError::BadKeyMaterial)
    ));
    // a bad paste changes nothing: the Session is still Idle and can still send
    assert_eq!(s.state(), State::Idle);
    s.compose(b"x", PTYPE_TEXT).unwrap();
    // and once composing, key material is refused
    assert!(matches!(
        s.add_key_material("aska1qqqq"),
        Err(SessionError::WrongState(State::Composing))
    ));

    // no relays configured → NoRelays on post
    let mut s = Session::with_connector(
        SessionConfig {
            relays: vec![],
            ..c
        },
        conn,
    )
    .unwrap();
    s.compose(b"x", PTYPE_TEXT).unwrap();
    s.seal(Level::Quick).unwrap();
    assert!(matches!(s.post(), Err(SessionError::NoRelays)));
}

#[test]
fn foreign_share_is_rejected_and_key_material_can_be_cleared() {
    let relay = start_relay(Config::default());
    let (c, conn) = cfg(&relay);
    // two different Guarded seals → two share sets
    let mut a = Session::with_connector(c.clone(), conn.clone()).unwrap();
    a.compose(b"a", PTYPE_TEXT).unwrap();
    a.seal(Level::Guarded { k: 2, n: 3 }).unwrap();
    let a0 = a.share_text(0).unwrap();
    let a1 = a.share_text(1).unwrap();
    let mut b = Session::with_connector(c.clone(), conn.clone()).unwrap();
    b.compose(b"b", PTYPE_TEXT).unwrap();
    b.seal(Level::Guarded { k: 2, n: 3 }).unwrap();
    let b0 = b.share_text(0).unwrap();

    let mut r = Session::with_connector(c.clone(), conn.clone()).unwrap();
    assert_eq!(
        r.add_key_material(&a0).unwrap(),
        KeyStatus::NeedShares { have: 1, need: 2 }
    );
    // a Share from another set is refused and NOT kept
    assert!(matches!(
        r.add_key_material(&b0),
        Err(SessionError::ForeignShare)
    ));
    assert_eq!(
        r.add_key_material(&a0).unwrap(),
        KeyStatus::NeedShares { have: 1, need: 2 }
    );
    // the right second Share completes the set
    assert_eq!(r.add_key_material(&a1).unwrap(), KeyStatus::Ready);
    // start over
    r.clear_key_material().unwrap();
    assert_eq!(r.state(), State::Idle);
    assert_eq!(
        r.add_key_material(&b0).unwrap(),
        KeyStatus::NeedShares { have: 1, need: 2 }
    );
}

#[test]
fn distress_destroys_label_and_block_and_jobs_can_be_cancelled() {
    let relay = start_relay(Config::default());
    let (mut c, conn) = cfg(&relay);
    let mut s = Session::with_connector(c.clone(), conn.clone()).unwrap();
    s.compose(b"real", PTYPE_TEXT).unwrap();
    s.set_distress("decoy", "help").unwrap();
    s.seal(Level::Quick).unwrap();
    let words = s.hand_over_words().unwrap();
    // job API: post on a worker, Session stays free
    let job = s.post_job().unwrap();
    let results = std::thread::spawn(move || job.run())
        .join()
        .unwrap()
        .unwrap();
    assert!(results[0].stored());
    s.record_post(&results).unwrap();
    assert_eq!(s.state(), State::Posted);

    let mut r = Session::with_connector(c.clone(), conn.clone()).unwrap();
    r.add_key_material(&words).unwrap();
    let job = r.fetch_job().unwrap();
    let out = job.run().unwrap();
    assert!(out.any_answered());
    assert!(r.accept_fetch(out).unwrap());
    let info = r.open(Some("help")).unwrap();
    assert!(info.distress);
    assert_eq!(r.plaintext().unwrap(), b"decoy");
    // the label is gone: a new fetch job cannot even be built; a further open fails like a
    // wrong passphrase (review finding A-2)
    assert!(matches!(r.fetch_job(), Err(SessionError::WrongState(_))));
    assert!(matches!(r.open(None), Err(SessionError::NoSlot)));

    // cancellation during the request delay returns at once
    c.request_delay_max = Duration::from_secs(60);
    let mut s2 = Session::with_connector(c.clone(), conn.clone()).unwrap();
    s2.compose(b"x", PTYPE_TEXT).unwrap();
    s2.seal(Level::Quick).unwrap();
    let job = s2.post_job().unwrap();
    let token = job.cancel_token();
    let t0 = std::time::Instant::now();
    let h = std::thread::spawn(move || job.run());
    std::thread::sleep(Duration::from_millis(100));
    token.cancel();
    assert!(matches!(h.join().unwrap(), Err(SessionError::Cancelled)));
    assert!(t0.elapsed() < Duration::from_secs(5));
    // the Session was never blocked: distress works immediately
    s2.distress();
    assert_eq!(s2.state(), State::Closed);
}

#[test]
fn auth_relay_without_control_port_is_refused_before_network() {
    let relay = start_relay(Config::default());
    let (mut c, conn) = cfg(&relay);
    let mut auth_relay = test_relay();
    auth_relay.auth_key = Some(aska_core::drop::secret32([7u8; 32]));
    c.relays = vec![auth_relay];
    c.tor.control = None;
    let mut s = Session::with_connector(c.clone(), conn.clone()).unwrap();
    s.compose(b"x", PTYPE_TEXT).unwrap();
    s.seal(Level::Quick).unwrap();
    assert!(matches!(
        s.post_job(),
        Err(SessionError::AuthUnavailable(_))
    ));
    // the Key Card carries the circle key, and the debug output never shows it
    let card = s.hand_over_keycard().unwrap();
    let kc = aska_core::encodings::KeyCard::decode(&card).unwrap();
    assert_eq!(kc.auth_key, Some([7u8; 32]));
    let dbg = format!("{:?}", c.relays[0]);
    assert!(dbg.contains("auth=true") && !dbg.contains("7, 7, 7"));
}

#[test]
fn locked_input_api() {
    use aska_core::secret::LockedBuf;
    let relay = start_relay(Config::default());
    let (c, conn) = cfg(&relay);
    let mut s = Session::with_connector(c.clone(), conn.clone()).unwrap();
    let mut note = LockedBuf::with_capacity(64);
    note.extend_from_slice("typed in the editor \u{fb01}".as_bytes()); // ligature: NFKC only applies to passphrases
    s.compose_locked(note, PTYPE_TEXT).unwrap();
    let mut pw = LockedBuf::with_capacity(16);
    pw.extend_from_slice("\u{fb01}sh".as_bytes()); // "ﬁsh" → NFKC → "fish"
    s.set_passphrase_locked(Some(pw)).unwrap();
    s.seal(Level::Quick).unwrap();
    let words = s.hand_over_words().unwrap();
    s.post().unwrap();

    let mut r = Session::with_connector(c, conn).unwrap();
    r.add_key_material(&words).unwrap();
    assert!(r.check_drops().unwrap());
    // the same passphrase typed with plain ASCII opens the slot (NFKC equivalence)
    let mut pw2 = LockedBuf::with_capacity(16);
    pw2.extend_from_slice(b"fish");
    r.open_locked(Some(pw2)).unwrap();
    assert_eq!(
        r.plaintext().unwrap(),
        "typed in the editor \u{fb01}".as_bytes()
    );
    // a non-UTF-8 passphrase buffer is refused cleanly
    let mut bad = LockedBuf::with_capacity(4);
    bad.extend_from_slice(&[0xff, 0xfe]);
    assert!(matches!(
        r.open_locked(Some(bad)),
        Err(SessionError::NotText)
    ));
}

#[test]
fn foreign_share_rejected_at_any_k_and_stale_fetch_refused() {
    let relay = start_relay(Config::default());
    let (c, conn) = cfg(&relay);
    // 3-of-5: the k ≥ 3 case where a stranger used to slip in before combine ran
    let mut a = Session::with_connector(c.clone(), conn.clone()).unwrap();
    a.compose(b"a", PTYPE_TEXT).unwrap();
    a.seal(Level::Guarded { k: 3, n: 5 }).unwrap();
    let a_shares: Vec<String> = (0..5)
        .map(|i| a.share_text(i).unwrap().to_string())
        .collect();
    a.post().unwrap();
    let mut b = Session::with_connector(c.clone(), conn.clone()).unwrap();
    b.compose(b"b", PTYPE_TEXT).unwrap();
    b.seal(Level::Guarded { k: 3, n: 5 }).unwrap();
    let b1 = b.share_text(1).unwrap();

    let mut r = Session::with_connector(c.clone(), conn.clone()).unwrap();
    r.add_key_material(&a_shares[0]).unwrap();
    assert!(matches!(
        r.add_key_material(&b1),
        Err(SessionError::ForeignShare)
    ));
    assert_eq!(
        r.add_key_material(&a_shares[3]).unwrap(),
        KeyStatus::NeedShares { have: 2, need: 3 }
    );
    assert_eq!(r.add_key_material(&a_shares[4]).unwrap(), KeyStatus::Ready);
    assert!(r.check_drops().unwrap());
    r.open(None).unwrap();
    assert_eq!(r.plaintext().unwrap(), b"a");

    // a fetch job built for one root cannot deliver a Block into a Session re-keyed since
    let mut w = Session::with_connector(c, conn).unwrap();
    let words_a = a.hand_over_words().unwrap();
    w.add_key_material(&words_a).unwrap();
    let job = w.fetch_job().unwrap();
    let out = job.run().unwrap();
    w.clear_key_material().unwrap();
    let words_b = b.hand_over_words().unwrap();
    w.add_key_material(&words_b).unwrap();
    assert!(matches!(w.accept_fetch(out), Err(SessionError::StaleJob)));
    assert_eq!(w.state(), State::Collecting);
}

#[test]
fn watchdog_is_suspended_while_a_job_is_in_flight() {
    let relay = start_relay(Config::default());
    let (mut c, conn) = cfg(&relay);
    c.idle_timeout = Duration::from_millis(300);
    // Sender: a post job that outlives the idle timeout must not expire the Session.
    let mut s = Session::with_connector(c.clone(), conn.clone()).unwrap();
    s.compose(b"slow network", PTYPE_TEXT).unwrap();
    s.seal(Level::Quick).unwrap();
    let words = s.hand_over_words().unwrap();
    let job = s.post_job().unwrap();
    assert!(s.job_in_flight());
    assert_eq!(s.remaining_idle(), Duration::from_millis(300));
    std::thread::sleep(Duration::from_millis(450));
    assert!(s.tick().is_ok(), "ticked to Closed while a job was out");
    let results = job.run().unwrap(); // guard dropped here → clock refreshed
    assert!(!s.job_in_flight());
    s.record_post(&results).unwrap();
    assert_eq!(s.state(), State::Posted);
    s.close();

    // Receiver: same for a fetch job, and an abandoned job releases the watchdog again.
    let mut r = Session::with_connector(c.clone(), conn).unwrap();
    r.add_key_material(&words).unwrap();
    let job = r.fetch_job().unwrap();
    std::thread::sleep(Duration::from_millis(450));
    assert!(r.tick().is_ok());
    let out = job.run().unwrap();
    assert!(r.accept_fetch(out).unwrap());
    r.open(None).unwrap();
    assert_eq!(r.plaintext().unwrap(), b"slow network");
    // A job that is dropped without running stops protecting the Session.
    let _ = r.fetch_job().map(drop);
    std::thread::sleep(Duration::from_millis(450));
    assert!(matches!(r.tick(), Err(SessionError::Expired)));
}

#[test]
fn split_shares_from_received_key_material_and_offline_bucket_match() {
    let relay = start_relay(Config::default());
    let (c, conn) = cfg(&relay);
    let mut s = Session::with_connector(c.clone(), conn.clone()).unwrap();
    s.compose(b"split mode", PTYPE_TEXT).unwrap();
    s.seal(Level::Quick).unwrap();
    let words = s.hand_over_words().unwrap();
    // Split mode, offline side: the sealed Block and label leave as a file …
    let (label, block) = s.sealed_block().unwrap();
    let block = block.to_vec();
    s.close();
    assert!(matches!(
        Session::with_connector(c.clone(), conn.clone())
            .unwrap()
            .sealed_block(),
        Err(SessionError::WrongState(State::Idle))
    ));

    // … the receiver's offline side matches a bucket that arrived by file.
    let mut r = Session::with_connector(c.clone(), conn.clone()).unwrap();
    assert!(matches!(
        r.accept_bucket(std::iter::empty()),
        Err(SessionError::WrongState(State::Idle))
    ));
    r.add_key_material(&words).unwrap();
    let decoy_record = ([9u8; 32], vec![0u8; block.len()]);
    assert!(!r.accept_bucket([decoy_record.clone()]).unwrap());
    assert_eq!(r.state(), State::Collecting);
    assert!(r
        .accept_bucket([decoy_record, (label, block.clone())])
        .unwrap());
    assert_eq!(r.state(), State::Fetched);
    r.open(None).unwrap();
    assert_eq!(r.plaintext().unwrap(), b"split mode");
    r.close();

    // Recovery drill: words in, 2-of-3 Shares out, any two reconstruct the same key.
    let mut k = Session::with_connector(c.clone(), conn.clone()).unwrap();
    assert!(matches!(
        k.split_shares(2, 3),
        Err(SessionError::WrongState(State::Idle))
    ));
    k.add_key_material(&words).unwrap();
    assert!(k.split_shares(1, 3).is_err());
    k.split_shares(2, 3).unwrap();
    assert_eq!(k.share_count(), 3);
    let s1 = k.share_text(0).unwrap();
    let s3 = k.share_text(2).unwrap();
    let card = k.hand_over_keycard().unwrap(); // re-encoding on the receiving side
    assert!(card.starts_with("aska1"));
    k.close();
    let mut t = Session::with_connector(c, conn).unwrap();
    assert!(matches!(
        t.add_key_material(&s1).unwrap(),
        KeyStatus::NeedShares { have: 1, need: 2 }
    ));
    assert_eq!(t.add_key_material(&s3).unwrap(), KeyStatus::Ready);
    assert_eq!(t.hand_over_words().unwrap().as_str(), words.as_str());
}

/// A Session moves between threads whole (the GUI seals on a worker and posts from another),
/// and a sealed Block can be re-targeted at other relays without re-sealing.
#[test]
fn session_is_send_and_relays_can_be_changed_after_sealing() {
    fn assert_send<T: Send>() {}
    assert_send::<Session>();
    assert_send::<aska_core::session::PostJob>();
    assert_send::<aska_core::session::FetchJob>();

    let relay = start_relay(Config::default());
    let (mut c, conn) = cfg(&relay);
    c.relays = vec![]; // "posted" nowhere yet
    let mut s = Session::with_connector(c.clone(), conn.clone()).unwrap();
    s.compose(b"moved", PTYPE_TEXT).unwrap();
    // Seal on another thread, get the Session back.
    let mut s = std::thread::spawn(move || {
        s.seal(Level::Quick).unwrap();
        s
    })
    .join()
    .unwrap();
    assert!(matches!(s.post(), Err(SessionError::NoRelays)));
    s.set_relays(vec![test_relay()]).unwrap();
    let results = s.post().unwrap();
    assert!(results.iter().any(|r| r.stored()));
    assert!(matches!(
        s.set_relays(vec![]),
        Err(SessionError::WrongState(State::Posted))
    ));
    let words = s.hand_over_words().unwrap();
    s.close();
    c.relays = vec![test_relay()];
    let mut r = Session::with_connector(c, conn).unwrap();
    r.add_key_material(&words).unwrap();
    // Collecting: the fallback relays may still change (the GUI's Receive screen lets the
    // user type them after the key material); a Key Card's own relays would take precedence.
    r.set_relays(vec![]).unwrap();
    assert!(matches!(r.check_drops(), Err(SessionError::NoRelays)));
    r.set_relays(vec![test_relay()]).unwrap();
    assert!(r.check_drops().unwrap());
    r.open(None).unwrap();
    assert_eq!(r.plaintext().unwrap(), b"moved");
}

// ---------------------------------------------------------------- receiving-key path (DC-02)

#[test]
fn receiving_key_path_end_to_end() {
    let relay = start_relay(Config::default());
    let (c, conn) = cfg(&relay);

    // Receiver: a seed (24 words) and the public Receiving Key with a relay hint.
    let words = aska_core::xwing::new_seed_words().unwrap();
    assert_eq!(words.split(' ').count(), 24);
    let rk = aska_core::xwing::receiving_key_from_words(&words, &[test_relay().pubkey], None, None)
        .unwrap();
    let askar = rk.encode().unwrap();
    assert!(askar.starts_with("askar1"), "{}", &askar[..12]);
    assert!(askar.len() > 1900 && askar.len() < 2100, "{}", askar.len());
    let check = aska_core::encodings::ReceivingKey::check_of_text(&askar).unwrap();
    assert_eq!(check.len(), 14, "{check}"); // 12 symbols in three groups of four

    // Two unrelated Blocks first (symmetric path, random KEM regions) so matching has to
    // pass over non-matching records.
    for i in 0..2u8 {
        let mut o = Session::with_connector(c.clone(), conn.clone()).unwrap();
        o.compose(&[b"other note ", &[b'0' + i][..]].concat(), PTYPE_TEXT)
            .unwrap();
        o.seal(Level::Quick).unwrap();
        assert!(o.post().unwrap().iter().all(|r| r.stored()));
        o.close();
    }

    // Sender: no relays configured — the key's hint supplies one. Guarded is refused; nothing
    // can be handed over; the root is gone once sealed.
    let mut s = Session::with_connector(
        SessionConfig {
            relays: vec![],
            ..c.clone()
        },
        conn.clone(),
    )
    .unwrap();
    s.set_recipient(&askar).unwrap();
    assert_eq!(s.recipient_check().as_deref(), Some(check.as_str()));
    assert!(matches!(
        s.set_recipient("askar1notakey"),
        Err(SessionError::BadReceivingKey)
    ));
    s.compose(b"for your eyes only, across the world", PTYPE_TEXT)
        .unwrap();
    s.add_decoy("weather is fine", "south").unwrap();
    s.set_distress("weather is fine", "help").unwrap();
    assert!(matches!(
        s.seal(Level::Guarded { k: 2, n: 3 }),
        Err(SessionError::RecipientPath)
    ));
    s.seal(Level::Quick).unwrap();
    assert!(s.sealed_for_recipient());
    assert!(matches!(
        s.hand_over_words(),
        Err(SessionError::RecipientPath)
    ));
    assert!(matches!(
        s.hand_over_keycard(),
        Err(SessionError::RecipientPath)
    ));
    assert!(matches!(s.share_text(0), Err(SessionError::RecipientPath)));
    let (label, block) = s.sealed_block().unwrap();
    let block = block.to_vec();
    assert!(s.post().unwrap().iter().all(|r| r.stored()));
    assert_eq!(s.state(), State::Posted);
    s.close();
    assert_eq!(relay.store.lock().unwrap().counts()[0], 3);

    // Receiver: the seed matches the right Block among three; real, decoy, wrong passphrase.
    let mut r = Session::with_connector(c.clone(), conn.clone()).unwrap();
    r.add_receiving_seed(&words).unwrap();
    assert!(r.has_receiving_seed());
    assert!(r.check_drops().unwrap());
    assert_eq!(r.state(), State::Fetched);
    let info = r.open(None).unwrap();
    assert!(!info.distress);
    assert_eq!(
        r.plaintext().unwrap(),
        b"for your eyes only, across the world"
    );
    assert!(!r.open(Some("south")).unwrap().distress);
    assert_eq!(r.plaintext().unwrap(), b"weather is fine");
    assert!(matches!(r.open(Some("wrong")), Err(SessionError::NoSlot)));
    r.close();

    // Split mode: the same matching over a bucket file's records; the distress slot.
    let mut d = Session::with_connector(c.clone(), conn.clone()).unwrap();
    d.add_receiving_seed(&words).unwrap();
    let random_block = vec![0x5Au8; block.len()];
    assert!(d
        .accept_bucket([([9u8; 32], random_block), (label, block.clone())])
        .unwrap());
    let info = d.open(Some("help")).unwrap();
    assert!(info.distress);
    // Distress destroys the receiving seed too (review findings C-2/A-3): the seed could
    // otherwise re-derive the root from the Block that is still on the relay.
    assert!(!d.has_receiving_seed());
    assert!(matches!(d.open(None), Err(SessionError::NoSlot)));
    d.close();

    // A different seed matches nothing; a wrong word list is rejected up front.
    let other = aska_core::xwing::new_seed_words().unwrap();
    let mut n = Session::with_connector(c.clone(), conn.clone()).unwrap();
    n.add_receiving_seed(&other).unwrap();
    assert!(!n.check_drops().unwrap());
    assert!(matches!(
        n.add_receiving_seed("abandon abandon abandon"),
        Err(SessionError::Format(_))
    ));
    n.close();

    // A receiver with a label-based key cannot be confused by a fetch_all outcome and vice
    // versa: the job types carry the mode.
    let mut k = Session::with_connector(c.clone(), conn.clone()).unwrap();
    k.add_receiving_seed(&words).unwrap();
    let job = k.fetch_job().unwrap();
    assert!(format!("{job:?}").contains("FetchJob"));
    k.close();
}
