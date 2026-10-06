//! Full send-and-receive against an in-process relay, without Tor, for the no-file-writes
//! gate (`scripts/no-file-writes-client.sh` runs this under strace). Prints `LOCAL E2E OK`.

use aska_core::cancel::{CancelToken, RegisteredStream};
use aska_core::consts::PTYPE_TEXT;
use aska_core::drop::{Connector, DropError, Relay, Stream};
use aska_core::kdf::KdfProfile;
use aska_core::session::{Level, Session, SessionConfig};
use aska_drop::{serve, Config, Store};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct Direct(SocketAddr);
impl Connector for Direct {
    fn connect(&self, _r: &Relay, cancel: &CancelToken) -> Result<Box<dyn Stream>, DropError> {
        let s = TcpStream::connect(self.0)
            .map_err(|e| DropError::Tor(aska_core::tor::TorError::Unreachable(self.0, e)))?;
        Ok(Box::new(RegisteredStream::new(
            s,
            cancel,
            Duration::from_secs(30),
            Duration::from_secs(60),
        )))
    }
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let store = Arc::new(Mutex::new(Store::new(Config::default())));
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    rt.spawn(async move { serve(listener, store, Duration::from_secs(30)).await });

    let conn = Arc::new(Direct(addr));
    let cfg = SessionConfig {
        relays: vec![Relay::from_onion(
            "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion",
        )
        .unwrap()],
        accept_unlocked_memory: true,
        request_delay_max: Duration::ZERO,
        profile: KdfProfile::P2,
        open_profiles: vec![KdfProfile::P2],
        ..SessionConfig::default()
    };
    let mut s = Session::with_connector(cfg.clone(), conn.clone()).unwrap();
    s.compose(b"the note", PTYPE_TEXT).unwrap();
    s.add_decoy("the decoy", "pw").unwrap();
    s.seal(Level::Guarded { k: 2, n: 3 }).unwrap();
    let words = s.hand_over_words().unwrap();
    let _card = s.hand_over_keycard().unwrap();
    let share0 = s.share_text(0).unwrap();
    let share2 = s.share_text(2).unwrap();
    assert!(s.post().unwrap().iter().all(|r| r.stored()));
    s.close();

    let mut r = Session::with_connector(cfg.clone(), conn.clone()).unwrap();
    r.add_key_material(&share0).unwrap();
    r.add_key_material(&share2).unwrap();
    assert!(r.check_drops().unwrap());
    assert_eq!(r.open(Some("pw")).unwrap().len, 9);
    assert_eq!(r.open(None).unwrap().len, 8);
    assert_eq!(r.plaintext().unwrap(), b"the note");
    r.close();

    let mut w = Session::with_connector(cfg, conn).unwrap();
    w.add_key_material(&words).unwrap();
    assert!(w.check_drops().unwrap());
    w.open(None).unwrap();
    w.close();
    aska_core::secret::scrub_stack();
    // Signal success via exit code only: under the file-writes gate stdout is /dev/null,
    // so nothing here writes a file. A human run passes --verbose to see the line.
    if std::env::args().any(|a| a == "--verbose") {
        println!("LOCAL E2E OK");
    }
    std::process::exit(0);
}
