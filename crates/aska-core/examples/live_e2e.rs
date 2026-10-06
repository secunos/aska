//! Live end-to-end over real Tor against a running relay (M3 gate, network half).
//! The owner runs this in the VM once the droplet relay is up:
//!
//!   cargo run --release -p aska-core --example live_e2e -- <onion-address> [socks_host:port]
//!
//! It seals a note, posts it through Tor (a fresh circuit per request), fetches it back on a
//! second Session, opens the real slot and the decoy, and prints each step. It writes nothing
//! to disk. Default SOCKS proxy is 127.0.0.1:9050.

use aska_core::consts::PTYPE_TEXT;
use aska_core::drop::{Relay, TorConnector};
use aska_core::session::{Level, Session, SessionConfig};
use aska_core::tor::TorConfig;
use std::sync::Arc;
use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: live_e2e <onion-address> [socks_host:port]");
        std::process::exit(2);
    }
    let onion = args[1].trim().to_string();
    let socks = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:9050".into());

    let relay = match Relay::from_onion(&onion) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("not a valid .onion address: {e}");
            std::process::exit(2);
        }
    };
    let tor = TorConfig {
        socks: socks.parse().expect("socks host:port"),
        ..TorConfig::default()
    };
    let cfg = SessionConfig {
        tor: tor.clone(),
        relays: vec![relay],
        accept_unlocked_memory: true, // a normal VM user cannot mlock; the doctor warns
        request_delay_max: Duration::from_secs(3),
        ..SessionConfig::default()
    };
    let connector = Arc::new(TorConnector { cfg: tor });

    println!("[1/5] sealing a note with a decoy slot …");
    let mut s = Session::with_connector(cfg.clone(), connector.clone()).unwrap();
    s.compose(b"live test: meet at the north gate, 14 Nov", PTYPE_TEXT)
        .unwrap();
    s.add_decoy("remember to buy milk", "south").unwrap();
    s.seal(Level::Quick).unwrap();
    let words = s.hand_over_words().unwrap();

    println!("[2/5] posting through Tor (10–120 s per attempt; a failed rendezvous is retried on a fresh circuit) …");
    let mut stored = false;
    for attempt in 1..=4 {
        let t0 = std::time::Instant::now();
        let results = s.post().unwrap();
        for r in &results {
            match &r.result {
                Ok(st) => println!(
                    "      attempt {attempt}: {:?} after {:.0?}",
                    st,
                    t0.elapsed()
                ),
                Err(e) => println!("      attempt {attempt}: {e} (after {:.0?})", t0.elapsed()),
            }
        }
        if results.iter().any(|r| r.stored()) {
            stored = true;
            break;
        }
    }
    if !stored {
        eprintln!("post failed on every attempt — check that Tor in the VM is bootstrapped (sudo journalctl -u tor@default | grep -i bootstrapped | tail -1)");
        std::process::exit(1);
    }
    s.close();

    println!("[3/5] fetching it back on a fresh Session …");
    let mut r = Session::with_connector(cfg, connector).unwrap();
    r.add_key_material(&words).unwrap();
    drop(words);
    let mut found = false;
    for attempt in 1..=6 {
        let t0 = std::time::Instant::now();
        match r.check_drops() {
            Ok(true) => {
                println!("      fetched after {:.0?}", t0.elapsed());
                found = true;
                break;
            }
            Ok(false) => println!("      not visible yet (attempt {attempt}/6), waiting 10 s …"),
            Err(e) => println!("      attempt {attempt}/6: {e} — retrying on a fresh circuit"),
        }
        std::thread::sleep(Duration::from_secs(10));
    }
    if !found {
        eprintln!("the Block was not retrieved");
        std::process::exit(1);
    }

    println!("[4/5] opening the real slot …");
    r.open(None).unwrap();
    let note = String::from_utf8_lossy(r.plaintext().unwrap()).to_string();
    println!("      note: {note:?}");

    println!("[5/5] opening the decoy slot …");
    r.open(Some("south")).unwrap();
    let decoy = String::from_utf8_lossy(r.plaintext().unwrap()).to_string();
    println!("      decoy: {decoy:?}");
    r.close();

    if note.contains("north gate") && decoy.contains("milk") {
        println!("\nLIVE E2E OK — sealed, posted over Tor, fetched and opened both slots.");
    } else {
        eprintln!("content mismatch");
        std::process::exit(1);
    }
}
