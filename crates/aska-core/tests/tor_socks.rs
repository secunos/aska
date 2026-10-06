//! The Tor transport against a SOCKS5 server that behaves like Tor's SOCKS port:
//! username/password isolation per request, hostname addressing, `.onion`-only.

mod common;

use aska_core::cancel::CancelToken;
use aska_core::drop::{DropClient, TorConnector};
use aska_core::tor::{connect_onion, TorConfig, TorError};
use aska_drop::Config;
use common::*;
use std::time::Duration;

#[test]
fn isolated_circuits_and_onion_only() {
    let relay = start_relay(Config::default());
    let socks = start_fake_socks(relay.addr);
    let cfg = TorConfig {
        socks: socks.addr,
        connect_timeout: Duration::from_secs(5),
        io_timeout: Duration::from_secs(5),
        ..TorConfig::default()
    };
    let connector = TorConnector { cfg: cfg.clone() };
    let client = DropClient::new(&connector, CancelToken::new());
    let relay_id = test_relay();

    let info = client.info(&relay_id).unwrap();
    assert_eq!(info.classes(), vec![1, 2, 3]);
    assert_eq!(client.decoy_get(&relay_id, 1).unwrap(), 0);
    assert_eq!(
        client.decoy_put(&relay_id, 1, 1).unwrap(),
        aska_proto::Status::Ok
    );
    assert_eq!(client.decoy_get(&relay_id, 1).unwrap(), 1);

    let users = socks.usernames.lock().unwrap().clone();
    assert_eq!(users.len(), 4, "one connection per request");
    let mut uniq = users.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(
        uniq.len(),
        4,
        "every request used fresh isolation credentials"
    );
    let hosts = socks.hosts.lock().unwrap().clone();
    assert!(hosts.iter().all(|h| h == &relay_id.onion()));

    // a clearnet destination is refused before any bytes reach the proxy
    let before = socks.hosts.lock().unwrap().len();
    assert!(matches!(
        connect_onion(&cfg, "relay.example.com", 4567, &CancelToken::new()),
        Err(TorError::NotOnion)
    ));
    assert_eq!(socks.hosts.lock().unwrap().len(), before);

    // unreachable proxy → Unreachable
    let dead = TorConfig {
        socks: "127.0.0.1:1".parse().unwrap(),
        ..cfg
    };
    assert!(matches!(
        connect_onion(&dead, &relay_id.onion(), 4567, &CancelToken::new()),
        Err(TorError::Unreachable(..))
    ));
}

/// D-16 option A: with a control port, the doctor tells a Tor that runs but cannot reach the
/// network (bootstrap stuck) from one that is fine, and points at the platform's bridge tool.
#[test]
fn doctor_flags_a_tor_that_cannot_reach_the_network() {
    use aska_core::doctor::{run, Check, DoctorConfig, Severity};
    let relay = start_relay(Config::default());
    let socks = start_fake_socks(relay.addr);
    let doctor_with = |progress: Option<u8>| {
        let control = start_fake_control_with_bootstrap(progress);
        run(&DoctorConfig {
            tor: TorConfig {
                socks: socks.addr,
                control: Some(control),
                control_auth: aska_core::tor::ControlAuth::None,
                ..TorConfig::default()
            },
            relay_addresses: vec![],
            probe_tor: true,
        })
    };
    let stuck = doctor_with(Some(5));
    let f = stuck
        .iter()
        .find(|f| f.check == Check::TorNetwork)
        .expect("TorNetwork finding");
    assert_eq!(
        f.severity,
        Severity::Warn,
        "a warning, not a refusal: Tor itself is there"
    );
    assert!(f.message.contains("bootstrap 5 %"), "{}", f.message);
    assert!(f.message.contains("bridge"), "{}", f.message);

    let done = doctor_with(Some(100));
    assert!(done.iter().all(|f| f.check != Check::TorNetwork));
    let unknown = doctor_with(None); // an old Tor without the field: no false alarm
    assert!(unknown.iter().all(|f| f.check != Check::TorNetwork));
}
