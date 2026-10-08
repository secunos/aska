//! End-to-end tests of the `aska` binary against an in-process relay behind a fake Tor SOCKS
//! port, all in `--stdin` scripting mode (Client Design §4, Prototype Plan M4 gate: exit codes,
//! refusals, no secret in argv / environment / files).

mod common;
use common::*;

const NOTE: &str = "meet at the north gate, 14 Nov\nbring the second key";

#[test]
fn doctor_reports_and_exits_0_or_2() {
    let b = Bench::new("doctor");
    let o = b.aska(&["doctor"], "");
    assert!(o.ok(), "{}", o.dump());
    assert!(
        o.stdout.contains('[') || o.stdout.contains("No findings"),
        "{}",
        o.dump()
    );
}

#[test]
fn quick_send_receive_with_passphrase_and_decoy() {
    let b = Bench::new("quick");
    // --stdin order for send: passphrase, decoy text, decoy passphrase, then the note.
    let sent = b.aska(
        &[
            "--relay",
            ONION,
            "send",
            "--passphrase",
            "--decoy",
            "--ttl",
            "6h",
        ],
        &format!("real-pass\nremember to buy milk\nmilk\n{NOTE}\n"),
    );
    assert!(sent.ok(), "{}", sent.dump());
    let card = sent.field("KEYCARD").expect("KEYCARD line");
    let words = sent.field("WORDS").expect("WORDS line");
    assert!(card.starts_with("aska1"));
    assert_eq!(words.split_whitespace().count(), 24);
    assert_eq!(sent.field("RELAYS").as_deref(), Some(ONION));
    // Nothing secret on stdout except the hand-over lines themselves.
    assert!(!sent.stdout.contains("north gate"));
    assert!(!sent.stderr.contains("real-pass") && !sent.stderr.contains("north gate"));

    // Receive with the Key Card and the real passphrase.
    let got = b.aska(&["receive"], &format!("{card}\n\nreal-pass\n"));
    assert!(got.ok(), "{}", got.dump());
    assert!(got.stdout.contains(NOTE), "{}", got.dump());

    // Receive with the 24 words and the decoy passphrase: the decoy, same output shape.
    let decoy = b.aska(
        &["--relay", ONION, "receive"],
        &format!("{words}\n\nmilk\n"),
    );
    assert!(decoy.ok(), "{}", decoy.dump());
    assert!(
        decoy.stdout.contains("remember to buy milk"),
        "{}",
        decoy.dump()
    );
    assert!(!decoy.stdout.contains("north gate"));

    // A camera scan returns the QR text UPPER-CASED (alphanumeric mode): both forms must work.
    let upper = b.aska(
        &["receive"],
        &format!("{}\n\nreal-pass\n", card.to_ascii_uppercase()),
    );
    assert!(upper.ok(), "{}", upper.dump());
    assert!(upper.stdout.contains(NOTE), "{}", upper.dump());
    let upper_words = b.aska(
        &["--relay", ONION, "receive"],
        &format!("{}\n\nreal-pass\n", words.to_ascii_uppercase()),
    );
    assert!(upper_words.ok(), "{}", upper_words.dump());
    assert!(upper_words.stdout.contains(NOTE), "{}", upper_words.dump());

    // Wrong passphrase: nothing opened, exit 5.
    let wrong = b.aska(&["receive"], &format!("{card}\n\nnope\n"));
    assert_eq!(wrong.code, 5, "{}", wrong.dump());

    // The Block is on the relay exactly once, in class 1.
    let counts = b.relay.store.lock().unwrap().counts();
    assert_eq!(counts, [1, 0, 0]);
}

#[test]
fn guarded_shares_split_combine_and_check_only() {
    let b = Bench::new("guarded");
    let sent = b.aska(
        &[
            "--relay", ONION, "send", "--shares", "2of3", "--for", "Anna", "--for", "Bo",
        ],
        &format!("{NOTE}\n"),
    );
    assert!(sent.ok(), "{}", sent.dump());
    let shares = sent.fields("SHARE");
    assert_eq!(shares.len(), 3, "{}", sent.dump());
    let texts: Vec<String> = shares
        .iter()
        .map(|s| s.split_once(' ').unwrap().1.to_string())
        .collect();
    assert!(texts.iter().all(|t| t.starts_with("askas1")));
    assert!(
        sent.field("KEYCARD").is_none(),
        "Guarded must not show the whole key"
    );

    // One Share is not enough.
    let one = b.aska(
        &["--relay", ONION, "share", "combine", "--check-only"],
        &format!("{}\n\n\n", texts[0]),
    );
    assert_eq!(one.code, 1, "{}", one.dump());
    assert!(one.stderr.contains("incomplete"), "{}", one.dump());

    // Two verify; a Key Card is refused in `share combine`.
    let two = b.aska(
        &["--relay", ONION, "share", "combine", "--check-only"],
        &format!("aska1notashare\n{}\n{}\n\n\n", texts[2], texts[0]),
    );
    assert!(two.ok(), "{}", two.dump());
    assert!(two.stderr.contains("Shares only"), "{}", two.dump());
    assert!(two.stderr.contains("reconstruct"), "{}", two.dump());

    // Two fetch and open the note (relay from --relay: Shares carry none).
    let got = b.aska(
        &["--relay", ONION, "share", "combine"],
        &format!("{}\n{}\n\n\n", texts[1], texts[2]),
    );
    assert!(got.ok(), "{}", got.dump());
    assert!(got.stdout.contains(NOTE), "{}", got.dump());

    // Recovery drill: re-split from two Shares → words → 3 fresh Shares, any two open the note.
    let words = b.aska(
        &["key", "words"],
        &format!("{}\n{}\n\n\n", texts[0], texts[1]),
    );
    assert!(words.ok(), "{}", words.dump());
    let w = words.field("WORDS").unwrap();
    let re = b.aska(
        &["share", "split", "--k", "2", "--n", "3"],
        &format!("{w}\n\n\n"),
    );
    assert!(re.ok(), "{}", re.dump());
    let fresh: Vec<String> = re
        .fields("SHARE")
        .iter()
        .map(|s| s.split_once(' ').unwrap().1.to_string())
        .collect();
    assert_eq!(fresh.len(), 3);
    assert!(
        fresh.iter().all(|f| !texts.contains(f)),
        "fresh Shares must differ"
    );
    let again = b.aska(
        &["--relay", ONION, "receive"],
        &format!("{}\n{}\n\n\n", fresh[2], fresh[0]),
    );
    assert!(again.ok(), "{}", again.dump());
    assert!(again.stdout.contains(NOTE));
    // A Share from the old set mixed into the new one is foreign and not kept.
    let mixed = b.aska(
        &["--relay", ONION, "receive"],
        &format!("{}\n{}\n{}\n\n\n", fresh[0], texts[1], fresh[1]),
    );
    assert!(mixed.ok(), "{}", mixed.dump());
    assert!(mixed.stderr.contains("different set"), "{}", mixed.dump());
}

#[test]
fn split_mode_seal_post_get_open_and_raw_drop_ops() {
    let b = Bench::new("split");
    let block = b.path("block.bin");
    let sealed = b.aska(
        &[
            "--relay",
            ONION,
            "seal",
            "--out",
            block.to_str().unwrap(),
            "--class",
            "2",
        ],
        &format!("{NOTE}\n"),
    );
    assert!(sealed.ok(), "{}", sealed.dump());
    let card = sealed.field("KEYCARD").unwrap();
    assert!(block.exists());
    assert_eq!(std::fs::metadata(&block).unwrap().len(), 6 + 32 + 16384);
    // Not overwritten a second time.
    let twice = b.aska(&["seal", "--out", block.to_str().unwrap()], "x\n");
    assert_eq!(twice.code, 1);
    assert!(twice.stderr.contains("not overwriting"), "{}", twice.dump());
    // Nothing posted yet: receive finds nothing, exit 5.
    let none = b.aska(&["receive", "--attempts", "1"], &format!("{card}\n\n\n"));
    assert_eq!(none.code, 5, "{}", none.dump());
    assert!(none.stderr.contains("Nothing found"), "{}", none.dump());

    // Networked side posts the file; a second put of the same Block is idempotent.
    let posted = b.aska(
        &[
            "--relay",
            ONION,
            "post",
            block.to_str().unwrap(),
            "--ttl",
            "1h",
        ],
        "",
    );
    assert!(posted.ok(), "{}", posted.dump());
    let put = b.aska(&["drop", "put", ONION, block.to_str().unwrap()], "");
    assert!(put.ok(), "{}", put.dump());
    assert_eq!(b.relay.store.lock().unwrap().counts(), [0, 1, 0]);

    let info = b.aska(&["drop", "info", ONION], "");
    assert!(info.ok(), "{}", info.dump());
    assert!(
        info.stdout.contains("classes: [1, 2, 3]"),
        "{}",
        info.dump()
    );

    // Fetch the class-2 bucket to a file, then open it offline.
    let bucket = b.path("bucket.bin");
    let got = b.aska(
        &[
            "drop",
            "get",
            ONION,
            "--class",
            "2",
            "--out",
            bucket.to_str().unwrap(),
        ],
        "",
    );
    assert!(got.ok(), "{}", got.dump());
    assert!(got.stdout.contains("1 record(s) in class 2"));
    let opened = b.aska(
        &["open", bucket.to_str().unwrap()],
        &format!("{card}\n\n\n"),
    );
    assert!(opened.ok(), "{}", opened.dump());
    assert!(opened.stdout.contains(NOTE), "{}", opened.dump());
    // A bucket of another class does not contain it.
    let other = b.path("bucket1.bin");
    b.aska(
        &[
            "drop",
            "get",
            ONION,
            "--class",
            "1",
            "--out",
            other.to_str().unwrap(),
        ],
        "",
    );
    let miss = b.aska(&["open", other.to_str().unwrap()], &format!("{card}\n\n\n"));
    assert_eq!(miss.code, 5, "{}", miss.dump());
}

#[test]
fn refusals_and_exit_codes() {
    let b = Bench::new("refuse");
    // Not a .onion relay: refused before anything else.
    let bad = b.aska(&["--relay", "example.com", "send"], "x\n");
    assert_eq!(bad.code, 6, "{}", bad.dump());
    // SOCKS proxy not on loopback: refused.
    let o = Command::new(env!("CARGO_BIN_EXE_aska"))
        .args(["--socks", "10.0.0.1:9050", "--stdin", "--yes", "doctor"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(6));
    // SOCKS port closed: doctor refuses network, send exits 6.
    let closed = Command::new(env!("CARGO_BIN_EXE_aska"))
        .args([
            "--socks",
            "127.0.0.1:9",
            "--stdin",
            "--yes",
            "--relay",
            ONION,
            "send",
        ])
        .stdin(std::process::Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(closed.status.code(), Some(6));
    // No relay at all: usage error.
    let none = b.aska(&["send"], "x\n");
    assert_eq!(none.code, 1, "{}", none.dump());
    assert!(none.stderr.contains("no relay"));
    // Empty note.
    let empty = b.aska(&["--relay", ONION, "send"], "");
    assert_eq!(empty.code, 1);
    // Unrecognised key material then EOF.
    let junk = b.aska(&["--relay", ONION, "receive"], "hello\n\n");
    assert_eq!(junk.code, 1, "{}", junk.dump());
    assert!(junk.stderr.contains("Not recognised"));
    // verify never touches the network and always prints the fingerprint block.
    let v = b.aska(&["verify"], "");
    assert!(v.ok(), "{}", v.dump());
    assert!(v.stdout.contains("SHA-256"));
    assert!(
        b.socks.hosts.lock().unwrap().is_empty(),
        "verify must not connect"
    );
}

use std::process::Command;

/// Receiving-key path: the closing lines after a real, a decoy and a distress open must be the
/// same, and so must the exit status — a distress open destroys the receiving seed, and 1.0.x
/// decided the "this receiving key has now been used" line *after* the open, so it was missing
/// exactly when the distress passphrase had been used (fixed in 1.1).
#[test]
fn distress_open_on_receiving_key_path_is_indistinguishable_from_decoy() {
    let b = Bench::new("rxdistress");
    let made = b.aska(&["--relay", ONION, "key", "receive"], "");
    assert!(made.ok(), "{}", made.dump());
    let seed = made.field("SEED").unwrap();
    let askar = made.field("RECEIVING").unwrap();
    let sent = b.aska(
        &[
            "send",
            "--to",
            &askar,
            "--passphrase",
            "--decoy",
            "--distress",
        ],
        &format!(
            "real-pass\ndecoy text here\ndecoy-pass\ndistress text here\ndistress-pass\n{NOTE}\n"
        ),
    );
    assert!(sent.ok(), "{}", sent.dump());
    let open = |pass: &str| {
        b.aska(
            &["--relay", ONION, "receive", "--receiving-seed"],
            &format!("{seed}\n{pass}\n"),
        )
    };
    let decoy = open("decoy-pass");
    assert!(
        decoy.ok() && decoy.stdout.contains("decoy text here"),
        "{}",
        decoy.dump()
    );
    let distress = open("distress-pass");
    assert!(
        distress.ok() && distress.stdout.contains("distress text here"),
        "{}",
        distress.dump()
    );
    assert_eq!(decoy.code, distress.code);
    // Everything after the note itself — the closing lines — is identical.
    let tail = |o: &Out| {
        o.stderr
            .lines()
            .filter(|l| l.starts_with("Closed") || l.starts_with("This receiving key"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(
        tail(&decoy),
        tail(&distress),
        "{}\n---\n{}",
        decoy.dump(),
        distress.dump()
    );
    assert!(tail(&decoy).contains("This receiving key has now been used"));
}

/// 1.0.0 aborted (exit 134, "failed printing to stdout: Broken pipe") when its reader went
/// away early, e.g. `aska verify | head -1`. Now: a quiet exit with 141, the status a shell
/// reports for a command ended by SIGPIPE — including in the middle of a hand-over.
#[test]
fn closed_stdout_exits_141_quietly() {
    let b = Bench::new("pipe");
    let cases: [(&[&str], &str); 3] = [
        (&["verify"], ""),
        (&["doctor"], ""),
        (&["--relay", ONION, "send"], "x\n"),
    ];
    for (args, stdin) in cases {
        let o = b.aska_closed_stdout(args, stdin);
        assert_eq!(o.code, 141, "{args:?}: {}", o.dump());
        assert!(
            !o.stderr.contains("panicked") && !o.stderr.contains("Broken pipe"),
            "{args:?} must stop quietly: {}",
            o.dump()
        );
    }
}

#[test]
fn profile_create_open_use_and_forget() {
    let b = Bench::new("profile");
    let prof = b.path("circle.aska");
    let made = b.aska(
        &[
            "--relay",
            ONION,
            "profile",
            "create",
            "--file",
            prof.to_str().unwrap(),
        ],
        "profile-pass\n",
    );
    assert!(made.ok(), "{}", made.dump());
    assert_eq!(
        std::fs::metadata(&prof).unwrap().len(),
        4096,
        "one class-1 Block"
    );
    let shown = b.aska(
        &["profile", "open", "--file", prof.to_str().unwrap()],
        "profile-pass\n",
    );
    assert!(shown.ok(), "{}", shown.dump());
    assert!(shown.stdout.contains(ONION));
    assert!(shown.stdout.contains("circle auth key: none"));
    let wrong = b.aska(
        &["profile", "open", "--file", prof.to_str().unwrap()],
        "other\n",
    );
    assert_eq!(wrong.code, 5);

    // Use the profile for a whole send/receive: its passphrase is the first stdin line.
    let sent = b.aska(
        &["--profile", prof.to_str().unwrap(), "send"],
        &format!("profile-pass\n{NOTE}\n"),
    );
    assert!(sent.ok(), "{}", sent.dump());
    let card = sent.field("KEYCARD").unwrap();
    let got = b.aska(
        &["--profile", prof.to_str().unwrap(), "receive"],
        &format!("profile-pass\n{card}\n\n\n"),
    );
    assert!(got.ok(), "{}", got.dump());
    assert!(got.stdout.contains(NOTE));

    let gone = b.aska(&["profile", "forget", "--file", prof.to_str().unwrap()], "");
    assert!(gone.ok(), "{}", gone.dump());
    assert!(!prof.exists());
}

#[test]
fn no_secret_in_argv_env_or_files_and_nothing_written() {
    use std::io::Write;
    use std::process::Stdio;
    let b = Bench::new("harness");
    let before: Vec<_> = walk(&b.dir);
    let mut child = Command::new(env!("CARGO_BIN_EXE_aska"))
        .current_dir(&b.dir)
        .env_clear()
        .env("HOME", &b.dir)
        .env("XDG_CONFIG_HOME", b.dir.join("xdg"))
        .env("TMPDIR", b.dir.join("tmp"))
        .args([
            "--socks",
            &b.socks.addr.to_string(),
            "--stdin",
            "--yes",
            "--fast",
            "--accept-unlocked-memory",
        ])
        .args(["--relay", ONION, "send", "--passphrase"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // While it waits for input, inspect what the kernel exposes about it.
    let pid = child.id();
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap();
    // /proc/PID/environ needs ptrace access. aska makes itself non-dumpable at start, after
    // which only root may read it — the stronger outcome, and a race with this read when the
    // tests run as an ordinary user (seen on a GitHub runner, 6 Oct 2026). Check it whenever
    // it is still readable; "permission denied" means nobody but root can see it at all.
    let environ = match std::fs::read(format!("/proc/{pid}/environ")) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Vec::new(),
        Err(e) => panic!("reading /proc/{pid}/environ: {e}"),
    };
    let mut si = child.stdin.take().unwrap();
    si.write_all(format!("secret-pass\n{NOTE}\n").as_bytes())
        .unwrap();
    drop(si);
    let out = child.wait_with_output().unwrap();
    assert!(out.status.code() == Some(0) || out.status.code() == Some(2));
    for hay in [&cmdline[..], &environ[..]] {
        let s = String::from_utf8_lossy(hay);
        assert!(
            !s.contains("secret-pass") && !s.contains("north gate"),
            "secret leaked: {s}"
        );
    }
    let card = String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("KEYCARD ").map(str::to_string))
        .unwrap();
    // Receive too, then compare the scratch tree: nothing new anywhere under HOME/XDG/TMPDIR.
    let got = b.aska(&["receive"], &format!("{card}\n\nsecret-pass\n"));
    assert!(got.ok(), "{}", got.dump());
    let after: Vec<_> = walk(&b.dir);
    assert_eq!(before, after, "the client wrote files: {after:?}");
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut v = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                v.extend(walk(&p));
            }
            v.push(p);
        }
    }
    v.sort();
    v
}

/// D-16 option A: a network that blocks Tor shows up as Tor answering but nothing beyond it;
/// the client says so once, names the platform's bridge tool, and exits 4. `--tor-browser`
/// points at Tor Browser's SOCKS port.
#[test]
fn blocked_network_guidance_and_tor_browser_flag() {
    use std::process::Stdio;
    let blocked = start_fake_socks_blocked();
    let out = Command::new(env!("CARGO_BIN_EXE_aska"))
        .args([
            "--socks",
            &blocked.addr.to_string(),
            "--stdin",
            "--yes",
            "--fast",
            "--accept-unlocked-memory",
        ])
        .args(["--relay", ONION, "send", "--attempts", "2"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map(|mut c| {
            use std::io::Write;
            c.stdin
                .take()
                .unwrap()
                .write_all(b"blocked test\n")
                .unwrap();
            c.wait_with_output().unwrap()
        })
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(4), "{err}");
    assert!(err.contains("blocked network"), "{err}");
    assert!(err.contains("bridge"), "{err}");
    assert_eq!(
        blocked.hosts.lock().unwrap().len(),
        2,
        "one CONNECT per attempt"
    );

    // A relay that is merely full is not a blocked network: no guidance.
    let b = Bench::new("notblocked");
    // (nothing to fill here cheaply; the classifier is unit-tested in aska-core — check only
    // that a normal failure path prints no bridge advice)
    let none = b.aska(
        &["--relay", ONION, "receive", "--attempts", "1"],
        "aska1qqqq\n\n\n",
    );
    assert!(!none.stderr.contains("bridge"), "{}", none.dump());

    // --tor-browser selects 127.0.0.1:9150; with nothing listening the doctor refuses (6).
    let tb = Command::new(env!("CARGO_BIN_EXE_aska"))
        .args(["--tor-browser", "--stdin", "--yes", "doctor"])
        .output()
        .unwrap();
    assert_eq!(tb.status.code(), Some(6));
    assert!(String::from_utf8_lossy(&tb.stdout).contains("127.0.0.1:9150"));
    // …and conflicts with an explicit --socks.
    let both = Command::new(env!("CARGO_BIN_EXE_aska"))
        .args(["--tor-browser", "--socks", "127.0.0.1:9050", "doctor"])
        .output()
        .unwrap();
    assert_ne!(both.status.code(), Some(0));
}

#[test]
fn receiving_key_path_send_to_and_receive_with_seed() {
    let b = Bench::new("rxkey");
    // Receiver: a new key with a relay hint. Seed on its own line, public key and check.
    let made = b.aska(&["--relay", ONION, "key", "receive"], "");
    assert!(made.ok(), "{}", made.dump());
    let seed = made.field("SEED").expect("SEED line");
    let askar = made.field("RECEIVING").expect("RECEIVING line");
    let check = made.field("CHECK").expect("CHECK line");
    assert_eq!(seed.split_whitespace().count(), 24);
    assert!(
        askar.starts_with("askar1") && askar.len() > 1900,
        "{}",
        askar.len()
    );
    // The check is a hash of the public key: 12 bech32 symbols in three groups of four.
    assert_eq!(check.len(), 14, "{check}");
    assert_eq!(
        check,
        aska_core::encodings::ReceivingKey::check_of_text(&askar).unwrap()
    );
    // The same seed re-derives the same public key.
    let again = b.aska(
        &["--relay", ONION, "key", "receive", "--from-words"],
        &format!("{seed}\n"),
    );
    assert!(again.ok(), "{}", again.dump());
    assert_eq!(again.field("RECEIVING").as_deref(), Some(askar.as_str()));
    assert!(again.field("SEED").is_none());

    // Sender: no --relay (the key's hint is used); a passphrase and a decoy as usual; no
    // hand-over lines at all, only the check.
    let sent = b.aska(
        &["send", "--to", &askar, "--passphrase", "--decoy"],
        &format!("real-pass\nnothing to see\nsouth\n{NOTE}\n"),
    );
    assert!(sent.ok(), "{}", sent.dump());
    assert_eq!(sent.field("POSTED").as_deref(), Some(check.as_str()));
    assert!(sent.field("KEYCARD").is_none() && sent.field("WORDS").is_none());
    // Guarded and --to do not combine.
    let bad = b.aska(&["send", "--to", &askar, "--level", "guarded"], NOTE);
    assert!(bad.stderr.contains("cannot be used with"), "{}", bad.dump());
    let notkey = b.aska(&["send", "--to", "askar1nope"], NOTE);
    assert_eq!(notkey.code, 1, "{}", notkey.dump());

    // Receiver: seed, then passphrase; the note. Then the decoy passphrase; then a wrong one.
    let got = b.aska(
        &["--relay", ONION, "receive", "--receiving-seed"],
        &format!("{seed}\nreal-pass\n"),
    );
    assert!(got.ok(), "{}", got.dump());
    assert!(got.stdout.contains(NOTE), "{}", got.dump());
    assert!(got.stderr.contains("create a new one"), "{}", got.dump());
    let decoy = b.aska(
        &["--relay", ONION, "receive", "--receiving-seed"],
        &format!("{seed}\nsouth\n"),
    );
    assert!(
        decoy.ok() && decoy.stdout.contains("nothing to see"),
        "{}",
        decoy.dump()
    );
    let wrong = b.aska(
        &["--relay", ONION, "receive", "--receiving-seed"],
        &format!("{seed}\nnope\n"),
    );
    assert_eq!(wrong.code, 5, "{}", wrong.dump());
    // Another seed finds nothing (exit 5, "Nothing found").
    let other = b.aska(&["--relay", ONION, "key", "receive"], "");
    let other_seed = other.field("SEED").unwrap();
    let none = b.aska(
        &[
            "--relay",
            ONION,
            "receive",
            "--receiving-seed",
            "--attempts",
            "1",
        ],
        &format!("{other_seed}\n\n"),
    );
    assert_eq!(none.code, 5, "{}", none.dump());
    assert!(none.stderr.contains("Nothing found"), "{}", none.dump());
    // Garbage seed words are refused before any network use.
    let junk = b.aska(
        &["--relay", ONION, "receive", "--receiving-seed"],
        "abandon abandon abandon\n\n",
    );
    assert_eq!(junk.code, 1, "{}", junk.dump());
}

/// M6 gate, the part a CI machine can do: every environment-derived doctor finding fires on
/// its trigger and stays silent otherwise (Client Design Table 4). Swap, mlock, core dumps
/// and Tails persistence depend on the host and are exercised on the platform checklists.
#[test]
fn doctor_findings_fire_on_their_triggers_and_stay_silent_otherwise() {
    let b = Bench::new("triggers");
    let run = |env: &[(&str, &str)]| b.aska_env(&b.dir, &["doctor"], "", env);
    let clean = run(&[("XDG_SESSION_TYPE", "wayland")]);
    assert!(clean.ok(), "{}", clean.dump());
    for absent in ["X11 session", "remote session", "accessibility service"] {
        assert!(!clean.stdout.contains(absent), "{absent}: {}", clean.dump());
    }
    let x11 = run(&[("XDG_SESSION_TYPE", "x11")]);
    assert!(x11.stdout.contains("[WARN] X11 session"), "{}", x11.dump());
    assert_eq!(x11.code, 2);
    let remote = run(&[
        ("XDG_SESSION_TYPE", "wayland"),
        ("SSH_CONNECTION", "10.0.0.2 22 10.0.0.1 22"),
        ("DISPLAY", ":10"),
    ]);
    assert!(
        remote.stdout.contains("[WARN] A remote session is active"),
        "{}",
        remote.dump()
    );
    // SSH alone (no forwarded display) is not a remote *desktop*.
    let ssh_only = run(&[
        ("XDG_SESSION_TYPE", "wayland"),
        ("SSH_CONNECTION", "10.0.0.2 22 10.0.0.1 22"),
    ]);
    assert!(
        !ssh_only.stdout.contains("remote session"),
        "{}",
        ssh_only.dump()
    );
    let a11y = run(&[
        ("XDG_SESSION_TYPE", "wayland"),
        ("GNOME_ACCESSIBILITY", "1"),
    ]);
    assert!(
        a11y.stdout.contains("[WARN] An accessibility service"),
        "{}",
        a11y.dump()
    );
    let a11y_off = run(&[
        ("XDG_SESSION_TYPE", "wayland"),
        ("GNOME_ACCESSIBILITY", "0"),
    ]);
    assert!(
        !a11y_off.stdout.contains("accessibility"),
        "{}",
        a11y_off.dump()
    );
    // Tor reachable through the bench's SOCKS: no Tor finding; a dead port: refusal.
    assert!(!clean.stdout.contains("Tor"), "{}", clean.dump());
    let dead = Command::new(env!("CARGO_BIN_EXE_aska"))
        .args(["--socks", "127.0.0.1:9", "--stdin", "--yes", "doctor"])
        .env("XDG_SESSION_TYPE", "wayland")
        .output()
        .unwrap();
    assert_eq!(dead.status.code(), Some(6));
    assert!(String::from_utf8_lossy(&dead.stdout).contains("[REFUSE]"));
}
