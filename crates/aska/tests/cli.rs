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

/// RM-09 (1.1): receiving seeds kept in the encrypted profile — add (new and from words),
/// list by check, show the public key again, receive with a stored seed, remove; a profile
/// written by 1.0.x (no seeds) still opens; the file stays one 4 KiB Block.
#[test]
fn profile_stores_receiving_seeds() {
    let b = Bench::new("profseed");
    let prof = b.path("keys.aska");
    let p = prof.to_str().unwrap();
    let made = b.aska(
        &["--relay", ONION, "profile", "create", "--file", p],
        "pp\n",
    );
    assert!(made.ok(), "{}", made.dump());
    // Add a fresh seed: words once (paper backup), public key and check.
    let added = b.aska(&["profile", "add-seed", "--file", p, "--new"], "pp\n");
    assert!(added.ok(), "{}", added.dump());
    let seed_words = added.field("SEED").expect("SEED line");
    let askar1 = added.field("RECEIVING").expect("RECEIVING line");
    let check1 = added.field("CHECK").expect("CHECK line");
    assert_eq!(seed_words.split_whitespace().count(), 24);
    assert_eq!(std::fs::metadata(&prof).unwrap().len(), 4096);
    // Add an existing seed from its words; the same seed again is refused.
    let other = b.aska(&["--relay", ONION, "key", "receive"], "");
    let words2 = other.field("SEED").unwrap();
    let check2 = other.field("CHECK").unwrap();
    let added2 = b.aska(
        &["profile", "add-seed", "--file", p],
        &format!("pp\n{words2}\n"),
    );
    assert!(added2.ok(), "{}", added2.dump());
    assert_eq!(added2.field("CHECK").as_deref(), Some(check2.as_str()));
    let dup = b.aska(
        &["profile", "add-seed", "--file", p],
        &format!("pp\n{words2}\n"),
    );
    assert_eq!(dup.code, 1, "{}", dup.dump());
    assert!(dup.stderr.contains("already holds"), "{}", dup.dump());
    // Listed by check; secrets never printed.
    let shown = b.aska(&["profile", "open", "--file", p], "pp\n");
    assert!(shown.ok(), "{}", shown.dump());
    assert!(
        shown.stdout.contains(&format!("receiving key {check1}")),
        "{}",
        shown.dump()
    );
    assert!(shown.stdout.contains(&format!("receiving key {check2}")));
    assert!(!shown.stdout.contains(&seed_words) && !shown.stdout.contains(&words2));
    // The public key of a stored seed, named by its check (dashes optional).
    let again = b.aska(
        &[
            "--profile",
            p,
            "--relay",
            ONION,
            "key",
            "receive",
            "--stored",
            &check1,
        ],
        "pp\n",
    );
    assert!(again.ok(), "{}", again.dump());
    let askar1_hinted = again.field("RECEIVING").unwrap();
    assert_eq!(again.field("CHECK").as_deref(), Some(check1.as_str()));
    // The profile's relay is already the hint; the same relay given again adds nothing.
    assert_eq!(askar1_hinted, askar1);
    let bare = b.aska(
        &[
            "--profile",
            p,
            "key",
            "receive",
            "--stored",
            &check1.replace('-', ""),
        ],
        "pp\n",
    );
    assert_eq!(bare.field("RECEIVING").as_deref(), Some(askar1.as_str()));
    // A sender posts to the stored key; the receiver names the stored seed by its check —
    // no words typed.
    let sent = b.aska(
        &["send", "--to", &askar1_hinted, "--passphrase"],
        &format!("real-pass\n{NOTE}\n"),
    );
    assert!(sent.ok(), "{}", sent.dump());
    let got = b.aska(
        &["--profile", p, "receive", "--receiving-seed"],
        &format!("pp\n{check1}\nreal-pass\n"),
    );
    assert!(got.ok(), "{}", got.dump());
    assert!(got.stdout.contains(NOTE), "{}", got.dump());
    assert!(
        got.stderr.contains("Stored receiving seed selected"),
        "{}",
        got.dump()
    );
    // Two stored seeds: an empty seed line is ambiguous; a wrong check is refused.
    let amb = b.aska(
        &[
            "--profile",
            p,
            "receive",
            "--receiving-seed",
            "--attempts",
            "1",
        ],
        "pp\n\n\n",
    );
    assert_eq!(amb.code, 1, "{}", amb.dump());
    assert!(amb.stderr.contains("several"), "{}", amb.dump());
    let bad = b.aska(
        &[
            "--profile",
            p,
            "receive",
            "--receiving-seed",
            "--attempts",
            "1",
        ],
        "pp\nqqqq-qqqq-qqqq\n\n",
    );
    assert_eq!(bad.code, 1, "{}", bad.dump());
    // Remove one; with one left, an empty seed line selects it; words still work too.
    let rm = b.aska(&["profile", "remove-seed", "--file", p, &check2], "pp\n");
    assert!(rm.ok(), "{}", rm.dump());
    let shown = b.aska(&["profile", "open", "--file", p], "pp\n");
    assert!(!shown.stdout.contains(&format!("receiving key {check2}")));
    let got = b.aska(
        &["--profile", p, "receive", "--receiving-seed"],
        "pp\n\nreal-pass\n",
    );
    assert!(got.ok() && got.stdout.contains(NOTE), "{}", got.dump());
    let got_words = b.aska(
        &["--profile", p, "receive", "--receiving-seed"],
        &format!("pp\n{seed_words}\nreal-pass\n"),
    );
    assert!(
        got_words.ok() && got_words.stdout.contains(NOTE),
        "{}",
        got_words.dump()
    );
    let none = b.aska(&["profile", "remove-seed", "--file", p, &check2], "pp\n");
    assert_eq!(none.code, 5, "{}", none.dump());
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
    // KDE Plasma on Wayland (1.1 step 4): 6.6+ gets the pointer to the per-window "Hide from
    // Screencast" action; older Plasma the "cannot hide" note; other desktops nothing.
    // `plasmashell --version` is answered by a stub on PATH.
    let stubs = b.path("stubs");
    std::fs::create_dir_all(&stubs).unwrap();
    let stub = |version: &str| {
        let path = stubs.join("plasmashell");
        std::fs::write(&path, format!("#!/bin/sh\necho 'plasmashell {version}'\n")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    };
    let path_with_stubs = format!(
        "{}:{}",
        stubs.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    stub("6.6.2");
    let plasma = b.aska_env(
        &b.dir,
        &["doctor"],
        "",
        &[
            ("XDG_SESSION_TYPE", "wayland"),
            ("XDG_CURRENT_DESKTOP", "KDE"),
            ("PATH", &path_with_stubs),
        ],
    );
    assert!(
        plasma.stdout.contains("[INFO] Plasma can hide this window"),
        "{}",
        plasma.dump()
    );
    assert!(
        plasma.ok(),
        "an INFO finding does not change the exit code: {}",
        plasma.dump()
    );
    stub("6.3.5");
    let old_plasma = b.aska_env(
        &b.dir,
        &["doctor"],
        "",
        &[
            ("XDG_SESSION_TYPE", "wayland"),
            ("XDG_CURRENT_DESKTOP", "KDE"),
            ("PATH", &path_with_stubs),
        ],
    );
    assert!(
        old_plasma.stdout.contains("[INFO] Plasma before 6.6"),
        "{}",
        old_plasma.dump()
    );
    let gnome = run(&[
        ("XDG_SESSION_TYPE", "wayland"),
        ("XDG_CURRENT_DESKTOP", "GNOME"),
    ]);
    assert!(!gnome.stdout.contains("Plasma"), "{}", gnome.dump());
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

// ---------------------------------------------------------------------------------------------
// Paper mode (DC-04, release 1.2)

const ROLLS: &str = "3614525316241365214652136415263152461352416352416352461523614526135241635241652314625314625314625362145263";

fn booklet_payloads(b: &Bench, set: &str) -> Vec<String> {
    let gen = b.aska(
        &[
            "paper",
            "generate",
            "--source",
            "dice",
            "--pages",
            "1",
            "--digits",
            "200",
            "--set-code",
            set,
            "--rows",
        ],
        &format!("{ROLLS}\n"),
    );
    assert!(gen.ok(), "{}", gen.dump());
    assert!(gen.stderr.contains("label SEEDED"), "{}", gen.dump());
    assert!(gen.stderr.contains("all within limits"), "{}", gen.dump());
    let payloads = gen.fields("PAYLOAD");
    assert_eq!(payloads.len(), 2, "{}", gen.dump());
    assert!(gen
        .stdout
        .contains(&format!("PAGE {set} A 01 N 200 SEEDED CHECK ")));
    assert!(gen
        .stdout
        .contains(&format!("PAGE {set} B 01 N 200 SEEDED CHECK ")));
    // Pad rows carry a check digit; key rows A000… and B; device keys R/S.
    assert!(gen.stdout.contains("\n01  "));
    assert!(gen.stdout.contains("\nA000  "));
    assert!(gen.stdout.contains("\nB     "));
    assert!(gen.stdout.contains("\nR "));
    payloads
}

#[test]
fn paper_generate_encipher_decipher_and_check_page() {
    let b = Bench::new("paper");
    let payloads = booklet_payloads(&b, "7342");
    let page = &payloads[0];
    assert!(page.chars().all(|c| c.is_ascii_digit()));
    assert!(page.len() > 600);

    // check-page verifies the checksum; a changed digit is caught.
    let chk = b.aska(
        &["paper", "check-page", "--page-from", "typed"],
        &format!("{page}\n"),
    );
    assert!(chk.ok(), "{}", chk.dump());
    assert!(
        chk.stdout
            .contains("PAGE 7342 A 01 N 200 HANDTAG yes CHECK"),
        "{}",
        chk.dump()
    );
    let mut bad = page.clone().into_bytes();
    bad[40] = if bad[40] == b'9' { b'0' } else { bad[40] + 1 };
    let bad = String::from_utf8(bad).unwrap();
    let chk2 = b.aska(
        &["paper", "check-page", "--page-from", "typed"],
        &format!("{bad}\n"),
    );
    assert_eq!(chk2.code, 5, "{}", chk2.dump());
    assert!(
        chk2.stderr.contains("checksum does not match"),
        "{}",
        chk2.dump()
    );

    // Encipher (padded to the page), both tags printed.
    let enc = b.aska(
        &["paper", "encipher", "--page-from", "typed"],
        &format!("{page}\n\nMEET 14 NOV NORTH GATE\n"),
    );
    assert!(enc.ok(), "{}", enc.dump());
    let cipher = enc.field("CIPHER").unwrap().replace(' ', "");
    let hand = enc.field("HANDTAG").unwrap();
    let dev = enc.field("DEVTAG").unwrap();
    assert!(
        cipher.len() >= 199 && cipher.len() <= 200,
        "{}",
        cipher.len()
    );
    assert_eq!(hand.len(), 4);
    assert_eq!(dev.len(), 19);
    // Unpadded: the length shows.
    let enc2 = b.aska(
        &["paper", "encipher", "--page-from", "typed", "--no-pad"],
        &format!("{page}\n\nMEET 14 NOV NORTH GATE\n"),
    );
    assert!(enc2.ok(), "{}", enc2.dump());
    assert_eq!(enc2.field("CIPHER").unwrap().replace(' ', "").len(), 33);
    // Punctuation is refused with the character named.
    let enc3 = b.aska(
        &["paper", "encipher", "--page-from", "typed"],
        &format!("{page}\n\nHi, there\n"),
    );
    assert_eq!(enc3.code, 1);
    assert!(enc3.stderr.contains("','"), "{}", enc3.dump());

    // Decipher with both tags; with only the device tag; with none (warning).
    for tags in [
        format!("{hand}\n{dev}\n"),
        format!("\n{dev}\n"),
        String::from("\n\n"),
    ] {
        let dec = b.aska(
            &["paper", "decipher", "--page-from", "typed"],
            &format!("{page}\n\n{cipher}\n{tags}"),
        );
        assert!(dec.ok(), "{}", dec.dump());
        assert_eq!(
            dec.stdout.trim(),
            "MEET 14 NOV NORTH GATE",
            "{}",
            dec.dump()
        );
        if tags == "\n\n" {
            assert!(dec.stderr.contains("no tag was checked"), "{}", dec.dump());
        }
    }
    // A wrong hand tag, a wrong device tag, and the other page: nothing shown, exit 5. The
    // wrong tags are the right ones with their last digit changed — never, by chance, the
    // right one (a fixed digit was, once in ten runs, on CI).
    let bump = |t: &str| {
        let mut b = t.as_bytes().to_vec();
        let last = b.len() - 1;
        b[last] = b'0' + (b[last] - b'0' + 1) % 10;
        String::from_utf8(b).unwrap()
    };
    for (c, h, d) in [
        (cipher.clone(), bump(&hand), String::new()),
        (cipher.clone(), String::new(), bump(&dev)),
    ] {
        let dec = b.aska(
            &["paper", "decipher", "--page-from", "typed"],
            &format!("{page}\n\n{c}\n{h}\n{d}\n"),
        );
        assert_eq!(dec.code, 5, "{}", dec.dump());
        assert!(dec.stdout.is_empty(), "{}", dec.dump());
        assert!(dec.stderr.contains("does not verify"), "{}", dec.dump());
    }
    let other = &payloads[1];
    let dec = b.aska(
        &["paper", "decipher", "--page-from", "typed"],
        &format!("{other}\n\n{cipher}\n{hand}\n\n"),
    );
    assert_eq!(dec.code, 5, "{}", dec.dump());

    // Worksheet is plain text with the table.
    let ws = b.aska(&["paper", "worksheet"], "");
    assert!(ws.ok());
    assert!(ws.stdout.contains("70 R  71 H") && ws.stdout.contains("10000 = 9973 + 27"));

    // Too few rolls / a non-roll are refused; a bad page size too.
    let few = b.aska(
        &[
            "paper", "generate", "--source", "dice", "--pages", "1", "--rows",
        ],
        "123456\n",
    );
    assert_eq!(few.code, 1, "{}", few.dump());
    assert!(few.stderr.contains("at least 100"), "{}", few.dump());
    let bad = b.aska(
        &[
            "paper", "generate", "--source", "dice", "--pages", "1", "--rows",
        ],
        "1234567\n",
    );
    assert_eq!(bad.code, 1);
    assert!(bad.stderr.contains("not a die roll"), "{}", bad.dump());
    let size = b.aska(
        &[
            "paper", "generate", "--source", "dice", "--digits", "300", "--rows",
        ],
        &format!("{ROLLS}\n"),
    );
    assert_eq!(size.code, 1);
}

#[test]
fn paper_cover_page_turns_the_ciphertext_innocent() {
    let b = Bench::new("cover");
    let page = booklet_payloads(&b, "0101").remove(0);
    let enc = b.aska(
        &["paper", "encipher", "--page-from", "typed", "--no-pad"],
        &format!("{page}\n\nMEET 14 NOV NORTH GATE\n"),
    );
    assert!(enc.ok(), "{}", enc.dump());
    let cipher = enc.field("CIPHER").unwrap();
    let cover = b.aska(
        &[
            "paper",
            "cover",
            "--set-code",
            "0101",
            "--direction",
            "A",
            "--number",
            "1",
            "--digits",
            "200",
            "--rows",
        ],
        &format!("{cipher}\nSEE YOU ON SUNDAY LOVE\n"),
    );
    assert!(cover.ok(), "{}", cover.dump());
    let cover_page = cover.field("PAYLOAD").unwrap();
    assert!(cover.stdout.contains("PAGE 0101 A 01 N 200"));
    let dec = b.aska(
        &["paper", "decipher", "--page-from", "typed"],
        &format!("{cover_page}\n\n{}\n\n\n", cipher.replace(' ', "")),
    );
    assert!(dec.ok(), "{}", dec.dump());
    assert_eq!(
        dec.stdout.trim(),
        "SEE YOU ON SUNDAY LOVE",
        "{}",
        dec.dump()
    );
    // Lengths must match.
    let wrong = b.aska(
        &[
            "paper",
            "cover",
            "--set-code",
            "0101",
            "--direction",
            "A",
            "--number",
            "1",
            "--rows",
        ],
        &format!("{cipher}\nHELLO\n"),
    );
    assert_eq!(wrong.code, 1);
    assert!(wrong.stderr.contains("must match"), "{}", wrong.dump());
}

#[test]
fn paper_block_cards_seal_and_open() {
    let b = Bench::new("cards");
    let sealed = b.aska(
        &["--relay", ONION, "paper", "seal-cards", "--rows"],
        "hello paper world\n",
    );
    assert!(sealed.ok(), "{}", sealed.dump());
    let cards = sealed.fields("CARD");
    assert_eq!(cards.len(), 4, "{}", sealed.dump());
    assert!(cards[0].starts_with("1/4 "));
    let key = sealed.field("KEYCARD").unwrap();
    assert_eq!(b.relay.store.lock().unwrap().counts(), [0, 0, 0]); // nothing posted
    let card_lines: String = sealed
        .stdout
        .lines()
        .filter(|l| l.starts_with("CARD "))
        .map(|l| format!("{l}\n"))
        .collect();
    // Any order; a duplicate is tolerated.
    let shuffled: String = {
        let mut v: Vec<&str> = card_lines.lines().collect();
        v.reverse();
        v.insert(1, v[0]); // a duplicate before the set completes
        v.iter().map(|l| format!("{l}\n")).collect()
    };
    let opened = b.aska(&["paper", "open-cards"], &format!("{shuffled}{key}\n\n\n"));
    assert!(opened.ok(), "{}", opened.dump());
    assert!(
        opened.stdout.contains("hello paper world"),
        "{}",
        opened.dump()
    );
    assert!(
        opened.stderr.contains("Already have that card"),
        "{}",
        opened.dump()
    );
    // The wrong key opens nothing (exit 5); a damaged card is refused and the set stays
    // incomplete (exit 1); a class-3 note cannot go on paper.
    let other = b.aska(
        &["--relay", ONION, "paper", "seal-cards", "--rows"],
        "another\n",
    );
    let other_key = other.field("KEYCARD").unwrap();
    let wrong = b.aska(
        &["paper", "open-cards"],
        &format!("{card_lines}{other_key}\n\n\n"),
    );
    assert_eq!(wrong.code, 5, "{}", wrong.dump());
    let mut damaged = card_lines.clone();
    let i = damaged.find("1/4 ").unwrap() + 30;
    let ch = damaged.as_bytes()[i];
    damaged.replace_range(i..i + 1, if ch == b'0' { "1" } else { "0" });
    let dmg = b.aska(&["paper", "open-cards"], &format!("{damaged}{key}\n\n\n"));
    assert_eq!(dmg.code, 1, "{}", dmg.dump());
    assert!(
        dmg.stderr.contains("did not scan cleanly"),
        "{}",
        dmg.dump()
    );
    let big = b.aska(
        &[
            "--relay",
            ONION,
            "paper",
            "seal-cards",
            "--class",
            "3",
            "--rows",
        ],
        "x\n",
    );
    assert_eq!(big.code, 1, "{}", big.dump());
    assert!(big.stderr.contains("class 3"), "{}", big.dump());
}

#[test]
fn paper_sheets_ps_pbm_and_print_rules() {
    let b = Bench::new("sheets");
    let ps = b.aska(
        &[
            "paper", "generate", "--source", "dice", "--pages", "1", "--digits", "200", "--ps",
        ],
        &format!("{ROLLS}\n"),
    );
    assert!(ps.ok(), "{}", ps.dump());
    assert!(
        ps.stdout.starts_with("%!PS-Adobe-3.0\n%%Pages: 4\n"),
        "{}",
        &ps.stdout[..60]
    );
    assert_eq!(ps.stdout.matches("showpage").count(), 4); // 2 pages × 2 copies
    let pbm = b.aska(
        &[
            "paper", "generate", "--source", "dice", "--pages", "1", "--digits", "200", "--copies",
            "1", "--pbm",
        ],
        &format!("{ROLLS}\n"),
    );
    assert!(pbm.ok(), "{}", pbm.dump());
    assert!(
        pbm.stdout.starts_with("P4\n1240 1754\n"),
        "{}",
        &pbm.stdout[..20]
    );
    assert_eq!(pbm.stdout.matches("P4\n").count(), 2);
    // Printing a pad without the rules acknowledged is refused before anything is generated.
    let pr = b.aska(
        &[
            "paper", "generate", "--source", "dice", "--pages", "1", "--print", "lp0",
        ],
        &format!("{ROLLS}\n"),
    );
    assert_eq!(pr.code, 1, "{}", pr.dump());
    assert!(pr.stderr.contains("i-have-read-the-rules"), "{}", pr.dump());
    assert!(!pr.stderr.contains("Booklet"), "{}", pr.dump());
    // Share cards as text and as sheets; Block cards as PostScript.
    let shares = "askas1qpzry9x8gf2tvdw0s3jn54khce6mua7lqpzry9x8gf2tvdw0s3jn54khce6mua7l\naskas1qpzry9x8gf2tvdw0s3jn54khce6mua7lqpzry9x8gf2tvdw0s3jn54khce6mua7m\n";
    let sc = b.aska(
        &["paper", "share-cards", "--rows", "--threshold", "2"],
        shares,
    );
    assert!(sc.ok(), "{}", sc.dump());
    assert!(
        sc.stdout
            .contains("SHARE 1 OF 2 — ANY 2 OPEN THE NOTE\naska s1qp zry9"),
        "{}",
        sc.dump()
    );
    let sc_ps = b.aska(&["paper", "share-cards", "--ps"], shares);
    assert!(sc_ps.ok(), "{}", sc_ps.dump());
    assert!(sc_ps.stdout.contains("%%Pages: 2\n"));
    let cards_ps = b.aska(&["--relay", ONION, "paper", "seal-cards", "--ps"], "x\n");
    assert!(cards_ps.ok(), "{}", cards_ps.dump());
    assert!(cards_ps.stdout.contains("%%Pages: 1\n"));
    assert!(cards_ps.field("KEYCARD").is_some());
    // An output must be chosen for generate.
    let none = b.aska(
        &["paper", "generate", "--source", "dice", "--pages", "1"],
        &format!("{ROLLS}\n"),
    );
    assert_eq!(none.code, 1);
    assert!(none.stderr.contains("choose an output"), "{}", none.dump());
}
