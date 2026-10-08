//! The remaining Table 3 commands: `share split`, `key words|card`, `drop info|put|get`,
//! `post`, `verify` and `profile create|open|forget`.

use crate::cmd_receive::collect;
use crate::ctx::{exit, CmdResult, Ctx, Fail};
use crate::files;
use crate::handover::{hand_over, show_material};
use aska_core::cancel::CancelToken;
use aska_core::cover::real_request_delay;
use aska_core::drop::{DropClient, Relay, TorConnector};
use aska_core::profile::{open_profile, seal_profile, Profile};
use aska_core::rng::OsRng;
use aska_core::session::Level;
use aska_proto::Status;
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

// ------------------------------------------------------------------ share split

/// Recovery drill: key material in (words or Key Card), fresh Shares out, one at a time.
pub fn share_split(ctx: &mut Ctx, k: u8, n: u8, for_labels: &[String]) -> CmdResult {
    ctx.doctor_gate(false)?;
    let mut s = ctx.new_session(aska_proto::DEFAULT_TTL_HOURS, None)?;
    collect(ctx, &mut s, false)?;
    s.split_shares(k, n)?;
    hand_over(ctx, &mut s, Level::Guarded { k, n }, for_labels, None)?;
    s.close();
    Ok(())
}

// ------------------------------------------------------------------ key

/// Accept a circle auth key as 64 hex characters or Tor's 52-character base32.
pub fn parse_auth_key(t: &str) -> Result<Zeroizing<[u8; 32]>, Fail> {
    let t = t.trim();
    let bytes: Zeroizing<Vec<u8>> = if t.len() == 64 {
        Zeroizing::new(
            data_encoding::HEXLOWER_PERMISSIVE
                .decode(t.as_bytes())
                .map_err(|_| Fail::new(exit::ERROR, "auth key: not valid hex"))?,
        )
    } else if t.len() == 52 {
        Zeroizing::new(
            data_encoding::BASE32_NOPAD
                .decode(t.to_ascii_uppercase().as_bytes())
                .map_err(|_| Fail::new(exit::ERROR, "auth key: not valid base32"))?,
        )
    } else {
        return Err(Fail::new(
            exit::ERROR,
            "auth key: give 64 hex characters or Tor's 52-character base32 private key",
        ));
    };
    let arr: [u8; 32] = bytes[..]
        .try_into()
        .map_err(|_| Fail::new(exit::ERROR, "auth key: wrong length"))?;
    Ok(Zeroizing::new(arr))
}

fn maybe_apply_auth_key(ctx: &mut Ctx, ask: bool) -> CmdResult {
    if !ask {
        return Ok(());
    }
    if ctx.relays.is_empty() {
        return Err(Fail::new(
            exit::ERROR,
            "--auth-key needs at least one --relay to apply to",
        ));
    }
    let t = ctx
        .input
        .read_hidden("Circle auth key (hex or base32): ")?
        .ok_or_else(|| Fail::new(exit::ERROR, "no auth key given"))?;
    let key = parse_auth_key(&t)?;
    for r in &mut ctx.relays {
        r.auth_key = Some(Box::new(key.clone()));
    }
    Ok(())
}

/// Re-encode the current key material as words or a Key Card (with the relays given).
pub fn key(ctx: &mut Ctx, card: bool, auth_key: bool) -> CmdResult {
    ctx.doctor_gate(false)?;
    maybe_apply_auth_key(ctx, auth_key)?;
    let mut s = ctx.new_session(aska_proto::DEFAULT_TTL_HOURS, None)?;
    collect(ctx, &mut s, false)?;
    if card {
        let text = s.hand_over_keycard()?;
        let relays: Vec<String> = ctx.relays.iter().map(|r| r.onion()).collect();
        let notes = if relays.is_empty() {
            "This card names no relay (none given with --relay).".to_string()
        } else {
            format!("Relay(s) in the card: {}", relays.join(", "))
        };
        show_material(
            ctx,
            &s,
            "Key Card",
            &text,
            &notes,
            "Press any key to forget it",
            "KEYCARD",
        )?;
    } else {
        let text = s.hand_over_words()?;
        let notes = crate::term::words_block(&text);
        show_material(
            ctx,
            &s,
            "24 words",
            &text,
            &notes,
            "Press any key to forget them",
            "WORDS",
        )?;
    }
    s.close();
    Ok(())
}

/// `aska key receive [--from-words]` (DC-02): a receiving seed (24 words, shown once on the
/// alternate screen) and its public Receiving Key (`askar1…`, printed — it is not secret) with
/// the twelve-character check (a hash of the public key) to confirm over another channel.
pub fn key_receive(ctx: &mut Ctx, from_words: bool, stored: Option<&str>) -> CmdResult {
    ctx.doctor_gate(false)?;
    if let Some(check) = stored {
        // A seed kept in the profile (RM-09): show its public key again, nothing secret.
        if ctx.profile_seeds.is_empty() {
            return Err(Fail::new(
                exit::ERROR,
                "--stored needs a --profile that holds a receiving seed",
            ));
        }
        let seed = ctx.stored_seed_for(check)?.ok_or_else(|| {
            Fail::new(
                exit::ERROR,
                format!("not the check of a stored key: {check}"),
            )
        })?;
        let relays: Vec<[u8; 32]> = ctx.relays.iter().map(|r| r.pubkey).collect();
        let rk = aska_core::xwing::receiving_key_from_seed(seed, &relays, None, None);
        let text = rk.encode()?;
        let check = rk.check();
        out!("RECEIVING {text}")?;
        out!("CHECK {check}")?;
        if ctx.input.is_interactive() {
            note!(
                "\nReceiving Key of the stored seed {check} ({} characters).",
                text.len()
            );
        }
        return Ok(());
    }
    let words: crate::term::SecretLine = if from_words {
        ctx.input
            .read_hidden("Receiving seed (24 words): ")?
            .ok_or_else(|| Fail::new(exit::ERROR, "no seed given"))?
    } else {
        let fresh = aska_core::xwing::new_seed_words()?;
        crate::term::SecretLine::from_text(&fresh)?
    };
    let relays: Vec<[u8; 32]> = ctx.relays.iter().map(|r| r.pubkey).collect();
    let rk = aska_core::xwing::receiving_key_from_words(&words, &relays, None, None)
        .map_err(|_| Fail::new(exit::ERROR, "not a valid 24-word receiving seed"))?;
    let text = rk.encode()?;
    let check = rk.check();
    if !ctx.input.is_interactive() {
        if !from_words {
            out!("SEED {}", words.as_str())?;
        }
        out!("RECEIVING {text}")?;
        out!("CHECK {check}")?;
        return Ok(());
    }
    if !from_words {
        let s = ctx.new_session(aska_proto::DEFAULT_TTL_HOURS, None)?;
        let wb = crate::term::words_block(&words);
        let mut notes = Zeroizing::new(String::with_capacity(wb.len() + 128));
        notes.push_str(&wb);
        notes.push_str(
            "\nKeep these 24 words: they are the only way to read notes sent to this key.\n\
             One key per note; nothing is stored.",
        );
        drop(wb);
        crate::handover::show_material(
            ctx,
            &s,
            "Receiving seed — keep these words",
            &words,
            &notes,
            "Press any key to continue to the public key",
            "SEED",
        )?;
    }
    drop(words);
    let relay_note = if relays.is_empty() {
        "The key names no relay (none given with --relay): senders will need one from you."
            .to_string()
    } else {
        format!(
            "Relay hint(s) in the key: {}",
            ctx.relays
                .iter()
                .map(|r| r.onion())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    out!("{text}")?;
    note!(
        "\nReceiving Key ({} characters), check: {check}\n{relay_note}\n\
         Give the key to the sender by any channel and confirm the check with them by another.",
        text.len()
    );
    Ok(())
}

// ------------------------------------------------------------------ drop / post

fn raw_client(ctx: &Ctx) -> (TorConnector, CancelToken) {
    (
        TorConnector {
            cfg: ctx.tor.clone(),
        },
        CancelToken::new(),
    )
}

fn delay(ctx: &Ctx) {
    if !ctx.fast {
        let d = real_request_delay(Duration::from_secs(90), &mut OsRng);
        note!("(cover delay {} s)", d.as_secs());
        std::thread::sleep(d);
    }
}

fn parse_relay(onion: &str) -> Result<Relay, Fail> {
    Relay::from_onion(onion).map_err(|_| {
        Fail::new(
            exit::DOCTOR_REFUSED,
            format!("only .onion relays are allowed; not a valid v3 onion address: {onion}"),
        )
    })
}

pub fn drop_info(ctx: &mut Ctx, onion: &str) -> CmdResult {
    let relay = parse_relay(onion)?;
    ctx.relays = vec![relay.clone()];
    ctx.doctor_gate(true)?;
    let (conn, cancel) = raw_client(ctx);
    let client = DropClient::new(&conn, cancel);
    delay(ctx);
    let info = client
        .info(&relay)
        .map_err(|e| Fail::new(exit::RELAY, format!("INFO failed: {e}")))?;
    out!(
        "relay {}\n  max TTL: {} h\n  classes: {:?}\n  PoW base difficulty: {} bits",
        relay.onion(),
        info.max_ttl_hours,
        info.classes(),
        info.pow_base_difficulty
    )?;
    Ok(())
}

fn status_result(st: Status) -> CmdResult {
    match st {
        Status::Ok => Ok(()),
        Status::Full => Err(Fail::new(exit::RELAY, "relay answered FULL")),
        other => Err(Fail::new(exit::RELAY, format!("relay answered {other:?}"))),
    }
}

pub fn drop_put(ctx: &mut Ctx, onion: &str, file: &Path, ttl: u16) -> CmdResult {
    let relay = parse_relay(onion)?;
    ctx.relays = vec![relay.clone()];
    ctx.doctor_gate(true)?;
    let (label, block) = files::read_block(file)?;
    let (conn, cancel) = raw_client(ctx);
    let client = DropClient::new(&conn, cancel);
    delay(ctx);
    let st = client
        .put(&relay, label, &block, ttl)
        .map_err(|e| Fail::new(exit::RELAY, format!("PUT failed: {e}")))?;
    note!("PUT → {st:?}");
    status_result(st)
}

pub fn drop_get(ctx: &mut Ctx, onion: &str, class: u8, out: Option<&Path>) -> CmdResult {
    let relay = parse_relay(onion)?;
    ctx.relays = vec![relay.clone()];
    ctx.doctor_gate(true)?;
    let (conn, cancel) = raw_client(ctx);
    let client = DropClient::new(&conn, cancel);
    delay(ctx);
    let records = client
        .get_all(&relay, class)
        .map_err(|e| Fail::new(exit::RELAY, format!("GET_ALL failed: {e}")))?;
    out!("{} record(s) in class {class}", records.len())?;
    if let Some(p) = out {
        files::write_bucket(p, class, &records)?;
        note!(
            "Bucket written to {} — match it offline with: aska open {}",
            p.display(),
            p.display()
        );
    }
    Ok(())
}

/// Split mode, networked side: post a Block file to the configured relays.
pub fn post(ctx: &mut Ctx, file: &Path, ttl: u16) -> CmdResult {
    ctx.doctor_gate(true)?;
    if ctx.relays.is_empty() {
        return Err(Fail::new(
            exit::ERROR,
            "no relay: pass --relay ONION (repeatable) or --profile FILE",
        ));
    }
    let (label, block) = files::read_block(file)?;
    let (conn, cancel) = raw_client(ctx);
    let client = DropClient::new(&conn, cancel);
    delay(ctx);
    let results = client.post_all(&ctx.relays, label, &block, ttl);
    let mut stored = false;
    for r in &results {
        match &r.result {
            Ok(st) => {
                note!("  {}: {st:?}", r.relay.onion());
                stored |= r.stored();
            }
            Err(e) => note!("  {}: {e}", r.relay.onion()),
        }
    }
    if stored {
        note!("Posted.");
        Ok(())
    } else {
        Err(Fail::new(
            exit::RELAY,
            "the Block was not stored on any relay",
        ))
    }
}

// ------------------------------------------------------------------ verify

pub fn verify(ctx: &mut Ctx) -> CmdResult {
    use aska_core::fingerprint::{self, Signature};
    ctx.doctor_gate(false)?;
    let fp = fingerprint::check();
    out!(
        "aska {} — verification (nothing is sent anywhere)",
        env!("CARGO_PKG_VERSION")
    )?;
    out!(
        "  this binary's SHA-256:   {}",
        fp.own_sha256
            .as_deref()
            .unwrap_or("(could not read /proc/self/exe)")
    )?;
    out!(
        "  release:                 {}",
        fp.release_tag
            .as_deref()
            .unwrap_or("(none — this is a development build)")
    )?;
    out!(
        "  release key id:          {}",
        fingerprint::RELEASE_PUBKEY
            .and_then(fingerprint::key_id_of)
            .unwrap_or_else(|| "(no key embedded)".into())
    )?;
    out!(
        "  Rekor transparency entry: {}",
        fp.rekor_entry.as_deref().unwrap_or("(not recorded)")
    )?;
    match &fp.signature {
        Signature::NoKey => {
            out!("  signed hash list:        (not checked — no release key in this build)")?;
            out!("  status: unverifiable (development build)")?;
        }
        Signature::NotFound { looked_in } => {
            out!("  signed hash list:        not found (looked for SHA256SUMS + SHA256SUMS.minisig in:")?;
            for d in looked_in {
                out!("                             {})", d.display())?;
            }
            out!("  status: unverifiable here — keep the release's SHA256SUMS and SHA256SUMS.minisig next to the binary, or re-run install.sh")?;
        }
        Signature::Invalid { file, reason } => {
            out!(
                "  signed hash list:        {} — INVALID ({reason})",
                file.display()
            )?;
            out!("  status: MISMATCH — do not use this binary for anything real")?;
        }
        Signature::Valid {
            file,
            key_id,
            trusted_comment,
            lists_this_binary,
        } => {
            out!(
                "  signed hash list:        {} — signature VALID (key {key_id}; \"{trusted_comment}\")",
                file.display()
            )?;
            if *lists_this_binary {
                out!("  status: MATCH — this binary is in the signed release list")?;
            } else {
                out!("  status: MISMATCH — the signed list does not name this binary; do not use it for anything real")?;
            }
        }
    }
    out!(
        "\nHow to check (Client Design §9.4):\n\
         1. Get the release fingerprint out of band — spoken, on paper, or with a Key Card — BEFORE\n\
            you get the binary.\n\
         2. Compare it with the SHA-256 above (sha256sum on the file gives the same value).\n\
         3. The signed hash list above ties the binary to the release key; the key id and the Rekor\n\
            entry can be compared with the project's published values in a browser of your choosing.\n\
         4. Never install an update because software told you one exists; repeat step 1 instead."
    )?;
    Ok(())
}

// ------------------------------------------------------------------ profile

pub fn profile_create(ctx: &mut Ctx, file: &Path, auth_key: bool) -> CmdResult {
    ctx.doctor_gate(false)?;
    if ctx.relays.is_empty() {
        return Err(Fail::new(
            exit::ERROR,
            "a profile needs at least one --relay",
        ));
    }
    maybe_apply_auth_key(ctx, auth_key)?;
    let pw = loop {
        let a = ctx
            .input
            .read_hidden("Profile passphrase: ")?
            .ok_or_else(|| Fail::new(exit::ERROR, "no passphrase given"))?;
        if a.trim().is_empty() {
            note!("A passphrase cannot be empty.");
            continue;
        }
        if !ctx.input.is_interactive() {
            break a;
        }
        let b = ctx
            .input
            .read_hidden("Profile passphrase (again): ")?
            .ok_or_else(|| Fail::new(exit::ERROR, "no passphrase given"))?;
        if a.as_str() == b.as_str() {
            break a;
        }
        note!("They differ; try again.");
    };
    let p = Profile {
        relays: ctx.relays.iter().map(|r| r.pubkey).collect(),
        auth_key: ctx.relays.first().and_then(|r| r.auth_key.clone()),
        seeds: Vec::new(),
    };
    note!("Deriving the profile key (Argon2id, 256 MiB) …");
    let bytes = seal_profile(&p, &pw)?;
    use std::io::Write;
    let mut f = files::create_new(file)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    note!(
        "Profile written to {} ({} relays{}). Use it with --profile {}.",
        file.display(),
        p.relays.len(),
        if p.auth_key.is_some() {
            ", circle key"
        } else {
            ""
        },
        file.display()
    );
    Ok(())
}

pub fn profile_open(ctx: &mut Ctx, file: &Path) -> CmdResult {
    ctx.doctor_gate(false)?;
    let bytes = files::read_profile(file)
        .map_err(|e| Fail::new(exit::ERROR, format!("{}: {e}", file.display())))?;
    let pw = ctx
        .input
        .read_hidden("Profile passphrase: ")?
        .ok_or_else(|| Fail::new(exit::ERROR, "no passphrase given"))?;
    let p = open_profile(&bytes, &pw).map_err(|_| {
        Fail::new(
            exit::NOTHING,
            "profile did not open (wrong passphrase, or not a profile)",
        )
    })?;
    out!("profile {}", file.display())?;
    for r in p.relays() {
        out!("  relay {}", r.onion())?;
    }
    out!(
        "  circle auth key: {}",
        if p.auth_key.is_some() {
            "present (not shown)"
        } else {
            "none"
        }
    )?;
    for s in p.stored_seeds() {
        out!("  receiving key {} (seed stored, not shown)", s.check)?;
    }
    Ok(())
}

/// Open `file` with a prompted passphrase, for the commands that rewrite it.
fn open_for_update(ctx: &mut Ctx, file: &Path) -> Result<(Profile, crate::term::SecretLine), Fail> {
    let bytes = files::read_profile(file)
        .map_err(|e| Fail::new(exit::ERROR, format!("{}: {e}", file.display())))?;
    let pw = ctx
        .input
        .read_hidden("Profile passphrase: ")?
        .ok_or_else(|| Fail::new(exit::ERROR, "no passphrase given"))?;
    let p = open_profile(&bytes, &pw).map_err(|_| {
        Fail::new(
            exit::NOTHING,
            "profile did not open (wrong passphrase, or not a profile)",
        )
    })?;
    Ok((p, pw))
}

/// Seal and write the profile back over the same file (same size, in place).
fn rewrite(ctx: &Ctx, file: &Path, p: &Profile, pw: &str) -> CmdResult {
    let _ = ctx;
    note!("Deriving the profile key (Argon2id, 256 MiB) …");
    let bytes = seal_profile(p, pw)?;
    files::rewrite_profile(file, &bytes)?;
    Ok(())
}

/// `aska profile add-seed --file F [--new]` (RM-09).
pub fn profile_add_seed(ctx: &mut Ctx, file: &Path, new: bool) -> CmdResult {
    ctx.doctor_gate(false)?;
    let (mut p, pw) = open_for_update(ctx, file)?;
    let seed: aska_core::drop::Secret32 = if new {
        aska_core::drop::secret32(*aska_core::xwing::generate_seed()?)
    } else {
        let words = ctx
            .input
            .read_hidden("Receiving seed (24 words): ")?
            .ok_or_else(|| Fail::new(exit::ERROR, "no seed given"))?;
        let root = aska_core::Root::from_words(&words)
            .map_err(|_| Fail::new(exit::ERROR, "not a valid 24-word receiving seed"))?;
        aska_core::drop::secret32(*root.as_bytes())
    };
    let relays: Vec<[u8; 32]> = p.relays.clone();
    let rk = aska_core::xwing::receiving_key_from_seed(&seed, &relays, None, None);
    let check = rk.check();
    let text = rk.encode()?;
    p.add_seed(seed).map_err(|e| match e {
        aska_core::Error::TooLarge => Fail::new(
            exit::ERROR,
            format!(
                "the profile already holds {} receiving seeds (the most it can)",
                aska_core::profile::MAX_SEEDS
            ),
        ),
        _ => Fail::new(
            exit::ERROR,
            format!("the profile already holds the key {check}"),
        ),
    })?;
    rewrite(ctx, file, &p, &pw)?;
    drop(pw);
    if new {
        // Words once, for a paper backup: the profile now holds the seed, but a lost or
        // forgotten profile would otherwise lose the key with it.
        let words = aska_core::Root::from_bytes(***p.seeds.last().expect("just added")).to_words();
        if ctx.input.is_interactive() {
            let s = ctx.new_session(aska_proto::DEFAULT_TTL_HOURS, None)?;
            let wb = crate::term::words_block(&words);
            let mut notes = Zeroizing::new(String::with_capacity(wb.len() + 160));
            notes.push_str(&wb);
            notes.push_str(
                "\nThe seed is stored in the profile; these words are its paper backup.\n\
                 Without the profile or the words, notes sent to this key cannot be read.",
            );
            drop(wb);
            crate::handover::show_material(
                ctx,
                &s,
                "Receiving seed stored — its words, once",
                &words,
                &notes,
                "Press any key to continue to the public key",
                "SEED",
            )?;
        } else {
            out!("SEED {}", words.as_str())?;
        }
    }
    out!("RECEIVING {text}")?;
    out!("CHECK {check}")?;
    note!(
        "Stored in {} as receiving key {check} ({} of {}).",
        file.display(),
        p.seeds.len(),
        aska_core::profile::MAX_SEEDS
    );
    Ok(())
}

/// `aska profile remove-seed --file F CHECK` (RM-09).
pub fn profile_remove_seed(ctx: &mut Ctx, file: &Path, check: &str) -> CmdResult {
    ctx.doctor_gate(false)?;
    let (mut p, pw) = open_for_update(ctx, file)?;
    let i = p.seed_by_check(check).ok_or_else(|| {
        Fail::new(
            exit::NOTHING,
            format!("no stored receiving key has the check {check}"),
        )
    })?;
    let removed = p.remove_seed(i).expect("index from seed_by_check");
    drop(removed);
    rewrite(ctx, file, &p, &pw)?;
    note!(
        "Removed receiving key {check} from {} ({} stored seed(s) left). Notes sent to it can no longer be read here.",
        file.display(),
        p.seeds.len()
    );
    Ok(())
}

pub fn profile_forget(ctx: &mut Ctx, file: &Path) -> CmdResult {
    ctx.doctor_gate(false)?;
    files::check_profile_path(file)?;
    if !ctx.yes {
        let a = ctx.input.read_line(&format!(
            "Overwrite and delete {}? Type 'forget' to confirm: ",
            file.display()
        ))?;
        if a.as_deref().map(|s| s.trim()) != Some("forget") {
            return Err(Fail::new(exit::USER_REFUSED, "not forgotten"));
        }
    }
    files::shred(file)?;
    note!(
        "Forgotten: {} overwritten with random bytes and removed.",
        file.display()
    );
    Ok(())
}
