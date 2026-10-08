//! `aska receive`, `aska open BUCKET` (split mode) and `aska share combine`: collect key
//! material, fetch (or match a bucket file), open, show the note with a countdown, burn.

use crate::ctx::{exit, CmdResult, Ctx, Fail};
use crate::files;
use aska_core::consts::PTYPE_TEXT;
use aska_core::session::{KeyStatus, Session, SessionError};
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

pub struct ReceiveOpts {
    pub class: Option<u8>,
    pub view_seconds: u64,
    pub attempts: u32,
    pub interval_secs: u64,
    /// `share combine`: accept Shares only.
    pub shares_only: bool,
    /// `share combine --check-only`: stop after the Shares reconstruct; fetch nothing.
    pub check_only: bool,
    /// `--receiving-seed`: the 24 seed words instead of key material (DC-02).
    pub receiving_seed: bool,
}

pub const NOTHING_FOUND: &str =
    "Nothing found — the note may not be posted yet, or the drop may have expired.";

/// Collect key material until the Session reports it complete.
pub fn collect(ctx: &mut Ctx, s: &mut Session, shares_only: bool) -> CmdResult {
    let mut ready = false;
    loop {
        let prompt = if shares_only {
            "Share (askas1…; 'scan' for the camera; empty line to stop): "
        } else {
            "Key material — Key Card, 24 words or a Share ('scan' for the camera; empty line to stop): "
        };
        let Some(line) = ctx.read_material(prompt)? else {
            if ready {
                break;
            }
            return Err(Fail::new(
                exit::ERROR,
                "key material incomplete; nothing fetched",
            ));
        };
        if ready {
            // --stdin protocol: material lines, an EMPTY line, then the passphrase line.
            return Err(Fail::new(
                exit::ERROR,
                "unexpected extra input after the key material was complete",
            ));
        }
        if shares_only && !line.trim().to_ascii_lowercase().starts_with("askas1") {
            note!("Shares only here (askas1…); a Key Card or words go to `aska receive`.");
            continue;
        }
        match s.add_key_material(&line) {
            Ok(KeyStatus::Ready) => {
                note!("Key material complete.");
                ready = true;
                if ctx.input.is_interactive() {
                    break;
                }
            }
            Ok(KeyStatus::NeedShares { have, need }) => {
                note!("Share accepted — {have} of {need}.");
            }
            Err(SessionError::ForeignShare) => {
                note!("That Share belongs to a different set; it was not kept.");
            }
            Err(SessionError::BadKeyMaterial) => {
                note!("Not recognised as a Key Card, 24 words or a Share.");
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn fetch_with_retries(s: &mut Session, o: &ReceiveOpts) -> Result<bool, Fail> {
    let attempts = o.attempts.max(1);
    let mut unanswered = 0;
    let mut all_blocked = true;
    for attempt in 1..=attempts {
        match s.check_drops() {
            Ok(true) => return Ok(true),
            Ok(false) => note!("Not in the drop (attempt {attempt}/{attempts})."),
            Err(SessionError::NoRelayAnswered(e)) => {
                unanswered += 1;
                all_blocked &= crate::ctx::looks_blocked(&e);
                note!("No relay answered (attempt {attempt}/{attempts}): {e}");
            }
            Err(SessionError::AuthUnavailable(m)) => {
                return Err(Fail::new(exit::DOCTOR_REFUSED, m))
            }
            Err(SessionError::NoRelays) => {
                return Err(Fail::new(
                    exit::ERROR,
                    "no relay: the key material names none; pass --relay ONION or --profile FILE",
                ))
            }
            Err(e) => return Err(e.into()),
        }
        if attempt < attempts {
            note!(
                "Waiting {} s before trying again on fresh circuits …",
                o.interval_secs
            );
            std::thread::sleep(Duration::from_secs(o.interval_secs));
        }
    }
    if unanswered == attempts {
        if all_blocked {
            crate::ctx::print_blocked_hint();
        }
        return Err(Fail::new(exit::RELAY, "no relay could be reached"));
    }
    Ok(false)
}

pub fn run(ctx: &mut Ctx, o: &ReceiveOpts, bucket: Option<&Path>) -> CmdResult {
    let network = bucket.is_none() && !o.check_only;
    ctx.doctor_gate(network)?;
    let mut s = ctx.new_session(aska_proto::DEFAULT_TTL_HOURS, o.class)?;
    if o.receiving_seed {
        let words = ctx
            .input
            .read_hidden("Receiving seed (24 words): ")?
            .ok_or_else(|| Fail::new(exit::ERROR, "no seed given"))?;
        s.add_receiving_seed(&words).map_err(|e| match e {
            SessionError::Format(_) => Fail::new(exit::ERROR, "not a valid 24-word receiving seed"),
            e => e.into(),
        })?;
        note!("Receiving seed accepted.");
    } else {
        collect(ctx, &mut s, o.shares_only)?;
    }
    if o.check_only {
        note!("The Shares reconstruct the key. Nothing was fetched and nothing is shown.");
        s.close();
        return Ok(());
    }

    let pass = ctx
        .input
        .read_hidden("Passphrase (press Enter if the sender set none): ")?
        .filter(|p| !p.is_empty());

    let found = match bucket {
        Some(p) => {
            let (class, records) = files::read_bucket(p)?;
            note!(
                "Matching {} record(s) of class {class} from {} …",
                records.len(),
                p.display()
            );
            s.accept_bucket(records)?
        }
        None => {
            note!(
                "Fetching through Tor (whole buckets, matched locally; this can take a minute) …"
            );
            fetch_with_retries(&mut s, o)?
        }
    };
    if !found {
        s.close();
        return Err(Fail::new(exit::NOTHING, NOTHING_FOUND));
    }

    // Decided BEFORE the open: a distress open destroys the receiving seed (pre-review A-3),
    // so asking afterwards would make the closing line differ between a distress and a decoy
    // open — a tell for anyone watching the screen (finding of the v0.6 design re-issue).
    let used_seed = s.has_receiving_seed();
    let info = s.open(pass.as_deref()).map_err(|e| match e {
        SessionError::NoSlot => Fail::new(exit::NOTHING, "Nothing opened with that passphrase."),
        e => e.into(),
    })?;
    // Decoy, real and distress slots all pass through this same path with the same output
    // shape; nothing here looks at `info.distress`.
    let body: Zeroizing<String> = {
        let pt = s.plaintext().unwrap_or(&[]);
        if info.ptype == PTYPE_TEXT {
            Zeroizing::new(String::from_utf8_lossy(pt).into_owned())
        } else {
            Zeroizing::new(format!(
                "(binary note, {} bytes)\n{}",
                pt.len(),
                hexdump(pt)
            ))
        }
    };
    if ctx.input.is_interactive() {
        ctx.input.show_timed(
            &body,
            "Press any key to close and burn",
            Duration::from_secs(o.view_seconds.max(5)),
        )?;
    } else {
        out!("{}", body.as_str())?;
    }
    s.close();
    note!("Closed and burned.");
    if used_seed {
        note!("This receiving key has now been used; create a new one for the next note (aska key receive).");
    }
    Ok(())
}

fn hexdump(b: &[u8]) -> String {
    b.chunks(32)
        .map(|c| c.iter().map(|x| format!("{x:02x}")).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}
