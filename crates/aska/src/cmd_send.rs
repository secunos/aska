//! `aska send` and `aska seal` (Client Design Table 3): read the note, seal it, post it (send)
//! or write the Block to a user-named file for a networked qube to post (seal), then the
//! hand-over flow.

use crate::ctx::{exit, CmdResult, Ctx, Fail};
use crate::files;
use crate::handover;
use aska_core::consts::{SizeClass, PTYPE_TEXT};
use aska_core::session::{Level, Session, SessionError};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub struct SendOpts {
    pub guarded: bool,
    pub shares: Option<(u8, u8)>,
    pub class: Option<u8>,
    pub ttl: u16,
    pub decoy: bool,
    pub distress: bool,
    pub passphrase: bool,
    pub out_keycard: Option<std::path::PathBuf>,
    pub for_labels: Vec<String>,
    pub attempts: u32,
    /// Receiving Key to seal for (DC-02).
    pub to: Option<String>,
}

type Pair = Option<(Zeroizing<String>, Zeroizing<String>)>;

/// Everything the user types, in the two modes' orders (see `--help`).
struct Inputs {
    passphrase: Option<Zeroizing<String>>,
    decoy: Pair,
    distress: Pair,
    note: Zeroizing<Vec<u8>>,
}

fn need(v: Option<Zeroizing<String>>, what: &str) -> Result<Zeroizing<String>, Fail> {
    v.ok_or_else(|| Fail::new(exit::ERROR, format!("missing input: {what}")))
}

fn read_confirmed(ctx: &mut Ctx, what: &str) -> Result<Zeroizing<String>, Fail> {
    loop {
        let a = need(ctx.input.read_hidden(&format!("{what}: "))?, what)?;
        if a.is_empty() {
            note!("A passphrase cannot be empty.");
            continue;
        }
        if !ctx.input.is_interactive() {
            return Ok(a);
        }
        let b = need(ctx.input.read_hidden(&format!("{what} (again): "))?, what)?;
        if a.as_str() == b.as_str() {
            return Ok(a);
        }
        note!("They differ; try again.");
    }
}

fn read_inputs(ctx: &mut Ctx, o: &SendOpts) -> Result<Inputs, Fail> {
    let interactive = ctx.input.is_interactive();
    let mut note = Zeroizing::new(Vec::new());
    if interactive {
        note = ctx.input.read_text_block(
            "Type the note. Finish with a line containing only a dot (.) or press Ctrl-D.\n",
        )?;
    }
    let passphrase = if o.passphrase {
        Some(read_confirmed(ctx, "Passphrase the receiver must enter")?)
    } else {
        None
    };
    let decoy = if o.decoy {
        let t = need(
            ctx.input
                .read_line("Decoy note (one line, shown for the decoy passphrase): ")?,
            "decoy note",
        )?;
        let p = read_confirmed(ctx, "Decoy passphrase")?;
        Some((t, p))
    } else {
        None
    };
    let distress = if o.distress {
        let t = need(
            ctx.input
                .read_line("Distress note (one line, shown while the real note is destroyed): ")?,
            "distress note",
        )?;
        let p = read_confirmed(ctx, "Distress passphrase")?;
        Some((t, p))
    } else {
        None
    };
    if !interactive {
        note = ctx.input.read_text_block("")?;
    }
    if note.is_empty() {
        return Err(Fail::new(exit::ERROR, "the note is empty"));
    }
    Ok(Inputs {
        passphrase,
        decoy,
        distress,
        note,
    })
}

fn post_with_retries(s: &mut Session, attempts: u32) -> CmdResult {
    // Stays true only while every failure so far has the blocked-network signature (D-16).
    let mut all_blocked = true;
    for attempt in 1..=attempts.max(1) {
        let results = match s.post() {
            Ok(r) => r,
            Err(SessionError::AuthUnavailable(m)) => {
                return Err(Fail::new(exit::DOCTOR_REFUSED, m))
            }
            Err(e) => return Err(e.into()),
        };
        let mut stored = false;
        for r in &results {
            let onion = r.relay.onion();
            let short = &onion[..onion.len().min(12)];
            match &r.result {
                Ok(st) => {
                    note!("  {short}…: {st:?}");
                    stored |= r.stored();
                    all_blocked = false;
                }
                Err(e) => {
                    note!("  {short}…: {e}");
                    all_blocked &= crate::ctx::looks_blocked(e);
                }
            }
        }
        if stored {
            return Ok(());
        }
        if attempt < attempts {
            note!(
                "Not stored yet — retrying on fresh circuits ({}/{attempts}) …",
                attempt + 1
            );
        }
    }
    if all_blocked {
        crate::ctx::print_blocked_hint();
    }
    Err(Fail::new(
        exit::RELAY,
        "the Block was not stored on any relay (unreachable or full); the note was not sent",
    ))
}

pub fn run(ctx: &mut Ctx, o: &SendOpts, seal_out: Option<&Path>) -> CmdResult {
    let network = seal_out.is_none();
    ctx.doctor_gate(network)?;
    // A Receiving Key may carry its own relay hints; otherwise relays must be given.
    let recipient = match &o.to {
        Some(t) => Some(
            aska_core::encodings::ReceivingKey::decode(t)
                .map_err(|_| Fail::new(exit::ERROR, "--to is not a Receiving Key (askar1…)"))?,
        ),
        None => None,
    };
    let key_relays = recipient.as_ref().map_or(0, |rk| rk.relays.len());
    if network && ctx.relays.is_empty() && key_relays == 0 {
        return Err(Fail::new(
            exit::ERROR,
            "no relay: pass --relay ONION (repeatable) or --profile FILE",
        ));
    }
    let level = match (o.guarded, o.shares) {
        (_, Some((k, n))) => Level::Guarded { k, n },
        (true, None) => Level::Guarded { k: 2, n: 3 },
        (false, None) => Level::Quick,
    };
    let mut inputs = read_inputs(ctx, o)?;

    let mut s = ctx.new_session(o.ttl, o.class)?;
    if let Some(t) = &o.to {
        s.set_recipient(t)?;
    }
    s.compose(&inputs.note, PTYPE_TEXT).map_err(|e| match e {
        SessionError::TooLarge => too_large(inputs.note.len()),
        e => e.into(),
    })?;
    inputs.note.zeroize();
    if let Some(p) = &inputs.passphrase {
        s.set_passphrase(Some(p))?;
    }
    if let Some((t, p)) = &inputs.decoy {
        s.add_decoy(t, p)?;
    }
    if let Some((t, p)) = &inputs.distress {
        s.set_distress(t, p)?;
    }
    drop(inputs);
    s.seal(level).map_err(|e| match e {
        SessionError::TooLarge => too_large(0),
        e => e.into(),
    })?;
    note!("Sealed.");

    match seal_out {
        Some(out) => {
            let (label, block) = s.sealed_block()?;
            files::write_block(out, &label, block)?;
            note!(
                "Block written to {} ({} bytes). It is safe to move; post it from a networked machine with:\n  aska post {} --relay <onion>",
                out.display(),
                block.len(),
                out.display()
            );
        }
        None => {
            note!("Posting through Tor (a fresh circuit per request; this can take a minute) …");
            post_with_retries(&mut s, o.attempts)?;
            note!("Posted.");
        }
    }

    if s.sealed_for_recipient() {
        // KEY-10: nothing to hand over; the receiver's seed opens it.
        let check = s.recipient_check().unwrap_or_default();
        if ctx.input.is_interactive() {
            note!(
                "Sealed for the Receiving Key with check {check}. Nothing to hand over — the receiver opens it with their seed.\n\
                 Confirm the check with them over another channel if you have not already."
            );
        } else {
            out!("POSTED {check}")?;
        }
        s.close();
        note!("Done.");
        return Ok(());
    }
    handover::hand_over(ctx, &mut s, level, &o.for_labels, o.out_keycard.as_deref())?;
    s.close();
    note!("Done — the key has been forgotten.");
    Ok(())
}

fn too_large(len: usize) -> Fail {
    let max = SizeClass::C3.max_note_len();
    Fail::new(
        exit::ERROR,
        if len > 0 {
            format!("the note ({len} bytes, with any decoy) does not fit the largest Block; the limit is about {max} bytes")
        } else {
            format!(
                "the note and its decoy slots do not fit any Block; the limit is about {max} bytes"
            )
        },
    )
}
