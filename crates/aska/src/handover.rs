//! Hand-over display (Client Design §5.3 in terminal form): one piece of key material at a
//! time, as a QR code plus text, on the alternate screen, until a key is pressed or the
//! Session's idle countdown runs out; then the screen is cleared. In `--stdin` mode the same
//! material is printed once as `KEY value` lines for scripts, with no QR.

use crate::ctx::{CmdResult, Ctx};
use aska_core::session::{Level, Session};
use zeroize::Zeroizing;

/// Residual-risk banner for the Quick level (CLI-14).
pub const QUICK_BANNER: &str = "Quick level: whoever holds this key before the drop expires can read the note.\n\
Show or read it to the receiver through a DIFFERENT channel than the one you use to mention the note.";

/// Show one item. `machine_key` is the line prefix used in `--stdin` mode.
pub fn show_material(
    ctx: &mut Ctx,
    s: &Session,
    title: &str,
    text: &str,
    notes: &str,
    footer: &str,
    machine_key: &str,
) -> CmdResult {
    if !ctx.input.is_interactive() {
        println!("{machine_key} {text}");
        return Ok(());
    }
    let rendered = ctx.render_material(text)?;
    let mut body = Zeroizing::new(String::with_capacity(
        title.len() + rendered.len() + notes.len() + 8,
    ));
    body.push_str(title);
    body.push_str("\n\n");
    body.push_str(&rendered);
    if !notes.is_empty() {
        body.push('\n');
        body.push_str(notes);
        body.push('\n');
    }
    ctx.input.show_timed(&body, footer, s.remaining_idle())?;
    Ok(())
}

/// The whole hand-over flow after sealing: Key Card + words for Quick, one Share at a time for
/// Guarded. `for_labels` are the optional "for:" names, displayed only.
pub fn hand_over(
    ctx: &mut Ctx,
    s: &mut Session,
    level: Level,
    for_labels: &[String],
    out_keycard: Option<&std::path::Path>,
) -> CmdResult {
    let relays: Vec<String> = ctx.relays.iter().map(|r| r.onion()).collect();
    let relay_note = if relays.is_empty() {
        String::from("No relay is named in the Key Card; the receiver passes --relay.")
    } else {
        format!("Relay(s): {}", relays.join(", "))
    };
    match level {
        Level::Quick => {
            let card = s.hand_over_keycard()?;
            let words = s.hand_over_words()?;
            if let Some(p) = out_keycard {
                ctx.write_named(p, &card)?;
                eprintln!(
                    "Key Card written to {} (you asked for it; delete it when handed over).",
                    p.display()
                );
            }
            if !ctx.input.is_interactive() {
                println!("KEYCARD {}", card.as_str());
                println!("WORDS {}", words.as_str());
                println!("RELAYS {}", relays.join(","));
                return Ok(());
            }
            let wb = crate::term::words_block(&words);
            let mut notes = Zeroizing::new(String::with_capacity(
                64 + wb.len() + relay_note.len() + QUICK_BANNER.len(),
            ));
            notes.push_str("The same key as 24 words:\n");
            notes.push_str(&wb);
            notes.push('\n');
            notes.push_str(&relay_note);
            notes.push_str("\n\n");
            notes.push_str(QUICK_BANNER);
            drop(wb);
            show_material(
                ctx,
                s,
                "Key Card — for the receiver",
                &card,
                &notes,
                "Press any key to forget the key",
                "KEYCARD",
            )?;
        }
        Level::Guarded { k, n } => {
            let count = s.share_count();
            for i in 0..count {
                let text = s.share_text(i)?;
                let who = for_labels.get(i).map(|l| l.as_str()).unwrap_or("(unnamed)");
                if !ctx.input.is_interactive() {
                    println!("SHARE {}/{} {}", i + 1, count, text.as_str());
                    continue;
                }
                let title = format!("Share {} of {} — for: {who}", i + 1, count);
                let notes = format!(
                    "Any {k} of the {n} Shares reconstruct the key; fewer reveal nothing.\n\
                     Give each Share to a different person, never two on one screen.\n{relay_note}"
                );
                let footer = if i + 1 == count {
                    "Press any key to finish and forget the key"
                } else {
                    "Press any key to show the next Share"
                };
                show_material(ctx, s, &title, &text, &notes, footer, "SHARE")?;
            }
            if !ctx.input.is_interactive() {
                println!("RELAYS {}", relays.join(","));
            }
        }
    }
    Ok(())
}
