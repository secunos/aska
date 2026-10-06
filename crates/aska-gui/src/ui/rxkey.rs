//! Receiving key (DC-02 §6): create a receiving seed — 24 words the receiver keeps — and show
//! the public Receiving Key (`askar1…`) with its twelve-character check and a QR code. Or
//! re-derive the public key from an existing seed. The seed exists only on this screen; the
//! public key is public and may be copied (it is the one thing here the clipboard may hold).

use super::qr::qr_widget;
use super::{body, heading, hint, pill, Ui};
use crate::i18n::{tr, trf};
use adw::prelude::*;
use aska_core::drop::Relay;
use std::rc::Rc;
use zeroize::Zeroizing;

pub fn build(ui: &Rc<Ui>) -> adw::NavigationPage {
    let (root, clamp) = body(720);

    root.append(&heading(&tr("rxkey.title")));
    root.append(&hint(&tr("rxkey.intro")));

    let g = adw::PreferencesGroup::new();
    let relays = adw::EntryRow::builder()
        .title(tr("send.relays"))
        .text(
            ui.app
                .borrow()
                .relays
                .iter()
                .map(|r| r.onion())
                .collect::<Vec<_>>()
                .join(" "),
        )
        .build();
    g.add(&relays);
    root.append(&g);
    root.append(&hint(&tr("rxkey.relays.hint")));

    let existing = adw::SwitchRow::builder()
        .title(tr("rxkey.existing"))
        .subtitle(tr("rxkey.existing.sub"))
        .build();
    let g2 = adw::PreferencesGroup::new();
    g2.add(&existing);
    root.append(&g2);
    // Typing 24 dictionary words on the shuffled keypad is impractical; a text view (no undo,
    // no copy) with the physical keyboard is the sensible input here, as on Receive.
    let words_tv = super::secret_text_view(70, true);
    let words_frame = gtk::Frame::builder()
        .child(
            &gtk::ScrolledWindow::builder()
                .child(&words_tv)
                .hscrollbar_policy(gtk::PolicyType::Never)
                .min_content_height(70)
                .build(),
        )
        .visible(false)
        .build();
    root.append(&words_frame);

    let go = pill(&tr("rxkey.create"), true);
    let error = gtk::Label::builder()
        .wrap(true)
        .xalign(0.0)
        .css_classes(["error"])
        .build();
    root.append(&go);
    root.append(&error);

    // ---- result area (filled after Create) ----
    let result = gtk::Box::new(gtk::Orientation::Vertical, 12);
    result.set_visible(false);
    let words_heading = heading(&tr("rxkey.words"));
    let words_grid = gtk::Grid::builder()
        .row_spacing(4)
        .column_spacing(18)
        .halign(gtk::Align::Center)
        .build();
    let words_note = hint(&tr("rxkey.words.note"));
    let check_heading = heading(&tr("rxkey.check"));
    let check_label = gtk::Label::builder()
        .css_classes(["title-1", "aska-mono"])
        .selectable(true)
        .build();
    let check_note = hint(&tr("rxkey.check.note"));
    let key_heading = heading(&tr("rxkey.public"));
    let qr_holder = gtk::Box::new(gtk::Orientation::Vertical, 0);
    qr_holder.set_halign(gtk::Align::Center);
    let key_text = gtk::Label::builder()
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::WordChar)
        .xalign(0.0)
        .selectable(true) // public: the one string here that may be copied
        .css_classes(["aska-mono", "caption"])
        .build();
    let copy = gtk::Button::builder()
        .label(tr("rxkey.copy"))
        .halign(gtk::Align::Start)
        .build();
    let key_note = hint(&tr("rxkey.public.note"));
    let done = pill(&tr("rxkey.done"), false);
    result.append(&words_heading);
    result.append(&words_grid);
    result.append(&words_note);
    result.append(&check_heading);
    result.append(&check_label);
    result.append(&check_note);
    result.append(&key_heading);
    result.append(&qr_holder);
    result.append(&key_text);
    result.append(&copy);
    result.append(&key_note);
    result.append(&done);
    root.append(&result);

    {
        let (frame, wh, wg, wn) = (
            words_frame.clone(),
            words_heading.clone(),
            words_grid.clone(),
            words_note.clone(),
        );
        let go2 = go.clone();
        existing.connect_active_notify(move |s| {
            let on = s.is_active();
            frame.set_visible(on);
            go2.set_label(&tr(if on { "rxkey.derive" } else { "rxkey.create" }));
            // With an existing seed the words are not re-shown: the user has them.
            wh.set_visible(!on);
            wg.set_visible(!on);
            wn.set_visible(!on);
        });
    }

    {
        let ui = ui.clone();
        let (
            relays,
            existing,
            words_tv,
            error,
            result,
            words_grid,
            check_label,
            qr_holder,
            key_text,
            go2,
        ) = (
            relays.clone(),
            existing.clone(),
            words_tv.clone(),
            error.clone(),
            result.clone(),
            words_grid.clone(),
            check_label.clone(),
            qr_holder.clone(),
            key_text.clone(),
            go.clone(),
        );
        go.connect_clicked(move |_| {
            error.set_label("");
            let relay_pks: Vec<[u8; 32]> = match parse_relays(&relays.text()) {
                Ok(r) => {
                    ui.app.borrow_mut().set_relays(r.clone());
                    r.iter().map(|r| r.pubkey).collect()
                }
                Err(e) => return error.set_label(&e),
            };
            let words: Zeroizing<String> = if existing.is_active() {
                let b = words_tv.buffer();
                let (s, e) = b.bounds();
                let w = Zeroizing::new(b.text(&s, &e, false).to_string());
                super::wipe_text_view(&words_tv);
                if w.split_whitespace().count() != 24 {
                    return error.set_label(&tr("rxkey.error.words"));
                }
                w
            } else {
                match aska_core::xwing::new_seed_words() {
                    Ok(w) => w,
                    Err(e) => return error.set_label(&e.to_string()),
                }
            };
            let rk =
                match aska_core::xwing::receiving_key_from_words(&words, &relay_pks, None, None) {
                    Ok(rk) => rk,
                    Err(_) => return error.set_label(&tr("rxkey.error.words")),
                };
            let text = match rk.encode() {
                Ok(t) => t,
                Err(e) => return error.set_label(&e.to_string()),
            };
            // Show: words (new seed only), check, QR + text.
            while let Some(c) = words_grid.first_child() {
                words_grid.remove(&c);
            }
            if !existing.is_active() {
                for (n, w) in words.split_whitespace().enumerate() {
                    let l = gtk::Label::builder()
                        .label(format!("{:>2}. {w}", n + 1))
                        .xalign(0.0)
                        .css_classes(["aska-words"])
                        .build();
                    words_grid.attach(&l, (n % 4) as i32, (n / 4) as i32, 1, 1);
                }
            }
            drop(words);
            check_label.set_label(&rk.check());
            while let Some(c) = qr_holder.first_child() {
                qr_holder.remove(&c);
            }
            qr_holder.append(&qr_widget(&text, 560));
            key_text.set_label(&text);
            result.set_visible(true);
            go2.set_sensitive(false);
        });
    }
    {
        let key_text = key_text.clone();
        copy.connect_clicked(move |b| {
            b.clipboard().set_text(&key_text.text());
        });
    }
    {
        let ui = ui.clone();
        done.connect_clicked(move |_| ui.go_home(None));
    }

    let page = ui.page("rxkey", &tr("rxkey.title"), &clamp);
    // Leaving wipes the words from the widgets.
    {
        let words_grid = words_grid.clone();
        page.connect_hidden(move |_| {
            let mut child = words_grid.first_child();
            while let Some(c) = child {
                child = c.next_sibling();
                if let Ok(l) = c.downcast::<gtk::Label>() {
                    super::wipe_label(&l);
                }
            }
        });
    }
    page
}

fn parse_relays(text: &str) -> Result<Vec<Relay>, String> {
    let mut out: Vec<Relay> = Vec::new();
    for tok in text
        .split([' ', ',', ';', '\n'])
        .filter(|t| !t.trim().is_empty())
    {
        let r = Relay::from_onion(tok.trim())
            .map_err(|_| trf("send.relays.bad", &[("addr", tok.trim())]))?;
        if !out.iter().any(|x| x.pubkey == r.pubkey) {
            out.push(r);
        }
    }
    Ok(out)
}
