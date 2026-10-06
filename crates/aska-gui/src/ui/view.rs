//! Screen 5 — View (Client Design §5.5): the note, rendered from the Session's locked buffer
//! into a read-only, non-selectable label; a visible countdown; a single **Close and burn**.
//! No copy, save, forward, print or share. A footer states plainly what this system can and
//! cannot block about screen capture (§6.2). Decoy, real and distress slots all arrive here
//! through the same `OpenInfo` and are drawn by the same code — the distress action already
//! happened in the core before this page existed, and nothing here looks at it.

use super::{body, hint, pill, Ui};
use crate::i18n::{tr, trf};
use adw::prelude::*;
use aska_core::consts::PTYPE_TEXT;
use aska_core::session::OpenInfo;
use gtk::glib;
use std::cell::Cell;
use std::rc::Rc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// `seed_used`: the note was opened with a receiving seed — say so when it burns (one key per
/// note, DC-02 §1).
pub fn build(ui: &Rc<Ui>, info: OpenInfo, seed_used: bool) -> adw::NavigationPage {
    let (root, clamp) = body(720);

    // The text is copied out of locked memory into the label's own storage for as long as
    // the page lives (the C-02 residual: GTK owns the rendering buffer), then cleared.
    let text: Zeroizing<String> = {
        let a = ui.app.borrow();
        let pt = a
            .session
            .as_ref()
            .and_then(|s| s.plaintext())
            .unwrap_or(&[]);
        if info.ptype == PTYPE_TEXT {
            Zeroizing::new(String::from_utf8_lossy(pt).into_owned())
        } else {
            Zeroizing::new(trf(
                "view.binary",
                &[("n", &pt.len().to_string()), ("hex", &hexdump(pt))],
            ))
        }
    };

    let note = gtk::Label::builder()
        .label(text.as_str())
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::WordChar)
        .xalign(0.0)
        .yalign(0.0)
        .selectable(false)
        .can_focus(false)
        .css_classes(["aska-note"])
        .build();
    drop(text);
    let frame = gtk::Frame::builder().child(&note).build();
    let sw = gtk::ScrolledWindow::builder()
        .child(&frame)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .min_content_height(320)
        .vexpand(true)
        .build();
    root.append(&sw);

    let countdown = gtk::Label::builder().css_classes(["dim-label"]).build();
    let burn = pill(&tr("view.burn"), true);
    burn.add_css_class("destructive-action");
    burn.remove_css_class("suggested-action");
    root.append(&burn);
    root.append(&countdown);
    root.append(&hint(&capture_line()));
    root.append(&hint(&tr("view.footer.rules")));

    // Auto-close (C-05): the note's own countdown; the Session is kept alive meanwhile so the
    // idle watchdog does not race it.
    let deadline = Instant::now() + ui.app.borrow().view_timeout;
    let closed = Rc::new(Cell::new(false));
    let finish = {
        let ui = ui.clone();
        let closed = closed.clone();
        let note = note.clone();
        Rc::new(move || {
            if closed.replace(true) {
                return;
            }
            super::wipe_label(&note);
            ui.go_home(Some(&tr(if seed_used {
                "view.burned_seed"
            } else {
                "view.burned"
            })));
        })
    };
    {
        let finish = finish.clone();
        burn.connect_clicked(move |_| finish());
    }
    {
        let ui = ui.clone();
        let countdown = countdown.clone();
        let finish = finish.clone();
        let closed = closed.clone();
        glib::timeout_add_local(Duration::from_secs(1), move || {
            if closed.get() {
                return glib::ControlFlow::Break;
            }
            let alive = {
                let mut a = ui.app.borrow_mut();
                match a.session.as_mut() {
                    Some(s) => s.keep_alive().is_ok(),
                    None => false,
                }
            };
            let left = deadline.saturating_duration_since(Instant::now());
            if !alive || left.is_zero() {
                finish();
                return glib::ControlFlow::Break;
            }
            countdown.set_label(&trf(
                "view.countdown",
                &[(
                    "mmss",
                    &format!("{:02}:{:02}", left.as_secs() / 60, left.as_secs() % 60),
                )],
            ));
            glib::ControlFlow::Continue
        });
    }

    let page = ui.page("view", &tr("view.title"), &clamp);
    // The back arrow burns too.
    {
        let note = note.clone();
        let ui = ui.clone();
        page.connect_hidden(move |_| {
            if !closed.replace(true) {
                super::wipe_label(&note);
                ui.app.borrow_mut().close_session();
                ui.toast(&tr("view.burned"));
            }
        });
    }
    page
}

/// §6.2, honestly: what this system does about screenshots while the note is on screen.
fn capture_line() -> String {
    match aska_core::platform::session_type().as_deref() {
        Some("x11") => tr("view.capture.x11"),
        // KDE's per-window capture flag (§6.2) is not requested yet — saying "blocked" would
        // not be true, so Wayland gets the detect-only line everywhere (residual, M6).
        Some("wayland") => tr("view.capture.wayland"),
        _ => tr("view.capture.unknown"),
    }
}

fn hexdump(b: &[u8]) -> String {
    b.chunks(32)
        .map(|c| c.iter().map(|x| format!("{x:02x}")).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}
