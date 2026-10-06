//! Screen 4 — Receive (Client Design §5.4): collect key material (a Key Card, 24 words or
//! Shares — pasted, typed or scanned), enter the passphrase on the in-app keypad, then
//! **Check the drop**: the whole bucket is fetched from every relay and matched locally on a
//! worker thread, the passphrase is tried across the KDF profiles, and the note opens on the
//! View screen — or "Nothing found", which does not say whether the note is not posted yet
//! or the drop has expired. The same screen serves `Shares → Combine` (`shares_only`).
//!
//! Camera: v1 drives the same external helper as the CLI (`zbarcam`, printing the decoded
//! text), started on a worker; the desktop-portal camera (C-04) is platform work for M6.

use super::keypad::PassphraseField;
use super::{body, heading, hint, pill, view, Ui};
use crate::i18n::{tr, trf};
use crate::state::App;
use crate::worker;
use adw::prelude::*;
use aska_core::drop::{FetchOutcome, Relay};
use aska_core::session::{KeyStatus, OpenInfo, Session, SessionError};
use std::rc::Rc;
use zeroize::{Zeroize, Zeroizing};

/// The camera helper (the CLI's default `--scan-cmd`): prints one decoded QR and exits.
const SCAN_CMD: &str = "zbarcam --raw --oneshot -Sdisable -Sqrcode.enable";

#[derive(Clone)]
struct Form {
    material: gtk::TextView,
    status: gtk::Label,
    add: gtk::Button,
    scan: gtk::Button,
    reset: gtk::Button,
    seed_switch: Option<adw::SwitchRow>,
    relays: adw::EntryRow,
    pass: PassphraseField,
    go: gtk::Button,
    progress: gtk::Label,
    error: gtk::Label,
    shares_only: bool,
}

pub fn build(ui: &Rc<Ui>, shares_only: bool) -> adw::NavigationPage {
    let (root, clamp) = body(720);

    // ---- Key material ----
    let km = gtk::Box::new(gtk::Orientation::Vertical, 6);
    km.append(&heading(&tr(if shares_only {
        "receive.shares_heading"
    } else {
        "receive.material"
    })));
    km.append(&hint(&tr(if shares_only {
        "receive.shares_hint"
    } else {
        "receive.material.hint"
    })));
    // The key is a secret too: no undo history, copy and cut off (paste stays available).
    let material = super::secret_text_view(90, true);
    let sw = gtk::ScrolledWindow::builder()
        .child(&material)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .min_content_height(90)
        .build();
    km.append(&gtk::Frame::builder().child(&sw).build());
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let add = gtk::Button::builder()
        .label(tr("receive.add"))
        .css_classes(["suggested-action"])
        .build();
    let scan = gtk::Button::with_label(&tr("receive.scan"));
    let reset = gtk::Button::with_label(&tr("receive.reset"));
    reset.set_sensitive(false);
    row.append(&add);
    row.append(&scan);
    row.append(&reset);
    km.append(&row);
    let status = gtk::Label::builder()
        .label(tr("receive.status.none"))
        .wrap(true)
        .xalign(0.0)
        .css_classes(["dim-label"])
        .build();
    km.append(&status);
    let seed_switch = if shares_only {
        None
    } else {
        let g = adw::PreferencesGroup::new();
        let sw = adw::SwitchRow::builder()
            .title(tr("receive.seed"))
            .subtitle(tr("receive.seed.sub"))
            .build();
        g.add(&sw);
        km.append(&g);
        let make = gtk::Button::builder()
            .label(tr("receive.seed.create"))
            .css_classes(["flat"])
            .halign(gtk::Align::Start)
            .build();
        {
            let ui = ui.clone();
            make.connect_clicked(move |_| ui.nav.push(&super::rxkey::build(&ui)));
        }
        km.append(&make);
        Some(sw)
    };
    root.append(&km);

    // ---- Relays (fallback) ----
    let rg = adw::PreferencesGroup::new();
    let relays = adw::EntryRow::builder()
        .title(tr("send.relays"))
        .text(relays_text(&ui.app.borrow()))
        .build();
    rg.add(&relays);
    let rbox = gtk::Box::new(gtk::Orientation::Vertical, 6);
    rbox.append(&rg);
    rbox.append(&hint(&tr("receive.relays.hint")));
    root.append(&rbox);

    // ---- Passphrase ----
    let pass = PassphraseField::new(&tr("receive.passphrase"));
    root.append(pass.widget());
    root.append(&hint(&tr("receive.passphrase.hint")));

    // ---- Go ----
    let go = pill(&tr("receive.go"), true);
    go.set_sensitive(false);
    let progress = gtk::Label::builder()
        .wrap(true)
        .xalign(0.0)
        .css_classes(["dim-label"])
        .build();
    let error = gtk::Label::builder()
        .wrap(true)
        .xalign(0.0)
        .css_classes(["error"])
        .build();
    root.append(&go);
    root.append(&progress);
    root.append(&error);

    let f = Form {
        material,
        status,
        add: add.clone(),
        scan: scan.clone(),
        reset: reset.clone(),
        seed_switch: seed_switch.clone(),
        relays,
        pass,
        go: go.clone(),
        progress,
        error,
        shares_only,
    };

    {
        let (ui2, f2) = (ui.clone(), f.clone());
        add.connect_clicked(move |_| {
            let text = {
                let b = f2.material.buffer();
                let (s, e) = b.bounds();
                Zeroizing::new(b.text(&s, &e, false).to_string())
            };
            super::wipe_text_view(&f2.material);
            add_material(&ui2, &f2, &text);
        });
    }
    {
        let (ui2, f2) = (ui.clone(), f.clone());
        scan.connect_clicked(move |_| scan_camera(&ui2, &f2));
    }
    {
        let (ui2, f2) = (ui.clone(), f.clone());
        reset.connect_clicked(move |_| {
            ui2.app.borrow_mut().close_session();
            f2.status.set_label(&tr("receive.status.none"));
            f2.go.set_sensitive(false);
            f2.reset.set_sensitive(false);
            f2.error.set_label("");
            f2.progress.set_label("");
        });
    }
    {
        let (ui2, f2) = (ui.clone(), f.clone());
        go.connect_clicked(move |_| check_drop(&ui2, &f2));
    }
    if let Some(sw) = &f.seed_switch {
        // Switching modes starts over: seed and key material never mix in one Session.
        let (ui2, f2) = (ui.clone(), f.clone());
        sw.connect_active_notify(move |_| {
            ui2.app.borrow_mut().close_session();
            f2.status.set_label(&tr("receive.status.none"));
            f2.status.add_css_class("dim-label");
            f2.go.set_sensitive(false);
            f2.reset.set_sensitive(false);
            f2.error.set_label("");
        });
    }

    let page = ui.page(
        "receive",
        &tr(if shares_only {
            "receive.title.combine"
        } else {
            "receive.title"
        }),
        &clamp,
    );
    // Leaving the screen (back arrow) forgets what was collected — unless the View screen is
    // now showing the note, which owns the Session from here on.
    {
        let ui = ui.clone();
        page.connect_hidden(move |_| {
            if ui.nav.visible_page().and_then(|p| p.tag()).as_deref() != Some("view") {
                ui.app.borrow_mut().close_session();
            }
        });
    }
    page
}

fn relays_text(a: &App) -> String {
    a.relays
        .iter()
        .map(|r| r.onion())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Relays typed on this screen, if any. Empty is fine (a Key Card carries its own).
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

fn fail(f: &Form, msg: &str) {
    f.error.set_label(msg);
    f.progress.set_label("");
    f.go.set_sensitive(true);
    f.add.set_sensitive(true);
    f.scan.set_sensitive(true);
}

/// Make sure a Session exists for collecting (created lazily, on the main thread: cheap).
fn ensure_session(ui: &Rc<Ui>, f: &Form) -> bool {
    let mut a = ui.app.borrow_mut();
    if a.session.is_some() {
        return true;
    }
    match Session::new(a.session_config(aska_proto::DEFAULT_TTL_HOURS, None)) {
        Ok(s) => {
            a.session = Some(s);
            true
        }
        Err(SessionError::MemoryUnlocked) => {
            drop(a);
            fail(f, &tr("send.error.memory"));
            false
        }
        Err(e) => {
            drop(a);
            fail(f, &e.to_string());
            false
        }
    }
}

fn add_material(ui: &Rc<Ui>, f: &Form, text: &str) {
    f.error.set_label("");
    if text.trim().is_empty() {
        return;
    }
    if f.shares_only && !text.trim().to_ascii_lowercase().starts_with("askas1") {
        f.status.set_label(&tr("receive.status.shares_only"));
        return;
    }
    if !ensure_session(ui, f) {
        return;
    }
    let seed_mode = f.seed_switch.as_ref().is_some_and(|s| s.is_active());
    if seed_mode {
        let result = {
            let mut a = ui.app.borrow_mut();
            match a.session.as_mut() {
                Some(s) => s.add_receiving_seed(text),
                None => Err(SessionError::WrongState(aska_core::session::State::Closed)),
            }
        };
        f.reset.set_sensitive(true);
        match result {
            Ok(()) => {
                f.status.set_label(&tr("receive.status.seed"));
                f.status.remove_css_class("dim-label");
                f.go.set_sensitive(true);
            }
            Err(SessionError::Format(_)) => f.status.set_label(&tr("receive.status.bad_seed")),
            Err(e) => fail(f, &e.to_string()),
        }
        return;
    }
    let result = {
        let mut a = ui.app.borrow_mut();
        match a.session.as_mut() {
            Some(s) => s.add_key_material(text),
            None => Err(SessionError::WrongState(aska_core::session::State::Closed)),
        }
    };
    f.reset.set_sensitive(true);
    match result {
        Ok(KeyStatus::Ready) => {
            let t = text.trim();
            let what = if t.len() >= 6 && t[..6].eq_ignore_ascii_case("askas1") {
                "receive.status.shares_complete"
            } else if t.len() >= 5 && t[..5].eq_ignore_ascii_case("aska1") {
                "receive.status.keycard"
            } else {
                "receive.status.words"
            };
            f.status.set_label(&tr(what));
            f.status.remove_css_class("dim-label");
            f.go.set_sensitive(true);
        }
        Ok(KeyStatus::NeedShares { have, need }) => {
            f.status.set_label(&trf(
                "receive.status.shares",
                &[("have", &have.to_string()), ("need", &need.to_string())],
            ));
            f.status.remove_css_class("dim-label");
        }
        Err(SessionError::ForeignShare) => f.status.set_label(&tr("receive.status.foreign")),
        Err(SessionError::BadKeyMaterial) => f.status.set_label(&tr("receive.status.bad")),
        Err(SessionError::WrongState(_)) => {
            // Key material is complete already; a second card or word list is refused.
            f.status.set_label(&tr("receive.status.already"));
        }
        Err(e) => fail(f, &e.to_string()),
    }
}

/// Run the camera helper on a worker and feed what it decoded.
fn scan_camera(ui: &Rc<Ui>, f: &Form) {
    f.error.set_label("");
    f.scan.set_sensitive(false);
    f.status.set_label(&tr("receive.scan.running"));
    let (ui2, f2) = (ui.clone(), f.clone());
    worker::run(
        || {
            let out = std::process::Command::new("sh")
                .arg("-c")
                .arg(SCAN_CMD)
                .stdin(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .output();
            match out {
                Ok(o) => {
                    let mut text = Zeroizing::new(String::from_utf8_lossy(&o.stdout).into_owned());
                    let first: Zeroizing<String> =
                        Zeroizing::new(text.lines().next().unwrap_or("").trim().to_string());
                    text.zeroize();
                    Ok(first)
                }
                Err(e) => Err(e.to_string()),
            }
        },
        move |r: Result<Zeroizing<String>, String>| {
            f2.scan.set_sensitive(true);
            match r {
                Ok(t) if !t.is_empty() => add_material(&ui2, &f2, &t),
                Ok(_) => f2.status.set_label(&tr("receive.scan.nothing")),
                Err(_) => f2.status.set_label(&tr("receive.scan.missing")),
            }
        },
    );
}

/// Fetch as a `FetchJob` on a worker while the Session stays on the main thread (review
/// finding C-1), match on the main thread, then open on a worker (the Session travels for
/// the few seconds of Argon2id only), then View.
fn check_drop(ui: &Rc<Ui>, f: &Form) {
    f.error.set_label("");
    if ui.app.borrow().network_refused() {
        return fail(f, &tr("send.error.refused"));
    }
    let relays = match parse_relays(&f.relays.text()) {
        Ok(r) => r,
        Err(e) => return fail(f, &e),
    };
    let pass = f.pass.value();
    let pass = (!pass.trim().is_empty()).then_some(pass);
    let job = {
        let mut a = ui.app.borrow_mut();
        if !relays.is_empty() {
            a.set_relays(relays.clone());
        }
        let Some(s) = a.session.as_mut() else {
            drop(a);
            return fail(f, &tr("handover.expired"));
        };
        if !relays.is_empty() {
            if let Err(e) = s.set_relays(relays) {
                drop(a);
                return fail(f, &e.to_string());
            }
        }
        match s.fetch_job() {
            Ok(j) => j,
            Err(e) => {
                drop(a);
                return fail(f, &e.to_string());
            }
        }
    };
    ui.app.borrow_mut().inflight = Some(job.cancel_token());
    f.go.set_sensitive(false);
    f.add.set_sensitive(false);
    f.scan.set_sensitive(false);
    f.progress.set_label(&tr("receive.progress.fetching"));
    let (ui2, f2) = (ui.clone(), f.clone());
    worker::run(
        move || job.run(),
        move |r: Result<FetchOutcome, SessionError>| {
            ui2.app.borrow_mut().inflight = None;
            // Match on the main thread (constant-time compare / decapsulation of every record).
            let found = match r {
                Ok(out) => {
                    let mut a = ui2.app.borrow_mut();
                    match a.session.as_mut() {
                        Some(s) => s.accept_fetch(out),
                        None => {
                            drop(a);
                            return fail(&f2, &tr("handover.expired"));
                        }
                    }
                }
                Err(e) => Err(e),
            };
            match found {
                Ok(true) => open_found(&ui2, &f2, pass),
                Ok(false) => {
                    ui2.app.borrow_mut().note_network_ok();
                    fail(&f2, &tr("receive.nothing"))
                }
                Err(e) => report_fetch_error(&ui2, &f2, e),
            }
        },
    );
}

/// The open step: Argon2id on a worker with the Session borrowed for those seconds only.
fn open_found(ui: &Rc<Ui>, f: &Form, pass: Option<Zeroizing<String>>) {
    let Some(mut s) = ui.app.borrow_mut().session.take() else {
        return fail(f, &tr("handover.expired"));
    };
    let (ui2, f2) = (ui.clone(), f.clone());
    worker::run(
        move || {
            // One code path for every slot: decoy, real and distress all come back as an
            // `OpenInfo` and are shown the same way; nothing here looks at `distress`.
            let r: Result<OpenInfo, SessionError> = s.open(pass.as_deref().map(|p| p.as_str()));
            drop(pass);
            let seed_used = s.has_receiving_seed();
            (s, r, seed_used)
        },
        move |(s, r, seed_used)| {
            ui2.app.borrow_mut().session = Some(s);
            match r {
                Ok(info) => {
                    ui2.app.borrow_mut().note_network_ok();
                    f2.pass.clear();
                    f2.progress.set_label("");
                    ui2.nav.push(&view::build(&ui2, info, seed_used));
                }
                Err(e) => report_fetch_error(&ui2, &f2, e),
            }
        },
    );
}

fn report_fetch_error(ui: &Rc<Ui>, f: &Form, e: SessionError) {
    match e {
        SessionError::NoSlot => fail(f, &tr("receive.no_slot")),
        SessionError::NoRelays => fail(f, &tr("receive.error.no_relay")),
        SessionError::NoRelayAnswered(e) => {
            let blocked = super::send::drop_error_looks_blocked(&e);
            if blocked {
                ui.app.borrow_mut().note_blocked_network();
                ui.recheck_home();
            }
            fail(
                f,
                &tr(if blocked {
                    "receive.error.blocked"
                } else {
                    "receive.error.unreachable"
                }),
            );
        }
        SessionError::AuthUnavailable(m) => fail(f, &m),
        e => fail(f, &e.to_string()),
    }
}
