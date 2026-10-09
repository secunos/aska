//! Screen 4 — Receive (Client Design §5.4): collect key material (a Key Card, 24 words or
//! Shares — pasted, typed or scanned), enter the passphrase on the in-app keypad, then
//! **Check the drop**: the whole bucket is fetched from every relay and matched locally on a
//! worker thread, the passphrase is tried across the KDF profiles, and the note opens on the
//! View screen — or "Nothing found", which does not say whether the note is not posted yet
//! or the drop has expired. The same screen serves `Shares → Combine` (`shares_only`).
//!
//! Camera (1.1, C-04): the QR code is read in-process by `aska-scan` — frames come from the
//! camera straight into this process, are shown in a viewfinder dialog and wiped; nothing
//! is written anywhere. Only when no camera can be read that way does the same external
//! helper as the CLI (`zbarcam`, printing the decoded text) run on a worker, as in 1.0.

use super::keypad::PassphraseField;
use super::{body, heading, hint, pill, view, Ui};
use crate::i18n::{tr, trf};
use crate::state::App;
use crate::worker;
use adw::prelude::*;
use aska_core::drop::{FetchOutcome, Relay};
use aska_core::session::{KeyStatus, OpenInfo, Session, SessionError};
use aska_scan::{Preview, ScanError};
use gtk::{gdk, glib};
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

/// The camera helper (the CLI's default `--scan-cmd`): prints one decoded QR and exits.
/// The fallback for cameras `aska-scan` cannot read (compressed-only formats, no device).
const SCAN_CMD: &str = "zbarcam --raw --oneshot -Sdisable -Sqrcode.enable";

/// Longest side of the viewfinder frames the scanning thread hands over.
const PREVIEW_SIZE: u32 = 320;

/// Give up on the in-process scan after this long without a decode.
const SCAN_TIMEOUT: Duration = Duration::from_secs(90);

/// How often the main loop looks for a new viewfinder frame (older ones are dropped).
const PREVIEW_POLL: Duration = Duration::from_millis(66);

/// What the scanning thread sends to the main loop.
enum ScanMsg {
    Frame(Preview),
    Done(Result<Zeroizing<String>, ScanError>),
}

#[derive(Clone)]
struct Form {
    material: gtk::TextView,
    /// The frame around `material`, hidden while a stored key stands in for the words.
    material_frame: gtk::Frame,
    status: gtk::Label,
    add: gtk::Button,
    scan: gtk::Button,
    reset: gtk::Button,
    seed_switch: Option<adw::SwitchRow>,
    /// "Use a stored key" (RM-09): entry 0 is "type the words", entry i the i-th seed of the
    /// open profile. Built only when the profile holds a seed, so a run without one lays the
    /// page out exactly as before; shown only while the seed switch is on.
    stored: Option<(adw::PreferencesGroup, adw::ComboRow)>,
    relays: adw::EntryRow,
    pass: PassphraseField,
    go: gtk::Button,
    /// Read the Block from cards with the camera instead of a relay (DC-04 §7).
    cards: gtk::Button,
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
    // A seed kept in the open profile may stand in for the 24 words (RM-09). The row stays
    // invisible — taking no space, so the layout does not shift — until the seed switch is
    // on and the profile holds a seed; its entries follow the profile each time the page is
    // shown (a key stored on the Receiving key screen must be offered on the way back).
    let stored = (!shares_only).then(|| {
        let g = adw::PreferencesGroup::builder().visible(false).build();
        let row = adw::ComboRow::builder()
            .title(tr("receive.stored"))
            .model(&gtk::StringList::new(&[&tr("receive.stored.type")]))
            .selected(0)
            .build();
        g.add(&row);
        km.append(&g);
        (g, row)
    });
    // The key is a secret too: no undo history, copy and cut off (paste stays available).
    let material = super::secret_text_view(90, true);
    let sw = gtk::ScrolledWindow::builder()
        .child(&material)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .min_content_height(90)
        .build();
    let material_frame = gtk::Frame::builder().child(&sw).build();
    km.append(&material_frame);
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
    // "Read Block cards…" sits beside the pill in one row, so the page's vertical layout is
    // exactly the 1.1 one (the GUI gates click by position); its explanation is a tooltip.
    let go_row = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(8)
        .halign(gtk::Align::Center)
        .build();
    let cards_btn = gtk::Button::builder()
        .label(tr("receive.cards"))
        .css_classes(["flat"])
        .tooltip_text(tr("receive.cards.hint"))
        .valign(gtk::Align::Center)
        .sensitive(false)
        .build();
    go_row.append(&go);
    go_row.append(&cards_btn);
    root.append(&go_row);
    root.append(&progress);
    root.append(&error);

    let f = Form {
        material,
        material_frame,
        status,
        add: add.clone(),
        scan: scan.clone(),
        reset: reset.clone(),
        seed_switch: seed_switch.clone(),
        stored,
        relays,
        pass,
        go: go.clone(),
        cards: cards_btn.clone(),
        progress,
        error,
        shares_only,
    };
    {
        let (ui2, f2) = (ui.clone(), f.clone());
        cards_btn.connect_clicked(move |_| read_cards(&ui2, &f2));
    }

    {
        let (ui2, f2) = (ui.clone(), f.clone());
        add.connect_clicked(move |_| {
            if let Some(i) = stored_choice(&f2) {
                return add_stored_seed(&ui2, &f2, i);
            }
            let text = {
                let b = f2.material.buffer();
                let (s, e) = b.bounds();
                Zeroizing::new(b.text(&s, &e, false).to_string())
            };
            super::wipe_text_view(&f2.material);
            add_material(&ui2, &f2, &text);
        });
    }
    if let Some((_, row)) = &f.stored {
        // Choosing another key starts over, as switching modes does.
        let (ui2, f2) = (ui.clone(), f.clone());
        row.connect_selected_notify(move |_| {
            ui2.app.borrow_mut().close_session();
            f2.status.set_label(&tr("receive.status.none"));
            f2.status.add_css_class("dim-label");
            f2.go.set_sensitive(false);
            f2.reset.set_sensitive(false);
            f2.error.set_label("");
            sync_stored(&f2);
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
            sync_stored(&f2);
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
    // The stored keys on offer follow the profile (first shown, and back from Receiving key).
    refresh_stored(ui, &f);
    {
        let (ui, f) = (ui.clone(), f.clone());
        page.connect_showing(move |_| refresh_stored(&ui, &f));
    }
    page
}

/// Put the open profile's stored keys (by check) into the "Use a stored key" row when they
/// changed; an unchanged list is left alone so the choice and the Session survive a visit
/// to the Receiving key screen.
fn refresh_stored(ui: &Rc<Ui>, f: &Form) {
    let Some((_, row)) = &f.stored else {
        return;
    };
    let mut names: Vec<String> = vec![tr("receive.stored.type")];
    names.extend(ui.app.borrow().profile_seed_checks());
    let same = row
        .model()
        .and_downcast::<gtk::StringList>()
        .is_some_and(|m| {
            m.n_items() as usize == names.len()
                && names
                    .iter()
                    .enumerate()
                    .all(|(i, n)| m.string(i as u32).as_deref() == Some(n.as_str()))
        });
    if !same {
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        row.set_model(Some(&gtk::StringList::new(&refs)));
        row.set_selected(0);
    }
    sync_stored(f);
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

/// The stored seed chosen on the page (its index in the profile), when the seed switch is on
/// and the "Use a stored key" row names one.
fn stored_choice(f: &Form) -> Option<usize> {
    let seed_mode = f.seed_switch.as_ref().is_some_and(|s| s.is_active());
    let (_, row) = f.stored.as_ref()?;
    (seed_mode && row.selected() > 0).then(|| row.selected() as usize - 1)
}

/// Show the stored-key row only in seed mode; while a stored key is chosen the words field
/// and the camera have nothing to add.
fn sync_stored(f: &Form) {
    let Some((group, row)) = &f.stored else {
        return;
    };
    let seed_mode = f.seed_switch.as_ref().is_some_and(|s| s.is_active());
    let any = row.model().is_some_and(|m| m.n_items() > 1);
    group.set_visible(seed_mode && any);
    let typed = stored_choice(f).is_none();
    f.material_frame.set_visible(typed);
    f.scan.set_sensitive(typed);
}

/// A seed from the open profile stands in for the 24 words (RM-09).
fn add_stored_seed(ui: &Rc<Ui>, f: &Form, index: usize) {
    f.error.set_label("");
    if !ensure_session(ui, f) {
        return;
    }
    let (result, check) = {
        let mut a = ui.app.borrow_mut();
        let Some(check) = a.profile_seed_checks().get(index).cloned() else {
            drop(a);
            return fail(f, &tr("settings.profile.not_open"));
        };
        let App {
            session,
            profile_seeds,
            ..
        } = &mut *a;
        let r = match (session.as_mut(), profile_seeds.get(index)) {
            (Some(s), Some(seed)) => s.add_receiving_seed_bytes(seed),
            _ => Err(SessionError::WrongState(aska_core::session::State::Closed)),
        };
        (r, check)
    };
    f.reset.set_sensitive(true);
    match result {
        Ok(()) => {
            f.status
                .set_label(&trf("receive.status.stored_seed", &[("check", &check)]));
            f.status.remove_css_class("dim-label");
            set_go(f, true);
        }
        Err(e) => fail(f, &e.to_string()),
    }
}

fn fail(f: &Form, msg: &str) {
    f.error.set_label(msg);
    f.progress.set_label("");
    set_go(f, true);
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
                set_go(f, true);
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
            set_go(f, true);
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

/// Scan in-process with a viewfinder dialog: `aska_scan::scan` runs on its own thread with
/// the dialog's Cancel (or closing it) as the cancel flag; preview frames reach the main loop
/// through a channel that is polled every `PREVIEW_POLL`, keeping only the newest frame. A
/// decode feeds `add_material` as the helper path does; no readable camera hands over to the
/// helper (`scan_helper`); a timeout or a cancel just closes the dialog.
///
/// Frames show the Key Card: the picture holds one texture at a time (each replaces the
/// last), every luma buffer is zeroising and dropped once converted, and the paintable is
/// dropped when the dialog closes, so nothing of a frame outlives the dialog.
fn scan_camera(ui: &Rc<Ui>, f: &Form) {
    f.error.set_label("");
    f.scan.set_sensitive(false);

    let cancel = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<ScanMsg>();
    {
        let cancel = cancel.clone();
        // 2 MiB stack, as `worker::run` (decoding a full frame is deep enough to matter).
        let _ = std::thread::Builder::new()
            .stack_size(2 * 1024 * 1024)
            .spawn(move || {
                let opts = aska_scan::ScanOptions {
                    device: None,
                    timeout: SCAN_TIMEOUT,
                    cancel,
                    preview_size: PREVIEW_SIZE,
                };
                let frames = tx.clone();
                let r = aska_scan::scan(&opts, move |p| {
                    // A frame nobody receives any more comes back in the error and is wiped.
                    let _ = frames.send(ScanMsg::Frame(p));
                });
                let _ = tx.send(ScanMsg::Done(r));
            });
    }

    // ---- The viewfinder dialog ----
    let dialog = adw::Dialog::builder()
        .title(tr("receive.scan.title"))
        .content_width(380)
        .build();
    let tv = adw::ToolbarView::new();
    tv.add_top_bar(&adw::HeaderBar::new());
    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .margin_top(6)
        .margin_bottom(18)
        .margin_start(18)
        .margin_end(18)
        .build();
    let picture = gtk::Picture::builder()
        .content_fit(gtk::ContentFit::Contain)
        .width_request(320)
        .height_request(240)
        .halign(gtk::Align::Center)
        .css_classes(["card"])
        .build();
    content.append(&picture);
    let status = gtk::Label::builder()
        .label(tr("receive.scan.point"))
        .wrap(true)
        .xalign(0.0)
        .css_classes(["dim-label"])
        .build();
    content.append(&status);
    let cancel_btn = gtk::Button::builder()
        .label(tr("common.cancel"))
        .halign(gtk::Align::End)
        .build();
    content.append(&cancel_btn);
    tv.set_content(Some(&content));
    dialog.set_child(Some(&tv));

    // Set once the dialog is gone (by the user or by an outcome): the poll then only drains
    // the channel. `handed_over` keeps the Scan button off while the helper runs instead.
    let closed = Rc::new(Cell::new(false));
    let handed_over = Rc::new(Cell::new(false));
    {
        let dialog = dialog.clone();
        cancel_btn.connect_clicked(move |_| {
            dialog.close();
        });
    }
    {
        let (cancel, closed, handed_over, picture, f) = (
            cancel.clone(),
            closed.clone(),
            handed_over.clone(),
            picture.clone(),
            f.clone(),
        );
        dialog.connect_closed(move |_| {
            cancel.store(true, Ordering::Relaxed);
            closed.set(true);
            picture.set_paintable(None::<&gdk::Paintable>);
            if !handed_over.get() {
                f.scan.set_sensitive(true);
            }
        });
    }
    dialog.present(ui.window().as_ref());

    let (ui, f) = (ui.clone(), f.clone());
    glib::timeout_add_local(PREVIEW_POLL, move || {
        let mut latest: Option<Preview> = None;
        let mut done: Option<Result<Zeroizing<String>, ScanError>> = None;
        loop {
            match rx.try_recv() {
                // An older frame is replaced here and wiped as it drops.
                Ok(ScanMsg::Frame(p)) => latest = Some(p),
                Ok(ScanMsg::Done(r)) => {
                    done = Some(r);
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                // The thread went away without a verdict: treat it as "no camera read".
                Err(mpsc::TryRecvError::Disconnected) => {
                    done = Some(Err(ScanError::NoCamera("scan thread ended".into())));
                    break;
                }
            }
        }
        if let Some(p) = latest {
            if !closed.get() {
                show_frame(&picture, p);
            }
        }
        let Some(r) = done else {
            return glib::ControlFlow::Continue;
        };
        if closed.get() {
            // Cancelled by the user; whatever came back is dropped (and wiped) unread.
            return glib::ControlFlow::Break;
        }
        closed.set(true);
        match r {
            Ok(text) => {
                dialog.close();
                add_material(&ui, &f, &text);
            }
            Err(ScanError::NoCamera(_)) => {
                handed_over.set(true);
                dialog.close();
                scan_helper(&ui, &f);
            }
            Err(ScanError::Timeout) => {
                dialog.close();
                f.status.set_label(&tr("receive.scan.timeout"));
            }
            Err(ScanError::Cancelled) => {
                dialog.close();
            }
            Err(e @ ScanError::Io(_)) => {
                dialog.close();
                fail(&f, &e.to_string());
            }
        }
        glib::ControlFlow::Break
    });
}

/// Put one greyscale frame on the viewfinder; the previous texture is released by the
/// picture, the luma buffer lives on inside the texture's bytes and is wiped when that goes.
fn show_frame(picture: &gtk::Picture, p: Preview) {
    let (w, h) = (p.width as usize, p.height as usize);
    if w == 0 || h == 0 || p.luma.len() < w * h || w > i32::MAX as usize || h > i32::MAX as usize {
        return;
    }
    let bytes = glib::Bytes::from_owned(p.luma);
    let tex = gdk::MemoryTexture::new(w as i32, h as i32, gdk::MemoryFormat::G8, &bytes, w);
    picture.set_paintable(Some(&tex));
}

/// Run the camera helper on a worker and feed what it decoded (the fallback when no camera
/// could be read in-process).
fn scan_helper(ui: &Rc<Ui>, f: &Form) {
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
                // The helper runs through `sh -c`: a helper that is not installed is the
                // shell's exit 127 ("command not found"), not a failure to start.
                Ok(o) if o.status.code() == Some(127) => Err("helper not found".to_string()),
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
/// The two "go" buttons move together: "Check the drop" and "Read Block cards".
fn set_go(f: &Form, on: bool) {
    f.go.set_sensitive(on);
    f.cards.set_sensitive(on);
}

/// Block cards (DC-04 §7): scan byte-mode QR codes until the set is complete, hand the Block
/// to the Session as if fetched, then open it like a fetched Block.
fn read_cards(ui: &Rc<Ui>, f: &Form) {
    f.error.set_label("");
    let pass = f.pass.value();
    let pass = (!pass.trim().is_empty()).then_some(pass);
    set_go(f, false);
    f.progress.set_label(&tr("receive.cards.progress"));
    let set = Rc::new(RefCell::new(aska_paper::cards::CardSet::new()));
    let (f2, set2) = (f.clone(), set.clone());
    let (ui3, f3, set3) = (ui.clone(), f.clone(), set.clone());
    let pass = Rc::new(RefCell::new(pass));
    super::scan::scan_dialog(
        ui,
        &tr("receive.cards.title"),
        true,
        move |d| {
            let super::scan::Decoded::Bytes(chunk) = d else {
                return super::scan::Next::Continue;
            };
            let r = set2.borrow_mut().accept(&chunk);
            match r {
                Ok(aska_paper::cards::Accepted::Complete) => super::scan::Next::Stop,
                Ok(aska_paper::cards::Accepted::Added { have, count })
                | Ok(aska_paper::cards::Accepted::Duplicate { have, count }) => {
                    f2.progress.set_label(&trf(
                        "receive.cards.have",
                        &[("have", &have.to_string()), ("count", &count.to_string())],
                    ));
                    super::scan::Next::Continue
                }
                Err(e) => {
                    f2.progress.set_label(&e.to_string());
                    super::scan::Next::Continue
                }
            }
        },
        move |err| {
            if let Some(e) = err {
                set_go(&f3, true);
                return fail(&f3, &e.to_string());
            }
            let block = set3.borrow().block();
            let Some(block) = block else {
                set_go(&f3, true);
                f3.progress.set_label("");
                return;
            };
            let accepted = {
                let mut a = ui3.app.borrow_mut();
                match a.session.as_mut() {
                    Some(s) => s.accept_block(block.to_vec()),
                    None => {
                        drop(a);
                        set_go(&f3, true);
                        return fail(&f3, &tr("handover.expired"));
                    }
                }
            };
            match accepted {
                Ok(()) => open_found(&ui3, &f3, pass.borrow_mut().take()),
                Err(e) => {
                    set_go(&f3, true);
                    report_fetch_error(&ui3, &f3, e);
                }
            }
        },
    );
}

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
    set_go(f, false);
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
            // `seed_used` is read BEFORE the open: a distress open destroys the seed (A-3), and
            // reading it afterwards made the View page's closing toast differ between a
            // distress and a decoy open — a tell for anyone watching (fixed in 1.1).
            let seed_used = s.has_receiving_seed();
            let r: Result<OpenInfo, SessionError> = s.open(pass.as_deref().map(|p| p.as_str()));
            drop(pass);
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
