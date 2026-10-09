//! Screen 2 — Send (Client Design §5.2): write, choose protection, options, seal and post.
//! The text lives in a GTK buffer until sealing (the accepted C-02 residual), then is copied
//! into the Session's locked memory and the buffer is cleared. Sealing and posting run on a
//! worker thread with the whole Session moved there and back; nothing is written anywhere.

use super::handover;
use super::keypad::PassphraseField;
use super::Ui;
use crate::i18n::{tr, trf};
use crate::worker;
use adw::prelude::*;
use aska_core::block::region_len;
use aska_core::consts::{SizeClass, HDR_P_LEN, INNER_HDR_LEN, PTYPE_TEXT, TAG_LEN};
use aska_core::drop::{PostResult, Relay};
use aska_core::session::{Level, Session, SessionError};
use std::cell::RefCell;
use std::rc::Rc;
use zeroize::Zeroizing;

const TTL_CHOICES: &[(&str, u16)] = &[
    ("send.ttl.1h", 1),
    ("send.ttl.6h", 6),
    ("send.ttl.24h", 24),
    ("send.ttl.48h", 48),
    ("send.ttl.72h", 72),
    ("send.ttl.168h", 168),
];

/// Smallest class whose payload holds every slot region, as the core will choose it.
pub fn fit_class(slot_lens: &[usize], pinned: Option<SizeClass>) -> Option<SizeClass> {
    let need: usize = slot_lens.iter().map(|&n| region_len(n)).sum();
    match pinned {
        Some(c) => (c.payload_len() >= need).then_some(c),
        None => SizeClass::ALL.into_iter().find(|c| c.payload_len() >= need),
    }
}

fn class_name(c: SizeClass) -> String {
    tr(match c {
        SizeClass::C1 => "send.class.c1",
        SizeClass::C2 => "send.class.c2",
        SizeClass::C3 => "send.class.c3",
    })
}

/// After a failed post: the level and "for:" names of the Block kept in the Session.
type Retry = Rc<RefCell<Option<(Level, Vec<String>)>>>;

/// Everything the page needs to read back when "Seal and post" is pressed.
#[derive(Clone)]
struct Form {
    editor: gtk::TextView,
    counter: gtk::Label,
    class_row: adw::ComboRow,
    guarded: gtk::ToggleButton,
    threshold_row: adw::ComboRow,
    for_rows: Vec<adw::EntryRow>,
    pass_switch: adw::SwitchRow,
    pass: PassphraseField,
    pass_repeat: PassphraseField,
    decoy_switch: adw::SwitchRow,
    decoy_text: gtk::TextView,
    decoy_pass: PassphraseField,
    distress_switch: adw::SwitchRow,
    distress_text: gtk::TextView,
    distress_pass: PassphraseField,
    ttl_row: adw::ComboRow,
    to: adw::EntryRow,
    relays: adw::EntryRow,
    /// The Paper level (DC-04 §7): the Block as QR cards instead of a relay; the key is
    /// handed over as for Quick.
    paper: gtk::ToggleButton,
    go: gtk::Button,
    progress: gtk::Label,
    error: gtk::Label,
}

fn text_of(tv: &gtk::TextView) -> Zeroizing<String> {
    let b = tv.buffer();
    let (s, e) = b.bounds();
    Zeroizing::new(b.text(&s, &e, false).to_string())
}

fn wipe(tv: &gtk::TextView) {
    super::wipe_text_view(tv);
}

/// A note editor: word-wrapped, no undo history, copy and cut disabled (§5.7: the clipboard
/// is off for note content; paste stays available). GTK's own buffer memory is the C-02
/// residual, reduced by `wipe_text_view`.
fn editor(height: i32) -> gtk::TextView {
    super::secret_text_view(height, false)
}

fn framed(tv: &gtk::TextView) -> gtk::Frame {
    let sw = gtk::ScrolledWindow::builder()
        .child(tv)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .min_content_height(tv.height_request())
        .build();
    gtk::Frame::builder().child(&sw).build()
}

pub fn build(ui: &Rc<Ui>) -> adw::NavigationPage {
    let root = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(18)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    let clamp = adw::Clamp::builder().maximum_size(720).child(&root).build();

    // ---- Write ---- (a plain section: the editor is not a list row)
    let write = gtk::Box::new(gtk::Orientation::Vertical, 6);
    write.append(
        &gtk::Label::builder()
            .label(tr("send.write"))
            .xalign(0.0)
            .css_classes(["heading"])
            .build(),
    );
    let hint = gtk::Label::builder()
        .label(tr("send.editor.placeholder"))
        .wrap(true)
        .xalign(0.0)
        .css_classes(["dim-label", "caption"])
        .build();
    let editor_tv = editor(220);
    let counter = gtk::Label::builder()
        .xalign(1.0)
        .css_classes(["dim-label", "caption", "aska-mono"])
        .build();
    let class_row = adw::ComboRow::builder()
        .title(tr("send.class"))
        .model(&gtk::StringList::new(&[
            &tr("send.class.auto"),
            &tr("send.class.c1"),
            &tr("send.class.c2"),
            &tr("send.class.c3"),
        ]))
        .build();
    write.append(&hint);
    write.append(&framed(&editor_tv));
    write.append(&counter);
    let size_group = adw::PreferencesGroup::new();
    size_group.add(&class_row);
    write.append(&size_group);
    root.append(&write);

    // ---- Choose protection ---- (plain section; the rows follow the cards)
    let prot = gtk::Box::new(gtk::Orientation::Vertical, 8);
    prot.append(
        &gtk::Label::builder()
            .label(tr("send.protection"))
            .xalign(0.0)
            .css_classes(["heading"])
            .build(),
    );
    let cards = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(12)
        .homogeneous(true)
        .build();
    let quick = card(&tr("send.level.quick"), &tr("send.level.quick.sub"));
    let guarded = card(&tr("send.level.guarded"), &tr("send.level.guarded.sub"));
    let paper = card(&tr("send.level.paper"), &tr("send.level.paper.sub"));
    guarded.set_group(Some(&quick));
    paper.set_group(Some(&quick));
    quick.set_active(true);
    cards.append(&quick);
    cards.append(&guarded);
    cards.append(&paper);
    prot.append(&cards);
    let guarded_group = adw::PreferencesGroup::new();
    let threshold_row = adw::ComboRow::builder()
        .title(tr("send.threshold"))
        .model(&gtk::StringList::new(&[
            &tr("send.threshold.2of3"),
            &tr("send.threshold.3of5"),
        ]))
        .build();
    guarded_group.add(&threshold_row);
    let mut for_rows = Vec::new();
    for i in 1..=5 {
        let r = adw::EntryRow::builder()
            .title(trf("send.for", &[("n", &i.to_string())]))
            .visible(false)
            .build();
        guarded_group.add(&r);
        for_rows.push(r);
    }
    guarded_group.set_visible(false);
    prot.append(&guarded_group);
    root.append(&prot);

    // ---- Options ---- (each switch row directly followed by its panel)
    let opts = gtk::Box::new(gtk::Orientation::Vertical, 8);
    opts.append(
        &gtk::Label::builder()
            .label(tr("send.options"))
            .xalign(0.0)
            .css_classes(["heading"])
            .build(),
    );
    let switch_group = |row: &adw::SwitchRow| {
        let g = adw::PreferencesGroup::new();
        g.add(row);
        g
    };
    let pass_switch = adw::SwitchRow::builder()
        .title(tr("send.passphrase"))
        .subtitle(tr("send.passphrase.sub"))
        .build();
    opts.append(&switch_group(&pass_switch));
    let pass = PassphraseField::new(&tr("send.passphrase"));
    let pass_repeat = PassphraseField::new(&tr("keypad.repeat"));
    let pass_box = gtk::Box::new(gtk::Orientation::Vertical, 12);
    pass_box.set_visible(false);
    pass_box.set_margin_start(12);
    pass_box.append(pass.widget());
    pass_box.append(pass_repeat.widget());
    opts.append(&pass_box);

    let decoy_switch = adw::SwitchRow::builder()
        .title(tr("send.decoy"))
        .subtitle(tr("send.decoy.sub"))
        .build();
    opts.append(&switch_group(&decoy_switch));
    let decoy_text = editor(80);
    let decoy_pass = PassphraseField::new(&tr("send.decoy.passphrase"));
    let decoy_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
    decoy_box.set_visible(false);
    decoy_box.set_margin_start(12);
    decoy_box.append(
        &gtk::Label::builder()
            .label(tr("send.decoy.text"))
            .xalign(0.0)
            .css_classes(["heading"])
            .build(),
    );
    decoy_box.append(&framed(&decoy_text));
    decoy_box.append(decoy_pass.widget());
    opts.append(&decoy_box);

    let distress_switch = adw::SwitchRow::builder()
        .title(tr("send.distress"))
        .subtitle(tr("send.distress.sub"))
        .build();
    opts.append(&switch_group(&distress_switch));
    let distress_text = editor(80);
    let distress_pass = PassphraseField::new(&tr("send.distress.passphrase"));
    let distress_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
    distress_box.set_visible(false);
    distress_box.set_margin_start(12);
    distress_box.append(
        &gtk::Label::builder()
            .label(tr("send.distress.text"))
            .xalign(0.0)
            .css_classes(["heading"])
            .build(),
    );
    distress_box.append(&framed(&distress_text));
    distress_box.append(distress_pass.widget());
    opts.append(&distress_box);

    let tail_group = adw::PreferencesGroup::new();
    let ttl_names: Vec<String> = TTL_CHOICES.iter().map(|(k, _)| tr(k)).collect();
    let ttl_refs: Vec<&str> = ttl_names.iter().map(String::as_str).collect();
    let ttl_row = adw::ComboRow::builder()
        .title(tr("send.ttl"))
        .model(&gtk::StringList::new(&ttl_refs))
        .selected(2)
        .build();
    tail_group.add(&ttl_row);
    let to = adw::EntryRow::builder().title(tr("send.to")).build();
    tail_group.add(&to);
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
    tail_group.add(&relays);
    opts.append(&tail_group);
    let to_hint = gtk::Label::builder()
        .label(tr("send.to.hint"))
        .wrap(true)
        .xalign(0.0)
        .css_classes(["dim-label", "caption"])
        .build();
    opts.append(&to_hint);
    let relays_hint = gtk::Label::builder()
        .label(tr("send.relays.placeholder"))
        .xalign(0.0)
        .css_classes(["dim-label", "caption"])
        .build();
    opts.append(&relays_hint);
    root.append(&opts);

    // ---- Go ----
    let go = gtk::Button::builder()
        .label(tr("send.go"))
        .css_classes(["suggested-action", "pill", "title-4"])
        .halign(gtk::Align::Center)
        .height_request(48)
        .width_request(280)
        .build();
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

    let form = Form {
        editor: editor_tv,
        counter,
        class_row,
        guarded: guarded.clone(),
        threshold_row: threshold_row.clone(),
        for_rows,
        pass_switch: pass_switch.clone(),
        pass,
        pass_repeat,
        decoy_switch: decoy_switch.clone(),
        decoy_text,
        decoy_pass,
        distress_switch: distress_switch.clone(),
        distress_text,
        distress_pass,
        ttl_row,
        to: to.clone(),
        relays,
        paper: paper.clone(),
        go: go.clone(),
        progress,
        error,
    };

    // Reveal/hide option blocks.
    {
        let f = form.clone();
        let pb = pass_box.clone();
        pass_switch.connect_active_notify(move |s| {
            pb.set_visible(s.is_active());
            if !s.is_active() {
                f.pass.clear();
                f.pass_repeat.clear();
            }
            update_counter(&f);
        });
        let f = form.clone();
        let db = decoy_box.clone();
        decoy_switch.connect_active_notify(move |s| {
            db.set_visible(s.is_active());
            if !s.is_active() {
                wipe(&f.decoy_text);
                f.decoy_pass.clear();
            }
            update_counter(&f);
        });
        let f = form.clone();
        let xb = distress_box.clone();
        distress_switch.connect_active_notify(move |s| {
            xb.set_visible(s.is_active());
            if !s.is_active() {
                wipe(&f.distress_text);
                f.distress_pass.clear();
            }
            update_counter(&f);
        });
        let f = form.clone();
        let gg = guarded_group.clone();
        guarded.connect_toggled(move |b| {
            let on = b.is_active();
            gg.set_visible(on);
            update_for_rows(&f);
        });
        let f = form.clone();
        threshold_row.connect_selected_notify(move |_| update_for_rows(&f));
    }
    // A Receiving Key means Quick only: Guarded and the Paper level do not apply to a key the
    // sender never holds (DC-02 §6).
    {
        let (cards, quick, gg) = (cards.clone(), quick.clone(), guarded_group.clone());
        to.connect_changed(move |e| {
            let filled = !e.text().trim().is_empty();
            if filled {
                quick.set_active(true);
                gg.set_visible(false);
            }
            cards.set_sensitive(!filled);
        });
    }
    // Live byte counter.
    for tv in [&form.editor, &form.decoy_text, &form.distress_text] {
        let f = form.clone();
        tv.buffer().connect_changed(move |_| update_counter(&f));
    }
    {
        let f = form.clone();
        form.class_row
            .connect_selected_notify(move |_| update_counter(&f));
    }
    update_counter(&form);

    // One click handler; after a failed post it re-targets the kept Block instead of sealing.
    let retry: Retry = Rc::new(RefCell::new(None));
    {
        let ui = ui.clone();
        let f = form.clone();
        let retry = retry.clone();
        go.connect_clicked(move |_| {
            let pending = retry.borrow().clone();
            match pending {
                None => seal_and_post(&ui, &f, &retry),
                Some((level, for_labels)) => repost(&ui, &f, &retry, level, for_labels),
            }
        });
    }

    ui.page("send", &tr("send.title"), &clamp)
}

fn card(title: &str, subtitle: &str) -> gtk::ToggleButton {
    let b = gtk::Box::new(gtk::Orientation::Vertical, 4);
    b.append(
        &gtk::Label::builder()
            .label(title)
            .css_classes(["title-3"])
            .build(),
    );
    b.append(
        &gtk::Label::builder()
            .label(subtitle)
            .wrap(true)
            .justify(gtk::Justification::Center)
            .css_classes(["dim-label", "caption"])
            .build(),
    );
    gtk::ToggleButton::builder()
        .child(&b)
        .css_classes(["aska-card", "card"])
        .height_request(84)
        .build()
}

fn threshold(f: &Form) -> (u8, u8) {
    if f.threshold_row.selected() == 1 {
        (3, 5)
    } else {
        (2, 3)
    }
}

fn update_for_rows(f: &Form) {
    let n = if f.guarded.is_active() {
        threshold(f).1 as usize
    } else {
        0
    };
    for (i, r) in f.for_rows.iter().enumerate() {
        r.set_visible(i < n);
    }
}

fn pinned_class(f: &Form) -> Option<SizeClass> {
    SizeClass::from_u8(f.class_row.selected() as u8)
}

fn update_counter(f: &Form) {
    // Lengths without extracting the text (review finding C-7: `TextBuffer::text()` returns
    // a fresh, never-wiped g_malloc copy on every keystroke).
    let note = super::text_view_byte_len(&f.editor);
    let mut lens = vec![note];
    if f.decoy_switch.is_active() {
        lens.push(super::text_view_byte_len(&f.decoy_text));
    }
    if f.distress_switch.is_active() {
        lens.push(super::text_view_byte_len(&f.distress_text));
    }
    let pinned = pinned_class(f);
    match fit_class(&lens, pinned) {
        Some(c) => {
            // Room left for the note itself in this class once the other slots' regions and
            // the note slot's own framing (32 + 6 + 16 bytes) are taken out.
            let others: usize = lens[1..].iter().map(|&n| region_len(n)).sum();
            let shown_max = c
                .payload_len()
                .saturating_sub(others)
                .saturating_sub(HDR_P_LEN + INNER_HDR_LEN + TAG_LEN);
            f.counter.set_label(&trf(
                "send.counter",
                &[
                    ("used", &note.to_string()),
                    ("max", &shown_max.to_string()),
                    ("block", &class_name(c)),
                ],
            ));
            f.counter.remove_css_class("error");
            f.go.set_sensitive(true);
        }
        None => {
            let max = pinned.unwrap_or(SizeClass::C3).max_note_len();
            f.counter.set_label(&trf(
                "send.counter.too_large",
                &[("used", &note.to_string()), ("max", &max.to_string())],
            ));
            f.counter.add_css_class("error");
            f.go.set_sensitive(false);
        }
    }
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
    if out.is_empty() {
        return Err(tr("send.relays.none"));
    }
    Ok(out)
}

fn fail(f: &Form, msg: &str) {
    f.error.set_label(msg);
    f.progress.set_label("");
    f.go.set_sensitive(true);
}

fn seal_and_post(ui: &Rc<Ui>, f: &Form, retry: &Retry) {
    f.error.set_label("");
    let to_cards = f.paper.is_active();
    if !to_cards && ui.app.borrow().network_refused() {
        return fail(f, &tr("send.error.refused"));
    }
    let note = text_of(&f.editor);
    if note.trim().is_empty() {
        return fail(f, &tr("send.error.empty"));
    }
    let to: Option<String> = {
        let t = f.to.text().trim().to_string();
        (!t.is_empty()).then_some(t)
    };
    let recipient = match &to {
        Some(t) => match aska_core::encodings::ReceivingKey::decode(t) {
            Ok(rk) => Some(rk),
            Err(_) => return fail(f, &tr("send.error.bad_to")),
        },
        None => None,
    };
    // Relays: typed here, or (for a Receiving Key) the hints it carries; none for cards.
    let relays = match parse_relays(&f.relays.text()) {
        Ok(r) => r,
        Err(e) => {
            let hinted = recipient.as_ref().is_some_and(|rk| !rk.relays.is_empty());
            if (hinted || to_cards) && f.relays.text().trim().is_empty() {
                Vec::new()
            } else {
                return fail(f, &e);
            }
        }
    };
    // Passphrases: present ⇒ non-empty, confirmed, and all distinct (distinct slot keys).
    let mut phrases: Vec<Zeroizing<String>> = Vec::new();
    let real_pass = if f.pass_switch.is_active() {
        let p = f.pass.value();
        if p.trim().is_empty() {
            return fail(f, &tr("send.error.passphrase_empty"));
        }
        if p.as_str() != f.pass_repeat.value().as_str() {
            return fail(f, &tr("send.error.passphrase_mismatch"));
        }
        phrases.push(p.clone());
        Some(p)
    } else {
        None
    };
    let decoy = if f.decoy_switch.is_active() {
        let t = text_of(&f.decoy_text);
        let p = f.decoy_pass.value();
        if t.trim().is_empty() {
            return fail(f, &tr("send.error.decoy_needs_text"));
        }
        if p.trim().is_empty() {
            return fail(f, &tr("send.error.passphrase_empty"));
        }
        phrases.push(p.clone());
        Some((t, p))
    } else {
        None
    };
    let distress = if f.distress_switch.is_active() {
        let t = text_of(&f.distress_text);
        let p = f.distress_pass.value();
        if t.trim().is_empty() {
            return fail(f, &tr("send.error.decoy_needs_text"));
        }
        if p.trim().is_empty() {
            return fail(f, &tr("send.error.passphrase_empty"));
        }
        phrases.push(p.clone());
        Some((t, p))
    } else {
        None
    };
    for i in 0..phrases.len() {
        for j in i + 1..phrases.len() {
            if phrases[i].as_str() == phrases[j].as_str() {
                return fail(f, &tr("send.error.same_passphrase"));
            }
        }
    }
    drop(phrases);
    let level = if f.guarded.is_active() {
        let (k, n) = threshold(f);
        Level::Guarded { k, n }
    } else {
        Level::Quick
    };
    let for_labels: Vec<String> = f
        .for_rows
        .iter()
        .filter(|r| r.is_visible())
        .map(|r| r.text().to_string())
        .collect();
    let ttl = TTL_CHOICES[f.ttl_row.selected() as usize].1;
    let class = pinned_class(f).map(|c| c as u8);

    // Build the Session on the main thread (cheap), fill it, wipe the widgets.
    let mut s = {
        let mut a = ui.app.borrow_mut();
        if !relays.is_empty() {
            a.set_relays(relays.clone());
        }
        match Session::new(a.session_config(ttl, class)) {
            Ok(s) => s,
            Err(SessionError::MemoryUnlocked) => {
                drop(a);
                return fail(f, &tr("send.error.memory"));
            }
            Err(e) => {
                drop(a);
                return fail(f, &e.to_string());
            }
        }
    };
    let staged: Result<(), SessionError> = (|| {
        if let Some(t) = &to {
            s.set_recipient(t)?;
        }
        s.compose(note.as_bytes(), PTYPE_TEXT)?;
        if let Some(p) = &real_pass {
            s.set_passphrase(Some(p))?;
        }
        if let Some((t, p)) = &decoy {
            s.add_decoy(t, p)?;
        }
        if let Some((t, p)) = &distress {
            s.set_distress(t, p)?;
        }
        Ok(())
    })();
    drop((note, real_pass, decoy, distress));
    if let Err(e) = staged {
        return fail(f, &e.to_string());
    }
    // The secrets are in locked memory now; clear the toolkit's copies.
    wipe(&f.editor);
    wipe(&f.decoy_text);
    wipe(&f.distress_text);
    f.pass.clear();
    f.pass_repeat.clear();
    f.decoy_pass.clear();
    f.distress_pass.clear();

    f.go.set_sensitive(false);
    f.progress.set_label(&tr("send.progress.sealing"));
    let ui2 = ui.clone();
    let f2 = f.clone();
    let retry2 = retry.clone();
    worker::run(
        move || {
            let r = s.seal(level);
            (s, r)
        },
        move |(mut s, r)| {
            if let Err(e) = r {
                let msg = match e {
                    SessionError::TooLarge => trf(
                        "send.counter.too_large",
                        &[
                            ("used", "?"),
                            ("max", &SizeClass::C3.max_note_len().to_string()),
                        ],
                    ),
                    e => e.to_string(),
                };
                return fail(&f2, &msg);
            }
            if to_cards {
                // Class 3 (64 cards) is not offered on paper.
                let too_big = s
                    .sealed_block()
                    .map(|(_, b)| b.len() > SizeClass::C2.len())
                    .unwrap_or(true);
                if too_big {
                    s.close();
                    f2.go.set_sensitive(true);
                    f2.progress.set_label("");
                    return fail(&f2, &tr("send.error.cards_class"));
                }
                ui2.app.borrow_mut().session = Some(s);
                f2.go.set_sensitive(true);
                f2.progress.set_label("");
                ui2.nav.push(&super::cards::build(&ui2, level, for_labels));
                return;
            }
            ui2.app.borrow_mut().session = Some(s);
            post(&ui2, &f2, &retry2, level, for_labels);
        },
    );
}

/// Second and later presses after a failed post: re-target the kept Block and post again.
fn repost(ui: &Rc<Ui>, f: &Form, retry: &Retry, level: Level, for_labels: Vec<String>) {
    f.error.set_label("");
    let relays = match parse_relays(&f.relays.text()) {
        Ok(r) => r,
        Err(e) => return fail(f, &e),
    };
    {
        let mut a = ui.app.borrow_mut();
        a.set_relays(relays.clone());
        match a.session.as_mut() {
            Some(s) => {
                if let Err(e) = s.set_relays(relays) {
                    drop(a);
                    return fail(f, &e.to_string());
                }
            }
            None => {
                drop(a);
                return fail(f, &tr("handover.expired"));
            }
        }
    }
    post(ui, f, retry, level, for_labels);
}

/// Post on a worker; on success go to Hand-over, otherwise keep the Block and offer a retry.
fn post(ui: &Rc<Ui>, f: &Form, retry: &Retry, level: Level, for_labels: Vec<String>) {
    f.progress.set_label(&tr("send.progress.posting"));
    f.go.set_sensitive(false);
    // The Session stays on the main thread; only the job travels (review finding C-1).
    let job = {
        let mut a = ui.app.borrow_mut();
        let Some(s) = a.session.as_mut() else {
            drop(a);
            return fail(f, &tr("handover.expired"));
        };
        match s.post_job() {
            Ok(j) => j,
            Err(e) => {
                drop(a);
                return offer_retry(f, retry, level, for_labels, &e.to_string());
            }
        }
    };
    ui.app.borrow_mut().inflight = Some(job.cancel_token());
    let ui2 = ui.clone();
    let f2 = f.clone();
    let retry2 = retry.clone();
    worker::run(
        move || job.run(),
        move |r: Result<Vec<PostResult>, SessionError>| {
            ui2.app.borrow_mut().inflight = None;
            if let Ok(results) = &r {
                let mut a = ui2.app.borrow_mut();
                match a.session.as_mut() {
                    Some(s) => {
                        let _ = s.record_post(results);
                    }
                    None => {
                        drop(a);
                        return fail(&f2, &tr("handover.expired"));
                    }
                }
            }
            match r {
                Ok(results) if results.iter().any(PostResult::stored) => {
                    ui2.app.borrow_mut().note_network_ok();
                    let ok = results.iter().filter(|r| r.stored()).count();
                    f2.progress.set_label(&trf(
                        "send.progress.posted",
                        &[("ok", &ok.to_string()), ("n", &results.len().to_string())],
                    ));
                    *retry2.borrow_mut() = None;
                    let for_recipient = ui2
                        .app
                        .borrow()
                        .session
                        .as_ref()
                        .is_some_and(|s| s.sealed_for_recipient());
                    if for_recipient {
                        f2.to.set_text("");
                        ui2.nav.push(&handover::build_posted(&ui2, &results));
                    } else {
                        ui2.nav.push(&handover::build(&ui2, level, for_labels));
                    }
                }
                Ok(results) => {
                    // Nothing stored anywhere. If every relay failed the way a blocked
                    // network fails (Tor answered, nothing beyond it did), raise the D-16
                    // direction on Home as well (CLI-15).
                    let blocked = !results.is_empty()
                        && results.iter().all(|r| match &r.result {
                            Err(e) => drop_error_looks_blocked(e),
                            Ok(_) => false,
                        });
                    post_failed(&ui2, &f2, &retry2, level, for_labels, blocked);
                }
                Err(SessionError::NoRelayAnswered(e)) => {
                    let blocked = drop_error_looks_blocked(&e);
                    post_failed(&ui2, &f2, &retry2, level, for_labels, blocked);
                }
                Err(SessionError::Drop(e)) => {
                    let blocked = drop_error_looks_blocked(&e);
                    post_failed(&ui2, &f2, &retry2, level, for_labels, blocked);
                }
                Err(e) => offer_retry(&f2, &retry2, level, for_labels, &e.to_string()),
            }
        },
    );
}

/// Is this the failure a network that blocks Tor produces? (D-16; `tor::looks_like_blocked_network`.)
pub fn drop_error_looks_blocked(e: &aska_core::drop::DropError) -> bool {
    use aska_core::drop::DropError as D;
    match e {
        // An I/O timeout on an *established* relay stream is a slow or stalling relay, not a
        // blocked network (review finding C-12); only Tor's own verdicts count.
        D::Timeout => false,
        D::Tor(t) => aska_core::tor::looks_like_blocked_network(t),
        _ => false,
    }
}

/// A failed post: keep the Block for a retry; when the failure looks like a blocked network,
/// say so here and raise the Home banner with the platform's direction.
fn post_failed(
    ui: &Rc<Ui>,
    f: &Form,
    retry: &Retry,
    level: Level,
    for_labels: Vec<String>,
    blocked: bool,
) {
    if blocked {
        ui.app.borrow_mut().note_blocked_network();
        ui.recheck_home();
        offer_retry(f, retry, level, for_labels, &tr("send.error.blocked"));
    } else {
        offer_retry(f, retry, level, for_labels, &tr("send.progress.failed"));
    }
}

/// The Block stays in the Session; the relay field is live again and the button posts again
/// (Client Design §5.2). Nothing is written anywhere.
fn offer_retry(f: &Form, retry: &Retry, level: Level, for_labels: Vec<String>, msg: &str) {
    f.error.set_label(msg);
    f.progress.set_label("");
    f.go.set_label(&tr("send.retry"));
    f.go.set_sensitive(true);
    *retry.borrow_mut() = Some((level, for_labels));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fit_class_matches_the_core_arithmetic() {
        // Single slot: each class's max_note_len is the largest note that still selects it.
        for c in SizeClass::ALL {
            assert_eq!(fit_class(&[c.max_note_len()], None), Some(c));
        }
        assert_eq!(fit_class(&[2506], None), Some(SizeClass::C1));
        assert_eq!(fit_class(&[2507], None), Some(SizeClass::C2));
        assert_eq!(fit_class(&[SizeClass::C3.max_note_len() + 1], None), None);
        // Pinned class refuses what does not fit, accepts what does.
        assert_eq!(fit_class(&[3000], Some(SizeClass::C1)), None);
        assert_eq!(fit_class(&[3000], Some(SizeClass::C2)), Some(SizeClass::C2));
        // Decoy and distress slots each take their own region; three small slots still fit C1.
        assert_eq!(fit_class(&[100, 100, 100], None), Some(SizeClass::C1));
        // 2560 payload = 10 granules; note of 2000 B → 2054 → 9 granules (2304); + a decoy
        // region of 256 → 2560 fits; two more do not.
        assert_eq!(fit_class(&[2000, 10], None), Some(SizeClass::C1));
        assert_eq!(fit_class(&[2000, 10, 10], None), Some(SizeClass::C2));
    }

    #[test]
    fn relay_parsing() {
        let ok = parse_relays(" 2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion, 2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion ").unwrap();
        assert_eq!(ok.len(), 1, "duplicates collapse");
        assert!(parse_relays("example.com").is_err());
        assert!(parse_relays("   ").is_err());
    }
}
