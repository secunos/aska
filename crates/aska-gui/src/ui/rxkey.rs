//! Receiving key (DC-02 §6): create a receiving seed — 24 words the receiver keeps — and show
//! the public Receiving Key (`askar1…`) with its twelve-character check and a QR code. Or
//! re-derive the public key from an existing seed. The seed exists only on this screen; the
//! public key is public and may be copied (it is the one thing here the clipboard may hold).
//!
//! With an encrypted profile open (RM-09, Client Design §5.6.3) the page also lists the seeds
//! the profile holds — by the check of the key each yields, never the seed — shows any of them
//! again, removes one, and stores the seed just created or re-derived, so the receiver need
//! not type the 24 words on Receive. Each change asks for the profile passphrase and rewrites
//! the profile in place.

use super::qr::qr_widget;
use super::{body, heading, hint, pill, Ui};
use crate::i18n::{tr, trf};
use adw::prelude::*;
use aska_core::drop::{secret32, Relay, Secret32};
use aska_core::profile::MAX_SEEDS;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use zeroize::Zeroizing;

/// The widgets of the result area and what they show.
#[derive(Clone)]
struct Shown {
    result: gtk::Box,
    words_heading: gtk::Label,
    words_grid: gtk::Grid,
    words_note: gtk::Label,
    check_label: gtk::Label,
    qr_holder: gtk::Box,
    key_text: gtk::Label,
    store: gtk::Button,
    store_note: gtk::Label,
    /// The seed behind the key on screen when it was created or re-derived here and is not
    /// (yet) in the profile; `None` while a stored key is shown. Dropped (zeroised) as soon
    /// as it is stored or the page is left.
    fresh_seed: Rc<RefCell<Option<Secret32>>>,
    /// A stored key is on screen (its words are never shown).
    stored_shown: Rc<Cell<bool>>,
}

impl Shown {
    fn clear_words(&self) {
        let mut child = self.words_grid.first_child();
        while let Some(c) = child {
            child = c.next_sibling();
            if let Ok(l) = c.clone().downcast::<gtk::Label>() {
                super::wipe_label(&l);
            }
            self.words_grid.remove(&c);
        }
    }

    /// Show a public key: check, QR and text.
    fn show_key(&self, rk: &aska_core::encodings::ReceivingKey) -> Result<(), String> {
        let text = rk.encode().map_err(|e| e.to_string())?;
        self.check_label.set_label(&rk.check());
        while let Some(c) = self.qr_holder.first_child() {
            self.qr_holder.remove(&c);
        }
        self.qr_holder.append(&qr_widget(&text, 560));
        self.key_text.set_label(&text);
        self.result.set_visible(true);
        Ok(())
    }

    fn set_words_visible(&self, on: bool) {
        self.words_heading.set_visible(on);
        self.words_grid.set_visible(on);
        self.words_note.set_visible(on);
    }

    /// The Store button for the key on screen: offered only when a profile is open, and
    /// only while the seed is fresh, not in the profile already and the profile has room.
    fn refresh_store(&self, ui: &Rc<Ui>) {
        let a = ui.app.borrow();
        let open = a.profile_path.is_some();
        self.store.set_visible(open);
        self.store_note.set_visible(open);
        self.store_note.remove_css_class("error");
        if !open {
            return;
        }
        let fresh = self.fresh_seed.borrow();
        let Some(seed) = fresh.as_ref() else {
            self.store.set_sensitive(false);
            return;
        };
        if a.profile_seeds.len() >= MAX_SEEDS {
            self.store.set_sensitive(false);
            self.store_note
                .set_label(&trf("rxkey.store.full", &[("max", &MAX_SEEDS.to_string())]));
        } else if a
            .profile_seeds
            .iter()
            .any(|s| s.as_slice() == seed.as_slice())
        {
            self.store.set_sensitive(false);
            self.store_note.set_label(&tr("rxkey.store.duplicate"));
        } else {
            self.store.set_sensitive(true);
            self.store_note.set_label(&trf(
                "rxkey.store.hint",
                &[
                    ("n", &a.profile_seeds.len().to_string()),
                    ("max", &MAX_SEEDS.to_string()),
                ],
            ));
        }
    }
}

/// The list of stored keys and its Remove button.
#[derive(Clone)]
struct StoredList {
    list: gtk::ListBox,
    none: gtk::Label,
    remove: gtk::Button,
    /// The outcome of a removal.
    msg: gtk::Label,
}

impl StoredList {
    /// Rebuild the rows from the run's copy of the profile's seeds (nothing is selected).
    fn refresh(&self, ui: &Rc<Ui>) {
        while let Some(row) = self.list.row_at_index(0) {
            self.list.remove(&row);
        }
        let checks = ui.app.borrow().profile_seed_checks();
        for check in &checks {
            let row = adw::ActionRow::builder().title(check.as_str()).build();
            row.add_css_class("aska-mono");
            self.list.append(&row);
        }
        self.list.set_visible(!checks.is_empty());
        self.none.set_visible(checks.is_empty());
        self.remove.set_visible(!checks.is_empty());
        self.remove.set_sensitive(false);
    }
}

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

    // ---- keys stored in the profile (only with a profile open) ----
    let profile_name = ui.app.borrow().profile.as_ref().map(|p| p.name.clone());
    let stored = profile_name.as_ref().map(|name| {
        let b = gtk::Box::new(gtk::Orientation::Vertical, 8);
        b.append(&heading(&tr("rxkey.stored")));
        b.append(&hint(&trf("rxkey.stored.hint", &[("name", name)])));
        let list = gtk::ListBox::builder()
            .selection_mode(gtk::SelectionMode::Single)
            .css_classes(["boxed-list"])
            .build();
        b.append(&list);
        let none = hint(&tr("rxkey.stored.none"));
        b.append(&none);
        let remove = gtk::Button::builder()
            .label(tr("rxkey.stored.remove"))
            .css_classes(["destructive-action"])
            .halign(gtk::Align::Start)
            .sensitive(false)
            .build();
        b.append(&remove);
        let msg = gtk::Label::builder().wrap(true).xalign(0.0).build();
        b.append(&msg);
        root.append(&b);
        StoredList {
            list,
            none,
            remove,
            msg,
        }
    });
    if let Some(s) = &stored {
        s.refresh(ui);
    }

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

    // ---- result area (filled after Create, or when a stored key is selected) ----
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
    let store = gtk::Button::builder()
        .label(tr("rxkey.store"))
        .halign(gtk::Align::Start)
        .visible(false)
        .sensitive(false)
        .build();
    let store_note = hint("");
    store_note.set_visible(false);
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
    result.append(&store);
    result.append(&store_note);
    result.append(&done);
    root.append(&result);

    let shown = Shown {
        result: result.clone(),
        words_heading: words_heading.clone(),
        words_grid: words_grid.clone(),
        words_note: words_note.clone(),
        check_label: check_label.clone(),
        qr_holder: qr_holder.clone(),
        key_text: key_text.clone(),
        store: store.clone(),
        store_note: store_note.clone(),
        fresh_seed: Rc::new(RefCell::new(None)),
        stored_shown: Rc::new(Cell::new(false)),
    };

    {
        let (frame, shown) = (words_frame.clone(), shown.clone());
        let go2 = go.clone();
        existing.connect_active_notify(move |s| {
            let on = s.is_active();
            frame.set_visible(on);
            go2.set_label(&tr(if on { "rxkey.derive" } else { "rxkey.create" }));
            // With an existing seed the words are not re-shown: the user has them. Nor are
            // a stored key's.
            shown.set_words_visible(!on && !shown.stored_shown.get());
        });
    }

    {
        let ui = ui.clone();
        let (relays, existing, words_tv, error, shown, go2) = (
            relays.clone(),
            existing.clone(),
            words_tv.clone(),
            error.clone(),
            shown.clone(),
            go.clone(),
        );
        let stored = stored.clone();
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
            // The seed as bytes, kept only while the page can still store it in the profile.
            let seed = match aska_core::Root::from_words(&words) {
                Ok(root) => secret32(*root.as_bytes()),
                Err(_) => return error.set_label(&tr("rxkey.error.words")),
            };
            let rk = aska_core::xwing::receiving_key_from_seed(&seed, &relay_pks, None, None);
            // Show: words (new seed only), check, QR + text.
            shown.clear_words();
            if !existing.is_active() {
                for (n, w) in words.split_whitespace().enumerate() {
                    let l = gtk::Label::builder()
                        .label(format!("{:>2}. {w}", n + 1))
                        .xalign(0.0)
                        .css_classes(["aska-words"])
                        .build();
                    shown
                        .words_grid
                        .attach(&l, (n % 4) as i32, (n / 4) as i32, 1, 1);
                }
            }
            drop(words);
            if let Err(e) = shown.show_key(&rk) {
                return error.set_label(&e);
            }
            shown.stored_shown.set(false);
            shown.set_words_visible(!existing.is_active());
            *shown.fresh_seed.borrow_mut() = Some(seed);
            shown.refresh_store(&ui);
            if let Some(s) = &stored {
                s.list.unselect_all();
            }
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

    // Store the fresh seed in the profile (passphrase asked in a dialog; file rewritten in
    // place on a worker).
    {
        let (ui, shown, error, stored) = (ui.clone(), shown.clone(), error.clone(), stored.clone());
        let name = profile_name.clone().unwrap_or_default();
        store.connect_clicked(move |b| {
            error.set_label("");
            // The seed travels to the worker by move; a copy stays here only until the
            // outcome is known, so a failed attempt (wrong passphrase) can be repeated.
            let Some(seed) = shown.fresh_seed.borrow().as_ref().cloned() else {
                return;
            };
            b.set_sensitive(false);
            let check = shown.check_label.text().to_string();
            let (ui2, shown2, stored2) = (ui.clone(), shown.clone(), stored.clone());
            super::settings::edit_profile(
                &ui,
                &tr("rxkey.store"),
                &trf("rxkey.store.body", &[("name", &name)]),
                move |p| {
                    p.add_seed(seed).map(|_| ()).map_err(|e| match e {
                        aska_core::Error::TooLarge => {
                            trf("rxkey.store.full", &[("max", &MAX_SEEDS.to_string())])
                        }
                        _ => tr("rxkey.store.duplicate"),
                    })
                },
                move |r| {
                    match r {
                        Ok(()) => {
                            // The profile holds it now: the page's own copy goes.
                            *shown2.fresh_seed.borrow_mut() = None;
                            shown2.refresh_store(&ui2);
                            shown2
                                .store_note
                                .set_label(&trf("rxkey.store.stored", &[("check", &check)]));
                            if let Some(s) = &stored2 {
                                s.refresh(&ui2);
                            }
                        }
                        Err(e) => {
                            shown2.refresh_store(&ui2);
                            shown2.store_note.add_css_class("error");
                            shown2.store_note.set_label(&e);
                        }
                    }
                },
            );
        });
    }

    // Selecting a stored key shows it with this page's relay hints; Remove takes it out of
    // the profile.
    if let Some(s) = &stored {
        {
            let (ui, shown, error, relays, s2) = (
                ui.clone(),
                shown.clone(),
                error.clone(),
                relays.clone(),
                s.clone(),
            );
            s.list.connect_row_selected(move |_, row| {
                let Some(row) = row else {
                    s2.remove.set_sensitive(false);
                    return;
                };
                s2.remove.set_sensitive(true);
                error.set_label("");
                let relay_pks: Vec<[u8; 32]> = match parse_relays(&relays.text()) {
                    Ok(r) => r.iter().map(|r| r.pubkey).collect(),
                    Err(e) => return error.set_label(&e),
                };
                let rk = {
                    let a = ui.app.borrow();
                    let Some(seed) = a.profile_seeds.get(row.index().max(0) as usize) else {
                        return;
                    };
                    aska_core::xwing::receiving_key_from_seed(seed, &relay_pks, None, None)
                };
                // A stored key replaces whatever was on screen; its seed is never shown.
                *shown.fresh_seed.borrow_mut() = None;
                shown.clear_words();
                shown.stored_shown.set(true);
                shown.set_words_visible(false);
                if let Err(e) = shown.show_key(&rk) {
                    return error.set_label(&e);
                }
                shown.refresh_store(&ui);
                shown
                    .store_note
                    .set_label(&trf("rxkey.stored.shown", &[("check", &rk.check())]));
            });
        }
        {
            let (ui, shown, error, s2) = (ui.clone(), shown.clone(), error.clone(), s.clone());
            let name = profile_name.clone().unwrap_or_default();
            s.remove.connect_clicked(move |b| {
                error.set_label("");
                s2.msg.remove_css_class("error");
                s2.msg.set_label("");
                let Some(row) = s2.list.selected_row() else {
                    return;
                };
                let check = ui
                    .app
                    .borrow()
                    .profile_seed_checks()
                    .get(row.index().max(0) as usize)
                    .cloned();
                let Some(check) = check else {
                    return;
                };
                b.set_sensitive(false);
                let (ui2, shown2, s3, check2) =
                    (ui.clone(), shown.clone(), s2.clone(), check.clone());
                super::settings::edit_profile(
                    &ui,
                    &tr("rxkey.stored.remove"),
                    &trf(
                        "rxkey.stored.remove.body",
                        &[("check", &check), ("name", &name)],
                    ),
                    move |p| {
                        let i = p
                            .seed_by_check(&check)
                            .ok_or_else(|| trf("rxkey.store.not_found", &[("check", &check)]))?;
                        drop(p.remove_seed(i));
                        Ok(())
                    },
                    move |r| match r {
                        Ok(()) => {
                            s3.refresh(&ui2);
                            s3.msg.remove_css_class("error");
                            // The removed key was the one on screen: nothing to show now.
                            if shown2.stored_shown.get() {
                                shown2.result.set_visible(false);
                                shown2.stored_shown.set(false);
                            }
                            shown2.refresh_store(&ui2);
                            s3.msg
                                .set_label(&trf("rxkey.stored.removed", &[("check", &check2)]));
                        }
                        Err(e) => {
                            s3.remove.set_sensitive(s3.list.selected_row().is_some());
                            s3.msg.add_css_class("error");
                            s3.msg.set_label(&e);
                        }
                    },
                );
            });
        }
    }

    let page = ui.page("rxkey", &tr("rxkey.title"), &clamp);
    // Leaving wipes the words from the widgets and drops the seed held for storing.
    {
        let shown = shown.clone();
        page.connect_hidden(move |_| {
            *shown.fresh_seed.borrow_mut() = None;
            let mut child = shown.words_grid.first_child();
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
