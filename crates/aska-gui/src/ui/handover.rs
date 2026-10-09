//! Screen 3 — Hand-over (Client Design §5.3). Quick: the Key Card as a large QR, the same key
//! as 24 words, the "different channel" instruction and the CLI-14 banner; "Done — forget the
//! key" or the five-minute countdown ends it. Guarded: one Share at a time — "Share 1 of 3 —
//! for: Anna" — so no two Shares are ever on screen together. No print action (§5.3).

use super::qr::qr_widget;
use super::Ui;
use crate::i18n::{tr, trf};
use adw::prelude::*;
use aska_core::drop::PostResult;
use aska_core::session::Level;
use gtk::glib;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;
use zeroize::Zeroizing;

pub fn build(ui: &Rc<Ui>, level: Level, for_labels: Vec<String>) -> adw::NavigationPage {
    let root = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(16)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    let clamp = adw::Clamp::builder().maximum_size(640).child(&root).build();

    let title = gtk::Label::builder()
        .css_classes(["title-2"])
        .wrap(true)
        .build();
    let qr_holder = gtk::Box::new(gtk::Orientation::Vertical, 0);
    qr_holder.set_halign(gtk::Align::Center);
    let text = gtk::Label::builder()
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::WordChar)
        .css_classes(["aska-mono", "caption"])
        .selectable(false)
        .build();
    let words_grid = gtk::Grid::builder()
        .row_spacing(4)
        .column_spacing(18)
        .halign(gtk::Align::Center)
        .build();
    let note = gtk::Label::builder().wrap(true).xalign(0.0).build();
    let banner = gtk::Label::builder()
        .wrap(true)
        .xalign(0.0)
        .css_classes(["aska-banner-warn"])
        .build();
    let countdown = gtk::Label::builder().css_classes(["dim-label"]).build();
    let action = gtk::Button::builder()
        .css_classes(["suggested-action", "pill", "title-4"])
        .halign(gtk::Align::Center)
        .height_request(48)
        .width_request(280)
        .build();
    root.append(&title);
    root.append(&qr_holder);
    root.append(&text);
    root.append(&words_grid);
    root.append(&note);
    root.append(&banner);
    root.append(&action);
    // Share cards (DC-04 §7.2): this Share as a printed card, through the client's own print
    // dialog (USB printers only). Guarded only.
    let print_card = gtk::Button::builder()
        .label(tr("handover.share.print"))
        .halign(gtk::Align::Center)
        .css_classes(["flat"])
        .visible(matches!(level, Level::Guarded { .. }))
        .build();
    root.append(&print_card);
    root.append(&countdown);

    let relays_line = {
        let a = ui.app.borrow();
        if a.relays.is_empty() {
            tr("handover.relays.none")
        } else {
            trf(
                "handover.relays",
                &[(
                    "relays",
                    &a.relays
                        .iter()
                        .map(|r| r.onion())
                        .collect::<Vec<_>>()
                        .join(", "),
                )],
            )
        }
    };

    // Which item is shown: Quick has one; Guarded has n.
    let index = Rc::new(RefCell::new(0usize));
    let count = match level {
        Level::Quick => 1,
        Level::Guarded { n, .. } => n as usize,
    };

    let show = {
        let ui = ui.clone();
        let (title, qr_holder, text, words_grid, note, banner, action) = (
            title.clone(),
            qr_holder.clone(),
            text.clone(),
            words_grid.clone(),
            note.clone(),
            banner.clone(),
            action.clone(),
        );
        let relays_line = relays_line.clone();
        let for_labels = for_labels.clone();
        Rc::new(move |i: usize| {
            wipe_shown(&text, &words_grid);
            while let Some(c) = qr_holder.first_child() {
                qr_holder.remove(&c);
            }
            while let Some(c) = words_grid.first_child() {
                words_grid.remove(&c);
            }
            let mut a = ui.app.borrow_mut();
            let Some(s) = a.session.as_mut() else {
                return false;
            };
            match level {
                Level::Quick => {
                    let Ok(card) = s.hand_over_keycard() else {
                        return false;
                    };
                    let Ok(words) = s.hand_over_words() else {
                        return false;
                    };
                    title.set_label(&tr("handover.keycard"));
                    qr_holder.append(&qr_widget(&card, 320));
                    text.set_label(&card);
                    let heading = gtk::Label::builder()
                        .label(tr("handover.words"))
                        .css_classes(["heading"])
                        .build();
                    words_grid.attach(&heading, 0, 0, 4, 1);
                    for (n, w) in words.split_whitespace().enumerate() {
                        let l = gtk::Label::builder()
                            .label(format!("{:>2}. {w}", n + 1))
                            .xalign(0.0)
                            .css_classes(["aska-words"])
                            .build();
                        words_grid.attach(&l, (n % 4) as i32, (n / 4) as i32 + 1, 1, 1);
                    }
                    let _z: Zeroizing<String> = words; // dropped and zeroised here
                    note.set_label(&format!("{}\n{relays_line}", tr("handover.instruction")));
                    banner.set_label(&tr("handover.quick_banner"));
                    banner.set_visible(true);
                    action.set_label(&tr("handover.done"));
                }
                Level::Guarded { k, n } => {
                    let Ok(share) = s.share_text(i) else {
                        return false;
                    };
                    let who = for_labels
                        .get(i)
                        .filter(|l| !l.trim().is_empty())
                        .cloned()
                        .unwrap_or_else(|| tr("handover.share.unnamed"));
                    title.set_label(&trf(
                        "handover.share",
                        &[
                            ("i", &(i + 1).to_string()),
                            ("n", &n.to_string()),
                            ("who", &who),
                        ],
                    ));
                    qr_holder.append(&qr_widget(&share, 300));
                    text.set_label(&share);
                    note.set_label(&format!(
                        "{}\n{relays_line}",
                        trf(
                            "handover.share.note",
                            &[("k", &k.to_string()), ("n", &n.to_string())]
                        )
                    ));
                    banner.set_visible(false);
                    action.set_label(&tr(if i + 1 == n as usize {
                        "handover.done"
                    } else {
                        "handover.next"
                    }));
                }
            }
            true
        })
    };

    if !show(0) {
        ui.go_home(Some(&tr("handover.expired")));
    }
    {
        let (ui, index) = (ui.clone(), index.clone());
        print_card.connect_clicked(move |_| {
            let i = *index.borrow();
            let (k, n) = match level {
                Level::Guarded { k, n } => (k, n),
                Level::Quick => return,
            };
            let share = {
                let mut a = ui.app.borrow_mut();
                a.session.as_mut().and_then(|s| s.share_text(i).ok())
            };
            let Some(share) = share else { return };
            let opts = aska_paper::render::RenderOptions::default();
            match aska_paper::render::render_share_card(&share, i as u8 + 1, n, k, &opts) {
                Ok(r) => {
                    super::printdlg::open(&ui, super::printdlg::Material::Share, vec![r], opts.dpi)
                }
                Err(e) => ui.toast(&e.to_string()),
            }
        });
    }

    // Next Share / Done.
    {
        let ui = ui.clone();
        let index = index.clone();
        let show = show.clone();
        action.connect_clicked(move |_| {
            let next = *index.borrow() + 1;
            if next < count {
                *index.borrow_mut() = next;
                if !show(next) {
                    ui.go_home(Some(&tr("handover.expired")));
                }
            } else {
                ui.go_home(Some(&tr("handover.forgotten")));
            }
        });
    }

    // Countdown mirrors the Session's idle watchdog (§2.3); the watchdog itself ends it.
    {
        let ui = ui.clone();
        let countdown = countdown.clone();
        glib::timeout_add_local(Duration::from_secs(1), move || {
            let a = ui.app.borrow();
            match a.session.as_ref() {
                Some(s) => {
                    let left = s.remaining_idle();
                    countdown.set_label(&trf(
                        "handover.countdown",
                        &[(
                            "mmss",
                            &format!("{:02}:{:02}", left.as_secs() / 60, left.as_secs() % 60),
                        )],
                    ));
                    glib::ControlFlow::Continue
                }
                None => glib::ControlFlow::Break,
            }
        });
    }

    // Leaving the page by the back arrow forgets the key too — and the widgets' copies of it.
    let page = ui.page("handover", &tr("handover.title"), &clamp);
    {
        let ui = ui.clone();
        let (text, words_grid) = (text.clone(), words_grid.clone());
        page.connect_hidden(move |_| {
            ui.app.borrow_mut().close_session();
            wipe_shown(&text, &words_grid);
        });
    }
    page
}

/// Overwrite the label copies of the key material (see `ui::wipe_label`).
fn wipe_shown(text: &gtk::Label, words_grid: &gtk::Grid) {
    super::wipe_label(text);
    let mut child = words_grid.first_child();
    while let Some(c) = child {
        child = c.next_sibling();
        if let Ok(l) = c.downcast::<gtk::Label>() {
            super::wipe_label(&l);
        }
    }
}

/// The end of a send to a Receiving Key (DC-02 §6): there is no key to hand over. Shows the
/// check of the key the Block was sealed for and which relays stored it, then Done.
pub fn build_posted(ui: &Rc<Ui>, results: &[PostResult]) -> adw::NavigationPage {
    let root = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(16)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    let clamp = adw::Clamp::builder().maximum_size(640).child(&root).build();
    let check = ui
        .app
        .borrow()
        .session
        .as_ref()
        .and_then(|s| s.recipient_check())
        .unwrap_or_default();
    root.append(
        &gtk::Label::builder()
            .label(tr("posted.title"))
            .css_classes(["title-2"])
            .wrap(true)
            .build(),
    );
    root.append(
        &gtk::Label::builder()
            .label(tr("posted.body"))
            .wrap(true)
            .xalign(0.0)
            .build(),
    );
    root.append(
        &gtk::Label::builder()
            .label(tr("rxkey.check"))
            .css_classes(["heading"])
            .xalign(0.0)
            .build(),
    );
    root.append(
        &gtk::Label::builder()
            .label(&check)
            .css_classes(["title-1", "aska-mono"])
            .selectable(true)
            .build(),
    );
    root.append(&super::hint(&tr("posted.check.note")));
    let stored: Vec<String> = results
        .iter()
        .filter(|r| r.stored())
        .map(|r| r.relay.onion())
        .collect();
    root.append(&super::hint(&trf(
        "posted.relays",
        &[("relays", &stored.join(", "))],
    )));
    let done = super::pill(&tr("posted.done"), true);
    root.append(&done);
    {
        let ui = ui.clone();
        done.connect_clicked(move |_| ui.go_home(Some(&tr("posted.toast"))));
    }
    let page = ui.page("posted", &tr("posted.title"), &clamp);
    {
        let ui = ui.clone();
        page.connect_hidden(move |_| {
            ui.app.borrow_mut().close_session();
        });
    }
    page
}
