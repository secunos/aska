//! Shares (Client Design §5.6, Table 3 `share split` / `share combine`): split a key that
//! arrived whole (24 words or a Key Card) into fresh Shares — the recovery drill — shown one
//! at a time on the Hand-over screen; or go and combine Shares on the Receive screen.

use super::{body, handover, heading, hint, pill, receive, Ui};
use crate::i18n::{tr, trf};
use adw::prelude::*;
use aska_core::session::{KeyStatus, Level, Session, SessionError};
use std::rc::Rc;
use zeroize::Zeroizing;

pub fn build(ui: &Rc<Ui>) -> adw::NavigationPage {
    let (root, clamp) = body(720);

    // ---- Split ----
    let split_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
    split_box.append(&heading(&tr("shares.split")));
    split_box.append(&hint(&tr("shares.split.hint")));
    let material = super::secret_text_view(80, true);
    let sw = gtk::ScrolledWindow::builder()
        .child(&material)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .min_content_height(80)
        .build();
    split_box.append(&gtk::Frame::builder().child(&sw).build());
    let group = adw::PreferencesGroup::new();
    let threshold_row = adw::ComboRow::builder()
        .title(tr("send.threshold"))
        .model(&gtk::StringList::new(&[
            &tr("send.threshold.2of3"),
            &tr("send.threshold.3of5"),
        ]))
        .build();
    group.add(&threshold_row);
    let mut for_rows = Vec::new();
    for i in 1..=5 {
        let r = adw::EntryRow::builder()
            .title(trf("send.for", &[("n", &i.to_string())]))
            .visible(i <= 3)
            .build();
        group.add(&r);
        for_rows.push(r);
    }
    split_box.append(&group);
    let go = pill(&tr("shares.split.go"), true);
    let error = gtk::Label::builder()
        .wrap(true)
        .xalign(0.0)
        .css_classes(["error"])
        .build();
    split_box.append(&go);
    split_box.append(&error);
    root.append(&split_box);

    {
        let rows = for_rows.clone();
        threshold_row.connect_selected_notify(move |r| {
            let n = if r.selected() == 1 { 5 } else { 3 };
            for (i, row) in rows.iter().enumerate() {
                row.set_visible(i < n);
            }
        });
    }
    {
        let ui = ui.clone();
        let (material, threshold_row, for_rows, error) = (
            material.clone(),
            threshold_row.clone(),
            for_rows.clone(),
            error.clone(),
        );
        go.connect_clicked(move |_| {
            error.set_label("");
            let text = {
                let b = material.buffer();
                let (s, e) = b.bounds();
                Zeroizing::new(b.text(&s, &e, false).to_string())
            };
            if text.trim().is_empty() {
                return error.set_label(&tr("shares.error.empty"));
            }
            let (k, n) = if threshold_row.selected() == 1 {
                (3u8, 5u8)
            } else {
                (2, 3)
            };
            let labels: Vec<String> = for_rows
                .iter()
                .filter(|r| r.is_visible())
                .map(|r| r.text().to_string())
                .collect();
            let mut a = ui.app.borrow_mut();
            a.close_session();
            let mut s = match Session::new(a.session_config(aska_proto::DEFAULT_TTL_HOURS, None)) {
                Ok(s) => s,
                Err(SessionError::MemoryUnlocked) => {
                    drop(a);
                    return error.set_label(&tr("send.error.memory"));
                }
                Err(e) => {
                    drop(a);
                    return error.set_label(&e.to_string());
                }
            };
            let staged = match s.add_key_material(&text) {
                Ok(KeyStatus::Ready) => s.split_shares(k, n),
                Ok(KeyStatus::NeedShares { .. }) => Err(SessionError::BadKeyMaterial),
                Err(e) => Err(e),
            };
            drop(text);
            super::wipe_text_view(&material);
            match staged {
                Ok(()) => {
                    a.session = Some(s);
                    drop(a);
                    ui.nav
                        .push(&handover::build(&ui, Level::Guarded { k, n }, labels));
                }
                Err(SessionError::BadKeyMaterial) => {
                    drop(a);
                    error.set_label(&tr("shares.error.whole_key"));
                }
                Err(e) => {
                    drop(a);
                    error.set_label(&e.to_string());
                }
            }
        });
    }

    // ---- Combine ----
    let combine_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
    combine_box.append(&heading(&tr("shares.combine")));
    combine_box.append(&hint(&tr("shares.combine.hint")));
    let combine = pill(&tr("shares.combine.go"), false);
    combine_box.append(&combine);
    root.append(&combine_box);
    {
        let ui = ui.clone();
        combine.connect_clicked(move |_| {
            ui.nav.push(&receive::build(&ui, true));
        });
    }

    // ---- Receiving key (DC-02) ----
    let rx_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
    rx_box.append(&heading(&tr("shares.rxkey")));
    rx_box.append(&hint(&tr("shares.rxkey.hint")));
    let rx = pill(&tr("shares.rxkey.go"), false);
    rx_box.append(&rx);
    root.append(&rx_box);
    {
        let ui = ui.clone();
        rx.connect_clicked(move |_| {
            ui.nav.push(&super::rxkey::build(&ui));
        });
    }

    ui.page("shares", &tr("shares.title"), &clamp)
}
