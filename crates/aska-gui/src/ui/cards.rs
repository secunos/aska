//! Block cards (DC-04 §7) in the graphical client: after a seal with "Block cards instead of a
//! relay", the Block's chunks are shown one QR at a time — the receiver scans them with their
//! own camera, device to device — or sent to any printer. Then the usual hand-over of the key
//! follows. The cards are noise without the key; the Block is dropped when the page is left.

use super::{body, hint, pill, printdlg, Ui};
use crate::i18n::{tr, trf};
use adw::prelude::*;
use aska_core::session::Level;
use aska_paper::cards;
use aska_paper::render::{self, RenderOptions};
use std::cell::RefCell;
use std::rc::Rc;
use zeroize::Zeroizing;

const RENDER_DPI: u32 = 150;

pub fn build(ui: &Rc<Ui>, level: Level, for_labels: Vec<String>) -> adw::NavigationPage {
    let (root, clamp) = body(640);
    let chunks: Vec<Zeroizing<Vec<u8>>> = {
        let a = ui.app.borrow();
        match a.session.as_ref().and_then(|s| s.sealed_block().ok()) {
            Some((_, block)) => cards::split_block(block).unwrap_or_default(),
            None => Vec::new(),
        }
    };
    let n = chunks.len();
    let chunks = Rc::new(RefCell::new(chunks));
    let index = Rc::new(RefCell::new(0usize));

    root.append(&hint(&tr("cards.intro")));
    let title = gtk::Label::builder().css_classes(["title-3"]).build();
    root.append(&title);
    let slot = gtk::Box::new(gtk::Orientation::Vertical, 0);
    slot.set_halign(gtk::Align::Center);
    root.append(&slot);
    let row = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(8)
        .halign(gtk::Align::Center)
        .build();
    let prev = gtk::Button::with_label(&tr("cards.prev"));
    let next = gtk::Button::builder()
        .label(tr("cards.next"))
        .css_classes(["suggested-action"])
        .build();
    let print = gtk::Button::with_label(&tr("cards.print"));
    row.append(&prev);
    row.append(&next);
    row.append(&print);
    root.append(&row);
    let go = pill(&tr("cards.handover"), true);
    root.append(&go);
    root.append(&hint(&tr("cards.hint")));

    let show = {
        let (chunks, index, title, slot, prev, next) = (
            chunks.clone(),
            index.clone(),
            title.clone(),
            slot.clone(),
            prev.clone(),
            next.clone(),
        );
        Rc::new(move || {
            let i = *index.borrow();
            while let Some(c) = slot.first_child() {
                slot.remove(&c);
            }
            let cs = chunks.borrow();
            if let Some(c) = cs.get(i) {
                title.set_label(&trf(
                    "cards.card",
                    &[("i", &(i + 1).to_string()), ("n", &cs.len().to_string())],
                ));
                slot.append(&super::qr::qr_widget_bytes(c, 440));
            }
            prev.set_sensitive(i > 0);
            next.set_sensitive(i + 1 < cs.len());
        })
    };
    show();
    {
        let (index, show) = (index.clone(), show.clone());
        prev.connect_clicked(move |_| {
            let mut i = index.borrow_mut();
            *i = i.saturating_sub(1);
            drop(i);
            show();
        });
    }
    {
        let (index, show) = (index.clone(), show.clone());
        next.connect_clicked(move |_| {
            *index.borrow_mut() += 1;
            show();
        });
    }
    {
        let (ui, chunks) = (ui.clone(), chunks.clone());
        print.connect_clicked(move |_| {
            let opts = RenderOptions {
                dpi: RENDER_DPI,
                ..RenderOptions::default()
            };
            let cs = chunks.borrow();
            match render::render_block_cards(&cs, &opts) {
                Ok(sheets) => printdlg::open(&ui, printdlg::Material::Block, sheets, RENDER_DPI),
                Err(e) => ui.toast(&e.to_string()),
            }
        });
    }
    {
        let ui = ui.clone();
        let chunks = chunks.clone();
        go.connect_clicked(move |_| {
            chunks.borrow_mut().clear();
            ui.nav
                .push(&super::handover::build(&ui, level, for_labels.clone()));
        });
    }
    if n == 0 {
        title.set_label(&tr("cards.none"));
    }
    let page = ui.page("cards", &tr("cards.title"), &clamp);
    {
        let (chunks, slot) = (chunks.clone(), slot.clone());
        page.connect_hidden(move |_| {
            chunks.borrow_mut().clear();
            while let Some(c) = slot.first_child() {
                slot.remove(&c);
            }
        });
    }
    page
}
