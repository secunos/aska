//! An on-screen digit pad (paper mode, DC-04 §8.3): digits typed by clicking keys the client
//! draws, so input-method frameworks and keyloggers see nothing — the same reason the
//! passphrase keypad exists. Used for die rolls (keys 1–6), tags and short digit strings. The
//! value lives in a zeroising buffer of fixed capacity; the screen shows the digits in groups
//! of five (they are not a passphrase — the user must be able to check what they typed).

use crate::i18n::{tr, trf};
use adw::prelude::*;
use std::cell::RefCell;
use std::rc::Rc;
use zeroize::{Zeroize, Zeroizing};

struct Inner {
    value: Zeroizing<String>,
    cap: usize,
}

#[derive(Clone)]
pub struct DigitPad {
    root: gtk::Box,
    inner: Rc<RefCell<Inner>>,
    shown: gtk::Label,
    count: gtk::Label,
}

impl DigitPad {
    /// `keys`: the digits offered (e.g. "123456" for dice, "0123456789" for tags);
    /// `cap`: most digits accepted.
    pub fn new(title: &str, keys: &str, cap: usize) -> Self {
        let root = gtk::Box::new(gtk::Orientation::Vertical, 6);
        let head = gtk::Label::builder()
            .label(title)
            .xalign(0.0)
            .css_classes(["heading"])
            .build();
        root.append(&head);
        let shown = gtk::Label::builder()
            .label("")
            .xalign(0.0)
            .wrap(true)
            .css_classes(["aska-mono"])
            .height_request(24)
            .selectable(false)
            .build();
        root.append(&shown);
        let count = gtk::Label::builder()
            .label(trf("digitpad.entered", &[("n", "0")]))
            .xalign(0.0)
            .css_classes(["dim-label", "caption"])
            .build();
        root.append(&count);
        let grid = gtk::Grid::builder()
            .row_spacing(4)
            .column_spacing(4)
            .halign(gtk::Align::Start)
            .build();
        root.append(&grid);
        let pad = DigitPad {
            root,
            inner: Rc::new(RefCell::new(Inner {
                value: Zeroizing::new(String::with_capacity(cap)),
                cap,
            })),
            shown,
            count,
        };
        let per_row = 10usize.min(keys.len());
        for (i, c) in keys.chars().enumerate() {
            let b = gtk::Button::builder()
                .label(c.to_string())
                .css_classes(["aska-key"])
                .build();
            let p = pad.clone();
            b.connect_clicked(move |_| p.push(c));
            grid.attach(&b, (i % per_row) as i32, (i / per_row) as i32, 1, 1);
        }
        let row = (keys.len().div_ceil(per_row)) as i32;
        let del = gtk::Button::builder()
            .label(tr("keypad.backspace"))
            .css_classes(["aska-key"])
            .build();
        let clr = gtk::Button::builder()
            .label(tr("keypad.clear"))
            .css_classes(["aska-key"])
            .build();
        {
            let p = pad.clone();
            del.connect_clicked(move |_| p.pop());
        }
        {
            let p = pad.clone();
            clr.connect_clicked(move |_| p.clear());
        }
        grid.attach(&del, 0, row, 3, 1);
        grid.attach(&clr, 3, row, 3, 1);
        pad
    }

    pub fn widget(&self) -> &gtk::Box {
        &self.root
    }

    fn push(&self, c: char) {
        {
            let mut i = self.inner.borrow_mut();
            if i.value.len() >= i.cap {
                return;
            }
            i.value.push(c);
        }
        self.refresh();
    }

    fn pop(&self) {
        self.inner.borrow_mut().value.pop();
        self.refresh();
    }

    pub fn clear(&self) {
        {
            let mut i = self.inner.borrow_mut();
            let cap = i.cap;
            i.value.zeroize();
            // Same-length filler then clear keeps the chunk in place (as wipe_text_view).
            i.value = Zeroizing::new(String::with_capacity(cap));
        }
        self.refresh();
    }

    fn refresh(&self) {
        let n = {
            let i = self.inner.borrow();
            // Grouped in fives for checking; the label's copy is a toolkit residual the
            // caller wipes with `clear()` (same-length filler) when done.
            let mut grouped = Zeroizing::new(String::with_capacity(i.value.len() * 6 / 5 + 1));
            for (k, ch) in i.value.chars().enumerate() {
                if k > 0 && k % 5 == 0 {
                    grouped.push(' ');
                }
                grouped.push(ch);
            }
            super::wipe_label(&self.shown);
            self.shown.set_label(&grouped);
            i.value.len()
        };
        self.count
            .set_label(&trf("digitpad.entered", &[("n", &n.to_string())]));
    }

    /// The digits typed so far (a zeroising copy).
    pub fn value(&self) -> Zeroizing<String> {
        self.inner.borrow().value.clone()
    }
}
