//! The in-app passphrase keypad (Client Design §6.3): a grid of keys drawn by the client, so
//! input-method frameworks and toolkit-level keyloggers see nothing; the layout is shuffled
//! for every entry (option, default on) against shoulder-surfing. The passphrase lives in a
//! zeroising buffer owned by the field; the screen shows only a dot per character. A physical
//! keyboard is available behind an explicit toggle with a warning.

use aska_core::rng::{OsRng, RandomSource};
use gtk::prelude::*;
use std::cell::RefCell;
use std::rc::Rc;
use zeroize::{Zeroize, Zeroizing};

use crate::i18n::{tr, trf};

const LETTERS: &str = "abcdefghijklmnopqrstuvwxyzåäö";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = ".,-!?";
/// Bytes reserved for a passphrase buffer: 256 characters of up to 4 UTF-8 bytes.
const PASSPHRASE_CAPACITY: usize = 256 * 4;

struct Inner {
    value: Zeroizing<String>,
    shift: bool,
    shuffle: bool,
}

/// One passphrase field. `widget()` is what goes on screen.
#[derive(Clone)]
pub struct PassphraseField {
    root: gtk::Box,
    inner: Rc<RefCell<Inner>>,
    dots: gtk::Label,
    grid: gtk::Grid,
    fallback: gtk::PasswordEntry,
    using_keyboard: Rc<RefCell<bool>>,
}

impl PassphraseField {
    pub fn new(title: &str) -> Self {
        let root = gtk::Box::new(gtk::Orientation::Vertical, 6);
        root.add_css_class("aska-keypad");
        let head = gtk::Label::builder()
            .label(title)
            .xalign(0.0)
            .css_classes(["heading"])
            .build();
        root.append(&head);

        let dots = gtk::Label::builder()
            .label("")
            .xalign(0.0)
            .css_classes(["title-3", "aska-dots"])
            .height_request(28)
            .build();
        root.append(&dots);
        let count = gtk::Label::builder()
            .label(trf("keypad.entered", &[("n", "0")]))
            .xalign(0.0)
            .css_classes(["dim-label", "caption"])
            .build();
        root.append(&count);

        let grid = gtk::Grid::builder()
            .row_spacing(4)
            .column_spacing(4)
            .halign(gtk::Align::Center)
            .build();
        root.append(&grid);

        // Physical keyboard fallback, off by default, with its warning.
        let fallback = gtk::PasswordEntry::builder()
            .show_peek_icon(false)
            .visible(false)
            .placeholder_text(title)
            .build();
        root.append(&fallback);
        let warn = gtk::Label::builder()
            .label(tr("keypad.keyboard_warning"))
            .wrap(true)
            .xalign(0.0)
            .visible(false)
            .css_classes(["warning", "caption"])
            .build();
        root.append(&warn);
        let controls = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        let kb = gtk::CheckButton::with_label(&tr("keypad.show_keyboard"));
        let sh = gtk::CheckButton::with_label(&tr("keypad.shuffle"));
        sh.set_active(true);
        controls.append(&kb);
        controls.append(&sh);
        root.append(&controls);

        let field = PassphraseField {
            root,
            inner: Rc::new(RefCell::new(Inner {
                // Fixed capacity for the 256-character maximum (4 bytes per char), so the
                // buffer never reallocates and leaves prefixes of the passphrase in freed
                // heap chunks (review finding C-6).
                value: Zeroizing::new(String::with_capacity(PASSPHRASE_CAPACITY)),
                shift: false,
                shuffle: true,
            })),
            dots,
            grid,
            fallback,
            using_keyboard: Rc::new(RefCell::new(false)),
        };

        {
            let f = field.clone();
            let count = count.clone();
            let update = move |n: usize| {
                f.dots.set_label(&"●".repeat(n.min(64)));
                count.set_label(&trf("keypad.entered", &[("n", &n.to_string())]));
            };
            let u = update.clone();
            field.fallback.connect_changed(move |e| {
                let t: Zeroizing<String> = Zeroizing::new(e.text().to_string());
                u(t.chars().count());
            });
            let f2 = field.clone();
            let warn2 = warn.clone();
            kb.connect_toggled(move |b| {
                let on = b.is_active();
                *f2.using_keyboard.borrow_mut() = on;
                f2.grid.set_visible(!on);
                f2.fallback.set_visible(on);
                warn2.set_visible(on);
                f2.clear();
                update(0);
            });
            let f3 = field.clone();
            sh.connect_toggled(move |b| {
                f3.inner.borrow_mut().shuffle = b.is_active();
                f3.rebuild_keys();
            });
        }
        field.rebuild_keys();
        field
    }

    pub fn widget(&self) -> &gtk::Box {
        &self.root
    }

    /// The passphrase as typed so far (a zeroising copy).
    pub fn value(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(PASSPHRASE_CAPACITY));
        if *self.using_keyboard.borrow() {
            out.push_str(&self.fallback.text());
        } else {
            out.push_str(&self.inner.borrow().value);
        }
        out
    }

    /// Wipe the buffer and the display (also re-shuffles the keys).
    pub fn clear(&self) {
        {
            let mut i = self.inner.borrow_mut();
            i.value.zeroize();
            i.value.clear();
            i.shift = false;
        }
        self.fallback.set_text("");
        // `refresh` redraws the dots, the "{n} characters entered" count (which `clear` used to
        // leave stale) and the keys.
        self.refresh();
        if !self.inner.borrow().shuffle {
            self.rebuild_keys();
        }
    }

    fn press(&self, ch: char) {
        {
            let mut i = self.inner.borrow_mut();
            let c = if i.shift {
                ch.to_uppercase().next().unwrap_or(ch)
            } else {
                ch
            };
            if i.value.chars().count() < 256 {
                i.value.push(c);
            }
            i.shift = false;
        }
        self.refresh();
    }

    fn refresh(&self) {
        let n = self.inner.borrow().value.chars().count();
        self.dots.set_label(&"●".repeat(n.min(64)));
        // the count label is the sibling after the dots
        if let Some(next) = self.dots.next_sibling() {
            if let Ok(l) = next.downcast::<gtk::Label>() {
                l.set_label(&trf("keypad.entered", &[("n", &n.to_string())]));
            }
        }
        // Re-shuffle after every key so the layout never stays put (§6.3).
        if self.inner.borrow().shuffle {
            self.rebuild_keys();
        }
    }

    fn rebuild_keys(&self) {
        while let Some(c) = self.grid.first_child() {
            self.grid.remove(&c);
        }
        let mut keys: Vec<char> = LETTERS
            .chars()
            .chain(DIGITS.chars())
            .chain(SYMBOLS.chars())
            .collect();
        if self.inner.borrow().shuffle {
            shuffle(&mut keys);
        }
        let cols = 11;
        let shift_on = self.inner.borrow().shift;
        for (i, ch) in keys.iter().enumerate() {
            let label = if shift_on && ch.is_alphabetic() {
                ch.to_uppercase().collect::<String>()
            } else {
                ch.to_string()
            };
            let b = gtk::Button::with_label(&label);
            b.add_css_class("aska-key");
            b.set_can_focus(false);
            let f = self.clone();
            let c = *ch;
            b.connect_clicked(move |_| f.press(c));
            self.grid
                .attach(&b, (i % cols) as i32, (i / cols) as i32, 1, 1);
        }
        let row = (keys.len() / cols + 1) as i32;
        let shift = gtk::ToggleButton::with_label(&tr("keypad.shift"));
        shift.set_active(shift_on);
        shift.set_can_focus(false);
        let f = self.clone();
        shift.connect_toggled(move |b| {
            f.inner.borrow_mut().shift = b.is_active();
            f.rebuild_keys();
        });
        let space = gtk::Button::with_label(&tr("keypad.space"));
        space.set_can_focus(false);
        let f = self.clone();
        space.connect_clicked(move |_| f.press(' '));
        let back = gtk::Button::with_label(&tr("keypad.backspace"));
        back.set_can_focus(false);
        let f = self.clone();
        back.connect_clicked(move |_| {
            f.inner.borrow_mut().value.pop();
            f.refresh();
        });
        let clear = gtk::Button::with_label(&tr("keypad.clear"));
        clear.set_can_focus(false);
        let f = self.clone();
        clear.connect_clicked(move |_| f.clear());
        self.grid.attach(&shift, 0, row, 2, 1);
        self.grid.attach(&space, 2, row, 5, 1);
        self.grid.attach(&back, 7, row, 2, 1);
        self.grid.attach(&clear, 9, row, 2, 1);
    }
}

/// Fisher–Yates with the OS CSPRNG; a failed read leaves the order unshuffled (still valid).
fn shuffle(v: &mut [char]) {
    let Ok(bytes) = OsRng.bytes(v.len() * 2) else {
        return;
    };
    for i in (1..v.len()).rev() {
        let r = u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]) as usize;
        v.swap(i, r % (i + 1));
    }
}
