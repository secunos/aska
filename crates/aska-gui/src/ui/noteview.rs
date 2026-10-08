//! A read-only note renderer that keeps the note out of the toolkit's text machinery
//! (Client Design C-02, built in 1.1). `gtk::Label` and `gtk::TextView` copy the whole text
//! into their own buffers, a `PangoLayout` of the whole text, the accessibility tree and
//! assorted caches, and free those copies without wiping them. This widget holds the note in a
//! `LockedBuf` (pinned, excluded from dumps, zeroised on `clear`) and draws it **one word at a
//! time**: each word gets a short-lived `PangoLayout` that is overwritten with a same-length
//! filler and re-laid out before it is dropped, so the toolkit never holds the note as one
//! string and the fragments it does touch are overwritten in place. There is nothing to
//! select or copy, and the accessibility tree sees an image, not text.
//!
//! Layout is done here too: words are placed left to right, wrapped at the widget's width,
//! explicit newlines start a new line, and a word wider than the widget is broken by
//! character. Measuring (for the scrolled window) and drawing share one cached word table —
//! positions and pixel widths only, never text.

use adw::prelude::*;
use adw::subclass::prelude::*;
use aska_core::secret::LockedBuf;
use gtk::{glib, graphene, pango};
use std::cell::{Cell, RefCell};

/// A word's byte range in the buffer and its measured pixel width.
#[derive(Clone, Copy, Debug)]
pub struct Word {
    start: usize,
    end: usize,
    width: i32,
    /// True when this word ends a paragraph (an explicit newline follows it).
    hard_break: bool,
}

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct NoteView {
        pub text: RefCell<Option<LockedBuf>>,
        pub words: RefCell<Vec<Word>>,
        /// Pixel height of one line and width of a space, for the current font.
        pub line_height: Cell<i32>,
        pub space_width: Cell<i32>,
        pub measured: Cell<bool>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for NoteView {
        const NAME: &'static str = "AskaNoteView";
        type Type = super::NoteView;
        type ParentType = gtk::Widget;

        fn class_init(klass: &mut Self::Class) {
            klass.set_css_name("label");
            klass.set_accessible_role(gtk::AccessibleRole::Img);
        }
    }

    impl ObjectImpl for NoteView {
        fn constructed(&self) {
            self.parent_constructed();
            let obj = self.obj();
            obj.set_can_focus(false);
            obj.set_focusable(false);
            obj.set_hexpand(true);
        }
    }

    impl WidgetImpl for NoteView {
        fn request_mode(&self) -> gtk::SizeRequestMode {
            gtk::SizeRequestMode::HeightForWidth
        }

        fn measure(&self, orientation: gtk::Orientation, for_size: i32) -> (i32, i32, i32, i32) {
            self.obj().ensure_measured();
            match orientation {
                gtk::Orientation::Horizontal => {
                    // Wraps at any width; prefer the longest word so nothing is clipped.
                    let longest = self
                        .words
                        .borrow()
                        .iter()
                        .map(|w| w.width)
                        .max()
                        .unwrap_or(0);
                    (longest.min(120), longest, -1, -1)
                }
                _ => {
                    let width = if for_size > 0 { for_size } else { 600 };
                    let h = self.obj().layout_lines(width, None);
                    (h, h, -1, -1)
                }
            }
        }

        fn snapshot(&self, snapshot: &gtk::Snapshot) {
            let obj = self.obj();
            obj.ensure_measured();
            let width = obj.width().max(1);
            let colour = obj.color();
            obj.layout_lines(width, Some((snapshot, &colour)));
        }
    }
}

glib::wrapper! {
    pub struct NoteView(ObjectSubclass<imp::NoteView>)
        @extends gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget;
}

impl Default for NoteView {
    fn default() -> Self {
        glib::Object::new()
    }
}

impl NoteView {
    pub fn new() -> Self {
        Self::default()
    }

    /// Show `text` (UTF-8), taking ownership of the locked buffer.
    pub fn set_text(&self, text: LockedBuf) {
        let imp = self.imp();
        if let Some(mut old) = imp.text.replace(Some(text)) {
            old.clear();
        }
        imp.words.borrow_mut().clear();
        imp.measured.set(false);
        self.queue_resize();
    }

    /// Zeroise the note and show nothing. Called when the page burns or is left.
    pub fn clear(&self) {
        let imp = self.imp();
        if let Some(mut old) = imp.text.take() {
            old.clear();
        }
        imp.words.borrow_mut().clear();
        imp.measured.set(false);
        self.queue_resize();
    }

    /// A Pango layout of `s` that is overwritten with a same-length filler, re-laid out and
    /// dropped after `f` has used it — so neither the text nor its glyphs survive in the
    /// toolkit's freed memory as the note's own characters.
    fn with_layout<R>(&self, s: &str, f: impl FnOnce(&pango::Layout) -> R) -> R {
        let layout = self.create_pango_layout(Some(s));
        let r = f(&layout);
        let filler: String = s
            .chars()
            .map(|c| if c.is_whitespace() { ' ' } else { 'x' })
            .collect();
        layout.set_text(&filler);
        let _ = layout.pixel_size(); // forces the glyph caches to be rebuilt for the filler
        r
    }

    /// Build the word table (byte ranges and pixel widths) if it is stale.
    fn ensure_measured(&self) {
        let imp = self.imp();
        if imp.measured.get() {
            return;
        }
        let (lh, sw) = self.with_layout("Xg", |l| {
            let (_, h) = l.pixel_size();
            (h, 0)
        });
        let sw = self.with_layout(" ", |l| l.pixel_size().0).max(sw);
        imp.line_height.set(lh.max(1));
        imp.space_width.set(sw.max(1));
        let mut words = Vec::new();
        if let Some(buf) = imp.text.borrow().as_ref() {
            let text = std::str::from_utf8(buf.as_slice()).unwrap_or("");
            let mut pos = 0;
            for line in text.split('\n') {
                let line_start = pos;
                let mut cursor = line_start;
                let mut first_in_line = true;
                for piece in line.split(' ') {
                    let start = cursor;
                    let end = start + piece.len();
                    cursor = end + 1;
                    if piece.is_empty() {
                        if first_in_line {
                            // A line that starts with a space, or an empty line: keep an
                            // empty word so the paragraph still takes a line.
                            words.push(Word {
                                start,
                                end,
                                width: 0,
                                hard_break: false,
                            });
                        }
                        first_in_line = false;
                        continue;
                    }
                    first_in_line = false;
                    let width = self.with_layout(piece, |l| l.pixel_size().0);
                    words.push(Word {
                        start,
                        end,
                        width,
                        hard_break: false,
                    });
                }
                if let Some(last) = words.last_mut() {
                    if last.start >= line_start {
                        last.hard_break = true;
                    }
                }
                if words.last().is_none_or(|w| w.start < line_start) {
                    words.push(Word {
                        start: line_start,
                        end: line_start,
                        width: 0,
                        hard_break: true,
                    });
                }
                pos += line.len() + 1;
            }
        }
        *imp.words.borrow_mut() = words;
        imp.measured.set(true);
    }

    /// Place the words for `width`; draw them when `draw` is given. Returns the total height.
    fn layout_lines(&self, width: i32, draw: Option<(&gtk::Snapshot, &gtk::gdk::RGBA)>) -> i32 {
        let imp = self.imp();
        let lh = imp.line_height.get();
        let sw = imp.space_width.get();
        let words = imp.words.borrow();
        let text_ref = imp.text.borrow();
        let text = text_ref
            .as_ref()
            .and_then(|b| std::str::from_utf8(b.as_slice()).ok())
            .unwrap_or("");
        let (mut x, mut y) = (0, 0);
        let mut line_has_word = false;
        let draw_piece = |piece: &str, px: i32, py: i32| {
            if let Some((snapshot, colour)) = draw {
                self.with_layout(piece, |l| {
                    snapshot.save();
                    snapshot.translate(&graphene::Point::new(px as f32, py as f32));
                    snapshot.append_layout(l, colour);
                    snapshot.restore();
                });
            }
        };
        for w in words.iter() {
            let piece = text.get(w.start..w.end).unwrap_or("");
            if w.width > width {
                // Wider than the widget: break by character (after the usual space).
                if line_has_word {
                    x += sw;
                }
                for ch in piece.chars() {
                    let mut tmp = [0u8; 4];
                    let s = ch.encode_utf8(&mut tmp);
                    let cw = self.with_layout(s, |l| l.pixel_size().0);
                    if x > 0 && x + cw > width {
                        x = 0;
                        y += lh;
                    }
                    draw_piece(s, x, y);
                    x += cw;
                    line_has_word = true;
                }
            } else if !piece.is_empty() {
                let needed = if line_has_word { sw + w.width } else { w.width };
                if line_has_word && x + needed > width {
                    x = 0;
                    y += lh;
                    line_has_word = false;
                }
                if line_has_word {
                    x += sw;
                }
                draw_piece(piece, x, y);
                x += w.width;
                line_has_word = true;
            }
            if w.hard_break {
                x = 0;
                y += lh;
                line_has_word = false;
            }
        }
        if line_has_word {
            y += lh;
        }
        y.max(lh)
    }
}
