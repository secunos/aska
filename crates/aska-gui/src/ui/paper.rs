//! The Paper page (DC-04 §8.3, release 1.2): make a pad booklet and use a pad page.
//!
//! A booklet is generated on a worker thread from the chosen source — the camera's sensor
//! noise (PHYSICAL when the budget is met), die rolls on the digit pad or keyboard timing
//! (SEEDED) — and then leaves the process one of two ways: shown row by row in the locked
//! viewer for copying by hand, or printed through the client's own print dialog under the
//! printing rule. A page comes back from the camera or typed; a message is enciphered or
//! deciphered in locked memory; the tags are checked before anything is shown. Nothing of a
//! booklet or a page survives leaving the page: the paper is the record.

use super::digitpad::DigitPad;
use super::noteview::NoteView;
use super::scan::{self, Decoded, Next};
use super::{body, heading, hint, pill, printdlg, Ui};
use crate::i18n::{tr, trf};
use crate::worker;
use adw::prelude::*;
use aska_core::secret::LockedBuf;
use aska_paper::booklet::{self, Booklet, BookletSpec};
use aska_paper::entropy::{self, Label, Seeded};
use aska_paper::page::Page;
use aska_paper::render::{self, RenderOptions};
use aska_paper::{checkerboard, devtag, handtag, pad, print, PaperError};
use gtk::glib;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Instant;
use zeroize::{Zeroize, Zeroizing};

const RENDER_DPI: u32 = 150;

struct State {
    booklet: Option<Booklet>,
    page: Option<Page>,
    /// Inter-key intervals of the typing source (microseconds).
    timings: Vec<u32>,
    last_key: Option<Instant>,
}

impl State {
    fn clear(&mut self) {
        if let Some(mut b) = self.booklet.take() {
            b.clear();
        }
        if let Some(mut p) = self.page.take() {
            p.clear();
        }
        self.timings.zeroize();
        self.timings.clear();
    }
}

#[derive(Clone)]
struct Make {
    source: adw::ComboRow,
    pages: adw::SpinRow,
    digits: adw::ComboRow,
    hand_tag: adw::SwitchRow,
    set_code: adw::EntryRow,
    dice_box: gtk::Box,
    dice: DigitPad,
    typing_box: gtk::Box,
    typing_count: gtk::Label,
    go: gtk::Button,
    progress: gtk::Label,
    result: gtk::Label,
    result_box: gtk::Box,
}

#[derive(Clone)]
struct Use {
    scan: gtk::Button,
    page_label: gtk::Label,
    message: gtk::TextView,
    encipher: gtk::Button,
    cipher: gtk::TextView,
    hand: DigitPad,
    dev: DigitPad,
    decipher: gtk::Button,
    output: NoteView,
    output_frame: gtk::Frame,
    done: gtk::Button,
    error: gtk::Label,
}

pub fn build(ui: &Rc<Ui>) -> adw::NavigationPage {
    let (root, clamp) = body(760);
    let state = Rc::new(RefCell::new(State {
        booklet: None,
        page: None,
        timings: Vec::new(),
        last_key: None,
    }));

    root.append(&hint(&tr("paper.intro")));

    // ---- Facts about printing on this system ----
    let facts = gtk::Label::builder()
        .label(tr("print.checking"))
        .wrap(true)
        .xalign(0.0)
        .css_classes(["dim-label", "caption"])
        .build();
    root.append(&facts);
    {
        let facts = facts.clone();
        worker::run(
            || (print::spool_is_volatile(), print::list_printers()),
            move |(spool, printers)| {
                let spool_line = match spool {
                    Ok(()) => tr("print.spool.volatile"),
                    Err(print::Refusal::SpoolPersistent(why)) => {
                        trf("print.spool.persistent", &[("why", &why)])
                    }
                    Err(e) => e.to_string(),
                };
                let usb = printers
                    .as_ref()
                    .map(|l| l.iter().filter(|p| p.is_usb()).count())
                    .unwrap_or(0);
                facts.set_label(&trf(
                    "paper.facts",
                    &[("spool", &spool_line), ("usb", &usb.to_string())],
                ));
            },
        );
    }

    // ---- Make a pad booklet ----
    root.append(&heading(&tr("paper.make")));
    let make_group = adw::PreferencesGroup::new();
    let sources = [
        tr("paper.source.camera"),
        tr("paper.source.dice"),
        tr("paper.source.typing"),
    ];
    let source_refs: Vec<&str> = sources.iter().map(String::as_str).collect();
    let source = adw::ComboRow::builder()
        .title(tr("paper.source"))
        .model(&gtk::StringList::new(&source_refs))
        .selected(0)
        .build();
    make_group.add(&source);
    let pages = adw::SpinRow::with_range(1.0, 50.0, 1.0);
    pages.set_title(&tr("paper.pages"));
    pages.set_value(10.0);
    make_group.add(&pages);
    let digits = adw::ComboRow::builder()
        .title(tr("paper.digits"))
        .model(&gtk::StringList::new(&["200", "400", "600"]))
        .selected(1)
        .build();
    make_group.add(&digits);
    let hand_tag = adw::SwitchRow::builder()
        .title(tr("paper.hand_tag"))
        .subtitle(tr("paper.hand_tag.hint"))
        .active(true)
        .build();
    make_group.add(&hand_tag);
    let set_code = adw::EntryRow::builder()
        .title(tr("paper.set_code"))
        .input_purpose(gtk::InputPurpose::Digits)
        .build();
    make_group.add(&set_code);
    root.append(&make_group);
    root.append(&hint(&tr("paper.source.hint")));

    let dice_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
    let dice = DigitPad::new(&tr("paper.dice.title"), "123456", 2000);
    dice_box.append(dice.widget());
    dice_box.append(&hint(&tr("paper.dice.hint")));
    dice_box.set_visible(false);
    root.append(&dice_box);

    let typing_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
    typing_box.append(&heading(&tr("paper.typing.title")));
    let typing = gtk::PasswordEntry::builder()
        .show_peek_icon(false)
        .placeholder_text(tr("paper.typing.placeholder"))
        .build();
    typing_box.append(&typing);
    let typing_count = gtk::Label::builder()
        .label(trf("paper.typing.count", &[("n", "0")]))
        .xalign(0.0)
        .css_classes(["dim-label", "caption"])
        .build();
    typing_box.append(&typing_count);
    typing_box.append(&hint(&tr("paper.typing.hint")));
    typing_box.set_visible(false);
    root.append(&typing_box);

    let go = pill(&tr("paper.make.go"), true);
    root.append(&go);
    let progress = gtk::Label::builder()
        .wrap(true)
        .xalign(0.0)
        .css_classes(["dim-label"])
        .build();
    root.append(&progress);

    let result_box = gtk::Box::new(gtk::Orientation::Vertical, 8);
    result_box.set_visible(false);
    let result = gtk::Label::builder()
        .wrap(true)
        .xalign(0.0)
        .css_classes(["aska-banner-info"])
        .build();
    result_box.append(&result);
    let out_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let show = gtk::Button::builder()
        .label(tr("paper.show"))
        .css_classes(["suggested-action"])
        .build();
    let print_btn = gtk::Button::with_label(&tr("paper.print"));
    let forget = gtk::Button::builder()
        .label(tr("paper.forget"))
        .css_classes(["destructive-action"])
        .build();
    out_row.append(&show);
    out_row.append(&print_btn);
    out_row.append(&forget);
    result_box.append(&out_row);
    result_box.append(&hint(&tr("paper.result.hint")));
    root.append(&result_box);

    let make = Make {
        source: source.clone(),
        pages,
        digits,
        hand_tag,
        set_code,
        dice_box: dice_box.clone(),
        dice,
        typing_box: typing_box.clone(),
        typing_count,
        go: go.clone(),
        progress,
        result,
        result_box,
    };
    {
        let m = make.clone();
        source.connect_selected_notify(move |s| {
            m.dice_box.set_visible(s.selected() == 1);
            m.typing_box.set_visible(s.selected() == 2);
        });
    }
    // Keyboard timing: the keys are discarded as they arrive; only the intervals are kept.
    {
        let (state, m) = (state.clone(), make.clone());
        let ctl = gtk::EventControllerKey::new();
        ctl.connect_key_pressed(move |_, _, _, _| {
            let now = Instant::now();
            let mut st = state.borrow_mut();
            if let Some(last) = st.last_key {
                let us = now
                    .duration_since(last)
                    .as_micros()
                    .min(u128::from(u32::MAX)) as u32;
                st.timings.push(us);
            }
            st.last_key = Some(now);
            let n = st.timings.len();
            drop(st);
            m.typing_count
                .set_label(&trf("paper.typing.count", &[("n", &n.to_string())]));
            glib::Propagation::Proceed
        });
        typing.add_controller(ctl);
        let t = typing.clone();
        typing.connect_changed(move |e| {
            if e.text().len() > 8 {
                t.set_text("");
            }
        });
    }
    {
        let (ui, m, state) = (ui.clone(), make.clone(), state.clone());
        go.connect_clicked(move |_| make_booklet(&ui, &m, &state));
    }
    {
        let (ui, state) = (ui.clone(), state.clone());
        show.connect_clicked(move |_| {
            let st = state.borrow();
            if let Some(b) = st.booklet.as_ref() {
                show_rows(&ui, b);
            }
        });
    }
    {
        let (ui, state, m) = (ui.clone(), state.clone(), make.clone());
        print_btn.connect_clicked(move |_| {
            let st = state.borrow();
            let Some(b) = st.booklet.as_ref() else { return };
            let opts = RenderOptions {
                dpi: RENDER_DPI,
                ..RenderOptions::default()
            };
            let mut sheets = Vec::with_capacity(b.pages.len() * 2);
            for _ in 0..2 {
                for p in &b.pages {
                    match render::render_page(p, b.label, &opts) {
                        Ok(r) => sheets.push(r),
                        Err(e) => {
                            m.progress.set_label(&e.to_string());
                            return;
                        }
                    }
                }
            }
            printdlg::open(&ui, printdlg::Material::Pad, sheets, RENDER_DPI);
        });
    }
    {
        let (state, m, ui) = (state.clone(), make.clone(), ui.clone());
        forget.connect_clicked(move |_| {
            if let Some(mut b) = state.borrow_mut().booklet.take() {
                b.clear();
            }
            m.result_box.set_visible(false);
            super::wipe_label(&m.result);
            m.progress.set_label("");
            m.go.set_sensitive(true);
            ui.toast(&tr("paper.forgotten"));
        });
    }

    // ---- Use a pad page ----
    root.append(&heading(&tr("paper.use")));
    let use_box = gtk::Box::new(gtk::Orientation::Vertical, 10);
    let page_row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let scan_btn = gtk::Button::with_label(&tr("paper.page.scan"));
    let typed_btn = gtk::Button::with_label(&tr("paper.page.typed"));
    page_row.append(&scan_btn);
    page_row.append(&typed_btn);
    use_box.append(&page_row);
    let page_label = gtk::Label::builder()
        .label(tr("paper.page.none"))
        .wrap(true)
        .xalign(0.0)
        .css_classes(["dim-label"])
        .build();
    use_box.append(&page_label);

    use_box.append(&heading(&tr("paper.encipher.title")));
    let message = super::secret_text_view(90, false);
    let mframe = gtk::Frame::builder().child(&message).build();
    use_box.append(&mframe);
    use_box.append(&hint(&tr("paper.encipher.hint")));
    let encipher = gtk::Button::builder()
        .label(tr("paper.encipher"))
        .css_classes(["suggested-action"])
        .halign(gtk::Align::Start)
        .build();
    use_box.append(&encipher);

    use_box.append(&heading(&tr("paper.decipher.title")));
    let cipher = super::secret_text_view(70, true);
    let cframe = gtk::Frame::builder().child(&cipher).build();
    use_box.append(&cframe);
    use_box.append(&hint(&tr("paper.decipher.hint")));
    let tags_row = gtk::Box::new(gtk::Orientation::Horizontal, 18);
    let hand = DigitPad::new(&tr("paper.tag.hand"), "0123456789", 4);
    let dev = DigitPad::new(&tr("paper.tag.device"), "0123456789", 19);
    tags_row.append(hand.widget());
    tags_row.append(dev.widget());
    use_box.append(&tags_row);
    let decipher = gtk::Button::builder()
        .label(tr("paper.decipher"))
        .css_classes(["suggested-action"])
        .halign(gtk::Align::Start)
        .build();
    use_box.append(&decipher);

    let output = NoteView::new();
    output.add_css_class("aska-note");
    let output_frame = gtk::Frame::builder().child(&output).visible(false).build();
    use_box.append(&output_frame);
    let done = gtk::Button::builder()
        .label(tr("paper.done"))
        .css_classes(["destructive-action"])
        .halign(gtk::Align::Start)
        .visible(false)
        .build();
    use_box.append(&done);
    let error = gtk::Label::builder()
        .wrap(true)
        .xalign(0.0)
        .css_classes(["error"])
        .build();
    use_box.append(&error);
    use_box.append(&hint(&tr("paper.use.hint")));
    root.append(&use_box);

    let u = Use {
        scan: scan_btn.clone(),
        page_label,
        message,
        encipher: encipher.clone(),
        cipher,
        hand,
        dev,
        decipher: decipher.clone(),
        output,
        output_frame,
        done: done.clone(),
        error,
    };
    {
        let (ui, u, state) = (ui.clone(), u.clone(), state.clone());
        scan_btn.connect_clicked(move |_| scan_page(&ui, &u, &state));
    }
    {
        let (ui, u, state) = (ui.clone(), u.clone(), state.clone());
        typed_btn.connect_clicked(move |_| type_page(&ui, &u, &state));
    }
    {
        let (u, state) = (u.clone(), state.clone());
        encipher.connect_clicked(move |_| do_encipher(&u, &state));
    }
    {
        let (u, state) = (u.clone(), state.clone());
        decipher.connect_clicked(move |_| do_decipher(&u, &state));
    }
    {
        let (u, state, ui) = (u.clone(), state.clone(), ui.clone());
        done.connect_clicked(move |_| {
            finish_page(&u, &state);
            ui.toast(&tr("paper.page.destroy"));
        });
    }

    // Leaving the page wipes everything it held.
    let page = ui.page("paper", &tr("paper.title"), &clamp);
    {
        let (state, u, m) = (state.clone(), u.clone(), make.clone());
        page.connect_hidden(move |_| {
            state.borrow_mut().clear();
            finish_page(&u, &state);
            m.dice.clear();
            super::wipe_label(&m.result);
        });
    }
    page
}

fn paper_msg(e: &PaperError) -> String {
    match e {
        PaperError::Tag => tr("paper.error.tag"),
        PaperError::Checksum => tr("paper.error.checksum"),
        PaperError::Alphabet(c) => trf("paper.error.alphabet", &[("c", &c.to_string())]),
        PaperError::TooLong { need, have } => trf(
            "paper.error.too_long",
            &[("need", &need.to_string()), ("have", &have.to_string())],
        ),
        e => e.to_string(),
    }
}

// ---------------------------------------------------------------------------------------------
// Make

fn make_booklet(ui: &Rc<Ui>, m: &Make, state: &Rc<RefCell<State>>) {
    m.progress.set_label("");
    let set_code = {
        let t = m.set_code.text().trim().to_string();
        if t.is_empty() {
            None
        } else {
            match t.parse::<u16>() {
                Ok(v) if v <= 9999 => Some(v),
                _ => {
                    m.progress.set_label(&tr("paper.error.set_code"));
                    return;
                }
            }
        }
    };
    let spec = BookletSpec {
        set_code,
        pages_per_direction: m.pages.value() as u8,
        pad_len: [200usize, 400, 600][m.digits.selected() as usize],
        hand_tag: m.hand_tag.is_active(),
    };
    if let Err(e) = spec.validate() {
        m.progress.set_label(&paper_msg(&e));
        return;
    }
    // The physical input, prepared on the main thread.
    enum Input {
        Camera,
        Seed(Box<Result<Seeded, PaperError>>),
    }
    let input = match m.source.selected() {
        0 => Input::Camera,
        1 => {
            let v = m.dice.value();
            let rolls: Vec<u8> = v.bytes().map(|b| b - b'0').collect();
            drop(v);
            Input::Seed(Box::new(Seeded::from_dice(&rolls)))
        }
        _ => {
            let st = state.borrow();
            Input::Seed(Box::new(Seeded::from_timings(&st.timings)))
        }
    };
    let seeded = match input {
        Input::Camera => None,
        Input::Seed(r) => match *r {
            Ok(s) => Some(s),
            Err(e) => {
                m.progress.set_label(&paper_msg(&e));
                return;
            }
        },
    };
    m.go.set_sensitive(false);
    m.progress.set_label(&tr(if seeded.is_some() {
        "paper.progress.seeded"
    } else {
        "paper.progress.camera"
    }));
    let (ui2, m2, state2) = (ui.clone(), m.clone(), state.clone());
    worker::run(
        move || match seeded {
            Some(s) => booklet::generate_seeded(spec, s),
            None => {
                let mut cam = entropy::camera::CameraSource::open(None)?;
                booklet::generate_physical(spec, &mut cam, |_| {})
            }
        },
        move |r: Result<Booklet, PaperError>| {
            m2.go.set_sensitive(true);
            match r {
                Ok(b) => {
                    m2.progress.set_label("");
                    let label_text = tr(match b.label {
                        Label::Physical => "paper.label.physical",
                        Label::Seeded => "paper.label.seeded",
                    });
                    m2.result.set_label(&trf(
                        "paper.result",
                        &[
                            ("set", &format!("{:04}", b.set_code)),
                            ("pages", &b.pages.len().to_string()),
                            ("label", &label_text),
                            ("source", &b.source),
                            ("digits", &b.stats.digits.to_string()),
                        ],
                    ));
                    m2.result_box.set_visible(true);
                    m2.dice.clear();
                    {
                        let mut st = state2.borrow_mut();
                        st.timings.zeroize();
                        st.timings.clear();
                        if let Some(mut old) = st.booklet.replace(b) {
                            old.clear();
                        }
                    }
                    m2.go.set_sensitive(false);
                }
                Err(e) => {
                    let msg = match &e {
                        PaperError::Entropy(_) if m2.source.selected() == 0 => {
                            format!("{}\n{}", paper_msg(&e), tr("paper.error.no_camera"))
                        }
                        e => paper_msg(e),
                    };
                    m2.progress.set_label(&msg);
                    let _ = &ui2;
                }
            }
        },
    );
}

/// The hand-copy view (DC-04 §5.5): one row at a time in the locked viewer, no way back once
/// a page is finished; the page's QR on the first screen so a second device can scan it.
fn show_rows(ui: &Rc<Ui>, b: &Booklet) {
    // Row texts for every page, prepared now in locked buffers; the booklet itself stays in
    // the page state and is not referenced by the dialog.
    struct Row {
        head: String,
        text: LockedBuf,
        qr: Option<Zeroizing<String>>,
    }
    let mut rows: Vec<Row> = Vec::new();
    for p in &b.pages {
        let s = p.spec();
        let head = trf(
            "paper.rows.page",
            &[
                ("set", &format!("{:04}", s.set_code)),
                ("dir", &s.direction.letter().to_string()),
                ("no", &format!("{:02}", s.number)),
                ("label", b.label.as_str()),
                ("check", std::str::from_utf8(&p.checksum()).unwrap_or("")),
            ],
        );
        let payload = p.qr_payload();
        rows.push(Row {
            head: head.clone(),
            text: LockedBuf::from_slice(tr("paper.rows.intro").as_bytes()),
            qr: Some(Zeroizing::new(
                String::from_utf8_lossy(payload.as_slice()).into_owned(),
            )),
        });
        let pad_rows = render::page_rows_text(p);
        let n = pad_rows.len();
        for (i, r) in pad_rows.into_iter().enumerate() {
            let mut t = LockedBuf::with_capacity(r.len() + 32);
            t.extend_from_slice(
                trf(
                    "paper.rows.pad",
                    &[("i", &(i + 1).to_string()), ("n", &n.to_string())],
                )
                .as_bytes(),
            );
            t.extend_from_slice(b"\n\n");
            t.extend_from_slice(r.as_slice());
            rows.push(Row {
                head: head.clone(),
                text: t,
                qr: None,
            });
        }
        let krows = p.key_rows();
        let kn = krows.len();
        for (i, (first, row, check)) in krows.iter().enumerate() {
            let mut t = LockedBuf::with_capacity(row.len() * 2 + 48);
            t.extend_from_slice(
                trf(
                    "paper.rows.keys",
                    &[("i", &(i + 1).to_string()), ("n", &kn.to_string())],
                )
                .as_bytes(),
            );
            t.extend_from_slice(b"\n\n");
            if *first == usize::MAX {
                t.extend_from_slice(b"B     ");
            } else {
                t.extend_from_slice(format!("A{first:03}  ").as_bytes());
            }
            for (gi, g) in row.chunks(handtag::KEY_DIGITS).enumerate() {
                if gi > 0 {
                    t.extend_from_slice(b" ");
                }
                t.extend_from_slice(g);
            }
            t.extend_from_slice(format!("  {check}").as_bytes());
            rows.push(Row {
                head: head.clone(),
                text: t,
                qr: None,
            });
        }
        let c = p.canonical();
        let end = c.len();
        let mut t = LockedBuf::with_capacity(96);
        t.extend_from_slice(tr("paper.rows.device").as_bytes());
        t.extend_from_slice(b"\n\nR ");
        t.extend_from_slice(&c[end - 38..end - 19]);
        t.extend_from_slice(b"\nS ");
        t.extend_from_slice(&c[end - 19..]);
        rows.push(Row {
            head,
            text: t,
            qr: None,
        });
    }
    let rows = Rc::new(RefCell::new(rows));
    let index = Rc::new(RefCell::new(0usize));

    let dialog = adw::Dialog::builder()
        .title(tr("paper.rows.title"))
        .content_width(640)
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
    let head = gtk::Label::builder()
        .xalign(0.0)
        .css_classes(["heading"])
        .build();
    content.append(&head);
    let qr_slot = gtk::Box::new(gtk::Orientation::Vertical, 0);
    content.append(&qr_slot);
    let view = NoteView::new();
    view.add_css_class("aska-note");
    content.append(&gtk::Frame::builder().child(&view).build());
    content.append(&hint(&super::view::capture_line()));
    let nav = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(8)
        .halign(gtk::Align::End)
        .build();
    let progress = gtk::Label::builder()
        .css_classes(["dim-label"])
        .hexpand(true)
        .xalign(0.0)
        .build();
    let next = gtk::Button::builder()
        .label(tr("paper.rows.next"))
        .css_classes(["suggested-action"])
        .build();
    let close = gtk::Button::with_label(&tr("common.close"));
    nav.append(&progress);
    nav.append(&close);
    nav.append(&next);
    content.append(&nav);
    tv.set_content(Some(&content));
    dialog.set_child(Some(&tv));

    let show_row = {
        let (rows, index, head, view, progress, qr_slot, next) = (
            rows.clone(),
            index.clone(),
            head.clone(),
            view.clone(),
            progress.clone(),
            qr_slot.clone(),
            next.clone(),
        );
        Rc::new(move || {
            let i = *index.borrow();
            let rs = rows.borrow();
            let Some(r) = rs.get(i) else { return };
            head.set_label(&r.head);
            view.clear();
            view.set_text(LockedBuf::from_slice(r.text.as_slice()));
            while let Some(c) = qr_slot.first_child() {
                qr_slot.remove(&c);
            }
            if let Some(q) = &r.qr {
                qr_slot.append(&super::qr::qr_widget(q, 300));
            }
            progress.set_label(&trf(
                "paper.rows.progress",
                &[("i", &(i + 1).to_string()), ("n", &rs.len().to_string())],
            ));
            next.set_sensitive(i + 1 < rs.len());
        })
    };
    show_row();
    {
        let (index, show_row) = (index.clone(), show_row.clone());
        next.connect_clicked(move |_| {
            *index.borrow_mut() += 1;
            show_row();
        });
    }
    {
        let dialog = dialog.clone();
        close.connect_clicked(move |_| {
            dialog.close();
        });
    }
    {
        let (rows, view, qr_slot) = (rows.clone(), view.clone(), qr_slot.clone());
        dialog.connect_closed(move |_| {
            view.clear();
            while let Some(c) = qr_slot.first_child() {
                qr_slot.remove(&c);
            }
            for r in rows.borrow_mut().iter_mut() {
                r.text.clear();
                if let Some(q) = r.qr.as_mut() {
                    q.zeroize();
                }
            }
            rows.borrow_mut().clear();
        });
    }
    dialog.present(ui.window().as_ref());
}

// ---------------------------------------------------------------------------------------------
// Use a page

fn take_page(u: &Use, state: &Rc<RefCell<State>>, payload: &[u8]) {
    match Page::parse_with_checksum(payload) {
        Ok(p) => {
            let s = p.spec();
            u.page_label.set_label(&trf(
                "paper.page.loaded",
                &[
                    ("set", &format!("{:04}", s.set_code)),
                    ("dir", &s.direction.letter().to_string()),
                    ("no", &format!("{:02}", s.number)),
                    ("n", &s.pad_len.to_string()),
                    (
                        "hand",
                        &tr(if s.hand_tag {
                            "common.yes"
                        } else {
                            "common.no"
                        }),
                    ),
                ],
            ));
            u.error.set_label("");
            let mut st = state.borrow_mut();
            if let Some(mut old) = st.page.replace(p) {
                old.clear();
            }
        }
        Err(e) => u.error.set_label(&paper_msg(&e)),
    }
}

fn scan_page(ui: &Rc<Ui>, u: &Use, state: &Rc<RefCell<State>>) {
    u.error.set_label("");
    let (u2, state2) = (u.clone(), state.clone());
    let u3 = u.clone();
    u.scan.set_sensitive(false);
    scan::scan_dialog(
        ui,
        &tr("paper.page.scan.title"),
        false,
        move |d| {
            if let Decoded::Text(t) = d {
                take_page(&u2, &state2, t.as_bytes());
            }
            Next::Stop
        },
        move |err| {
            u3.scan.set_sensitive(true);
            if let Some(e) = err {
                u3.error.set_label(&e.to_string());
            }
        },
    );
}

/// Type (or paste) the page's digits — the QR payload. A secret text view, wiped afterwards.
fn type_page(ui: &Rc<Ui>, u: &Use, state: &Rc<RefCell<State>>) {
    let dialog = adw::Dialog::builder()
        .title(tr("paper.page.typed.title"))
        .content_width(520)
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
    content.append(&hint(&tr("paper.page.typed.hint")));
    let text = super::secret_text_view(160, true);
    let sw = gtk::ScrolledWindow::builder()
        .child(&text)
        .min_content_height(160)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .build();
    content.append(&gtk::Frame::builder().child(&sw).build());
    let err = gtk::Label::builder()
        .wrap(true)
        .xalign(0.0)
        .css_classes(["error"])
        .build();
    content.append(&err);
    let row = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(8)
        .halign(gtk::Align::End)
        .build();
    let cancel = gtk::Button::with_label(&tr("common.cancel"));
    let ok = gtk::Button::builder()
        .label(tr("paper.page.typed.ok"))
        .css_classes(["suggested-action"])
        .build();
    row.append(&cancel);
    row.append(&ok);
    content.append(&row);
    tv.set_content(Some(&content));
    dialog.set_child(Some(&tv));
    {
        let dialog = dialog.clone();
        cancel.connect_clicked(move |_| {
            dialog.close();
        });
    }
    {
        let (dialog, text, u, state, err) = (
            dialog.clone(),
            text.clone(),
            u.clone(),
            state.clone(),
            err.clone(),
        );
        ok.connect_clicked(move |_| {
            let raw: Zeroizing<String> = {
                let b = text.buffer();
                let (s, e) = b.bounds();
                Zeroizing::new(b.text(&s, &e, false).to_string())
            };
            let mut digits = LockedBuf::with_capacity(raw.len().max(1));
            for ch in raw.chars() {
                if ch.is_ascii_digit() {
                    digits.extend_from_slice(&[ch as u8]);
                } else if !ch.is_whitespace() {
                    err.set_label(&trf("paper.error.not_digit", &[("c", &ch.to_string())]));
                    digits.clear();
                    return;
                }
            }
            drop(raw);
            match Page::parse_with_checksum(digits.as_slice()) {
                Ok(_) => {
                    take_page(&u, &state, digits.as_slice());
                    digits.clear();
                    super::wipe_text_view(&text);
                    dialog.close();
                }
                Err(e) => {
                    digits.clear();
                    err.set_label(&paper_msg(&e));
                }
            }
        });
    }
    {
        let text = text.clone();
        dialog.connect_closed(move |_| super::wipe_text_view(&text));
    }
    dialog.present(ui.window().as_ref());
}

fn do_encipher(u: &Use, state: &Rc<RefCell<State>>) {
    u.error.set_label("");
    let st = state.borrow();
    let Some(page) = st.page.as_ref() else {
        u.error.set_label(&tr("paper.error.no_page"));
        return;
    };
    let text: Zeroizing<String> = {
        let b = u.message.buffer();
        let (s, e) = b.bounds();
        Zeroizing::new(b.text(&s, &e, false).to_string())
    };
    let r: Result<LockedBuf, PaperError> = (|| {
        let mut digits = checkerboard::encode(&text)?;
        if digits.is_empty() {
            return Err(PaperError::Digits("empty"));
        }
        let n = page.spec().pad_len;
        if digits.len() > n {
            return Err(PaperError::TooLong {
                need: digits.len(),
                have: n,
            });
        }
        let padded = pad::pad_with_spaces(digits.as_slice(), n)?;
        digits.clear();
        let cipher = pad::encipher(padded.as_slice(), page.pad())?;
        let ht = page.hand_tag(cipher.as_slice()).ok();
        let dt = page.device_tag(cipher.as_slice())?;
        let mut out = LockedBuf::with_capacity(cipher.len() * 6 / 5 + 96);
        out.extend_from_slice(tr("paper.out.cipher").as_bytes());
        out.extend_from_slice(b"\n");
        for (i, g) in cipher.as_slice().chunks(5).enumerate() {
            if i > 0 {
                out.extend_from_slice(if i % 10 == 0 { b"\n" } else { b" " });
            }
            out.extend_from_slice(g);
        }
        if let Some(t) = ht {
            out.extend_from_slice(b"\n\n");
            out.extend_from_slice(tr("paper.out.hand").as_bytes());
            out.extend_from_slice(format!(" {t:04}").as_bytes());
        }
        out.extend_from_slice(b"\n");
        out.extend_from_slice(tr("paper.out.device").as_bytes());
        out.extend_from_slice(format!(" {dt:019}").as_bytes());
        Ok(out)
    })();
    drop(st);
    match r {
        Ok(out) => {
            super::wipe_text_view(&u.message);
            u.output.clear();
            u.output.set_text(out);
            u.output_frame.set_visible(true);
            u.done.set_visible(true);
            u.encipher.set_sensitive(false);
            u.decipher.set_sensitive(false);
        }
        Err(PaperError::Digits(_)) => u.error.set_label(&tr("paper.error.empty")),
        Err(e) => u.error.set_label(&paper_msg(&e)),
    }
}

fn do_decipher(u: &Use, state: &Rc<RefCell<State>>) {
    u.error.set_label("");
    let st = state.borrow();
    let Some(page) = st.page.as_ref() else {
        u.error.set_label(&tr("paper.error.no_page"));
        return;
    };
    let raw: Zeroizing<String> = {
        let b = u.cipher.buffer();
        let (s, e) = b.bounds();
        Zeroizing::new(b.text(&s, &e, false).to_string())
    };
    let mut cipher = LockedBuf::with_capacity(raw.len().max(1));
    for ch in raw.chars() {
        if ch.is_ascii_digit() {
            cipher.extend_from_slice(&[ch as u8]);
        } else if !ch.is_whitespace() {
            u.error
                .set_label(&trf("paper.error.not_digit", &[("c", &ch.to_string())]));
            return;
        }
    }
    drop(raw);
    if cipher.is_empty() {
        u.error.set_label(&tr("paper.error.no_cipher"));
        return;
    }
    let hand = u.hand.value();
    let dev = u.dev.value();
    let r: Result<(LockedBuf, bool), PaperError> = (|| {
        let mut checked = false;
        if !dev.is_empty() {
            let (r, s) = page.device_keys();
            devtag::verify(cipher.as_slice(), r, s, dev.as_bytes())?;
            checked = true;
        }
        if !hand.is_empty() {
            if let Some(keys) = page.hand_keys() {
                handtag::verify(cipher.as_slice(), &keys, hand.as_bytes())?;
                checked = true;
            }
        }
        let digits = pad::decipher(cipher.as_slice(), page.pad())?;
        let mut text = checkerboard::from_digits(digits.as_slice())?;
        let mut len = text.len();
        while len > 0 && text.as_slice()[len - 1] == b' ' {
            len -= 1;
        }
        text.truncate(len);
        Ok((text, checked))
    })();
    drop(st);
    cipher.clear();
    match r {
        Ok((text, checked)) => {
            super::wipe_text_view(&u.cipher);
            u.hand.clear();
            u.dev.clear();
            let mut out = LockedBuf::with_capacity(text.len() + 96);
            if !checked {
                out.extend_from_slice(tr("paper.out.unchecked").as_bytes());
                out.extend_from_slice(b"\n\n");
            }
            out.extend_from_slice(text.as_slice());
            u.output.clear();
            u.output.set_text(out);
            u.output_frame.set_visible(true);
            u.done.set_visible(true);
            u.encipher.set_sensitive(false);
            u.decipher.set_sensitive(false);
        }
        Err(e) => u.error.set_label(&paper_msg(&e)),
    }
}

/// Wipe the page and everything shown; the paper is to be destroyed now.
fn finish_page(u: &Use, state: &Rc<RefCell<State>>) {
    if let Some(mut p) = state.borrow_mut().page.take() {
        p.clear();
    }
    u.output.clear();
    u.output_frame.set_visible(false);
    u.done.set_visible(false);
    super::wipe_text_view(&u.message);
    super::wipe_text_view(&u.cipher);
    u.hand.clear();
    u.dev.clear();
    u.page_label.set_label(&tr("paper.page.none"));
    u.encipher.set_sensitive(true);
    u.decipher.set_sensitive(true);
    u.error.set_label("");
}
