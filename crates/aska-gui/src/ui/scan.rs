//! A reusable camera dialog (1.1's viewfinder, generalised for the paper mode): scans one
//! QR symbol as text (a pad page) or as bytes (a Block card), or keeps scanning for a whole
//! set of byte symbols until the caller says the set is complete. The scanning thread's cancel
//! flag is the dialog's Cancel; preview frames reach the main loop through a channel polled
//! every `PREVIEW_POLL`, newest frame only. Every luma buffer is zeroising; the paintable is
//! dropped when the dialog closes.

use super::Ui;
use crate::i18n::tr;
use adw::prelude::*;
use aska_scan::{Preview, ScanError, ScanOptions};
use gtk::{gdk, glib};
use std::cell::Cell;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;
use zeroize::Zeroizing;

const PREVIEW_SIZE: u32 = 320;
const SCAN_TIMEOUT: Duration = Duration::from_secs(90);
const PREVIEW_POLL: Duration = Duration::from_millis(66);

/// What one scan produced.
pub enum Decoded {
    Text(Zeroizing<String>),
    Bytes(Zeroizing<Vec<u8>>),
}

enum Msg {
    Frame(Preview),
    Done(Result<Decoded, ScanError>),
}

/// How the caller wants to be fed. `Continue` keeps the dialog open and scans the next symbol
/// (card sets); `Stop` closes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    Continue,
    Stop,
}

/// Open the viewfinder. `bytes` selects byte-mode decoding. `on_decoded` is called on the
/// main thread for every symbol; `on_end` once, with `None` for a plain cancel/timeout or
/// `Some(error)` for a camera failure, after the dialog closed.
pub fn scan_dialog(
    ui: &Rc<Ui>,
    title: &str,
    bytes: bool,
    on_decoded: impl Fn(Decoded) -> Next + 'static,
    on_end: impl Fn(Option<ScanError>) + 'static,
) {
    let cancel = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<Msg>();
    let spawn = {
        let cancel = cancel.clone();
        let tx = tx.clone();
        move || {
            let (cancel, tx) = (cancel.clone(), tx.clone());
            let _ = std::thread::Builder::new()
                .stack_size(2 * 1024 * 1024)
                .spawn(move || {
                    let opts = ScanOptions {
                        device: None,
                        timeout: SCAN_TIMEOUT,
                        cancel,
                        preview_size: PREVIEW_SIZE,
                    };
                    let frames = tx.clone();
                    let preview = move |p| {
                        let _ = frames.send(Msg::Frame(p));
                    };
                    let r = if bytes {
                        aska_scan::scan_bytes(&opts, preview).map(Decoded::Bytes)
                    } else {
                        aska_scan::scan(&opts, preview).map(Decoded::Text)
                    };
                    let _ = tx.send(Msg::Done(r));
                });
        }
    };
    spawn();

    let dialog = adw::Dialog::builder()
        .title(title)
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

    let closed = Rc::new(Cell::new(false));
    let ended = Rc::new(Cell::new(false));
    {
        let dialog = dialog.clone();
        cancel_btn.connect_clicked(move |_| {
            dialog.close();
        });
    }
    {
        let (cancel, closed, picture) = (cancel.clone(), closed.clone(), picture.clone());
        dialog.connect_closed(move |_| {
            cancel.store(true, Ordering::Relaxed);
            closed.set(true);
            picture.set_paintable(None::<&gdk::Paintable>);
        });
    }
    dialog.present(ui.window().as_ref());

    let on_decoded = Rc::new(on_decoded);
    let on_end = Rc::new(on_end);
    let status2 = status.clone();
    glib::timeout_add_local(PREVIEW_POLL, move || {
        let mut latest: Option<Preview> = None;
        let mut done: Option<Result<Decoded, ScanError>> = None;
        loop {
            match rx.try_recv() {
                Ok(Msg::Frame(p)) => latest = Some(p),
                Ok(Msg::Done(r)) => {
                    done = Some(r);
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    done = Some(Err(ScanError::Cancelled));
                    break;
                }
            }
        }
        if closed.get() {
            if !ended.replace(true) {
                on_end(None);
            }
            return glib::ControlFlow::Break;
        }
        if let Some(p) = latest {
            let bytes = glib::Bytes::from(&p.luma[..]);
            let tex = gdk::MemoryTexture::new(
                p.width as i32,
                p.height as i32,
                gdk::MemoryFormat::G8,
                &bytes,
                p.width as usize,
            );
            picture.set_paintable(Some(&tex));
        }
        match done {
            None => glib::ControlFlow::Continue,
            Some(Ok(d)) => match on_decoded(d) {
                Next::Continue => {
                    status2.set_label(&tr("scan.next"));
                    spawn();
                    glib::ControlFlow::Continue
                }
                Next::Stop => {
                    ended.set(true);
                    dialog.close();
                    on_end(None);
                    glib::ControlFlow::Break
                }
            },
            Some(Err(e)) => {
                ended.set(true);
                dialog.close();
                on_end(match e {
                    ScanError::Cancelled | ScanError::Timeout => None,
                    e => Some(e),
                });
                glib::ControlFlow::Break
            }
        }
    });
}
