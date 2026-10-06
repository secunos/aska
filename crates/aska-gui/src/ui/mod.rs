//! The window: one `NavigationView` holding the screens of Client Design §5, a toast overlay,
//! and the behaviours common to every screen (§5.7): the title is always "aska", there are
//! no notifications, and an idle Session closes itself and returns to Home.

pub mod handover;
pub mod home;
pub mod keypad;
pub mod qr;
pub mod receive;
pub mod rxkey;
pub mod send;
pub mod settings;
pub mod shares;
pub mod view;

use crate::i18n::tr;
use crate::state::Shared;
use adw::prelude::*;
use gtk::glib;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

const CSS: &str = r#"
.aska-qr { border: 12px solid white; border-radius: 6px; }
.aska-key { min-width: 34px; min-height: 34px; padding: 2px 6px; font-family: monospace; }
.aska-dots { letter-spacing: 2px; }
.aska-card { border-radius: 12px; padding: 12px; }
.aska-card:checked { background: alpha(@accent_bg_color, 0.18); border: 2px solid @accent_bg_color; }
.aska-words { font-family: monospace; font-size: 1.05em; }
.aska-mono { font-family: monospace; }
.aska-note { font-size: 1.1em; padding: 12px; }
.aska-banner-warn { background: alpha(@warning_bg_color, 0.25); border-radius: 8px; padding: 8px 12px; }
.aska-banner-refuse { background: alpha(@error_bg_color, 0.25); border-radius: 8px; padding: 8px 12px; }
.aska-banner-info { background: alpha(@accent_bg_color, 0.12); border-radius: 8px; padding: 8px 12px; }
"#;

/// A callback installed by one screen for another to trigger.
pub type Hook = Rc<RefCell<Option<Rc<dyn Fn()>>>>;

/// Handles the screens share.
#[derive(Clone)]
pub struct Ui {
    pub app: Shared,
    pub nav: adw::NavigationView,
    pub toasts: adw::ToastOverlay,
    /// Home's "run the environment checks again" — installed by Home, used by Settings
    /// after the Tor source changes.
    pub home_recheck: Hook,
}

impl Ui {
    pub fn toast(&self, text: &str) {
        self.toasts.add_toast(adw::Toast::new(text));
    }

    /// The top-level window (for dialogs).
    pub fn window(&self) -> Option<gtk::Window> {
        self.nav.root().and_downcast::<gtk::Window>()
    }

    /// Wrap content in a page with a header bar; the visible title is the page title, but the
    /// window title stays "aska" (§5.7: no title leakage).
    pub fn page(
        &self,
        tag: &str,
        title: &str,
        content: &impl IsA<gtk::Widget>,
    ) -> adw::NavigationPage {
        let tv = adw::ToolbarView::new();
        let header = adw::HeaderBar::new();
        tv.add_top_bar(&header);
        let scroller = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .child(content)
            .vexpand(true)
            .build();
        tv.set_content(Some(&scroller));
        adw::NavigationPage::builder()
            .title(title)
            .tag(tag)
            .child(&tv)
            .build()
    }

    /// Back to Home, closing any Session (the idle lock, "Done", or an error path).
    pub fn go_home(&self, message: Option<&str>) {
        self.app.borrow_mut().close_session();
        self.nav.pop_to_tag("home");
        if let Some(m) = message {
            self.toast(m);
        }
    }

    /// Rebuild every screen in the current language: the stack becomes a fresh Home.
    pub fn rebuild_home(self: &Rc<Self>) {
        self.app.borrow_mut().close_session();
        self.nav.replace(&[home::build(self)]);
    }

    pub fn recheck_home(&self) {
        if let Some(f) = self.home_recheck.borrow().as_ref() {
            f();
        }
    }
}

/// Clear a text buffer that held a secret. GTK frees the old text without zeroising it, so a
/// plain `set_text("")` leaves the bytes in freed heap memory; writing a same-length filler
/// first makes the allocator hand the *same* chunk back (glibc's size-class caches) and
/// overwrite it, then the filler is cleared. Best effort against the C-02 residual until the
/// custom editor/viewer (v1.1) owns its buffers; measured by `scripts/memory-gate-gui.sh`.
pub fn wipe_text_view(tv: &gtk::TextView) {
    let b = tv.buffer();
    // Size from the buffer's own count — extracting the text would make one more unwiped
    // copy of the secret (review finding C-7).
    let n = b.char_count().max(0) as usize;
    b.set_text("");
    if n > 0 {
        b.set_text(&"x".repeat(n));
        b.set_text("");
    }
}

/// The same for a label (GTK keeps the text in the label and in its Pango layout).
pub fn wipe_label(l: &gtk::Label) {
    let n = l.text().len();
    if n > 0 {
        l.set_label(&"x".repeat(n));
    }
    l.set_label("");
}

/// A text view for secret input: no undo history (which would keep every keystroke), copy
/// and cut disabled (paste stays available), as the editor in Send.
pub fn secret_text_view(height: i32, monospace: bool) -> gtk::TextView {
    let tv = gtk::TextView::builder()
        .wrap_mode(gtk::WrapMode::WordChar)
        .top_margin(8)
        .bottom_margin(8)
        .left_margin(10)
        .right_margin(10)
        .height_request(height)
        .accepts_tab(false)
        .monospace(monospace)
        .build();
    tv.buffer().set_enable_undo(false);
    // `copy-clipboard` / `cut-clipboard` are RUN_LAST signals: a handler connected the
    // ordinary way runs *before* GTK's own copy, which would then still put the text on the
    // clipboard (review finding C-4). Stop the emission so the class handler never runs, and
    // clear the clipboard in case something was there.
    let block_clipboard = |tv: &gtk::TextView, name: &str| {
        glib::signal::signal_stop_emission_by_name(tv, name);
        tv.clipboard().set_text("");
    };
    tv.connect_copy_clipboard(move |tv| block_clipboard(tv, "copy-clipboard"));
    tv.connect_cut_clipboard(move |tv| block_clipboard(tv, "cut-clipboard"));
    tv
}

/// Byte length of a text view's content without extracting the text (review finding C-7):
/// UTF-8 length per line via the buffer's own counters.
pub fn text_view_byte_len(tv: &gtk::TextView) -> usize {
    let b = tv.buffer();
    let (mut it, end) = b.bounds();
    let mut n = 0usize;
    while it != end {
        let c = it.char();
        // `char()` yields U+FFFC for embedded objects and '\0' at the end; neither occurs in
        // a plain text editor, and either counts for its UTF-8 length anyway.
        n += c.len_utf8();
        if !it.forward_char() {
            break;
        }
    }
    n
}

/// A section heading in the page's own style.
pub fn heading(text: &str) -> gtk::Label {
    gtk::Label::builder()
        .label(text)
        .xalign(0.0)
        .css_classes(["heading"])
        .build()
}

/// A dim explanatory line under a control.
pub fn hint(text: &str) -> gtk::Label {
    gtk::Label::builder()
        .label(text)
        .wrap(true)
        .xalign(0.0)
        .css_classes(["dim-label", "caption"])
        .build()
}

/// The one big action button of a screen.
pub fn pill(label: &str, suggested: bool) -> gtk::Button {
    let b = gtk::Button::builder()
        .label(label)
        .css_classes(["pill", "title-4"])
        .halign(gtk::Align::Center)
        .height_request(48)
        .width_request(280)
        .build();
    if suggested {
        b.add_css_class("suggested-action");
    }
    b
}

/// A vertical page body inside a clamp.
pub fn body(max_width: i32) -> (gtk::Box, adw::Clamp) {
    let root = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(18)
        .margin_top(12)
        .margin_bottom(24)
        .margin_start(24)
        .margin_end(24)
        .build();
    let clamp = adw::Clamp::builder()
        .maximum_size(max_width)
        .child(&root)
        .build();
    (root, clamp)
}

pub fn build(application: &adw::Application) {
    let provider = gtk::CssProvider::new();
    provider.load_from_string(CSS);
    if let Some(display) = gtk::gdk::Display::default() {
        gtk::style_context_add_provider_for_display(
            &display,
            &provider,
            gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
        );
    }

    let app = crate::state::App::new();
    let nav = adw::NavigationView::new();
    let toasts = adw::ToastOverlay::new();
    toasts.set_child(Some(&nav));
    let window = adw::ApplicationWindow::builder()
        .application(application)
        .title(tr("app.title"))
        .default_width(760)
        .default_height(720)
        .content(&toasts)
        .build();
    let ui = Rc::new(Ui {
        app,
        nav: nav.clone(),
        toasts,
        home_recheck: Rc::new(RefCell::new(None)),
    });

    nav.push(&home::build(&ui));

    // Idle watchdog mirror (§2.3): tick the Session once a second; on expiry, return Home.
    {
        let ui = ui.clone();
        glib::timeout_add_local(Duration::from_secs(1), move || {
            let expired = {
                let mut a = ui.app.borrow_mut();
                match a.session.as_mut() {
                    Some(s) => s.tick().is_err(),
                    None => false,
                }
            };
            if expired {
                ui.go_home(Some(&tr("handover.expired")));
            }
            glib::ControlFlow::Continue
        });
    }

    // Closing the window closes the Session and stops cover traffic first.
    {
        let ui = ui.clone();
        window.connect_close_request(move |_| {
            ui.app.borrow_mut().shutdown();
            glib::Propagation::Proceed
        });
    }
    window.present();
}
