//! The Aska brand (brand kit 1.0, release 1.2.1): the "Nordic calm" palette as libadwaita
//! colour overrides, swapped with the style manager's light/dark state, and the horizontal
//! lockup (the Glow mark and the wordmark) for the Home screen. Everything is embedded in the
//! binary — no file is read at run time, no font is needed (the wordmark is outlines).

use adw::prelude::*;
use gtk::{gdk, glib};

const LIGHT_CSS: &str = include_str!("../../brand/aska.css");
const DARK_CSS: &str = include_str!("../../brand/aska-dark.css");
const LOCKUP_LIGHT: &[u8] = include_bytes!("../../brand/aska-horizontal-short-on-light.png");
const LOCKUP_DARK: &[u8] = include_bytes!("../../brand/aska-horizontal-short-on-dark.png");

/// Height of the lockup on the Home screen, in pixels. Chosen so that the header block keeps
/// the height of the former `title-1` label and the buttons below it do not move (the GUI
/// gates click them by coordinate).
pub const LOCKUP_HEIGHT: i32 = 44;

/// Install the brand palette for the display and keep it in step with light/dark changes.
/// `app_css` is the client's own rule set, loaded after the palette so that it can refer to
/// the palette's colours.
pub fn install(app_css: &'static str) {
    let Some(display) = gdk::Display::default() else {
        return;
    };
    let palette = gtk::CssProvider::new();
    let sm = adw::StyleManager::default();
    palette.load_from_string(if sm.is_dark() { DARK_CSS } else { LIGHT_CSS });
    gtk::style_context_add_provider_for_display(
        &display,
        &palette,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );
    let rules = gtk::CssProvider::new();
    rules.load_from_string(app_css);
    gtk::style_context_add_provider_for_display(
        &display,
        &rules,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION + 1,
    );
    sm.connect_dark_notify(move |sm| {
        palette.load_from_string(if sm.is_dark() { DARK_CSS } else { LIGHT_CSS });
    });
}

fn texture(bytes: &'static [u8]) -> Option<gdk::Texture> {
    gdk::Texture::from_bytes(&glib::Bytes::from_static(bytes)).ok()
}

mod imp {
    use super::*;
    use adw::subclass::prelude::*;
    use std::cell::RefCell;

    /// A widget that draws one of two textures at a **fixed logical height** (the textures are
    /// large and are scaled down by the renderer, so they stay crisp on HiDPI). `gtk::Picture`
    /// was not usable here: its natural size is the texture's pixel size, so in a box with spare
    /// room it grew and pushed the buttons below it — which the GUI gates click by coordinate.
    #[derive(Default)]
    pub struct Lockup {
        pub light: RefCell<Option<gdk::Texture>>,
        pub dark: RefCell<Option<gdk::Texture>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Lockup {
        const NAME: &'static str = "AskaLockup";
        type Type = super::Lockup;
        type ParentType = gtk::Widget;

        fn class_init(klass: &mut Self::Class) {
            klass.set_css_name("picture");
            klass.set_accessible_role(gtk::AccessibleRole::Img);
        }
    }

    impl ObjectImpl for Lockup {
        fn constructed(&self) {
            self.parent_constructed();
            let obj = self.obj();
            obj.set_can_focus(false);
            obj.set_focusable(false);
            obj.set_halign(gtk::Align::Center);
            obj.set_valign(gtk::Align::Center);
        }
    }

    impl WidgetImpl for Lockup {
        fn request_mode(&self) -> gtk::SizeRequestMode {
            gtk::SizeRequestMode::ConstantSize
        }

        fn measure(&self, orientation: gtk::Orientation, _for_size: i32) -> (i32, i32, i32, i32) {
            let h = LOCKUP_HEIGHT;
            let w = self
                .current()
                .map(|t| (t.width() as f64 * h as f64 / t.height().max(1) as f64).round() as i32)
                .unwrap_or(h * 4);
            match orientation {
                gtk::Orientation::Horizontal => (w, w, -1, -1),
                _ => (h, h, -1, -1),
            }
        }

        fn snapshot(&self, snapshot: &gtk::Snapshot) {
            let obj = self.obj();
            if let Some(t) = self.current() {
                t.snapshot(snapshot, obj.width() as f64, obj.height() as f64);
            }
        }
    }

    impl Lockup {
        pub fn current(&self) -> Option<gdk::Texture> {
            if adw::StyleManager::default().is_dark() {
                self.dark.borrow().clone()
            } else {
                self.light.borrow().clone()
            }
        }
    }
}

glib::wrapper! {
    pub struct Lockup(ObjectSubclass<imp::Lockup>)
        @extends gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget;
}

/// The horizontal lockup (mark + wordmark, no slogan), following the light/dark state.
/// Falls back to the plain wordmark label if the images cannot be decoded.
pub fn lockup(fallback_text: &str) -> gtk::Widget {
    let (Some(light), Some(dark)) = (texture(LOCKUP_LIGHT), texture(LOCKUP_DARK)) else {
        return gtk::Label::builder()
            .label(fallback_text)
            .css_classes(["title-1"])
            .build()
            .upcast();
    };
    let w: Lockup = glib::Object::new();
    {
        use adw::subclass::prelude::ObjectSubclassIsExt;
        let imp = w.imp();
        *imp.light.borrow_mut() = Some(light);
        *imp.dark.borrow_mut() = Some(dark);
    }
    w.update_property(&[gtk::accessible::Property::Label(fallback_text)]);
    {
        let w = w.clone();
        adw::StyleManager::default().connect_dark_notify(move |_| {
            w.queue_resize();
            w.queue_draw();
        });
    }
    w.upcast()
}
