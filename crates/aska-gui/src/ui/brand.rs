//! The Aska brand (brand kit 2.0, release 1.2.2): the Graphite palette as libadwaita colour
//! overrides, swapped with the style manager's light/dark state, and the horizontal lockup —
//! the Fade mark and the name ASKA, nothing else — for the Home screen. Everything is embedded
//! in the binary: no file is read at run time and no font is needed (the name is outlines).
//!
//! Brand kit 1.0 (release 1.2.1: the Glow mark, the Nordic calm palette, a slogan under the
//! lockup) was superseded by the brand guidelines 2.0 on 17 October 2026.

use adw::prelude::*;
use gtk::{gdk, glib};

const LIGHT_CSS: &str = include_str!("../../brand/aska.css");
const DARK_CSS: &str = include_str!("../../brand/aska-dark.css");
/// Black lockup for light grounds, white lockup for dark grounds (the kit has no colour
/// version). Both files share one geometry.
const LOCKUP_LIGHT: &[u8] = include_bytes!("../../brand/aska-horizontal-black.png");
const LOCKUP_DARK: &[u8] = include_bytes!("../../brand/aska-horizontal-white.png");

/// Height of the header block on the Home screen, in pixels: the height of the former title
/// label plus the tagline line that 1.x showed under it, kept so that the buttons below do not
/// move (the GUI gates click them by coordinate). The lockup is drawn centred inside it.
pub const LOCKUP_HEIGHT: i32 = 84;

/// Height at which the lockup is drawn: the guidelines put the mark at 64 px on Home, and the
/// mark spans the lockup's full height.
const MARK_HEIGHT: f64 = 64.0;

/// Aspect ratio (width / height) of the lockup images, from the kit's `viewBox`
/// (`-3 -95.75 483.87 119.1`).
const LOCKUP_ASPECT: f64 = 483.87 / 119.1;

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

    /// A widget that draws one of two textures at a **fixed logical size** (the textures are
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
            let w = (MARK_HEIGHT * LOCKUP_ASPECT).round() as i32;
            match orientation {
                gtk::Orientation::Horizontal => (w, w, -1, -1),
                _ => (h, h, -1, -1),
            }
        }

        fn snapshot(&self, snapshot: &gtk::Snapshot) {
            let obj = self.obj();
            let Some(t) = self.current() else {
                return;
            };
            // The lockup at MARK_HEIGHT, centred in the allocation.
            let h = MARK_HEIGHT.min(obj.height() as f64);
            let w = h * LOCKUP_ASPECT;
            let x = (obj.width() as f64 - w) / 2.0;
            let y = (obj.height() as f64 - h) / 2.0;
            snapshot.save();
            snapshot.translate(&gtk::graphene::Point::new(x as f32, y as f32));
            t.snapshot(snapshot, w, h);
            snapshot.restore();
        }
    }

    impl Lockup {
        pub(super) fn current(&self) -> Option<gdk::Texture> {
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

/// The horizontal lockup (mark + name), following the light/dark state. `name` is the text
/// for assistive technology and for the fallback — a plain label in the place of the image,
/// should it fail to decode.
pub fn lockup(name: &str) -> gtk::Widget {
    let (Some(light), Some(dark)) = (texture(LOCKUP_LIGHT), texture(LOCKUP_DARK)) else {
        return gtk::Label::builder()
            .label(name)
            .css_classes(["title-1"])
            .height_request(LOCKUP_HEIGHT)
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
    w.update_property(&[gtk::accessible::Property::Label(name)]);
    {
        let w = w.clone();
        adw::StyleManager::default().connect_dark_notify(move |_| {
            w.queue_draw();
        });
    }
    w.upcast()
}
