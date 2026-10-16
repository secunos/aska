//! The Aska brand (brand kit 1.0, release 1.2.1): the "Nordic calm" palette as libadwaita
//! colour overrides, swapped with the style manager's light/dark state, and the horizontal
//! lockup (the Glow mark, the wordmark and the slogan "Notes that leave no trace") for the
//! Home screen. Everything is embedded in the binary — no file is read at run time, no font is
//! needed (the wordmark and the slogan are outlines, as the kit requires).

use adw::prelude::*;
use gtk::{gdk, glib};

const LIGHT_CSS: &str = include_str!("../../brand/aska.css");
const DARK_CSS: &str = include_str!("../../brand/aska-dark.css");
const LOCKUP_LIGHT: &[u8] = include_bytes!("../../brand/aska-horizontal-on-light.png");
const LOCKUP_DARK: &[u8] = include_bytes!("../../brand/aska-horizontal-on-dark.png");

/// Height of the lockup on the Home screen, in pixels: the height of the former title label
/// plus the tagline line it also replaces, so that the buttons below do not move (the GUI
/// gates click them by coordinate).
pub const LOCKUP_HEIGHT: i32 = 84;

/// Geometry of a lockup image in the kit's design units (its SVG `viewBox`). The two images
/// draw the mark, the wordmark and the slogan at identical positions and sizes; the on-dark
/// one is 13.33 units larger on the left, top and bottom to make room for the mark's glow.
/// The widget is sized for the *frame* (the on-light geometry) and draws the on-dark image at
/// the same scale, offset by its inset, so that switching the colour scheme changes nothing in
/// the layout — the glow overflows into the margins around the widget.
#[derive(Clone, Copy)]
struct Geometry {
    width: f64,
    height: f64,
    inset_x: f64,
    inset_y: f64,
}

const FRAME: Geometry = Geometry {
    width: 470.7,
    height: 107.3,
    inset_x: 0.0,
    inset_y: 0.0,
};
const GEOMETRY_LIGHT: Geometry = FRAME;
const GEOMETRY_DARK: Geometry = Geometry {
    width: 484.03,
    height: 133.95,
    inset_x: 13.33,
    inset_y: 13.33,
};

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
            // The on-dark image's glow is drawn outside the allocation (see `Geometry`).
            obj.set_overflow(gtk::Overflow::Visible);
        }
    }

    impl WidgetImpl for Lockup {
        fn request_mode(&self) -> gtk::SizeRequestMode {
            gtk::SizeRequestMode::ConstantSize
        }

        fn measure(&self, orientation: gtk::Orientation, _for_size: i32) -> (i32, i32, i32, i32) {
            // The same size in both colour schemes: the frame scaled to LOCKUP_HEIGHT.
            let h = LOCKUP_HEIGHT;
            let w = (FRAME.width * h as f64 / FRAME.height).round() as i32;
            match orientation {
                gtk::Orientation::Horizontal => (w, w, -1, -1),
                _ => (h, h, -1, -1),
            }
        }

        fn snapshot(&self, snapshot: &gtk::Snapshot) {
            let obj = self.obj();
            let Some((t, g)) = self.current() else {
                return;
            };
            // Pixels per design unit, from the allocated height and the frame.
            let s = obj.height() as f64 / FRAME.height;
            snapshot.save();
            snapshot.translate(&gtk::graphene::Point::new(
                (-g.inset_x * s) as f32,
                (-g.inset_y * s) as f32,
            ));
            t.snapshot(snapshot, g.width * s, g.height * s);
            snapshot.restore();
        }
    }

    impl Lockup {
        pub(super) fn current(&self) -> Option<(gdk::Texture, Geometry)> {
            if adw::StyleManager::default().is_dark() {
                self.dark.borrow().clone().map(|t| (t, GEOMETRY_DARK))
            } else {
                self.light.borrow().clone().map(|t| (t, GEOMETRY_LIGHT))
            }
        }
    }
}

glib::wrapper! {
    pub struct Lockup(ObjectSubclass<imp::Lockup>)
        @extends gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget;
}

/// The horizontal lockup (mark + wordmark + slogan), following the light/dark state. `name`
/// and `slogan` are the texts for assistive technology and for the fallback — two plain labels
/// in the place of the images, should they fail to decode.
pub fn lockup(name: &str, slogan: &str) -> gtk::Widget {
    let (Some(light), Some(dark)) = (texture(LOCKUP_LIGHT), texture(LOCKUP_DARK)) else {
        let b = gtk::Box::builder()
            .orientation(gtk::Orientation::Vertical)
            .spacing(18)
            .build();
        b.append(
            &gtk::Label::builder()
                .label(name)
                .css_classes(["title-1"])
                .build(),
        );
        b.append(
            &gtk::Label::builder()
                .label(slogan)
                .css_classes(["dim-label", "title-4"])
                .build(),
        );
        return b.upcast();
    };
    let w: Lockup = glib::Object::new();
    {
        use adw::subclass::prelude::ObjectSubclassIsExt;
        let imp = w.imp();
        *imp.light.borrow_mut() = Some(light);
        *imp.dark.borrow_mut() = Some(dark);
    }
    w.update_property(&[gtk::accessible::Property::Label(&format!(
        "{name} — {slogan}"
    ))]);
    {
        let w = w.clone();
        adw::StyleManager::default().connect_dark_notify(move |_| {
            w.queue_resize();
            w.queue_draw();
        });
    }
    w.upcast()
}
