//! A QR code drawn by the app itself from `aska_core::qr::QrMatrix` — dark modules on a white
//! field with a quiet zone, scaled to the widget. No image file is ever created; the matrix
//! (which *is* the key) is zeroised when the widget goes away.

use aska_core::qr::{self, QrMatrix};
use gtk::prelude::*;
use std::rc::Rc;

/// Build a square drawing area showing `text` as a QR code. `size` is the requested side in
/// pixels; the symbol scales to whatever the layout gives it.
pub fn qr_widget(text: &str, size: i32) -> gtk::DrawingArea {
    let area = gtk::DrawingArea::new();
    area.set_content_width(size);
    area.set_content_height(size);
    area.set_halign(gtk::Align::Center);
    area.add_css_class("aska-qr");
    let matrix: Option<Rc<QrMatrix>> = qr::encode(text).ok().map(Rc::new);
    area.set_draw_func(move |_, cr, w, h| {
        cr.set_source_rgb(1.0, 1.0, 1.0);
        cr.rectangle(0.0, 0.0, f64::from(w), f64::from(h));
        let _ = cr.fill();
        let Some(m) = &matrix else { return };
        let n = m.size() as f64 + 2.0 * qr::QUIET as f64;
        let side = f64::from(w.min(h));
        let cell = (side / n).floor().max(1.0);
        let off_x = (f64::from(w) - cell * n) / 2.0;
        let off_y = (f64::from(h) - cell * n) / 2.0;
        cr.set_source_rgb(0.0, 0.0, 0.0);
        let s = m.size() as isize;
        for y in 0..s {
            for x in 0..s {
                if m.dark(x, y) {
                    cr.rectangle(
                        off_x + (x as f64 + qr::QUIET as f64) * cell,
                        off_y + (y as f64 + qr::QUIET as f64) * cell,
                        cell,
                        cell,
                    );
                }
            }
        }
        let _ = cr.fill();
    });
    area
}
