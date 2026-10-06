//! `aska-gui` — the Aska graphical client (Client Design §5), GTK4 + libadwaita.
//!
//! A thin layer over `aska-core`: screens, widgets, timers. It holds no secret of its own —
//! every secret lives in the core's `Session`, which is moved (never shared) to worker threads
//! for the slow steps. Nothing is written to disk; there are no notifications, no history and
//! no clipboard for note content; the window title is always "aska".
//!
//! Screens: Home, Send, Hand-over, Receive, View, Settings, Shares (M5a + M5b).
#![deny(unsafe_code)]

mod i18n;
mod state;
mod ui;
mod worker;

use adw::prelude::*;
use gtk::glib;

fn main() -> glib::ExitCode {
    aska_core::platform::disable_core_dumps();
    // The toolkit stack would otherwise write two things to disk that Aska itself never
    // would (found by the strace gate): Mesa's compiled-shader cache under ~/.cache, and
    // dconf's shared-memory file under the runtime directory. Both are switched off here,
    // before GTK initialises and before any other thread exists. Theme and font settings
    // still arrive through the desktop's settings portal / xsettings, not through dconf.
    std::env::set_var("MESA_SHADER_CACHE_DISABLE", "1");
    std::env::set_var("MESA_GLSL_CACHE_DISABLE", "1"); // the same switch on older Mesa
    std::env::set_var("GSETTINGS_BACKEND", "memory");
    i18n::init_from_env();
    // GTK reads `argv`; the client takes no options that could carry a secret.
    let app = adw::Application::builder()
        .application_id("org.aska.Aska")
        .build();
    app.connect_activate(ui::build);
    app.run()
}
