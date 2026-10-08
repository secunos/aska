//! Screen 6 — Settings (Client Design §5.6): the environment checks with their explanations,
//! relays for this run with a reachability check (one INFO call per relay over Tor), the Tor
//! source (system Tor, or Tor Browser's Tor — D-16), cover-traffic level, the two timers
//! (C-05), the language (C-06), the **Verify this app** panel, and the optional encrypted
//! profile (C-07: create, open, forget) — the only thing this client ever writes to disk, and
//! only to a file the user names.

use super::keypad::PassphraseField;
use super::{body, heading, hint, Ui};
use crate::i18n::{self, tr, trf};
use crate::state::{ProfileInfo, TorSource};
use crate::worker;
use adw::prelude::*;
use aska_core::cancel::CancelToken;
use aska_core::cover::CoverLevel;
use aska_core::doctor::Severity;
use aska_core::drop::{DropClient, Relay, Secret32};
use aska_core::profile::{open_profile, seal_profile, Profile, MAX_SEEDS, PROFILE_LEN};
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Duration;
use zeroize::Zeroizing;

pub fn build(ui: &Rc<Ui>) -> adw::NavigationPage {
    let (root, clamp) = body(720);

    doctor_section(ui, &root);
    relay_section(ui, &root);
    tor_section(ui, &root);
    cover_section(ui, &root);
    timer_section(ui, &root);
    language_section(ui, &root);
    verify_section(&root);
    profile_section(ui, &root);

    ui.page("settings", &tr("settings.title"), &clamp)
}

fn group(title: &str) -> adw::PreferencesGroup {
    adw::PreferencesGroup::builder().title(title).build()
}

// ------------------------------------------------------------------ checks

fn doctor_section(ui: &Rc<Ui>, root: &gtk::Box) {
    let b = gtk::Box::new(gtk::Orientation::Vertical, 8);
    b.append(&heading(&tr("settings.checks")));
    let a = ui.app.borrow();
    if a.findings.is_empty() {
        b.append(&hint(&tr("settings.checks.none")));
    }
    for f in &a.findings {
        let row = gtk::Box::new(gtk::Orientation::Vertical, 2);
        row.add_css_class(match f.severity {
            Severity::Refuse => "aska-banner-refuse",
            Severity::Warn => "aska-banner-warn",
            Severity::Info => "aska-banner-info",
        });
        row.append(
            &gtk::Label::builder()
                .label(&f.message)
                .wrap(true)
                .xalign(0.0)
                .build(),
        );
        row.append(&hint(&tr(match f.severity {
            Severity::Refuse => "settings.checks.refuse",
            Severity::Warn => "settings.checks.warn",
            Severity::Info => "settings.checks.info",
        })));
        b.append(&row);
    }
    drop(a);
    let again = gtk::Button::with_label(&tr("home.doctor.recheck"));
    again.set_halign(gtk::Align::Start);
    {
        let ui = ui.clone();
        again.connect_clicked(move |_| {
            ui.recheck_home();
            ui.toast(&tr("settings.checks.rerun"));
        });
    }
    b.append(&again);
    root.append(&b);
}

// ------------------------------------------------------------------ relays

fn parse_relays(text: &str) -> Result<Vec<Relay>, String> {
    let mut out: Vec<Relay> = Vec::new();
    for tok in text
        .split([' ', ',', ';', '\n'])
        .filter(|t| !t.trim().is_empty())
    {
        let r = Relay::from_onion(tok.trim())
            .map_err(|_| trf("send.relays.bad", &[("addr", tok.trim())]))?;
        if !out.iter().any(|x| x.pubkey == r.pubkey) {
            out.push(r);
        }
    }
    Ok(out)
}

fn relay_section(ui: &Rc<Ui>, root: &gtk::Box) {
    let b = gtk::Box::new(gtk::Orientation::Vertical, 8);
    let g = group(&tr("settings.relays"));
    let entry = adw::EntryRow::builder()
        .title(tr("send.relays"))
        .text(
            ui.app
                .borrow()
                .relays
                .iter()
                .map(|r| r.onion())
                .collect::<Vec<_>>()
                .join(" "),
        )
        .build();
    g.add(&entry);
    b.append(&g);
    b.append(&hint(&tr("settings.relays.hint")));
    let circle = ui.app.borrow().relays.iter().any(|r| r.auth_key.is_some());
    let indicator = hint(&tr(if circle {
        "settings.relays.circle_key"
    } else {
        "settings.relays.no_circle_key"
    }));
    b.append(&indicator);
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let apply = gtk::Button::with_label(&tr("settings.relays.apply"));
    let check = gtk::Button::with_label(&tr("settings.relays.check"));
    row.append(&apply);
    row.append(&check);
    b.append(&row);
    let results = gtk::Label::builder()
        .wrap(true)
        .xalign(0.0)
        .css_classes(["aska-mono", "caption"])
        .selectable(true) // relay addresses are copyable (§5.7)
        .build();
    b.append(&results);
    root.append(&b);

    {
        let (ui2, entry2, results2) = (ui.clone(), entry.clone(), results.clone());
        apply.connect_clicked(move |_| match parse_relays(&entry2.text()) {
            Ok(r) => {
                let n = r.len();
                // Keep a circle key already loaded from a profile for relays that stay.
                let a_relays = ui2.app.borrow().relays.clone();
                let merged: Vec<Relay> = r
                    .into_iter()
                    .map(|mut x| {
                        if let Some(old) = a_relays.iter().find(|o| o.pubkey == x.pubkey) {
                            x.auth_key = old.auth_key.clone();
                        }
                        x
                    })
                    .collect();
                ui2.app.borrow_mut().set_relays(merged);
                results2.set_label(&trf("settings.relays.applied", &[("n", &n.to_string())]));
            }
            Err(e) => results2.set_label(&e),
        });
    }
    {
        let (ui2, entry2, results2, check2) =
            (ui.clone(), entry.clone(), results.clone(), check.clone());
        check.connect_clicked(move |_| {
            let relays = match parse_relays(&entry2.text()) {
                Ok(r) if !r.is_empty() => r,
                Ok(_) => return results2.set_label(&tr("send.relays.none")),
                Err(e) => return results2.set_label(&e),
            };
            if ui2.app.borrow().network_refused() {
                return results2.set_label(&tr("send.error.refused"));
            }
            check2.set_sensitive(false);
            results2.set_label(&tr("settings.relays.checking"));
            let connector = ui2.app.borrow().connector();
            let results3 = results2.clone();
            let check3 = check2.clone();
            let ui3 = ui2.clone();
            worker::run(
                move || {
                    let client = DropClient::new(connector.as_ref(), CancelToken::new());
                    let mut any_ok = false;
                    let mut all_blocked = !relays.is_empty();
                    let text = relays
                        .iter()
                        .map(|r| {
                            let line = match client.info(r) {
                                Ok(i) => {
                                    any_ok = true;
                                    all_blocked = false;
                                    let classes: Vec<String> = (1..=3u8)
                                        .filter(|c| i.serves(*c))
                                        .map(|c| c.to_string())
                                        .collect();
                                    trf(
                                        "settings.relays.reachable",
                                        &[
                                            ("classes", &classes.join(",")),
                                            ("ttl", &i.max_ttl_hours.to_string()),
                                            ("pow", &i.pow_base_difficulty.to_string()),
                                        ],
                                    )
                                }
                                Err(e) => {
                                    if !super::send::drop_error_looks_blocked(&e) {
                                        all_blocked = false;
                                    }
                                    trf("settings.relays.unreachable", &[("err", &e.to_string())])
                                }
                            };
                            format!("{}\n    {line}", r.onion())
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    (text, any_ok, all_blocked)
                },
                move |(text, any_ok, all_blocked): (String, bool, bool)| {
                    check3.set_sensitive(true);
                    results3.set_label(&text);
                    // D-16: a check that failed everywhere the way a blocked network fails
                    // raises the Home banner; a reachable relay clears it.
                    if all_blocked {
                        ui3.app.borrow_mut().note_blocked_network();
                        ui3.recheck_home();
                    } else if any_ok {
                        ui3.app.borrow_mut().note_network_ok();
                    }
                },
            );
        });
    }
}

// ------------------------------------------------------------------ tor

fn tor_section(ui: &Rc<Ui>, root: &gtk::Box) {
    let b = gtk::Box::new(gtk::Orientation::Vertical, 8);
    let g = group(&tr("settings.tor"));
    let row = adw::ComboRow::builder()
        .title(tr("settings.tor.source"))
        .model(&gtk::StringList::new(&[
            &tr("settings.tor.system"),
            &tr("settings.tor.browser"),
        ]))
        .selected(match ui.app.borrow().tor_source {
            TorSource::System => 0,
            TorSource::TorBrowser => 1,
        })
        .build();
    g.add(&row);
    b.append(&g);
    b.append(&hint(&tr("settings.tor.hint")));
    root.append(&b);
    {
        let ui = ui.clone();
        row.connect_selected_notify(move |r| {
            let src = if r.selected() == 1 {
                TorSource::TorBrowser
            } else {
                TorSource::System
            };
            let changed = {
                let mut a = ui.app.borrow_mut();
                let c = a.tor_source != src;
                a.set_tor_source(src);
                c
            };
            if changed {
                ui.recheck_home();
                ui.app.borrow_mut().restart_cover();
            }
        });
    }
}

// ------------------------------------------------------------------ cover

fn cover_section(ui: &Rc<Ui>, root: &gtk::Box) {
    let b = gtk::Box::new(gtk::Orientation::Vertical, 8);
    let g = group(&tr("settings.cover"));
    let row = adw::ComboRow::builder()
        .title(tr("settings.cover.level"))
        .model(&gtk::StringList::new(&[
            &tr("settings.cover.off"),
            &tr("settings.cover.modest"),
            &tr("settings.cover.high"),
        ]))
        .selected(match ui.app.borrow().cover_level {
            CoverLevel::Off => 0,
            CoverLevel::Modest => 1,
            CoverLevel::High => 2,
        })
        .build();
    g.add(&row);
    b.append(&g);
    let status = hint("");
    let set_status = {
        let ui = ui.clone();
        let status = status.clone();
        Rc::new(move || {
            let a = ui.app.borrow();
            status.set_label(&if a.cover_running() {
                trf(
                    "settings.cover.running",
                    &[("n", &a.relays.len().to_string())],
                )
            } else {
                tr("settings.cover.idle")
            });
        })
    };
    set_status();
    b.append(&status);
    b.append(&hint(&tr("settings.cover.hint")));
    root.append(&b);
    // The scheduler starts and stops as relays and Tor come and go: keep the line current
    // while this page is alive.
    {
        let (status, set_status) = (status.clone(), set_status.clone());
        gtk::glib::timeout_add_local(Duration::from_secs(2), move || {
            if status.root().is_none() {
                return gtk::glib::ControlFlow::Break;
            }
            set_status();
            gtk::glib::ControlFlow::Continue
        });
    }
    {
        let ui = ui.clone();
        row.connect_selected_notify(move |r| {
            let level = match r.selected() {
                0 => CoverLevel::Off,
                2 => CoverLevel::High,
                _ => CoverLevel::Modest,
            };
            ui.app.borrow_mut().set_cover_level(level);
            set_status();
        });
    }
}

// ------------------------------------------------------------------ timers

fn timer_section(ui: &Rc<Ui>, root: &gtk::Box) {
    let g = group(&tr("settings.timers"));
    let idle = adw::SpinRow::with_range(1.0, 60.0, 1.0);
    idle.set_title(&tr("settings.timers.idle"));
    idle.set_subtitle(&tr("settings.timers.idle.sub"));
    idle.set_value((ui.app.borrow().idle_timeout.as_secs() / 60) as f64);
    let view = adw::SpinRow::with_range(1.0, 60.0, 1.0);
    view.set_title(&tr("settings.timers.view"));
    view.set_subtitle(&tr("settings.timers.view.sub"));
    view.set_value((ui.app.borrow().view_timeout.as_secs() / 60) as f64);
    g.add(&idle);
    g.add(&view);
    root.append(&g);
    {
        let ui = ui.clone();
        idle.connect_value_notify(move |r| {
            ui.app.borrow_mut().idle_timeout = Duration::from_secs(r.value() as u64 * 60);
        });
    }
    {
        let ui = ui.clone();
        view.connect_value_notify(move |r| {
            ui.app.borrow_mut().view_timeout = Duration::from_secs(r.value() as u64 * 60);
        });
    }
}

// ------------------------------------------------------------------ language

fn language_section(ui: &Rc<Ui>, root: &gtk::Box) {
    let g = group(&tr("settings.language"));
    let names: Vec<&str> = i18n::LANGUAGES.iter().map(|(_, n, _)| *n).collect();
    let current = i18n::LANGUAGES
        .iter()
        .position(|(c, _, _)| *c == i18n::language())
        .unwrap_or(0) as u32;
    let row = adw::ComboRow::builder()
        .title(tr("settings.language.choose"))
        .subtitle(tr("settings.language.sub"))
        .model(&gtk::StringList::new(&names))
        .selected(current)
        .build();
    g.add(&row);
    root.append(&g);
    {
        let ui = ui.clone();
        row.connect_selected_notify(move |r| {
            let Some((code, _, _)) = i18n::LANGUAGES.get(r.selected() as usize) else {
                return;
            };
            if *code == i18n::language() {
                return;
            }
            i18n::set_language(code);
            // Every screen is built from strings at construction: rebuild the stack in the
            // new language and come back here.
            let ui2 = ui.clone();
            gtk::glib::idle_add_local_once(move || {
                ui2.rebuild_home();
                ui2.nav.push(&build(&ui2));
            });
        });
    }
}

// ------------------------------------------------------------------ verify

fn verify_section(root: &gtk::Box) {
    use aska_core::fingerprint::{self, Signature};
    let b = gtk::Box::new(gtk::Orientation::Vertical, 6);
    b.append(&heading(&tr("settings.verify")));
    let fp = fingerprint::check();
    let mono = |text: &str| {
        gtk::Label::builder()
            .label(text)
            .wrap(true)
            .wrap_mode(gtk::pango::WrapMode::WordChar)
            .xalign(0.0)
            .selectable(true) // the fingerprint is copyable by design (§5.7)
            .css_classes(["aska-mono", "caption"])
            .build()
    };
    b.append(&hint(&tr("settings.verify.own")));
    b.append(&mono(
        fp.own_sha256
            .as_deref()
            .unwrap_or(&tr("settings.verify.unreadable")),
    ));
    b.append(&hint(&tr("settings.verify.release")));
    let release = match (
        &fp.release_tag,
        fingerprint::RELEASE_PUBKEY.and_then(fingerprint::key_id_of),
    ) {
        (Some(tag), Some(id)) => format!("{tag} — {} {id}", tr("settings.verify.key_id")),
        (Some(tag), None) => tag.clone(),
        _ => tr("settings.verify.dev_build"),
    };
    b.append(&mono(&release));
    b.append(&hint(&tr("settings.verify.rekor")));
    b.append(&mono(
        fp.rekor_entry
            .as_deref()
            .unwrap_or(&tr("settings.verify.not_recorded")),
    ));
    let (key, error) = match &fp.signature {
        Signature::NoKey => ("settings.verify.unverifiable", false),
        Signature::NotFound { .. } => ("settings.verify.not_found", false),
        Signature::Invalid { .. } => ("settings.verify.mismatch", true),
        Signature::Valid {
            lists_this_binary: true,
            ..
        } => ("settings.verify.match", false),
        Signature::Valid {
            lists_this_binary: false,
            ..
        } => ("settings.verify.not_listed", true),
    };
    let status = gtk::Label::builder()
        .label(tr(key))
        .wrap(true)
        .xalign(0.0)
        .build();
    if error {
        status.add_css_class("error");
    }
    b.append(&status);
    b.append(&hint(&tr("settings.verify.how")));
    root.append(&b);
}

// ------------------------------------------------------------------ profile

fn create_new(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Overwrite with random bytes, then remove (the CLI's `profile forget`).
fn shred(path: &Path) -> std::io::Result<()> {
    use aska_core::rng::{OsRng, RandomSource};
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    // Only a regular file that is not a symlink, and only of a profile's size: never follow a
    // link planted at the typed path, never overwrite a device (review finding C-14).
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() || meta.len() as usize != PROFILE_LEN {
        return Err(std::io::Error::other("not a profile file"));
    }
    let len = meta.len() as usize;
    let noise = OsRng
        .bytes(len)
        .map_err(|_| std::io::Error::other("randomness unavailable"))?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(&noise)?;
    f.sync_all()?;
    drop(f);
    std::fs::remove_file(path)
}

/// A profile path must name a regular file (not a symlink, device or FIFO) of exactly the
/// profile size (review finding C-14: `read` of a device path would never return).
fn check_profile_path(path: &Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.file_type().is_file() || meta.len() as usize != PROFILE_LEN {
        return Err(tr("settings.profile.wrong"));
    }
    Ok(())
}

/// Read a profile file after `check_profile_path`, without following a symlink.
fn read_profile(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    check_profile_path(path)?;
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let mut buf = Zeroizing::new(Vec::with_capacity(PROFILE_LEN + 1));
    f.read_to_end(&mut buf)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if buf.len() != PROFILE_LEN {
        return Err(tr("settings.profile.wrong"));
    }
    Ok(buf)
}

/// Overwrite a profile in place with a new sealed image of the same size — no new file, no
/// rename: the same blocks are rewritten, and both images are random-looking Blocks under
/// the same passphrase (the CLI's `files::rewrite_profile`). Checks the path like
/// `read_profile`.
fn rewrite_profile(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    check_profile_path(path)?;
    if bytes.len() != PROFILE_LEN {
        return Err(tr("settings.profile.wrong"));
    }
    let io = |e: std::io::Error| format!("{}: {e}", path.display());
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(io)?;
    f.write_all(bytes).map_err(io)?;
    f.sync_all().map_err(io)
}

/// Change the open profile (RM-09: a receiving seed stored or removed): ask for its
/// passphrase in a dialog holding the in-app keypad, then on a worker read the file, open it,
/// apply `op`, seal it again and overwrite it **in place**; finally the run's copy of the
/// seeds is replaced by what the file now holds and `on_done` hears the outcome. `op`'s error
/// text is shown as is; a wrong passphrase, a damaged file and I/O failures get their own.
pub fn edit_profile<F, D>(ui: &Rc<Ui>, heading: &str, body: &str, op: F, on_done: D)
where
    F: FnOnce(&mut Profile) -> Result<(), String> + Send + 'static,
    D: FnOnce(Result<(), String>) + 'static,
{
    let Some(path) = ui.app.borrow().profile_path.clone() else {
        return on_done(Err(tr("settings.profile.not_open")));
    };
    // A plain dialog rather than an alert: the keypad is wider than an alert's message area.
    let dialog = adw::Dialog::builder()
        .title(heading)
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
    content.append(
        &gtk::Label::builder()
            .label(body)
            .wrap(true)
            .xalign(0.0)
            .build(),
    );
    let pass = PassphraseField::new(&tr("settings.profile.passphrase"));
    content.append(pass.widget());
    let row = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(8)
        .halign(gtk::Align::End)
        .build();
    let cancel = gtk::Button::with_label(&tr("common.cancel"));
    let ok = gtk::Button::builder()
        .label(tr("settings.profile.unlock"))
        .css_classes(["suggested-action"])
        .build();
    row.append(&cancel);
    row.append(&ok);
    content.append(&row);
    tv.set_content(Some(&content));
    dialog.set_child(Some(&tv));

    let pending: Rc<RefCell<Option<(F, D)>>> = Rc::new(RefCell::new(Some((op, on_done))));
    {
        let dialog = dialog.clone();
        cancel.connect_clicked(move |_| {
            dialog.close();
        });
    }
    {
        let pass = pass.clone();
        dialog.connect_closed(move |_| pass.clear());
    }
    {
        let (ui, dialog, pass) = (ui.clone(), dialog.clone(), pass.clone());
        ok.connect_clicked(move |_| {
            let Some((op, on_done)) = pending.borrow_mut().take() else {
                return;
            };
            let pw = pass.value();
            pass.clear();
            dialog.close();
            if pw.trim().is_empty() {
                return on_done(Err(tr("send.error.passphrase_empty")));
            }
            let path = path.clone();
            let ui2 = ui.clone();
            worker::run(
                move || -> Result<Vec<Secret32>, String> {
                    let bytes = read_profile(&path)?;
                    let mut p =
                        open_profile(&bytes, &pw).map_err(|_| tr("settings.profile.wrong"))?;
                    drop(bytes);
                    op(&mut p)?;
                    let sealed = seal_profile(&p, &pw).map_err(|e| e.to_string())?;
                    drop(pw);
                    rewrite_profile(&path, &sealed)?;
                    Ok(std::mem::take(&mut p.seeds))
                },
                move |r| match r {
                    Ok(seeds) => {
                        ui2.app.borrow_mut().set_profile_seeds(seeds);
                        on_done(Ok(()));
                    }
                    Err(e) => on_done(Err(e)),
                },
            );
        });
    }
    dialog.present(ui.window().as_ref());
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

/// Expand a leading `~`; relative paths are taken from the home directory, never from the
/// process's working directory (which could be anywhere).
fn resolve_path(text: &str) -> Option<PathBuf> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    Some(if let Some(rest) = t.strip_prefix("~/") {
        home?.join(rest)
    } else if t.starts_with('/') {
        PathBuf::from(t)
    } else {
        home?.join(t)
    })
}

/// No toolkit file chooser here, on purpose: GTK's dialog records every file it saves or
/// opens in `~/.local/share/recently-used.xbel` (seen under strace; `gtk-recent-files-enabled
/// = false` still leaves an empty file behind), and on Flatpak the portal keeps a copy in the
/// document store. A typed path keeps "the only thing written is the file you named" true.
fn profile_section(ui: &Rc<Ui>, root: &gtk::Box) {
    let b = gtk::Box::new(gtk::Orientation::Vertical, 8);
    b.append(&heading(&tr("settings.profile")));
    b.append(&hint(&tr("settings.profile.hint")));
    let status = gtk::Label::builder().wrap(true).xalign(0.0).build();
    let refresh_status = {
        let ui = ui.clone();
        let status = status.clone();
        Rc::new(move || {
            let a = ui.app.borrow();
            status.set_label(&match &a.profile {
                Some(p) => format!(
                    "{}\n{}",
                    trf(
                        "settings.profile.open_status",
                        &[
                            ("name", &p.name),
                            ("n", &p.relays.to_string()),
                            (
                                "key",
                                &tr(if p.circle_key {
                                    "settings.profile.key_yes"
                                } else {
                                    "settings.profile.key_no"
                                }),
                            ),
                        ],
                    ),
                    trf(
                        "settings.profile.keys_status",
                        &[("n", &p.seeds.to_string()), ("max", &MAX_SEEDS.to_string())],
                    )
                ),
                None => tr("settings.profile.none"),
            });
        })
    };
    refresh_status();
    b.append(&status);
    let g = adw::PreferencesGroup::new();
    let path_row = adw::EntryRow::builder()
        .title(tr("settings.profile.path"))
        .text("~/aska.profile")
        .build();
    g.add(&path_row);
    b.append(&g);
    b.append(&hint(&tr("settings.profile.path.hint")));
    let pass = PassphraseField::new(&tr("settings.profile.passphrase"));
    b.append(pass.widget());
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let create = gtk::Button::with_label(&tr("settings.profile.create"));
    let open = gtk::Button::with_label(&tr("settings.profile.open"));
    let forget = gtk::Button::with_label(&tr("settings.profile.forget"));
    forget.add_css_class("destructive-action");
    row.append(&create);
    row.append(&open);
    row.append(&forget);
    b.append(&row);
    let msg = gtk::Label::builder().wrap(true).xalign(0.0).build();
    b.append(&msg);
    root.append(&b);

    let say = |msg: &gtk::Label, text: &str, error: bool| {
        if error {
            msg.add_css_class("error");
        } else {
            msg.remove_css_class("error");
        }
        msg.set_label(text);
    };

    // Create: relays from this run + passphrase → one random-looking 4 KiB file.
    {
        let (ui2, pass2, msg2, refresh2, path2) = (
            ui.clone(),
            pass.clone(),
            msg.clone(),
            refresh_status.clone(),
            path_row.clone(),
        );
        create.connect_clicked(move |_| {
            let relays = ui2.app.borrow().relays.clone();
            if relays.is_empty() {
                return say(&msg2, &tr("settings.profile.need_relays"), true);
            }
            let Some(path) = resolve_path(&path2.text()) else {
                return say(&msg2, &tr("settings.profile.need_path"), true);
            };
            let pw = pass2.value();
            if pw.trim().is_empty() {
                return say(&msg2, &tr("send.error.passphrase_empty"), true);
            }
            pass2.clear();
            say(&msg2, &tr("settings.profile.sealing"), false);
            let p = Profile {
                relays: relays.iter().map(|r| r.pubkey).collect(),
                auth_key: relays.first().and_then(|r| r.auth_key.clone()),
                seeds: Vec::new(),
            };
            let (n, circle) = (relays.len(), p.auth_key.is_some());
            let (ui3, msg3, refresh3) = (ui2.clone(), msg2.clone(), refresh2.clone());
            worker::run(
                move || -> Result<PathBuf, String> {
                    let bytes = seal_profile(&p, &pw).map_err(|e| e.to_string())?;
                    drop(pw);
                    use std::io::Write;
                    let mut f = create_new(&path).map_err(|e| {
                        if e.kind() == std::io::ErrorKind::AlreadyExists {
                            trf("settings.profile.exists", &[("name", &file_name(&path))])
                        } else {
                            format!("{}: {e}", path.display())
                        }
                    })?;
                    f.write_all(&bytes).map_err(|e| e.to_string())?;
                    f.sync_all().map_err(|e| e.to_string())?;
                    Ok(path)
                },
                move |r| match r {
                    Ok(path) => {
                        ui3.app.borrow_mut().set_profile(
                            ProfileInfo {
                                name: file_name(&path),
                                relays: n,
                                circle_key: circle,
                                seeds: 0,
                            },
                            path.clone(),
                            Vec::new(),
                        );
                        refresh3();
                        say(
                            &msg3,
                            &trf("settings.profile.created", &[("name", &file_name(&path))]),
                            false,
                        );
                    }
                    Err(e) => say(&msg3, &e, true),
                },
            );
        });
    }

    // Open: file + passphrase → relays (and circle key) for this run.
    {
        let (ui2, pass2, msg2, refresh2, path2) = (
            ui.clone(),
            pass.clone(),
            msg.clone(),
            refresh_status.clone(),
            path_row.clone(),
        );
        open.connect_clicked(move |_| {
            let Some(path) = resolve_path(&path2.text()) else {
                return say(&msg2, &tr("settings.profile.need_path"), true);
            };
            let pw = pass2.value();
            if pw.trim().is_empty() {
                return say(&msg2, &tr("send.error.passphrase_empty"), true);
            }
            pass2.clear();
            say(&msg2, &tr("settings.profile.opening"), false);
            let (ui3, msg3, refresh3) = (ui2.clone(), msg2.clone(), refresh2.clone());
            worker::run(
                move || -> Result<(PathBuf, Profile), String> {
                    // A profile is exactly PROFILE_LEN bytes; refuse links and anything else
                    // before reading (review finding C-14: `read` of a device path would
                    // never return).
                    let bytes = read_profile(&path)?;
                    let p = open_profile(&bytes, &pw).map_err(|_| tr("settings.profile.wrong"))?;
                    drop(pw);
                    Ok((path, p))
                },
                move |r| match r {
                    Ok((path, mut p)) => {
                        let name = file_name(&path);
                        let relays = p.relays();
                        let info = ProfileInfo {
                            name: name.clone(),
                            relays: relays.len(),
                            circle_key: p.auth_key.is_some(),
                            seeds: p.seeds.len(),
                        };
                        let seeds = std::mem::take(&mut p.seeds);
                        let mut a = ui3.app.borrow_mut();
                        a.set_relays(relays);
                        a.set_profile(info, path, seeds);
                        drop(a);
                        refresh3();
                        say(
                            &msg3,
                            &trf("settings.profile.opened", &[("name", &name)]),
                            false,
                        );
                    }
                    Err(e) => say(&msg3, &e, true),
                },
            );
        });
    }

    // Forget: confirm, overwrite with noise and remove.
    {
        let (ui2, msg2, refresh2, path2) = (
            ui.clone(),
            msg.clone(),
            refresh_status.clone(),
            path_row.clone(),
        );
        forget.connect_clicked(move |_| {
            let Some(path) = resolve_path(&path2.text()) else {
                return say(&msg2, &tr("settings.profile.need_path"), true);
            };
            if !path.is_file() {
                return say(
                    &msg2,
                    &trf("settings.profile.missing", &[("name", &file_name(&path))]),
                    true,
                );
            }
            let name = file_name(&path);
            let confirm = adw::AlertDialog::new(
                Some(&tr("settings.profile.forget")),
                Some(&trf(
                    "settings.profile.forget.confirm",
                    &[("name", &path.display().to_string())],
                )),
            );
            confirm.add_responses(&[
                ("cancel", &tr("common.cancel")),
                ("forget", &tr("settings.profile.forget.yes")),
            ]);
            confirm.set_response_appearance("forget", adw::ResponseAppearance::Destructive);
            confirm.set_default_response(Some("cancel"));
            confirm.set_close_response("cancel");
            let (ui3, msg3, refresh3) = (ui2.clone(), msg2.clone(), refresh2.clone());
            confirm.connect_response(Some("forget"), move |_, _| match shred(&path) {
                Ok(()) => {
                    let mut a = ui3.app.borrow_mut();
                    if a.profile_path.as_deref() == Some(path.as_path())
                        || a.profile.as_ref().map(|p| p.name.as_str()) == Some(name.as_str())
                    {
                        a.forget_profile();
                    }
                    drop(a);
                    refresh3();
                    say(
                        &msg3,
                        &trf("settings.profile.forgotten", &[("name", &name)]),
                        false,
                    );
                }
                Err(e) => say(&msg3, &e.to_string(), true),
            });
            confirm.present(ui2.window().as_ref());
        });
    }
}
