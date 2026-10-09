//! Screen 1 — Home (Client Design §5.1). Identical on every launch: the name, one line, three
//! buttons, a footer with the build fingerprint prefix and the Tor state, and the doctor's
//! findings as banners above the footer. There is no list of anything, because there is
//! nothing to list.

use super::{paper, receive, send, settings, shares, Ui};
use crate::i18n::{tr, trf};
use crate::state::{TorSource, TorState};
use crate::worker;
use aska_core::doctor::{self, Check, DoctorConfig, Finding, Severity};
use gtk::prelude::*;
use std::rc::Rc;

#[derive(Clone)]
struct Widgets {
    banners: gtk::Box,
    tor_label: gtk::Label,
    send_btn: gtk::Button,
}

pub fn build(ui: &Rc<Ui>) -> adw::NavigationPage {
    let root = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(18)
        .margin_top(36)
        .margin_bottom(18)
        .margin_start(36)
        .margin_end(36)
        .valign(gtk::Align::Fill)
        .build();

    let title = gtk::Label::builder()
        .label(tr("app.name"))
        .css_classes(["title-1"])
        .build();
    let tagline = gtk::Label::builder()
        .label(tr("app.tagline"))
        .css_classes(["dim-label", "title-4"])
        .build();
    root.append(&title);
    root.append(&tagline);

    let buttons = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .halign(gtk::Align::Center)
        .margin_top(24)
        .width_request(320)
        .build();
    let send_btn = big_button(&tr("home.send"), true);
    let recv_btn = big_button(&tr("home.receive"), false);
    let shares_btn = big_button(&tr("home.shares"), false);
    let paper_btn = big_button(&tr("home.paper"), false);
    buttons.append(&send_btn);
    buttons.append(&recv_btn);
    buttons.append(&shares_btn);
    buttons.append(&paper_btn);
    root.append(&buttons);

    // Spacer pushes banners + footer to the bottom.
    let spacer = gtk::Box::builder().vexpand(true).build();
    root.append(&spacer);

    let banners = gtk::Box::new(gtk::Orientation::Vertical, 8);
    root.append(&banners);

    let footer = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    let fp = aska_core::fingerprint::check();
    let fp_text = match fp.own_sha256.as_deref() {
        Some(h) => trf("home.footer.build", &[("fp", &h[..h.len().min(12)])]),
        None => tr("home.footer.build_unknown"),
    };
    let fp_label = gtk::Label::builder()
        .label(fp_text)
        .css_classes(["dim-label", "caption", "aska-mono"])
        .selectable(true) // the fingerprint is one of the two copyable strings (§5.7)
        .build();
    let tor_label = gtk::Label::builder()
        .label(tr("home.footer.tor.checking"))
        .css_classes(["dim-label", "caption"])
        .hexpand(true)
        .xalign(0.0)
        .build();
    let profile_label = match &ui.app.borrow().profile {
        Some(p) => trf("home.footer.profile_open", &[("name", &p.name)]),
        None => tr("home.footer.profile"),
    };
    let profile_btn = gtk::Button::builder()
        .label(profile_label)
        .css_classes(["flat", "caption"])
        .build();
    let gear = gtk::Button::builder()
        .icon_name("emblem-system-symbolic")
        .tooltip_text(tr("home.settings"))
        .css_classes(["flat"])
        .build();
    footer.append(&fp_label);
    footer.append(&tor_label);
    footer.append(&profile_btn);
    footer.append(&gear);
    root.append(&footer);

    let w = Widgets {
        banners,
        tor_label,
        send_btn: send_btn.clone(),
    };

    {
        let ui = ui.clone();
        send_btn.connect_clicked(move |_| {
            ui.nav.push(&send::build(&ui));
        });
    }
    {
        let ui = ui.clone();
        recv_btn.connect_clicked(move |_| {
            ui.nav.push(&receive::build(&ui, false));
        });
    }
    {
        let ui = ui.clone();
        paper_btn.connect_clicked(move |_| {
            ui.nav.push(&paper::build(&ui));
        });
    }
    {
        let ui = ui.clone();
        shares_btn.connect_clicked(move |_| {
            ui.nav.push(&shares::build(&ui));
        });
    }
    for b in [&profile_btn, &gear] {
        let ui = ui.clone();
        b.connect_clicked(move |_| {
            ui.nav.push(&settings::build(&ui));
        });
    }

    // Settings can ask for the checks to run again (after a Tor-source change).
    {
        let (ui2, w2) = (ui.clone(), w.clone());
        *ui.home_recheck.borrow_mut() = Some(Rc::new(move || run_doctor_forced(&ui2, &w2)));
    }

    run_doctor(ui, &w);

    ui.page("home", tr("app.title").as_str(), &root)
}

fn big_button(label: &str, suggested: bool) -> gtk::Button {
    let b = gtk::Button::builder()
        .label(label)
        .css_classes(["pill", "title-4"])
        .height_request(48)
        .build();
    if suggested {
        b.add_css_class("suggested-action");
    }
    b
}

/// Run the environment checks on a worker (the SOCKS probe can block for seconds), then
/// draw the banners. If the system Tor is down or cannot reach the network, try Tor
/// Browser's Tor as well (D-16): if that one is fine, use it and say so.
fn run_doctor(ui: &Rc<Ui>, w: &Widgets) {
    w.tor_label.set_label(&tr("home.footer.tor.checking"));
    let cfg_system = ui.app.borrow().tor_config();
    let cfg_tb = aska_core::tor::TorConfig {
        socks: TorSource::TorBrowser.socks(),
        ..aska_core::tor::TorConfig::default()
    };
    let doctor_cfg = |tor| DoctorConfig {
        tor,
        relay_addresses: vec![],
        probe_tor: true,
    };
    let (dc_sys, dc_tb) = (doctor_cfg(cfg_system), doctor_cfg(cfg_tb));
    let ui2 = ui.clone();
    let w2 = w.clone();
    worker::run(
        move || {
            let sys = doctor::run(&dc_sys);
            let sys_bad = sys.iter().any(|f| {
                (f.check == Check::Tor && f.severity == Severity::Refuse)
                    || f.check == Check::TorNetwork
            });
            if !sys_bad {
                return (TorSource::System, sys);
            }
            let tb = doctor::run(&dc_tb);
            let tb_ok = !tb
                .iter()
                .any(|f| matches!(f.check, Check::Tor | Check::TorNetwork));
            if tb_ok {
                (TorSource::TorBrowser, tb)
            } else {
                (TorSource::System, sys)
            }
        },
        move |(source, findings)| {
            {
                let mut a = ui2.app.borrow_mut();
                a.set_tor_source(source);
                a.apply_findings(findings);
            }
            refresh(&ui2, &w2);
        },
    );
}

fn refresh(ui: &Rc<Ui>, w: &Widgets) {
    let a = ui.app.borrow();
    let via_tb = a.tor_source == TorSource::TorBrowser;
    w.tor_label.set_label(&tr(match (a.tor_state, via_tb) {
        (TorState::Checking, _) => "home.footer.tor.checking",
        (TorState::Ok, true) => "home.footer.tor.tor_browser",
        (TorState::Ok, false) => "home.footer.tor.ok",
        (TorState::NoCircuit, _) => "home.footer.tor.no_circuit",
        (TorState::Blocked, _) => "home.footer.tor.blocked",
        (TorState::Down, _) => "home.footer.tor.down",
    }));
    w.send_btn.set_sensitive(!a.network_refused());
    let findings = a.findings.clone();
    drop(a);

    while let Some(c) = w.banners.first_child() {
        w.banners.remove(&c);
    }
    for f in &findings {
        w.banners.append(&banner(ui, w, f));
    }
}

/// One finding as an amber (Warn), red (Refuse) or blue (Info) banner with the action that
/// fits: Accept for a warning, Check again / Use Tor Browser's Tor for the Tor findings.
fn banner(ui: &Rc<Ui>, w: &Widgets, f: &Finding) -> gtk::Box {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    row.add_css_class(match f.severity {
        Severity::Refuse => "aska-banner-refuse",
        Severity::Warn => "aska-banner-warn",
        Severity::Info => "aska-banner-info",
    });
    let mut text = f.message.clone();
    if f.severity == Severity::Refuse {
        text.push(' ');
        text.push_str(&tr("home.doctor.refused"));
    }
    let label = gtk::Label::builder()
        .label(text)
        .wrap(true)
        .xalign(0.0)
        .hexpand(true)
        .build();
    row.append(&label);

    let check = f.check;
    match (f.check, f.severity) {
        (Check::Tor | Check::TorNetwork, _) => {
            if ui.app.borrow().tor_source == TorSource::System {
                let tb = gtk::Button::with_label(&tr("home.doctor.use_tor_browser"));
                tb.set_valign(gtk::Align::Center);
                let (ui2, w2) = (ui.clone(), w.clone());
                tb.connect_clicked(move |_| {
                    ui2.app.borrow_mut().set_tor_source(TorSource::TorBrowser);
                    run_doctor_forced(&ui2, &w2);
                });
                row.append(&tb);
            }
            let again = gtk::Button::with_label(&tr("home.doctor.recheck"));
            again.set_valign(gtk::Align::Center);
            let (ui2, w2) = (ui.clone(), w.clone());
            again.connect_clicked(move |_| run_doctor(&ui2, &w2));
            row.append(&again);
        }
        (_, Severity::Warn) => {
            let ok = gtk::Button::with_label(&tr("home.doctor.accept"));
            ok.set_valign(gtk::Align::Center);
            let (ui2, w2) = (ui.clone(), w.clone());
            ok.connect_clicked(move |_| {
                ui2.app.borrow_mut().acknowledge(check);
                ui2.toast(&tr("home.doctor.accepted"));
                refresh(&ui2, &w2);
            });
            row.append(&ok);
        }
        (_, Severity::Info) => {
            let x = gtk::Button::with_label(&tr("home.doctor.dismiss"));
            x.set_valign(gtk::Align::Center);
            let (ui2, w2) = (ui.clone(), w.clone());
            x.connect_clicked(move |_| {
                ui2.app.borrow_mut().acknowledge(check);
                refresh(&ui2, &w2);
            });
            row.append(&x);
        }
        (_, Severity::Refuse) => {}
    }
    row
}

/// Re-run the doctor against the currently selected Tor only (after the user chose one).
fn run_doctor_forced(ui: &Rc<Ui>, w: &Widgets) {
    w.tor_label.set_label(&tr("home.footer.tor.checking"));
    let cfg = DoctorConfig {
        tor: ui.app.borrow().tor_config(),
        relay_addresses: vec![],
        probe_tor: true,
    };
    let (ui2, w2) = (ui.clone(), w.clone());
    worker::run(
        move || doctor::run(&cfg),
        move |findings| {
            ui2.app.borrow_mut().apply_findings(findings);
            refresh(&ui2, &w2);
        },
    );
}
