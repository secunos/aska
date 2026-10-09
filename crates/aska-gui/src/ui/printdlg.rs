//! The print dialog of the paper mode (DC-04 §5.2). Not GTK's print dialog: GTK's print
//! operation spools the job through a temporary file (`GtkPrintJob` writes its data to a
//! `g_file_open_tmp` file before the backend streams it), which would put a pad page on disk —
//! found while building this step. Instead the client lists the printers itself, applies the
//! rule (volatile spool, USB device, the rules acknowledged — for pads; USB for Share cards;
//! nothing for Block cards), builds the PostScript in locked memory and submits it to the
//! local CUPS over its socket (`aska_paper::print`). The sheets are rendered by the caller;
//! only the finished rasters enter here and they are wiped when the dialog closes.

use super::Ui;
use crate::i18n::{tr, trf};
use crate::worker;
use adw::prelude::*;
use aska_paper::print::{self, Printer, Refusal};
use aska_paper::render::Raster;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Material {
    Pad,
    Share,
    Block,
}

/// What the dialog found out about the system, shown as lines.
struct Facts {
    spool: Result<(), Refusal>,
    printers: Result<Vec<Printer>, Refusal>,
}

/// Open the dialog for `sheets` (consumed and wiped when the dialog closes).
pub fn open(ui: &Rc<Ui>, material: Material, sheets: Vec<Raster>, dpi: u32) {
    let sheets = Rc::new(RefCell::new(sheets));
    let dialog = adw::Dialog::builder()
        .title(tr("print.title"))
        .content_width(460)
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
    let facts_label = gtk::Label::builder()
        .label(tr("print.checking"))
        .wrap(true)
        .xalign(0.0)
        .css_classes(["dim-label"])
        .build();
    content.append(&facts_label);
    let printers_row = adw::ComboRow::builder().title(tr("print.printer")).build();
    let group = adw::PreferencesGroup::new();
    group.add(&printers_row);
    content.append(&group);

    // The checklist (pads only).
    let checks: Vec<gtk::CheckButton> = if material == Material::Pad {
        [
            "print.check.paper",
            "print.check.printer",
            "print.check.radios",
            "print.check.tray",
            "print.check.destroy",
        ]
        .iter()
        .map(|k| {
            let c = gtk::CheckButton::with_label(&tr(k));
            content.append(&c);
            c
        })
        .collect()
    } else {
        Vec::new()
    };
    let status = gtk::Label::builder()
        .wrap(true)
        .xalign(0.0)
        .css_classes(["dim-label"])
        .build();
    content.append(&status);
    let buttons = gtk::Box::builder()
        .orientation(gtk::Orientation::Horizontal)
        .spacing(8)
        .halign(gtk::Align::End)
        .build();
    let cancel = gtk::Button::with_label(&tr("common.cancel"));
    let go = gtk::Button::builder()
        .label(trf(
            "print.go",
            &[("n", &sheets.borrow().len().to_string())],
        ))
        .css_classes(["suggested-action"])
        .sensitive(false)
        .build();
    buttons.append(&cancel);
    buttons.append(&go);
    content.append(&buttons);
    tv.set_content(Some(&content));
    dialog.set_child(Some(&tv));
    {
        let dialog = dialog.clone();
        cancel.connect_clicked(move |_| {
            dialog.close();
        });
    }
    {
        let sheets = sheets.clone();
        dialog.connect_closed(move |_| {
            for s in sheets.borrow_mut().iter_mut() {
                s.clear();
            }
            sheets.borrow_mut().clear();
        });
    }
    dialog.present(ui.window().as_ref());

    // Facts on a worker (CUPS may be slow or absent).
    let printers: Rc<RefCell<Vec<Printer>>> = Rc::new(RefCell::new(Vec::new()));
    let refresh = {
        let (printers_row, go, status, checks, printers) = (
            printers_row.clone(),
            go.clone(),
            status.clone(),
            checks.clone(),
            printers.clone(),
        );
        let spool_ok = Rc::new(RefCell::new(false));
        let spool_ok2 = spool_ok.clone();
        Rc::new(move |facts: Option<&Facts>| {
            if let Some(f) = facts {
                *spool_ok2.borrow_mut() = f.spool.is_ok();
            }
            let idx = printers_row.selected() as usize;
            let list = printers.borrow();
            let verdict: Result<(), String> = match list.get(idx) {
                None => Err(tr("print.no_printer")),
                Some(p) => match material {
                    Material::Pad => {
                        if !*spool_ok.borrow() {
                            Err(tr("print.refuse.spool"))
                        } else if let Err(r) = print::check_printer(p) {
                            Err(r.to_string())
                        } else if !checks.iter().all(gtk::CheckButton::is_active) {
                            Err(tr("print.refuse.checklist"))
                        } else {
                            Ok(())
                        }
                    }
                    Material::Share => print::check_printer(p).map_err(|r| r.to_string()),
                    Material::Block => Ok(()),
                },
            };
            match verdict {
                Ok(()) => {
                    status.set_label(&tr("print.ready"));
                    status.remove_css_class("error");
                    go.set_sensitive(true);
                }
                Err(m) => {
                    status.set_label(&m);
                    status.add_css_class("error");
                    go.set_sensitive(false);
                }
            }
        })
    };
    {
        let (facts_label, printers_row, printers, refresh) = (
            facts_label.clone(),
            printers_row.clone(),
            printers.clone(),
            refresh.clone(),
        );
        worker::run(
            || Facts {
                spool: print::spool_is_volatile(),
                printers: print::list_printers(),
            },
            move |facts| {
                let spool_line = match &facts.spool {
                    Ok(()) => tr("print.spool.volatile"),
                    Err(Refusal::SpoolPersistent(why)) => {
                        trf("print.spool.persistent", &[("why", why)])
                    }
                    Err(e) => e.to_string(),
                };
                let names: Vec<String> = match &facts.printers {
                    Ok(list) => {
                        *printers.borrow_mut() = list.clone();
                        list.iter()
                            .map(|p| format!("{} ({})", p.name, p.scheme()))
                            .collect()
                    }
                    Err(e) => {
                        facts_label.set_label(&format!("{spool_line}\n{e}"));
                        Vec::new()
                    }
                };
                let refs: Vec<&str> = names.iter().map(String::as_str).collect();
                printers_row.set_model(Some(&gtk::StringList::new(&refs)));
                if facts.printers.is_ok() {
                    facts_label.set_label(&trf(
                        "print.facts",
                        &[("spool", &spool_line), ("n", &names.len().to_string())],
                    ));
                }
                refresh(Some(&facts));
            },
        );
    }
    {
        let r = refresh.clone();
        printers_row.connect_selected_notify(move |_| r(None));
    }
    for c in &checks {
        let r = refresh.clone();
        c.connect_toggled(move |_| r(None));
    }
    {
        let (ui, dialog, printers, printers_row, sheets, status, go2) = (
            ui.clone(),
            dialog.clone(),
            printers.clone(),
            printers_row.clone(),
            sheets.clone(),
            status.clone(),
            go.clone(),
        );
        go.connect_clicked(move |_| {
            let go = &go2;
            let Some(p) = printers
                .borrow()
                .get(printers_row.selected() as usize)
                .cloned()
            else {
                return;
            };
            // The rule is checked again here, on the final facts, before the job leaves.
            if material == Material::Pad {
                if let Err(r) = print::pad_print_checks(&p) {
                    status.set_label(&r.to_string());
                    return;
                }
            } else if material == Material::Share {
                if let Err(r) = print::check_printer(&p) {
                    status.set_label(&r.to_string());
                    return;
                }
            }
            go.set_sensitive(false);
            status.set_label(&tr("print.sending"));
            let ps = {
                let s = sheets.borrow();
                let refs: Vec<&Raster> = s.iter().collect();
                print::postscript(&refs, dpi)
            };
            let n = sheets.borrow().len();
            let (ui2, dialog, status) = (ui.clone(), dialog.clone(), status.clone());
            worker::run(
                move || {
                    let r = print::print_postscript(&p, ps.as_slice());
                    drop(ps);
                    r
                },
                move |r| match r {
                    Ok(id) => {
                        dialog.close();
                        ui2.toast(&trf(
                            "print.done",
                            &[("id", &id.to_string()), ("n", &n.to_string())],
                        ));
                        if material != Material::Block {
                            ui2.toast(&tr("print.caveat"));
                        }
                    }
                    Err(e) => {
                        status.set_label(&e.to_string());
                        status.add_css_class("error");
                    }
                },
            );
        });
    }
}
