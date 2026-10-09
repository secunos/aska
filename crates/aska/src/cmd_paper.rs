//! `aska paper …` — the paper mode on the command line (DC-04 §8.2, release 1.2).
//!
//! Pad booklets are generated here and leave the process in one of four ways: PostScript or
//! PBM on standard output (for an operator who pipes it somewhere deliberately), row by row on
//! the terminal for hand copying, or straight to a USB printer through the local print system
//! — the last only after the printing rule's checks (volatile spool, USB device, the rules
//! acknowledged). Pages are read back from the camera or typed; messages are enciphered and
//! deciphered in locked memory; Block cards and Share cards go the same four ways. Nothing is
//! remembered between commands: the paper is the record.

use crate::ctx::{exit, CmdResult, Ctx, Fail};
use crate::term::SecretLine;
use aska_core::secret::LockedBuf;
use aska_paper::booklet::{self, Booklet, BookletSpec};
use aska_paper::entropy::{self, Label, Seeded};
use aska_paper::page::{Direction, Page, PageSpec};
use aska_paper::render::{self, Paper, Raster, RenderOptions};
use aska_paper::{cards, checkerboard, devtag, handtag, pad, print, PaperError};
use std::io::Write;
use zeroize::Zeroize;

/// Where rendered sheets go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sink {
    /// PostScript on standard output.
    Ps,
    /// Binary PBM (P4) images on standard output, one after the other.
    Pbm,
    /// Row by row on the terminal (pads), or captions and hex (cards) in `--stdin` mode.
    Rows,
    /// A named printer through the local print system.
    Print(String),
}

/// What is being printed decides which checks apply (DC-04 §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Material {
    /// Volatile spool, USB printer, rules acknowledged.
    Pad,
    /// USB printer (not a shared or network printer).
    Share,
    /// Anywhere: the card is noise.
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum SourceArg {
    /// The camera's sensor noise (cover the lens) — the only source that can carry a whole
    /// booklet; the booklet is labelled PHYSICAL when the entropy budget is met
    Camera,
    /// Die rolls typed in (at least 100) — seeds the generator; the booklet is SEEDED
    Dice,
    /// Keyboard timing while you type freely (at least 256 keys) — SEEDED
    Typing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum PageFrom {
    /// Scan the page's QR code with the camera
    Camera,
    /// Type or paste every digit of the page (the QR payload), spaces allowed
    Typed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum PaperArg {
    A4,
    Letter,
}

pub struct GenerateOpts {
    pub pages: u8,
    pub digits: usize,
    pub source: SourceArg,
    pub hand_tag: bool,
    pub set_code: Option<u16>,
    pub camera: Option<std::path::PathBuf>,
    pub copies: u8,
    pub sink: Sink,
    pub rules_read: bool,
    pub paper: PaperArg,
    pub dpi: u32,
}

fn render_opts(paper: PaperArg, dpi: u32) -> RenderOptions {
    RenderOptions {
        dpi,
        paper: match paper {
            PaperArg::A4 => Paper::A4,
            PaperArg::Letter => Paper::Letter,
        },
        scale: if dpi >= 300 { 4 } else { 2 },
        margin: (dpi as usize) * 2 / 5,
    }
}

fn paper_err(e: PaperError) -> Fail {
    match e {
        PaperError::Tag | PaperError::Checksum => Fail::new(exit::NOTHING, e.to_string()),
        PaperError::Alphabet(_) | PaperError::TooLong { .. } | PaperError::Digits(_) => {
            Fail::new(exit::ERROR, e.to_string())
        }
        e => Fail::new(exit::ERROR, e.to_string()),
    }
}

// ---------------------------------------------------------------------------------------------
// Output

/// Send rendered sheets to the sink, applying the checks for `material`.
pub fn emit_sheets(
    _ctx: &mut Ctx,
    sheets: &[Raster],
    sink: &Sink,
    material: Material,
    rules_read: bool,
    dpi: u32,
) -> CmdResult {
    match sink {
        Sink::Ps => {
            let refs: Vec<&Raster> = sheets.iter().collect();
            let ps = print::postscript(&refs, dpi);
            if material == Material::Pad {
                note!("Writing pad pages as PostScript to standard output. Whatever receives this now holds the pad; the spool and log caveats of printing apply to it too.");
            }
            let mut o = std::io::stdout().lock();
            o.write_all(ps.as_slice())?;
            o.flush()?;
            Ok(())
        }
        Sink::Pbm => {
            let mut o = std::io::stdout().lock();
            for r in sheets {
                let pbm = r.to_pbm();
                o.write_all(pbm.as_slice())?;
            }
            o.flush()?;
            Ok(())
        }
        Sink::Rows => Err(Fail::new(
            exit::ERROR,
            "--rows applies to pad pages and cover pages only",
        )),
        Sink::Print(name) => {
            let printer =
                print::find_printer(name).map_err(|r| Fail::new(exit::ERROR, r.to_string()))?;
            match material {
                Material::Pad => {
                    if !rules_read {
                        return Err(Fail::new(
                            exit::ERROR,
                            "printing a pad needs --i-have-read-the-rules: soluble paper loaded, no colour laser, radios off, nobody at the output tray, and you know how the page is destroyed (see `aska paper worksheet`)",
                        ));
                    }
                    print::pad_print_checks(&printer)
                        .map_err(|r| Fail::new(exit::DOCTOR_REFUSED, r.to_string()))?;
                }
                Material::Share => {
                    print::check_printer(&printer)
                        .map_err(|r| Fail::new(exit::DOCTOR_REFUSED, r.to_string()))?;
                }
                Material::Block => {}
            }
            if printer.state == 5 {
                note!("The printer reports itself stopped; the job will wait in its queue.");
            }
            let refs: Vec<&Raster> = sheets.iter().collect();
            let ps = print::postscript(&refs, dpi);
            let id = print::print_postscript(&printer, ps.as_slice()).map_err(paper_err)?;
            note!(
                "Sent {} sheet(s) to {} as job {id} (named \"{}\").",
                sheets.len(),
                printer.name,
                print::JOB_NAME
            );
            if material != Material::Block {
                note!(
                    "What this could not prevent: the print system's page_log/error_log and the printer's own counter record that a job of {} page(s) was printed now. Clear the logs if your system keeps them, power-cycle the printer, and take the pages from the tray yourself.",
                    sheets.len()
                );
            }
            Ok(())
        }
    }
}

/// A booklet's pages, row by row (hand copy) or as text lines in `--stdin` mode.
fn emit_rows(ctx: &mut Ctx, b: &Booklet) -> CmdResult {
    for page in &b.pages {
        emit_page_rows(ctx, page, b.label)?;
    }
    Ok(())
}

fn page_header(page: &Page, label: Label) -> String {
    let s = page.spec();
    format!(
        "PAGE {:04} {} {:02} N {} {} CHECK {}",
        s.set_code,
        s.direction.letter(),
        s.number,
        s.pad_len,
        label.as_str(),
        std::str::from_utf8(&page.checksum()).unwrap_or("??????")
    )
}

fn emit_page_rows(ctx: &mut Ctx, page: &Page, label: Label) -> CmdResult {
    let header = page_header(page, label);
    let c = page.canonical();
    let end = c.len();
    if !ctx.input.is_interactive() {
        out!("{header}")?;
        for row in render::page_rows_text(page) {
            out!("{}", String::from_utf8_lossy(row.as_slice()))?;
        }
        for (first, row, check) in page.key_rows() {
            let mut line = String::new();
            if first == usize::MAX {
                line.push_str("B     ");
            } else {
                line.push_str(&format!("A{first:03}  "));
            }
            for (gi, g) in row.chunks(handtag::KEY_DIGITS).enumerate() {
                if gi > 0 {
                    line.push(' ');
                }
                line.push_str(std::str::from_utf8(g).unwrap_or("????"));
            }
            line.push_str(&format!("  {check}"));
            out!("{line}")?;
            line.zeroize();
        }
        out!(
            "R {}  S {}",
            String::from_utf8_lossy(&c[end - 38..end - 19]),
            String::from_utf8_lossy(&c[end - 19..])
        )?;
        // The QR payload — what `--page-from typed` takes back.
        let payload = page.qr_payload();
        out!("PAYLOAD {}", String::from_utf8_lossy(payload.as_slice()))?;
        out!("END")?;
        return Ok(());
    }
    let idle = ctx.idle;
    let intro = format!(
        "{header}\n\nCopy each row onto water-soluble paper, on glass, in water-soluble ink.\nThe last digit of a row is its check: the sum of the row's digits mod 10.\nPad rows come first, then the hand-tag keys (A000…, then B), then the device keys."
    );
    ctx.input
        .show_timed(&intro, "Press any key for the first row", idle)?;
    let rows = render::page_rows_text(page);
    let n = rows.len();
    for (i, row) in rows.iter().enumerate() {
        let body = format!(
            "{header}\n\nPAD ROW {} of {n}\n\n{}",
            i + 1,
            String::from_utf8_lossy(row.as_slice())
        );
        ctx.input
            .show_timed(&body, "Press any key for the next row", idle)?;
    }
    let krows = page.key_rows();
    let kn = krows.len();
    for (i, (first, row, check)) in krows.iter().enumerate() {
        let mut line = String::new();
        if *first == usize::MAX {
            line.push_str("B     ");
        } else {
            line.push_str(&format!("A{first:03}  "));
        }
        for (gi, g) in row.chunks(handtag::KEY_DIGITS).enumerate() {
            if gi > 0 {
                line.push(' ');
            }
            line.push_str(std::str::from_utf8(g).unwrap_or("????"));
        }
        line.push_str(&format!("  {check}"));
        let body = format!("{header}\n\nHAND-TAG KEY ROW {} of {kn}\n\n{line}", i + 1);
        line.zeroize();
        ctx.input
            .show_timed(&body, "Press any key for the next row", idle)?;
    }
    let body = format!(
        "{header}\n\nDEVICE-TAG KEYS\n\nR {}\nS {}",
        String::from_utf8_lossy(&c[end - 38..end - 19]),
        String::from_utf8_lossy(&c[end - 19..])
    );
    ctx.input
        .show_timed(&body, "Press any key to finish this page", idle)?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// generate

pub fn generate(ctx: &mut Ctx, o: &GenerateOpts) -> CmdResult {
    ctx.doctor_gate(false)?;
    let spec = BookletSpec {
        set_code: o.set_code,
        pages_per_direction: o.pages,
        pad_len: o.digits,
        hand_tag: o.hand_tag,
    };
    spec.validate().map_err(paper_err)?;
    if matches!(o.sink, Sink::Print(_)) && !o.rules_read {
        return Err(Fail::new(
            exit::ERROR,
            "printing a pad needs --i-have-read-the-rules (see `aska paper worksheet`)",
        ));
    }
    note!(
        "Generating a booklet: {} A-pages and {} B-pages of {} digits{} ({} extracted bits needed from the physical source).",
        o.pages,
        o.pages,
        o.digits,
        if o.hand_tag { " with hand-tag keys" } else { "" },
        spec.bits_needed()
    );
    let mut booklet = match o.source {
        SourceArg::Camera => {
            let mut cam =
                entropy::camera::CameraSource::open(o.camera.as_deref()).map_err(|e| {
                    Fail::new(
                        exit::ERROR,
                        format!("{e}. Use --source dice for a SEEDED booklet without a camera."),
                    )
                })?;
            note!(
                "Cover the lens (sensor noise) or point the camera at a textured, moving scene. Reading at least {} frames …",
                entropy::camera::MIN_FRAMES
            );
            let mut last = 0usize;
            booklet::generate_physical(spec, &mut cam, |p| {
                if p.raw_samples / 16384 != last {
                    last = p.raw_samples / 16384;
                    note!(
                        "  {} raw samples, estimate {} bits/sample, {} of {} bits extractable",
                        p.raw_samples,
                        p.estimate.map_or("—".to_string(), |e| format!("{e:.2}")),
                        p.extractable_bits,
                        p.need_bits
                    );
                }
            })
            .map_err(paper_err)?
        }
        SourceArg::Dice => {
            let rolls = read_dice(ctx)?;
            let seeded = Seeded::from_dice(&rolls).map_err(paper_err)?;
            booklet::generate_seeded(spec, seeded).map_err(paper_err)?
        }
        SourceArg::Typing => {
            let intervals = ctx.input.read_timed_keys(
                "Type freely — anything, at least 256 keys; the keys are discarded and only their timing is kept. Press Enter when done.\n",
                256,
            )?;
            let seeded = Seeded::from_timings(&intervals).map_err(paper_err)?;
            booklet::generate_seeded(spec, seeded).map_err(paper_err)?
        }
    };
    note!(
        "Booklet {:04}: {} pages, label {}. Source: {}.",
        booklet.set_code,
        booklet.pages.len(),
        booklet.label.as_str(),
        booklet.source
    );
    note!(
        "Digit statistics over {} digits: frequency χ² {:.1}, pairs χ² {}, repeats z {:+.2}, longest run {} — all within limits.",
        booklet.stats.digits,
        booklet.stats.chi2_frequency,
        booklet.stats.chi2_serial.map_or("—".to_string(), |v| format!("{v:.1}")),
        booklet.stats.repeats_z,
        booklet.stats.longest_run
    );
    if booklet.label == Label::Seeded {
        note!("SEEDED: this booklet is as strong as the generator that made it (computational), not a one-time pad with a proof. A camera gives the PHYSICAL label.");
    }
    let result = match &o.sink {
        Sink::Rows => emit_rows(ctx, &booklet),
        sink => {
            let ro = render_opts(o.paper, o.dpi);
            let mut sheets = Vec::with_capacity(booklet.pages.len() * o.copies as usize);
            for _ in 0..o.copies.max(1) {
                for p in &booklet.pages {
                    sheets.push(render::render_page(p, booklet.label, &ro).map_err(paper_err)?);
                }
            }
            let r = emit_sheets(ctx, &sheets, sink, Material::Pad, o.rules_read, o.dpi);
            for s in &mut sheets {
                s.clear();
            }
            r
        }
    };
    booklet.clear();
    result?;
    note!("Done — the booklet is not remembered here. Print the worksheet separately (`aska paper worksheet`); it is not secret.");
    Ok(())
}

fn read_dice(ctx: &mut Ctx) -> Result<Vec<u8>, Fail> {
    let mut rolls: Vec<u8> = Vec::new();
    note!("Type die rolls (1–6) as runs of digits, as many lines as you like; at least 100 rolls. An empty line finishes.");
    loop {
        let line = ctx
            .input
            .read_line(&format!("Rolls so far {}: ", rolls.len()))?;
        let Some(l) = line else { break };
        if l.trim().is_empty() {
            if rolls.len() >= 100 || !ctx.input.is_interactive() {
                break;
            }
            note!("At least 100 rolls are needed.");
            continue;
        }
        for ch in l.chars() {
            match ch {
                '1'..='6' => rolls.push(ch as u8 - b'0'),
                ' ' | '\t' | ',' => {}
                other => {
                    rolls.zeroize();
                    return Err(Fail::new(exit::ERROR, format!("not a die roll: {other:?}")));
                }
            }
        }
    }
    if rolls.len() < 100 {
        return Err(Fail::new(
            exit::ERROR,
            format!("only {} rolls; at least 100 are needed", rolls.len()),
        ));
    }
    Ok(rolls)
}

// ---------------------------------------------------------------------------------------------
// pages in

/// Read a page from the camera or from typed digits; the checksum must match.
fn read_page(ctx: &mut Ctx, from: PageFrom) -> Result<Page, Fail> {
    let payload: LockedBuf = match from {
        PageFrom::Camera if ctx.input.is_interactive() => {
            let text = ctx.scan()?;
            let mut b = LockedBuf::with_capacity(text.len().max(1));
            b.extend_from_slice(text.as_bytes());
            b
        }
        _ => {
            if ctx.input.is_interactive() {
                let mut block = ctx.input.read_text_block(
                    "Type or paste every digit of the page (the QR's content, in order; spaces and line breaks are ignored). Finish with a line containing only a dot (.) or press Ctrl-D.\n",
                )?;
                let d = digits_only(block.as_slice())?;
                block.clear();
                d
            } else {
                // --stdin: digit lines until an empty line.
                let mut all = LockedBuf::with_capacity(8192);
                loop {
                    match ctx.input.read_line("")? {
                        None => break,
                        Some(l) if l.trim().is_empty() => break,
                        Some(l) => all.extend_from_slice(l.as_bytes()),
                    }
                }
                let d = digits_only(all.as_slice())?;
                all.clear();
                d
            }
        }
    };
    let page = Page::parse_with_checksum(payload.as_slice()).map_err(|e| match e {
        PaperError::Checksum => Fail::new(
            exit::NOTHING,
            "the page's checksum does not match — a digit was mis-read or mis-typed; try again",
        ),
        e => paper_err(e),
    })?;
    let s = page.spec();
    note!(
        "Page {:04} {} {:02} (N {}, hand tag {}) read; checksum verified.",
        s.set_code,
        s.direction.letter(),
        s.number,
        s.pad_len,
        if s.hand_tag { "yes" } else { "no" }
    );
    Ok(page)
}

fn digits_only(b: &[u8]) -> Result<LockedBuf, Fail> {
    let mut out = LockedBuf::with_capacity(b.len().max(1));
    for &c in b {
        match c {
            b'0'..=b'9' => out.extend_from_slice(&[c]),
            b' ' | b'\n' | b'\r' | b'\t' => {}
            other => {
                out.clear();
                return Err(Fail::new(
                    exit::ERROR,
                    format!("not a digit: {:?}", other as char),
                ));
            }
        }
    }
    Ok(out)
}

fn groups_of_five(d: &[u8]) -> String {
    d.chunks(5)
        .map(|g| String::from_utf8_lossy(g).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

pub struct EncipherOpts {
    pub from: PageFrom,
    /// Pad the message with spaces to the page's length (DC-04 Q-5).
    pub pad_to_page: bool,
}

pub fn encipher(ctx: &mut Ctx, o: &EncipherOpts) -> CmdResult {
    ctx.doctor_gate(false)?;
    let mut page = read_page(ctx, o.from)?;
    let mut text = ctx.input.read_text_block(
        "Type the message (letters, digits, spaces; punctuation as words). Finish with a line containing only a dot (.) or press Ctrl-D.\n",
    )?;
    let mut digits = checkerboard::encode(std::str::from_utf8(text.as_slice()).unwrap_or(""))
        .map_err(paper_err)?;
    text.clear();
    if digits.is_empty() {
        page.clear();
        return Err(Fail::new(exit::ERROR, "the message is empty"));
    }
    let n = page.spec().pad_len;
    if digits.len() > n {
        let have = digits.len();
        page.clear();
        return Err(Fail::new(
            exit::ERROR,
            format!("the message needs {have} digits but the page holds {n}; shorten it or use a second page"),
        ));
    }
    if o.pad_to_page {
        let padded = pad::pad_with_spaces(digits.as_slice(), n).map_err(paper_err)?;
        digits.clear();
        digits = padded;
    }
    let cipher = pad::encipher(digits.as_slice(), page.pad()).map_err(paper_err)?;
    digits.clear();
    let ht = page.hand_tag(cipher.as_slice()).ok();
    let dt = page.device_tag(cipher.as_slice()).map_err(paper_err)?;
    let mut out_text = groups_of_five(cipher.as_slice());
    if ctx.input.is_interactive() {
        let mut body = format!(
            "{}\n\nCIPHERTEXT ({} digits)\n{out_text}\n",
            page_header(&page, Label::Physical).replace(" PHYSICAL", ""),
            cipher.len()
        );
        if let Some(t) = ht {
            body.push_str(&format!("\nHAND TAG   {t:04}\n"));
        }
        body.push_str(&format!("DEVICE TAG {dt:019}\n\nPost the digits and the tag(s) anywhere. Then destroy page {:04} {} {:02} — it is not remembered here.", page.spec().set_code, page.spec().direction.letter(), page.spec().number));
        let idle = ctx.idle;
        ctx.input
            .show_timed(&body, "Press any key to close", idle)?;
        body.zeroize();
    } else {
        out!("CIPHER {out_text}")?;
        if let Some(t) = ht {
            out!("HANDTAG {t:04}")?;
        }
        out!("DEVTAG {dt:019}")?;
    }
    out_text.zeroize();
    page.clear();
    note!("Done. Destroy the page now; it has been used.");
    Ok(())
}

pub fn decipher(ctx: &mut Ctx, from: PageFrom) -> CmdResult {
    ctx.doctor_gate(false)?;
    let mut page = read_page(ctx, from)?;
    let cipher_line = ctx
        .input
        .read_line("Ciphertext digits (spaces allowed): ")?
        .ok_or_else(|| Fail::new(exit::ERROR, "no ciphertext"))?;
    let cipher = digits_only(cipher_line.as_bytes())?;
    drop(cipher_line);
    if cipher.is_empty() {
        page.clear();
        return Err(Fail::new(exit::ERROR, "no ciphertext"));
    }
    let hand = ctx
        .input
        .read_line("Hand tag (4 digits; Enter if none): ")?;
    let dev = ctx
        .input
        .read_line("Device tag (19 digits; Enter if none): ")?;
    let hand: Option<SecretLine> = hand.filter(|l| !l.trim().is_empty());
    let dev: Option<SecretLine> = dev.filter(|l| !l.trim().is_empty());
    let mut checked = false;
    if let Some(d) = &dev {
        let (r, s) = page.device_keys();
        devtag::verify(cipher.as_slice(), r, s, d.trim().as_bytes()).map_err(|e| {
            page.clear();
            match e {
                PaperError::Tag => Fail::new(exit::NOTHING, "the device tag does not verify — the message was altered, or this is the wrong page; nothing is shown"),
                e => paper_err(e),
            }
        })?;
        checked = true;
        note!("Device tag verified.");
    }
    if let Some(h) = &hand {
        match page.hand_keys() {
            Some(keys) => {
                handtag::verify(cipher.as_slice(), &keys, h.trim().as_bytes()).map_err(|e| {
                    match e {
                        PaperError::Tag => Fail::new(exit::NOTHING, "the hand tag does not verify — the message was altered, or this is the wrong page; nothing is shown"),
                        e => paper_err(e),
                    }
                })?;
                checked = true;
                note!("Hand tag verified.");
            }
            None => note!("This page has no hand-tag keys; the hand tag was not checked."),
        }
    }
    if !checked {
        note!("WARNING: no tag was checked — the message may have been altered in transit.");
    }
    let digits = pad::decipher(cipher.as_slice(), page.pad()).map_err(paper_err)?;
    page.clear();
    let mut text = checkerboard::from_digits(digits.as_slice()).map_err(|e| {
        Fail::new(
            exit::NOTHING,
            format!("the digits do not decode — wrong page or mis-copied ciphertext ({e})"),
        )
    })?;
    // Trailing spaces from length padding.
    let mut len = text.len();
    while len > 0 && text.as_slice()[len - 1] == b' ' {
        len -= 1;
    }
    text.truncate(len);
    let body = String::from_utf8_lossy(text.as_slice()).into_owned();
    if ctx.input.is_interactive() {
        let idle = ctx.idle;
        ctx.input
            .show_timed(&body, "Press any key to close and burn", idle)?;
    } else {
        out!("{body}")?;
    }
    let mut body = body;
    body.zeroize();
    text.clear();
    note!("Closed. Destroy the page now; it has been used.");
    Ok(())
}

pub fn check_page(ctx: &mut Ctx, from: PageFrom) -> CmdResult {
    ctx.doctor_gate(false)?;
    let mut page = read_page(ctx, from)?;
    let s = page.spec();
    out!(
        "PAGE {:04} {} {:02} N {} HANDTAG {} CHECK {} OK",
        s.set_code,
        s.direction.letter(),
        s.number,
        s.pad_len,
        if s.hand_tag { "yes" } else { "no" },
        std::str::from_utf8(&page.checksum()).unwrap_or("??????")
    )?;
    page.clear();
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// cover page

pub struct CoverOpts {
    pub set_code: u16,
    pub direction: Direction,
    pub number: u8,
    pub digits: usize,
    pub hand_tag: bool,
    pub sink: Sink,
    pub rules_read: bool,
    pub paper: PaperArg,
    pub dpi: u32,
}

/// A cover page (DC-04 §3.7): the pad that turns a given ciphertext into an innocent text, in
/// a page of the same identity with fresh random tag keys.
pub fn cover(ctx: &mut Ctx, o: &CoverOpts) -> CmdResult {
    ctx.doctor_gate(false)?;
    let cipher_line = ctx
        .input
        .read_line("Ciphertext digits (spaces allowed): ")?
        .ok_or_else(|| Fail::new(exit::ERROR, "no ciphertext"))?;
    let cipher = digits_only(cipher_line.as_bytes())?;
    drop(cipher_line);
    let mut text = ctx.input.read_text_block(
        "Innocent text of exactly the same length in digits. Finish with a line containing only a dot (.) or press Ctrl-D.\n",
    )?;
    let mut innocent = checkerboard::encode(std::str::from_utf8(text.as_slice()).unwrap_or(""))
        .map_err(paper_err)?;
    text.clear();
    if innocent.len() != cipher.len() {
        let (a, b) = (innocent.len(), cipher.len());
        innocent.clear();
        return Err(Fail::new(
            exit::ERROR,
            format!("the innocent text is {a} digits, the ciphertext {b}; they must match (pad with spaces or reword)"),
        ));
    }
    if cipher.len() > o.digits {
        return Err(Fail::new(
            exit::ERROR,
            "the ciphertext is longer than the page",
        ));
    }
    if matches!(o.sink, Sink::Print(_)) && !o.rules_read {
        return Err(Fail::new(
            exit::ERROR,
            "printing a pad needs --i-have-read-the-rules (see `aska paper worksheet`)",
        ));
    }
    let cover = pad::cover_pad(cipher.as_slice(), innocent.as_slice()).map_err(paper_err)?;
    innocent.clear();
    // Fill the rest of the pad and all keys from the OS generator.
    let mut os = entropy::OsDigits::new();
    use entropy::DigitStream;
    let mut padd = LockedBuf::with_capacity(o.digits);
    padd.extend_from_slice(cover.as_slice());
    while padd.len() < o.digits {
        padd.extend_from_slice(&[b'0' + os.digit().map_err(paper_err)?]);
    }
    let mut keys = LockedBuf::with_capacity((o.digits / 2 + 2) * 4);
    if o.hand_tag {
        let mut tmp = [0u8; 4];
        for _ in 0..o.digits / 2 + 2 {
            let v = os.hand_key().map_err(paper_err)?;
            tmp = format!("{v:04}").into_bytes().try_into().expect("4 digits");
            keys.extend_from_slice(&tmp);
        }
        tmp.zeroize();
    }
    let r = os.device_key().map_err(paper_err)?;
    let s = os.device_key().map_err(paper_err)?;
    let spec = PageSpec {
        set_code: o.set_code,
        direction: o.direction,
        number: o.number,
        pad_len: o.digits,
        hand_tag: o.hand_tag,
    };
    let mut page =
        Page::assemble(spec, padd.as_slice(), keys.as_slice(), r, s).map_err(paper_err)?;
    padd.clear();
    keys.clear();
    note!("Cover page assembled: the ciphertext deciphers to the innocent text with it; its tag keys are fresh and will not verify the real message's tag.");
    let result = match &o.sink {
        Sink::Rows => emit_page_rows(ctx, &page, Label::Physical),
        sink => {
            let ro = render_opts(o.paper, o.dpi);
            let mut sheet = render::render_page(&page, Label::Physical, &ro).map_err(paper_err)?;
            let r = emit_sheets(
                ctx,
                std::slice::from_ref(&sheet),
                sink,
                Material::Pad,
                o.rules_read,
                o.dpi,
            );
            sheet.clear();
            r
        }
    };
    page.clear();
    result
}

// ---------------------------------------------------------------------------------------------
// worksheet

pub const WORKSHEET: &str = "\
ASKA PAPER MODE — WORKSHEET (not secret; print on any paper)

1. THE TABLE (text to digits). One digit for E T A O I N S; two digits for the rest.
      0 E   1 T   2 A   3 O   4 I   5 N   6 S
     70 R  71 H  72 L  73 D  74 C  75 U  76 M  77 F  78 P  79 G
     80 W  81 Y  82 B  83 V  84 K  85 X  86 J  87 Q  88 Z  89 space
     90 0  91 1  92 2  93 3  94 4  95 5  96 6  97 7  98 8  99 9
   Write AA for Å, AE for Ä, OE for Ö; punctuation as words (STOP, COMMA) or leave it out.
   Reading back: a 0–6 is a letter by itself; a 7, 8 or 9 always takes the next digit with it.

2. ENCIPHER. Write the message digits in a row. Under them, the page's pad digits from the
   first. Add each column WITHOUT carrying (7 + 5 = 2). The result is the ciphertext.
   DECIPHER: ciphertext minus pad, digit by digit, adding 10 when needed (2 − 5 = 7).

3. HAND TAG (four digits) over the CIPHERTEXT. Write the ciphertext in pairs: G1 G2 … (a
   lone last digit is its own group). L = number of ciphertext digits. With the page's keys:
      sum = A0 × L + A1 × G1 + A2 × G2 + … + B
   Reduce: split sum = q × 10000 + r and replace it by r + 27 × q; repeat until below 9973.
   (Because 10000 = 9973 + 27.) The result, as four digits, is the tag. The receiver recomputes
   it from the received ciphertext BEFORE deciphering; a difference means the message was
   altered or the wrong page was used.

4. SEND the ciphertext in groups of five, then the tag. Any channel will do.

5. RULES. One page, one message. Write on glass or a single sheet on a hard surface — never on
   a pad of paper (impressions). Never photograph a page. Destroy the page and the working
   sheet at once: soluble paper into water, STIR until nothing is left; if the page was
   laser-printed the toner floats as a film — break it up and pour through a sieve or down a
   running drain. Ordinary paper: cross-cut shred to dust, or burn and stir the ash.

6. DIRECTIONS. Holder A sends with A-pages, holder B with B-pages, each in order. Never use a
   page the other side sends with.

7. DEVICE TAG (nineteen digits) is computed and checked by the app only (`aska paper encipher`
   / `decipher`); a hand user may ignore it.
";

pub fn worksheet() -> CmdResult {
    out!("{WORKSHEET}")?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// cards

/// Block cards for a sealed Block: rendered sheets, or `CARD i/n <hex>` lines in `--stdin`
/// mode (and with `--rows`).
pub fn emit_block_cards(
    ctx: &mut Ctx,
    block: &[u8],
    sink: &Sink,
    paper: PaperArg,
    dpi: u32,
) -> CmdResult {
    let chunks = cards::split_block(block).map_err(paper_err)?;
    let n = chunks.len();
    if *sink == Sink::Rows || (!ctx.input.is_interactive() && !matches!(sink, Sink::Ps | Sink::Pbm))
    {
        for (i, c) in chunks.iter().enumerate() {
            out!("CARD {}/{n} {}", i + 1, hex(c))?;
        }
        return Ok(());
    }
    let ro = render_opts(paper, dpi);
    let mut sheets = render::render_block_cards(&chunks, &ro).map_err(paper_err)?;
    note!("Block cards: {n} codes on {} sheet(s). They are noise without the key; they may be matched to the printer that made them.", sheets.len());
    let r = emit_sheets(ctx, &sheets, sink, Material::Block, true, dpi);
    for s in &mut sheets {
        s.clear();
    }
    r
}

/// Collect Block cards (camera, or `CARD hex` lines in `--stdin` mode) until the set is complete.
pub fn collect_block_cards(ctx: &mut Ctx) -> Result<zeroize::Zeroizing<Vec<u8>>, Fail> {
    let mut set = cards::CardSet::new();
    loop {
        let chunk: zeroize::Zeroizing<Vec<u8>> = if ctx.input.is_interactive() {
            ctx.scan_bytes()?
        } else {
            match ctx.input.read_line("")? {
                None => return Err(Fail::new(exit::ERROR, "card set incomplete")),
                Some(l) if l.trim().is_empty() => {
                    return Err(Fail::new(exit::ERROR, "card set incomplete"))
                }
                Some(l) => {
                    let t = l.trim();
                    let hexpart = t.rsplit(' ').next().unwrap_or(t);
                    zeroize::Zeroizing::new(
                        unhex(hexpart)
                            .ok_or_else(|| Fail::new(exit::ERROR, "a CARD line must carry hex"))?,
                    )
                }
            }
        };
        match set.accept(&chunk) {
            Ok(cards::Accepted::Added { have, count }) => {
                note!("Card accepted — {have} of {count}.")
            }
            Ok(cards::Accepted::Duplicate { have, count }) => {
                note!("Already have that card — {have} of {count}.")
            }
            Ok(cards::Accepted::Complete) => {
                note!("All cards read.");
                break;
            }
            Err(e) => note!("{e}"),
        }
    }
    set.block()
        .ok_or_else(|| Fail::new(exit::ERROR, "the cards did not assemble into a Block"))
}

pub fn share_cards(
    ctx: &mut Ctx,
    sink: &Sink,
    threshold: Option<u8>,
    paper: PaperArg,
    dpi: u32,
) -> CmdResult {
    ctx.doctor_gate(false)?;
    let mut shares: Vec<SecretLine> = Vec::new();
    loop {
        let prompt = format!(
            "Share {} (askas1…; 'scan' for the camera; empty line to finish): ",
            shares.len() + 1
        );
        let Some(line) = ctx.read_material(&prompt)? else {
            break;
        };
        if !line.trim().to_ascii_lowercase().starts_with("askas1") {
            note!("Not a Share (askas1…).");
            continue;
        }
        shares.push(line);
    }
    if shares.is_empty() {
        return Err(Fail::new(exit::ERROR, "no Shares given"));
    }
    let total = shares.len() as u8;
    let k = threshold.unwrap_or(total.clamp(1, 2));
    let ro = render_opts(paper, dpi);
    let mut sheets = Vec::new();
    for (i, s) in shares.iter().enumerate() {
        if !ctx.input.is_interactive() && *sink == Sink::Rows {
            out!(
                "{}",
                cards::share_card_text(s.trim(), i as u8 + 1, total, k).trim_end()
            )?;
            continue;
        }
        sheets.push(
            render::render_share_card(s.trim(), i as u8 + 1, total, k, &ro).map_err(paper_err)?,
        );
    }
    if sheets.is_empty() {
        return Ok(());
    }
    note!(
        "{} Share card(s). Give each to a different person; never two on one printer tray at once.",
        sheets.len()
    );
    let r = emit_sheets(ctx, &sheets, sink, Material::Share, true, dpi);
    for s in &mut sheets {
        s.clear();
    }
    r
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}
