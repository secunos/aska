//! The worksheet (DC-04 §3.5, §5.1): the table, the arithmetic, the hand tag, the rules, the
//! worked example of §12 and blank working grids. **Not secret** — it is the same for every
//! booklet and may be printed on any printer and any paper. It exists so that a hand user never
//! has to remember a rule: the page carries the pad, the worksheet carries the method.
//!
//! The text is plain ASCII so that the terminal, the graphical client and the bitmap font
//! (which has no accents) show exactly the same words.

use crate::render::{Raster, RenderOptions, ADVANCE, GLYPH_H};

/// The worksheet as text (the terminal, the graphical client's viewer, and sheet 1).
pub const TEXT: &str = "\
ASKA PAPER MODE - WORKSHEET
Not secret: print it on any paper and keep it with the booklet.

1. THE TABLE - text to digits and back
      0 E   1 T   2 A   3 O   4 I   5 N   6 S
     70 R  71 H  72 L  73 D  74 C  75 U  76 M  77 F  78 P  79 G
     80 W  81 Y  82 B  83 V  84 K  85 X  86 J  87 Q  88 Z  89 space
     90 0  91 1  92 2  93 3  94 4  95 5  96 6  97 7  98 8  99 9
   Capitals only. Write AA for A-ring, AE for A-umlaut, OE for O-umlaut; other
   accents are dropped. Punctuation as words (STOP, COMMA) or left out. A digit in
   the text takes two digits. Reading back: a 0-6 is one letter by itself; a 7, 8
   or 9 always takes the next digit with it.
   Example: MEET 14 NOV = 76 0 0 1 89 91 94 89 5 3 83 -> 76001 89919 48953 83

2. BEFORE YOU START
   Check the page: add up the digits of each pad row; the last digit of the sum must
   equal the check digit at the end of the row. A row that fails was copied wrongly:
   fix it from the other copy, or skip the page. The sender uses the next unused page
   of HIS OWN direction (holder A sends with A-pages, holder B with B-pages), in
   order. One page, one message.

3. ENCIPHER (sender)
   Row M: the message digits from the table, in groups of five.
   Row K: the page's pad digits from the FIRST digit of row 01, under them, one for one.
   Row C: add each column and keep only the last digit (7 + 5 = 12 -> 2; 9 + 1 -> 0).
   The message may not need more digits than the page has: shorten it rather than
   use two pages. Optional: add 89 (space) codes at the end, so the length says nothing.

4. HAND TAG (sender, over row C: four digits)
   a) L = the number of digits in row C.
   b) Cut row C into PAIRS from the left: G1 G2 G3 ... (an odd last digit is a group
      by itself).
   c) From the page's key rows take a0, a1, a2, ... (four digits each, in order) and
      B (the last).
   d) SUM = a0 x L + a1 x G1 + a2 x G2 + ... + B  (ordinary multiplication and addition)
   e) REDUCE while SUM is 9973 or more: split SUM = Q x 10000 + R (R = the last four
      digits); the new SUM is R + 27 x Q. Repeat. (Because 10000 = 9973 + 27.)
   f) The result, written as four digits with leading zeros, is the TAG.
   SEND: row C in groups of five, then the four-digit tag. Any channel will do.

5. DECIPHER (receiver)
   a) FIRST recompute the tag (step 4) from the received digits with the matching
      page. If it differs, the message was altered, a digit was lost, or it is the
      wrong page: stop and ask for a repeat. Do not decipher.
   b) Row C: the received digits. Row K: the pad digits of the same page from the first.
   c) Row M: subtract each column; when the result would be negative add 10 first
      (2 - 5: 12 - 5 = 7).
   d) Read row M back through the table (the rule in step 1).
   Both sides destroy the page and every working sheet at once (step 7).

6. HOW TO WRITE
   On a single sheet on glass or a hard smooth surface - never on a pad or a stack
   (impressions go through several sheets). Soft pencil or water-soluble ink. Never
   photograph a page; never type it into anything but the app. Keep the booklet where
   you would keep cash.

7. DESTRUCTION (the page and the working sheets, immediately)
   Soluble paper: into water, STIR until no fragment is left. If the page was
   LASER-printed the toner floats as a film that stays legible: break it up and pour
   it through a fine sieve or down a running drain; never leave the glass standing.
   Hand-written or inkjet: stir and pour. Ordinary paper: cross-cut shred to dust, or
   burn and stir the ash. Shredding alone is not destruction.

8. THE DEVICE TAG (nineteen digits) and the keys R and S are for the app only
   ('aska paper encipher' / 'decipher', or the Paper page). A hand user ignores them.
";

/// The worked example (DC-04 §12) as text: sheet 2, and the guide's appendix.
pub const EXAMPLE: &str = "\
WORKED EXAMPLE
Check your arithmetic against it before the first real message.

The example page (deliberately short: 60 pad digits; a real page has 200, 400 or 600):

   SET 7342  PAGE A 03  N 060  EXAMPLE                         CHECK
   PAD   01  27974 91320 99457 14837 24546 26642                  2
         02  37595 14809 46439 19661 36317 51385                  2
   HAND-TAG KEYS  a0 ... a30, then B
   A000  5849 1573 2769 6170 2106 5152 6831 4251 1107 6609
   A010  5096 2484 0272 5425 7676 2832 7115 6601 5314 5029
   A020  8369 9720 9153 0768 0658 7564 9899 7707 5061 0499
   A030  4489   B 2691
   DEVICE KEYS   R 1231961752939033616   S 1450779715753509526

MESSAGE: MEET 14 NOV NORTH GATE

1. Table:   M  E E T sp  1  4 sp N O  V sp N O  R T  H sp  G A T E
           76  0 0 1 89 91 94 89 5 3 83 89 5 3 70 1 71 89 79 2 1 0
   M = 76001 89919 48953 83895 37017 18979 210          (L = 33 digits)

2. Add the pad (the first 33 digits of the page), column by column, no carrying:
   M   76001 89919 48953 83895 37017 18979 210
   K   27974 91320 99457 14837 24546 26642 375
   C   93975 70239 37300 97622 51553 34511 585

3. Hand tag over C.  Pairs: 93 97 57 02 39 37 30 09 76 22 51 55 33 45 11 58 5
   a0 x L  = 5849 x 33 = 193017
   a1 x G1 = 1573 x 93 = 146289        a10 x G10 = 5096 x 22 = 112112
   a2 x G2 = 2769 x 97 = 268593        a11 x G11 = 2484 x 51 = 126684
   a3 x G3 = 6170 x 57 = 351690        a12 x G12 = 0272 x 55 =  14960
   a4 x G4 = 2106 x 02 =   4212        a13 x G13 = 5425 x 33 = 179025
   a5 x G5 = 5152 x 39 = 200928        a14 x G14 = 7676 x 45 = 345420
   a6 x G6 = 6831 x 37 = 252747        a15 x G15 = 2832 x 11 =  31152
   a7 x G7 = 4251 x 30 = 127530        a16 x G16 = 7115 x 58 = 412670
   a8 x G8 = 1107 x 09 =   9963        a17 x G17 = 6601 x  5 =  33005
   a9 x G9 = 6609 x 76 = 502284        B                     =   2691
   SUM = 3314972
   Reduce:  3314972 = 331 x 10000 + 4972  ->  4972 + 27 x 331 = 4972 + 8937 = 13909
            13909   =   1 x 10000 + 3909  ->  3909 + 27 x 1   = 3936  (below 9973: stop)
   TAG = 3936

4. Send:   93975 70239 37300 97622 51553 34511 585  3936

5. Receiver: recomputes the tag from the 33 received digits with page A 03 -> 3936.
   C   93975 70239 37300 97622 51553 34511 585
   K   27974 91320 99457 14837 24546 26642 375
   M   76001 89919 48953 83895 37017 18979 210     (second column: 3 - 7 -> 13 - 7 = 6)
   Table back: 76 0 0 1 89 91 94 89 5 3 83 89 5 3 70 1 71 89 79 2 1 0
             = MEET 14 NOV NORTH GATE

6. Both destroy page A 03 and the working sheets. The device tag of this message,
   which only the app computes and checks, is 0876449745860556196.
";

/// Line height in pixels at `scale`.
fn line_height(scale: usize) -> usize {
    GLYPH_H * scale + 6 * scale / 2 + 2
}

/// Break one line into pieces of at most `cols` characters on spaces; a continuation keeps the
/// line's indentation plus three.
fn wrap(line: &str, cols: usize) -> Vec<String> {
    if line.len() <= cols {
        return vec![line.to_string()];
    }
    let indent = line.len() - line.trim_start().len();
    let cont = " ".repeat((indent + 3).min(cols / 2));
    let mut out = Vec::new();
    let mut cur = " ".repeat(indent);
    let mut has_word = false;
    for word in line.trim_start().split(' ') {
        if has_word && cur.len() + 1 + word.len() > cols {
            out.push(std::mem::replace(&mut cur, cont.clone()));
            has_word = false;
        }
        if has_word {
            cur.push(' ');
        }
        cur.push_str(word);
        has_word = true;
    }
    if has_word {
        out.push(cur);
    }
    out
}

/// Text sheets: `text` laid out line by line, paginated.
fn text_sheets(text: &str, opts: &RenderOptions) -> Vec<Raster> {
    let (w, h) = opts.paper.pixels(opts.dpi);
    let sc = opts.scale;
    let cols = (w - 2 * opts.margin) / (ADVANCE * sc);
    let mut sheets = Vec::new();
    let mut r = Raster::new(w, h);
    let mut y = opts.margin;
    for (i, line) in text.lines().enumerate() {
        let big = i == 0; // the title
        for piece in wrap(line, cols) {
            let s = if big { sc + 1 } else { sc };
            if y + line_height(s) > h - opts.margin {
                sheets.push(std::mem::replace(&mut r, Raster::new(w, h)));
                y = opts.margin;
            }
            r.text(opts.margin, y, s, piece.as_bytes());
            y += line_height(s);
        }
    }
    sheets.push(r);
    sheets
}

/// The blank working sheet: four M/K/C blocks of 25 cells (100 digits) and the hand-tag table.
fn working_sheet(opts: &RenderOptions) -> Raster {
    let (w, h) = opts.paper.pixels(opts.dpi);
    let sc = opts.scale;
    let u = opts.dpi as usize; // 150 units = one inch; sizes below are in 1/150 in
    let px = |v: usize| v * u / 150;
    let mut r = Raster::new(w, h);
    let x0 = opts.margin;
    let mut y = opts.margin;
    r.text(x0, y, sc + 1, b"WORKING SHEET - DESTROY WITH THE PAGE");
    y += line_height(sc + 1) + px(6);
    r.text(
        x0,
        y,
        sc,
        b"M = MESSAGE DIGITS   K = PAD DIGITS   C = M + K (SEND) OR M = C - K (RECEIVE)",
    );
    y += line_height(sc) + px(10);

    let cell = px(40);
    let gap = px(8);
    let label_w = px(30);
    let rule = px(2).max(1);
    let labels: [&[u8]; 3] = [b"M", b"K", b"C"];
    for block in 0..4 {
        // Group numbers above the first block only.
        if block == 0 {
            for g in 0..5 {
                let gx = x0 + label_w + g * (5 * cell + gap);
                let t = format!("{}-{}", g * 5 + 1, g * 5 + 5);
                r.text(gx, y, sc, t.as_bytes());
            }
            y += line_height(sc);
        }
        for (row, lab) in labels.iter().enumerate() {
            let ry = y + row * cell;
            r.text(x0, ry + (cell - GLYPH_H * sc) / 2, sc, lab);
            for g in 0..5 {
                let gx = x0 + label_w + g * (5 * cell + gap);
                // Horizontal rules of this group's row.
                r.fill_rect(gx, ry, 5 * cell + rule, rule);
                r.fill_rect(gx, ry + cell, 5 * cell + rule, rule);
                for c in 0..=5 {
                    r.fill_rect(gx + c * cell, ry, rule, cell + rule);
                }
            }
        }
        y += 3 * cell + px(18);
    }

    // Hand-tag table: two columns of rows (a0 x L, G1 ..., then B), no running sum — the
    // products are added at the end into the SUM box.
    y += px(6);
    r.text(x0, y, sc + 1, b"HAND TAG");
    y += line_height(sc + 1) + px(4);
    r.text(
        x0,
        y,
        sc,
        b"L = DIGITS IN C: ____    PAIRS G1 G2 ... FROM THE LEFT (AN ODD LAST DIGIT ALONE)",
    );
    y += line_height(sc) + px(6);
    let cols: [(&[u8], usize); 4] = [
        (b"", px(120)),
        (b"G", px(80)),
        (b"A (KEY)", px(110)),
        (b"A X G", px(190)),
    ];
    let table_w: usize = cols.iter().map(|c| c.1).sum();
    let col_gap = px(40);
    let row_h = px(30);
    let avail = h - opts.margin - y - row_h - 2 * line_height(sc) - px(16);
    let per_col = 26usize.min(avail / row_h);
    for t in 0..2 {
        let tx = x0 + t * (table_w + col_gap);
        let mut cx = tx;
        for (name, cw) in cols.iter() {
            r.text(cx + px(4), y + (row_h - GLYPH_H * sc) / 2, sc, name);
            cx += cw;
        }
        for i in 0..per_col {
            let ry = y + row_h + i * row_h;
            r.fill_rect(tx, ry, table_w, rule);
            let lab = if t == 0 && i == 0 {
                "A0 X L".to_string()
            } else if t == 1 && i == per_col - 1 {
                "B".to_string()
            } else {
                let j = t * per_col + i;
                format!("A{j} X G{j}")
            };
            r.text(
                tx + px(4),
                ry + (row_h - GLYPH_H * sc) / 2,
                sc,
                lab.as_bytes(),
            );
            let mut cx = tx;
            for (_, cw) in cols.iter() {
                r.fill_rect(cx, ry, rule, row_h);
                cx += cw;
            }
            r.fill_rect(tx + table_w, ry, rule, row_h);
        }
        r.fill_rect(tx, y + row_h + per_col * row_h, table_w + rule, rule);
    }
    y += row_h + per_col * row_h + px(10);
    r.text(
        x0,
        y,
        sc,
        b"SUM = ________   REDUCE: SUM = Q X 10000 + R  ->  R + 27 X Q = ________  ->  ________",
    );
    y += line_height(sc);
    r.text(
        x0,
        y,
        sc,
        b"TAG (FOUR DIGITS, BELOW 9973) = ____    SEND: ROW C IN FIVES, THEN THE TAG",
    );
    r
}

/// Render the worksheet: the text (one or two sheets), the worked example, the working sheet.
pub fn render(opts: &RenderOptions) -> Vec<Raster> {
    let mut sheets = text_sheets(TEXT, opts);
    sheets.extend(text_sheets(EXAMPLE, opts));
    sheets.push(working_sheet(opts));
    sheets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::render::Paper;

    #[test]
    fn text_is_ascii_and_narrow() {
        for t in [TEXT, EXAMPLE] {
            assert!(t.is_ascii());
            for l in t.lines() {
                assert!(l.len() <= 88, "line too long: {l}");
            }
        }
    }

    #[test]
    fn example_matches_the_reference_vector() {
        // The worked example's numbers come from DC-04 §12; recompute them with the crate.
        use crate::{checkerboard, handtag, pad};
        let pad_digits = b"279749132099457148372454626642375951480946439196613631751385";
        let m = checkerboard::encode("MEET 14 NOV NORTH GATE").unwrap();
        assert_eq!(m.as_slice(), b"760018991948953838953701718979210");
        let c = pad::encipher(m.as_slice(), &pad_digits[..m.len()]).unwrap();
        assert_eq!(c.as_slice(), b"939757023937300976225155334511585");
        let mult: Vec<u8> = [
            5849u16, 1573, 2769, 6170, 2106, 5152, 6831, 4251, 1107, 6609, 5096, 2484, 272, 5425,
            7676, 2832, 7115, 6601, 5314, 5029, 8369, 9720, 9153, 768, 658, 7564, 9899, 7707, 5061,
            499, 4489,
        ]
        .iter()
        .flat_map(|a| format!("{a:04}").into_bytes())
        .collect();
        let keys = handtag::HandKeys {
            multipliers: &mult,
            offset: b"2691",
        };
        let (sum, tag) = handtag::compute_with_sum(c.as_slice(), &keys).unwrap();
        assert_eq!(sum, 3_314_972);
        assert_eq!(tag, 3936);
        assert!(EXAMPLE.contains("SUM = 3314972") && EXAMPLE.contains("TAG = 3936"));
    }

    #[test]
    fn renders_on_both_papers() {
        for paper in [Paper::A4, Paper::Letter] {
            let opts = RenderOptions {
                paper,
                ..RenderOptions::default()
            };
            let sheets = render(&opts);
            assert!((3..=5).contains(&sheets.len()), "{} sheets", sheets.len());
            for s in &sheets {
                let dark = s
                    .rows()
                    .iter()
                    .map(|b| b.count_ones() as usize)
                    .sum::<usize>();
                assert!(dark > 2000, "a sheet is nearly blank");
            }
        }
    }

    #[test]
    fn wrap_keeps_words_and_indent() {
        let w = wrap("   abc def ghi jkl", 10);
        assert_eq!(w, vec!["   abc def", "     ghi", "     jkl"]); // continuation capped at cols / 2
        assert_eq!(wrap("short", 80), vec!["short"]);
    }
}
