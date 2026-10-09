# Aska — Design Change DC-04: The Paper Mode

- **Version:** 0.2 — 9 October 2026 (v0.1 approved by the owner on 9 October with every recommendation of §10; v0.2 folds in the three adjustments made while building the `aska-paper` crate in step 2 — see the change log)
- **Scope:** everything the 1.2 plan's proposals P-1…P-8 left to decide: the exact pad system (alphabet, arithmetic, the two integrity tags, page and booklet format, checksums), the randomness pipeline and its assurance labels, the printing and destruction rules and how the clients enforce them, the on-device path, the Block and Share cards, the client surfaces, and the specification deltas. Written from the standpoint of the person who will later be handed the paper, the printer, the disk and the room — a forensic examiner — and asks what each of them would still tell.
- **Does not change:** the Block Format, the wire protocol, the relay, the profile file. The pad is a paper artefact; its ciphertext is a string of digits.
- **Sibling documents:** *Aska 1.2 Plan v0.1*; *Decision Record and Threat Model v0.5* (D-02, D-12, RM-01, RM-07); *Option C Concept* §2.7, use cases 4–5; *Research 06 — pen-and-paper methods*; *Client Design v0.7*; *Block Format draft 0.7*.

---

## 1. What the examiner would find, and what this design does about it

The one-time pad has never been broken as mathematics. Every documented failure is an artefact left behind. The table lists what a competent examiner looks for after a seizure, in the order they would look, and the design rule that answers each. Items marked **new finding** were not in the research report and change earlier assumptions.

| # | What the examiner looks at | What it yields today, if nothing is done | Design rule in DC-04 |
|---|---|---|---|
| F-1 | **The print spool** (`/var/spool/cups/d*`) and its slack space on a persistent disk | A complete copy of every printed pad page, even after the job is "deleted" (unlinked, not wiped; on SSD, not even reliably unlinked) | A pad is printed **only when the spool directory is on volatile storage** (tmpfs/ramfs — Tails, or a system set up that way); otherwise the clients refuse and offer hand copy (§5.2). |
| F-2 | **CUPS logs** (`page_log`, `access_log`, `error_log`) and the printer's own job history | Job title, user, page count, time — proof that *something* was printed, when, how many pages | Job title is a fixed, meaningless word; the clients tell the user that the logs and the printer's memory still record a job (§5.2, residual). |
| F-3 | **The printer** — MFP hard disks keep job images; network printers received the job in clear over the LAN; any printer can be matched to a page by its mechanical defects (banding, drum marks) | A copy of the page on the printer; a LAN capture; attribution of a surviving card to a printer | Pad printing only to a **locally attached (USB) printer**; the guide says "a simple printer without storage, bought for cash, used for nothing else"; Block cards may be matched to a printer if they survive — stated (§5.3, T-33). |
| F-4 | **Printer tracking dots** (machine identification code) | Colour lasers embed serial and time in yellow dots; for monochrome lasers no yellow-dot scheme is known, but other markings (laser-intensity modulation) were called feasible and never ruled out; inkjets are not known to carry a code | **Colour laser never.** For pads: hand copy or inkjet preferred (also for F-5); monochrome laser accepted with the F-5 destruction step (§5.3). |
| F-5 | **The dissolved page — new finding.** Water-soluble paper dissolves; **laser toner does not**: the fused toner letters float off as a film that keeps the printed shapes and was still legible the next morning in a documented test. Inkjet ink and water-soluble pen inks disintegrate; ballpoint "shreds". | A complete pad page floating in the glass | **D-12 amended:** pad pages are hand-copied in water-soluble ink or printed with a dye inkjet; a laser-printed pad page must be **stirred to fragments and the water poured through a sieve or flushed**, and the guide says so; the client's checklist asks which printer type is in use and shows the matching destruction step (§5.4). |
| F-6 | **Impressions** on the sheet below (ESDA reads several sheets deep) | The plaintext written by hand, recovered from the pad of paper under it | "Write on glass or a single sheet on a hard surface" — printed on every page and on the worksheet (§3.6). |
| F-7 | **Photographs** of pad pages (camera roll, cloud, thumbnails, "recently deleted") | The whole booklet | Never photograph; the device path reads a page with the camera **into locked memory only** and the capture buffers are blanked (1.1.0's `aska-scan`) (§6). |
| F-8 | **Both booklets** — identical pages found with two people | Proof that two specific people hold matching key material | Accepted and stated: the booklet *is* the shared secret; the set code on the pages is the smallest possible link (4 digits) and can be left off at the owner's choice (§3.5, open question Q-3). |
| F-9 | **Pad reuse** — two messages enciphered with the same page (both parties sent at once; a page copied twice) | Both messages readable by subtraction (VENONA) | Pages are **directional** (A-pages for one holder's sending, B-pages for the other's) so simultaneous sending cannot collide; the device path marks a page used for the Session; the printed rule says "one page, one message, then destroy" (§3.5). |
| F-10 | **The device used to generate or encipher** (swap, hibernation file, core dumps, GPU memory, toolkit caches) | Pad digits and plaintext | All pad material and plaintext in `LockedBuf`s (pinned, dump-excluded, wiped); digits rendered with the 1.1 word-at-a-time viewer, never a label or text view; typed digits enter through the keypad widget; the print rendering writes into a locked raster that is wiped after the page is spooled (§8). Residual: GPU and compositor memory, as for notes (Client Design). |
| F-11 | **Weak randomness** — a pad that is not uniform (biased dice, a static camera scene) | The pad is breakable; the proof is void | Two independent sources; a seeded **universal-hash extractor** with an explicit min-entropy budget; health tests on the raw source and statistical tests on the pad; the booklet is labelled **physical** or **seeded** so the user knows which guarantee they hold (§4). |
| F-12 | **The ciphertext** — digits posted in public | Message length (in digits), the fact of a posting; nothing else | Stated. Length hiding by padding is offered on the device path, not by hand (§3.2, Q-5). |
| F-13 | **The hand-copy screen** — shoulder surfing, screen capture, window thumbnails | Pad digits on screen | One row at a time, the capture-status line from 1.1, the Plasma hide-from-capture note; nothing selectable (§5.5). |
| F-14 | **Block cards** that survive | Random bytes; a QR with a six-byte header | No note, no key; at most "this person had a QR card of random data" and F-3 attribution (§7). |

Sources for F-4 and F-5: the printer-tracking-dots article and the EFF list (research 06 §5), and a documented dissolving-paper test in which laser-printed letters floated intact while inkjet and pen inks disintegrated (links in §14).

---

## 2. Terms

| Term | Meaning |
|---|---|
| **Pad** | A sequence of uniformly random decimal digits used once. |
| **Page** | The unit of use: one message, one page. Holds pad digits for the message, the keys of the two integrity tags, check digits, a checksum and (printed) a QR of itself. |
| **Booklet** | 2·P pages generated together: P **A-pages** (used by holder A to send) and P **B-pages** (used by holder B to send). Printed twice, identically (copy 1 and copy 2). |
| **Set code** | Four decimal digits chosen at random, printed on every page of both copies, so the holders know their booklets match. Not secret. |
| **Checkerboard** | The fixed public table that turns text into digits and back (§3.1). |
| **Hand tag** | A four-digit one-time authentication tag a person can compute with pencil (§3.3). |
| **Device tag** | A nineteen-digit one-time authentication tag computed and checked by the app (§3.4). |
| **Physical / seeded** | The two assurance labels of a booklet (§4.4). |
| **Block card / Share card** | An ordinary Block or Share printed as QR for transport on paper (§7). |

---

## 3. The pad system

### 3.1 Alphabet and checkerboard (fixed, public)

Text is first normalised: NFKC, upper case, the Nordic letters as **AA, AE, OE** (Å, Ä/Æ, Ö/Ø), other accented letters to their base letter, every other character refused (the clients say which). Punctuation is written as words (STOP, COMMA) or left out. The alphabet has 37 symbols: 26 letters, space, 10 digits.

Seven frequent letters take one digit; three digits (7, 8, 9) are prefixes of two-digit codes. The code is prefix-free: a 0–6 is always a complete symbol, a 7–9 always starts a pair.

| Code | Symbol | | Code | Symbol | | Code | Symbol | | Code | Symbol |
|---|---|---|---|---|---|---|---|---|---|---|
| 0 | E | | 70 | R | | 80 | W | | 90 | 0 |
| 1 | T | | 71 | H | | 81 | Y | | 91 | 1 |
| 2 | A | | 72 | L | | 82 | B | | 92 | 2 |
| 3 | O | | 73 | D | | 83 | V | | 93 | 3 |
| 4 | I | | 74 | C | | 84 | K | | 94 | 4 |
| 5 | N | | 75 | U | | 85 | X | | 95 | 5 |
| 6 | S | | 76 | M | | 86 | J | | 96 | 6 |
| | | | 77 | F | | 87 | Q | | 97 | 7 |
| | | | 78 | P | | 88 | Z | | 98 | 8 |
| | | | 79 | G | | 89 | *space* | | 99 | 9 |

*Table 1 — The checkerboard. "ETAOINS" on the single digits; R H L D C U M F P G on 7x; W Y B V K X J Q Z and space on 8x; the ten digits on 9x.* English text averages about 1.5 digits per character; the worst case is 2.

**Why this table.** The straddling checkerboard with modulo-10 addition is the hand method with the longest field record (research 06 §1, §2) and the simplest arithmetic a person does reliably. The table is public: the security is in the pad. Letters-modulo-26 was rejected as slower by hand and less forgiving of errors.

### 3.2 Enciphering and deciphering

Message digits m₁…m_L (from Table 1). Page pad digits k₁…k_N, used from the first. Sender: cᵢ = (mᵢ + kᵢ) mod 10. Receiver: mᵢ = (cᵢ − kᵢ) mod 10, then Table 1 backwards. L ≤ N; a longer message takes a second page (the guide says: shorten it instead). The ciphertext is c₁…c_L followed by the tag(s) (§3.3–3.4), written in groups of five.

What the ciphertext reveals: its length in digits, and nothing else — for every same-length text there is a pad that produces it (§3.7). The device path can pad a message with trailing spaces (code 89) to a chosen length before enciphering; by hand that is extra work and is left to the user (Q-5).

### 3.3 Hand tag (four digits, prime 9 973)

Computed over the **ciphertext** (the receiver checks before deciphering and never handles a forged plaintext). Let the ciphertext be grouped in pairs G₁…G_J (G_j = 10·c₂ⱼ₋₁ + c₂ⱼ; if L is odd the last group is the single final digit). The page carries one-time multipliers a₀, a₁, …, a_{N/2} and an offset b, each a number in 0…9 972 printed as four digits.

> **tag = ( a₀·L + a₁·G₁ + a₂·G₂ + … + a_J·G_J + b ) mod 9 973**, written as four digits with leading zeros.

The sender appends the four digits to the ciphertext; the receiver recomputes and compares. Each page's multipliers are used for one message only.

**Security.** For two different ciphertexts the difference of the sums is a₀·(L−L′) + Σ a_j·(G_j − G′_j); at least one coefficient is non-zero and lies in −9 972…9 972 without 0, hence invertible modulo the prime, so the difference is uniform and a forgery succeeds with probability **1/9 973 ≈ 10⁻⁴** per attempt — unconditionally, regardless of computing power. (Multipliers must be uniform in 0…9 972, not 0…9 999; generation uses rejection, §4.3.)

**By hand.** J multiplications of a two-digit by a four-digit number (two partial products each), one running sum, one reduction. The reduction uses **10 000 ≡ 27 (mod 9 973)**: split the sum as *x = q·10 000 + r* and replace it by *r + 27·q*; repeat until below 9 973. A 33-digit ciphertext (17 groups) takes about fifteen minutes with the worksheet (§12 shows every step). Cost on the page: (N/2 + 1)·4 + 4 digits of key — for N = 400, **808 digits**. The hand tag is optional per booklet (Q-2); the default is on.

### 3.4 Device tag (nineteen digits, prime 2⁶¹ − 1)

Computed by the app from the ciphertext, verified by the app. Keys: r and s, uniform in 0…p−1 with p = 2 305 843 009 213 693 951, printed as nineteen digits each. The ciphertext digits are read in groups of eighteen as integers M₁…M_K (the last group shorter); the sequence hashed is [L, M₁, …, M_K] by Horner's rule:

> h ← 0; for x in [L, M₁, …, M_K]: h ← (h + x)·r mod p; **tag = (h + s) mod p**, nineteen digits with leading zeros.

Forgery probability ≤ (K+2)/p ≈ **2⁻⁵⁵** for a full page; unconditional. The leading length term binds the length, so no padding convention is needed. Implementation: 128-bit intermediate, constant-time reduction modulo the Mersenne prime (shift-and-add), keys and tag in locked memory. Truncation to twelve digits (≈ 40 bits) is possible for shorter messages; the default is the full tag (Q-4).

### 3.5 Page and booklet

**Page identity:** set code (4 digits) · direction (A or B) · page number (two digits, 01…P). Example: `7342 A 03`. A booklet has P A-pages and P B-pages, P chosen at generation (default 10, maximum 50). Holder A sends with A-pages in order, holder B with B-pages; each holder's copy carries both kinds, so a page is identified unambiguously and two senders can never use the same page at the same time (F-9).

**Page content (N = 400 pad digits, the default; 200 and 600 selectable):**

| Section | Content | Digits | Layout |
|---|---|---|---|
| Header | set code, direction, page number, assurance label (PHYSICAL / SEEDED), rules line | — | top |
| 1 Pad | k₁…k_N in groups of five, ten groups per row, row index at left, **row check digit** (sum of the row's digits mod 10) at right | 400 + 8 | 8 rows |
| 2 Hand-tag keys | a₀ … a₂₀₀, four digits each, ten per row with row check digits; then b | 804 + 4 + 21 | 21 rows |
| 3 Device-tag keys | r, s | 38 | 1 row |
| 4 Checksum | six digits: SHA3-256 of the canonical page string (§3.6), reduced mod 10⁶ | 6 | footer |
| QR | the canonical string in numeric mode, error correction M | — | right margin |

About 1 280 digits; on A4 in a 10–11 pt monospaced face with the QR beside the pad block, one page per sheet. The 200-digit page fits A5. The **worksheet** (one per booklet, not secret, printed on ordinary paper) carries Table 1, the add/subtract tables, the hand-tag procedure with the 10 000 ≡ 27 reduction, the rules and a blank layout.

**Canonical string** (hashed and encoded in the QR) — **all decimal digits**, so the QR uses its numeric mode: `1` (format version) ‖ set code (4) ‖ direction (`1` = A, `2` = B) ‖ page number (2) ‖ N as three digits ‖ pad digits ‖ hand-tag flag (`1` = keys follow, `0` = none) ‖ hand-tag keys (a₀…a_{N/2}, then b, four digits each, when present) ‖ r (19) ‖ s (19). The checksum is SHA3-256 of this string, its first eight bytes as a big-endian number modulo 10⁶, six digits; the QR payload is the canonical string followed by the checksum. The clients verify the checksum on every read (scan or typed) and refuse a page that fails. The printed header shows the direction as the letter A or B.

### 3.6 Printed rules

Every page carries, in one line: **"Use once · write on glass · never photograph · dissolve and stir after use"**; the worksheet carries the long form (§5.4). The page number and set code are printed small; the pad block large.

### 3.7 Deniability and cover pages

For any ciphertext c and any text m′ of the same digit length there is a pad k′ = c − m′ (mod 10) that "decrypts" c to m′. The device path offers **Make a cover page**: given a ciphertext and an innocent text of the same length it prints (or shows for hand copy) a page with the cover pad in the pad block and fresh random tag keys, in the same layout and with the same set code and page number as the destroyed real page. The hand tag of the real message will not verify against the cover page's keys; a coerced receiver can say the tag was never checked or copied wrongly — the design cannot do better, and the guide says so. Whether to ship cover pages in 1.2 is **Q-6**: the capability is in the concept paper (use case 5, step 5), but a cover page is itself a made object whose existence an examiner may infer from the app's feature list.

---

## 4. Randomness

### 4.1 Requirement

A page's pad digits, tag multipliers and tag keys must be uniform and independent. The one-time pad's proof needs **about 3.32 bits of true min-entropy per digit** — for a default booklet (20 pages × ~1 280 digits) about **85 000 bits**. That volume rules out dice and keyboard timing as the *only* physical source (a d6 roll gives 2.58 bits; 85 000 bits is 33 000 rolls). Only a camera or a hardware noise source can supply it. This is the first thing the design must be honest about.

### 4.2 Sources

| Source | How | Expected rate | Role |
|---|---|---|---|
| OS CSPRNG (`getrandom`) | 64-byte blocks | unlimited | Always mixed in. Computational security floor. |
| **Camera** (1.1.0 `aska-scan` capture layer) | Least-significant bits of the luma plane, with the lens **covered** (sensor dark noise) or pointed at a textured moving scene; 60+ frames | after health tests and the §4.3 budget: 0.1–0.5 bit per pixel sample | The physical source that can carry a whole booklet. |
| **Dice** | d6 rolls typed on the keypad, pairs → one digit by rejection (36 → 30 → mod 10) | 2.58 bits per roll | Second seed for *seeded* booklets; a user with no camera. |
| Keyboard timing | inter-key intervals of free typing, low 4 bits | ≤ 1 bit per key | Second seed only; never counted toward the physical budget. |
| USB hardware RNG (later) | `/dev/hwrng` or a known USB TRNG | high | Not in 1.2 (Q-7). |

### 4.3 Pipeline

1. **Raw sampling** into a `LockedBuf`; the camera path uses the existing V4L2 buffers (dump-excluded, blanked after use).
2. **Health tests on the raw stream** (as the NIST SP 800-90B continuous tests): repetition count and adaptive proportion on 8-bit samples; a failure aborts generation with a plain message ("the camera gave repeating values — uncover the lens or move it").
3. **Min-entropy estimate**, conservative: the smaller of the most-common-value estimate (−log₂ of a 99 % upper confidence bound on the largest symbol probability — the direct min-entropy estimate) and the collision entropy (−log₂ of an upper confidence bound on Σpᵢ², which bounds min-entropy from above and so only tightens the figure when a flat-looking distribution hides structure), then **halved** (margin for correlation between neighbouring pixels and frames), then capped at 4 bits per 8-bit sample. With 65 536 samples over 256 values the confidence bound keeps even a perfect source at about 3.8 bits after the halving, so the cap is a ceiling in principle rather than a figure a camera reaches. The estimate is heuristic; the margin and cap are the design's answer to that (Q-8).
4. **Extraction** with a **seeded universal hash** (Toeplitz matrix over GF(2); the seed from the OS CSPRNG, not secret). Output length per block = estimated min-entropy − 128 bits (leftover-hash lemma, ε = 2⁻⁶⁴). This step keeps the information-theoretic claim: the output is near-uniform *whatever* the seed and *whatever* the computational power, provided the entropy estimate holds. A hash function used as a conditioner would make the claim depend on the hash.
5. **Digits** from the extracted bits by rejection: a byte < 250 → byte mod 10; a 14-bit value < 9 973 → multiplier; a 61-bit value < p → r or s.
6. **Mixing with the OS stream**, digit by digit: k = (k_phys + k_os) mod 10; a = (a_phys + a_os) mod 9 973; r = (r_phys + r_os) mod p. Adding a uniform value leaves a uniform value, so the pad is uniform if *either* stream is; the physical stream carries the proof, the OS stream the floor.
7. **Statistical tests on the finished booklet's digits**: frequency (χ², 9 d.f.), serial (pairs), runs, longest run; rejection at p < 10⁻³ aborts with the reason. These catch gross faults, not subtle ones; they are the last line, not the first.
8. Page assembly, checksums, QR rendering — all in locked memory; nothing is written anywhere.

### 4.4 Assurance labels

A booklet is labelled **PHYSICAL** when every digit's physical share came through step 4 with the budget met, and **SEEDED** otherwise (dice or typing as the only physical input, or the camera budget not met: then the physical input seeds SHAKE256 and the booklet is computationally secure from both streams — still as strong as the Block's own ciphers, but without the pad's proof). The label is printed on every page and shown before printing. The guide explains the difference in two sentences.

---

## 5. Printing, copying and destruction

### 5.1 What the clients print

| Artefact | Secret? | Where it may be printed |
|---|---|---|
| Pad pages | **yes** | Only under §5.2; otherwise hand copy (§5.5). |
| Worksheet | no | Anywhere. |
| Cover page (if Q-6 yes) | yes (it is a pad) | As pad pages. |
| Block cards | no — random bytes | Anywhere (F-3 attribution stated). |
| Share cards | a Share alone is worthless below the threshold; **treat as secret** | Any local printer; the guide says not on a shared or network printer. |

### 5.2 The printing rule (enforced by both clients)

Before a pad page is sent to a printer the client checks, and refuses unless all hold:

1. **Volatile spool:** `statfs("/var/spool/cups")` reports tmpfs or ramfs. On Tails this is always true; on Debian the guide gives the one-line mount for a session that must print pads. Nothing else is accepted — not `PreserveJobFiles No` (the file still existed on the disk).
2. **Local printer:** the chosen printer's device URI starts with `usb://` (obtained from the local CUPS over its domain socket — IPP `CUPS-Get-Printers` with `device-uri`); `ipp://`, `socket://`, `dnssd://`, `cups-pdf:/`, `file:/` are refused with the reason. This also removes "print to file" and PDF printers.
3. **Checklist ticked** (GUI) or `--i-have-read-the-rules` (CLI): soluble paper loaded; printer type chosen (inkjet / monochrome laser / other) — a colour laser is refused outright; radios off; nobody else can see the output tray.

Then: job name `Document`; GTK print operation with preview disabled (the preview path writes a temporary PDF), progress dialog off, synchronous; `GTK_PRINT_BACKENDS=cups` set by the app before GTK starts (no file backend); the page raster drawn from locked buffers and wiped after `end-print`. The CLI's `--print` spools through the same IPP request (raw PostScript or PWG raster from memory), never through a temporary file; `--stdout` writes the page image to standard output for an operator who knows what they are doing, after one warning on stderr.

After printing the client says what it could not prevent: CUPS's `page_log`/`error_log` and the printer's own job counter record that a job of so many pages was printed at that time (F-2); the user may clear the CUPS logs (the guide gives the command) and should power-cycle the printer.

### 5.3 Printer guidance (D-12 amended)

- **Never a colour laser** (tracking dots). **Never a network or shared printer** for pads or Shares (job travels in clear; printer may keep it).
- **For pad pages**, in order of preference: (1) **hand copy** from the screen with a water-soluble ink (fountain pen or roller ball with water-based ink — not ballpoint, not permanent marker) on soluble paper, on glass; (2) a **dye-ink inkjet** on soluble paper that tolerates it (test a sheet: some soluble papers blot); (3) a **monochrome laser** with the §5.4 toner step. This amends D-12's "monochrome laser or hand-copy templates": the laser moves from first to last choice because of F-5.
- The printer should be simple (no hard disk, no network), bought for cash, used only for this, and its page counter noted: a surviving Block card can be matched to a printer by its mechanical defects (T-33 residual).

### 5.4 Destruction

A pad page is destroyed **immediately after its one use**, and the working sheet with it:

1. Soluble paper into water; **stir until no fragment remains**.
2. If the page was laser-printed: the toner film floats — break it up by stirring, pour the water through a fine sieve or straight down a drain with running water; do not leave the glass standing (the letters were still legible after a night in the documented test).
3. If the page was hand-written or inkjet-printed: the ink disintegrates with the paper; stir and pour.
4. A page that cannot be dissolved (ordinary paper): cross-cut shred to P-7 or burn and stir the ash; shredding alone is not destruction (research 06 §5).
5. Never photograph a page, never copy it to a device "for safety". The device path reads it into locked memory and tells the user to destroy it afterwards.

### 5.5 Hand copy from the screen

When printing is refused, or chosen, the GUI shows the page **one row at a time**: fifty pad digits in groups of five in a large face, the row index and the row check digit, with *Next row* and no way back once the page is finished; the digit widget is the 1.1 word-at-a-time viewer (locked buffer, nothing selectable, accessibility role image). The capture-status line from the View page is shown above it (and the Plasma hide-from-capture note). The user copies each row and checks the row's digit sum. The CLI prints rows to the terminal in the same shape when asked (`--rows`), one row per keypress.

---

## 6. The device path

A user with a trusted amnesic device but no relay can use a pad page on the device:

1. **Read a page:** scan its QR with the camera (1.1.0 `aska-scan`, numeric mode) or type its digits on the keypad (row by row with the row check digits, which the client verifies as it goes). The checksum (§3.5) is verified; the set code, direction and page number are shown.
2. **Encipher:** the note is typed (the Send editor — the C-02 input residual applies, as for notes), normalised (§3.1; refused characters named), turned into digits, enciphered; the hand tag and the device tag are computed; the result is shown in the locked viewer in groups of five — ciphertext, then the four-digit hand tag, then the nineteen-digit device tag — for the user to copy or read out. **Mark page used** wipes the page; the client reminds the user to destroy the paper.
3. **Decipher:** ciphertext (and tags) typed or pasted; the tags are checked first (device tag if present, else hand tag); on failure the note is **not shown** ("tag does not verify — the message was altered or the wrong page was used"); on success the text appears in the locked viewer and the page is marked used.
4. Nothing persists: a page lives in the Session like a Share; it is wiped on close, on timeout and on distress. The Session never records which pages were used — that is the paper's job (F-9).

The ciphertext digits can travel by any channel, including as the text of an ordinary Aska note. That gives no extra security; it is convenience.

---

## 7. Block cards and Share cards

### 7.1 Block cards

A Block (class 1: 4 096 bytes; class 2: 16 384 bytes) is cut into **chunks of 1 024 bytes**, each printed as one QR code in byte mode with error correction L (QR version 30, 137 modules — readable at the 1.1.0 capture resolution at about 3.5 pixels per module). Chunk = `set id (4 random bytes) ‖ index (1) ‖ count (1) ‖ class (1) ‖ data (1 024) ‖ CRC-32 (4)`. Class 1 is four codes (one A4 sheet), class 2 sixteen codes (four sheets); **class 3 is not offered on paper**. No magic string: the header is six bytes that look like any other; the decoder recognises a set by its id, index/count consistency, class and CRC.

**Import:** scan the codes in any order; the client shows "card 3 of 4 read"; duplicates are ignored; a code with another set id is reported and dropped; when all are present the Block is reassembled, its length checked against the class, and handed to the Session exactly as a fetched Block — opened with words, Shares or a receiving seed as usual. Import from image files is **not** offered (it would mean reading files the client did not write; the camera is the path).

### 7.2 Share cards

One card per Share: the Share's existing text encoding as QR (alphanumeric mode) and in print, grouped for hand copying, with the Share index and threshold ("Share 2 of 5, any 3 open the note") and no other words. Printed with the Share-card rules (§5.1). Read back with the camera as today.

---

## 8. Client surfaces and hardening rules

### 8.1 Core: crate `aska-paper` (MIT OR Apache-2.0)

Modules: `checkerboard` (Table 1, normalisation), `pad` (encipher/decipher over `LockedBuf`s), `handtag`, `devtag` (constant-time arithmetic mod 2⁶¹−1), `page` (canonical string, checksum, row checks, QR payload), `booklet` (directional pages, set code), `entropy` (sources trait, health tests, estimator, Toeplitz extractor, mixer, booklet tests), `cards` (Block chunking/reassembly, Share cards), `render` (page raster into a locked buffer; monospaced glyphs embedded as a bitmap font so no font cache sees the digits). The Python reference gains `aska_paper_ref.py` with the same test vectors.

**Rules:** no `String` or `Vec<u8>` for any digit sequence or key — `LockedBuf` throughout; every intermediate wiped on drop; no `format!` with secret data (the 1.1 `SecretLine` pattern); constant-time comparison of tags; rejection sampling never falls back to modulo; the extractor seed and all parameters logged nowhere; the camera frames never leave the capture layer except as LSB samples into a locked buffer that is wiped after extraction; no file is opened for writing anywhere in the crate (the no-file-writes gate covers both clients).

### 8.2 CLI

`aska paper generate --pages P --digits N --source camera|dice|typing [--no-hand-tag] (--print | --stdout | --rows)`, `aska paper encipher --page <scan|typed>`, `aska paper decipher`, `aska paper check-page`, `aska paper worksheet`, `aska block export` (Block cards from a Block in the Session) / `aska block import` (camera), `aska share cards`. Prompts use the locked, unbuffered reader from 1.1. The CLI applies §5.2 to `--print`.

### 8.3 GUI

A **Paper** page with four cards: *Make a pad booklet* (source choice with an entropy meter and the health/statistics result, pages and size, hand tag on/off, assurance label preview, the §5.2 checklist, then *Print* or *Show for copying*), *Use a pad page* (scan or type; encipher / decipher; mark used), *Block cards* (export from the current Block; import by camera), *Share cards*. Every digit display is the locked viewer; every digit entry the keypad. The doctor gains two INFO findings: print spool volatile / not volatile; a USB printer present / none.

### 8.4 Gates and tests

Test vectors (§12) in Rust and Python; property tests (encipher∘decipher identity, prefix-freeness, tag collision bound sampled, extractor output uniformity on a biased synthetic source, rejection-sampling uniformity); the no-file-writes gates extended to a print run against a throwaway CUPS in CI (tmpfs spool, a `file:` printer **must be refused**, a fake `usb:` printer accepted); the GUI memory gate with needles for a pad page's digits (fatal) after close; the CLI unbuffered-input gate over the new prompts; the Block-card round trip through rendered QR images at 640×480 (as the 1.1.0 scanner tests).

---

## 9. Deliberately not in 1.2

Splitting a booklet between couriers (k-of-n), the single-board reader (RM-07), hardware RNG devices, any hand cipher other than the pad, flash paper, import of cards from image files, length-hiding by hand. Each has a line in the plan's P-8 or in §10.

---

## 10. Open questions for the owner, with the recommendation

| # | Question | Recommendation |
|---|---|---|
| Q-1 | Page size default: 400 pad digits (~270 characters; one A4 sheet with the hand-tag keys) or 200 (~130 characters; A5; half the hand-tag work)? | **400 default**, 200 and 600 selectable at generation. |
| Q-2 | Hand tag on by default? It doubles the digits on the page and adds fifteen minutes of arithmetic per message; without it a hand user has no integrity check at all. | **On by default**; off is a generation option, printed on the page as `-` so the receiver knows. |
| Q-3 | Print the set code on pages? It links the two holders' booklets (F-8), but without it two people with several booklets cannot tell which match. | **Print it**, four digits, small; offer `--no-set-code` for a single-booklet pair. |
| Q-4 | Device tag at full nineteen digits or truncated to twelve? | **Nineteen**; it is copied by a device, not a hand. |
| Q-5 | Length hiding: should the device path pad messages to a fixed length (e.g. the page's N) by default? | **Yes on the device path** (trailing spaces to N, so every device-enciphered message on a 400-page is 400 digits + tags); never by hand. |
| Q-6 | Ship *Make a cover page* in 1.2? | **Yes, but only on the device path and only for a ciphertext the user types in** (no memory of past messages exists to offer it from); the guide states its limits (§3.7). The owner may prefer to leave it out of the first paper release and judge after the trial. |
| Q-7 | Hardware RNG support (USB TRNG, `/dev/hwrng`) in 1.2? | **No** — the camera covers the volume; add in 1.3 if users ask. |
| Q-8 | The min-entropy margin: halve the estimate and cap at 0.5 bit per pixel, as proposed, or stricter? | **As proposed**, and print the raw estimate and the budget used in the generation summary so an expert can judge. |
| Q-9 | Hand copy as the *recommended* path for pads (F-5), with printing as the exception? It costs the user 25 minutes per page. | **Yes in the guide's ordering** (§5.3); the client offers both. |
| Q-10 | Should the Paper page be hidden behind a setting ("Show paper mode") so the ordinary Send/Receive user never meets it? | **No** — one more card on the Home page; the concept paper's Level 3 belongs in view. |

Any answer other than the recommendation changes §3–§6 wording only; none changes the plan's steps.

---

## 11. Specification deltas (to be folded at release 1.2.0)

- **Decision Record v0.6:** D-23 "paper mode built as DC-04" (alphabet, tags, entropy labels, printing rule); **D-12 amended** (printer order: hand copy, inkjet, monochrome laser with toner step; never colour laser or network printers); RM-01 status built (without k-of-n split); new threats T-32 (pad page recovered: toner film, impressions, photograph), T-33 (printing leaves spool/log/printer copies; printer attribution of cards), T-34 (pad reuse), T-35 (weak physical entropy — labelled); assets AS-10 (pad booklet), AS-11 (Block card set); requirements PAP-01…PAP-12 (one per rule in §3–§6).
- **Client Design v0.8:** new §11 "Paper mode" (surfaces, printing rule, hand-copy view, device path), §6 table rows for `aska-paper`, Table 3 CLI commands, C-02 note (the device path's text entry shares the Send editor residual).
- **Block Format draft 0.8:** no byte changes; a note under §9 that Block cards carry a Block unchanged with a six-byte chunk header outside the format, and that classes 1–2 only are offered on paper.
- **User Guide 1.2:** chapter "Paper mode" (§5.3–5.5 and §6 in user words, the worksheet), the requirements table (printer, paper).
- **Release Checklist:** rows for the printing-rule gate and the hand trial.

---

## 12. Worked example (for the owner's hand trial) and test vectors

The example page is deliberately short — **60 pad digits**, so the whole round trip takes under an hour by hand. Its digits were derived deterministically for reproducibility; a real page never is.

**Example page `7342 A 03` (PHYSICAL)**

```
Pad (row · groups of five · check)
 1  27974 91320 99457 14837 24546 26642   2
 2  37595 14809 46439 19661 36317 51385   2

Hand-tag keys  a0 … a30, then b
 a0 5849   a1 1573   a2 2769   a3 6170   a4 2106   a5 5152
 a6 6831   a7 4251   a8 1107   a9 6609  a10 5096  a11 2484
a12 0272  a13 5425  a14 7676  a15 2832  a16 7115  a17 6601
a18 5314  a19 5029  a20 8369  a21 9720  a22 9153  a23 0768
a24 0658  a25 7564  a26 9899  a27 7707  a28 5061  a29 0499
a30 4489    b 2691

Device-tag keys
 r 1231961752939033616   s 1450779715753509526
```

**Message:** `MEET 14 NOV NORTH GATE`

1. *Table 1:* M→76 E→0 E→0 T→1 space→89 1→91 4→94 space→89 N→5 O→3 V→83 space→89 N→5 O→3 R→70 T→1 H→71 space→89 G→79 A→2 T→1 E→0
   → m = `76001 89919 48953 83895 37017 18979 210` (33 digits).
2. *Add the pad, digit by digit, mod 10* (first 33 pad digits `27974 91320 99457 14837 24546 26642 375`):
   → c = `93975 70239 37300 97622 51553 34511 585` (33 digits).
3. *Hand tag.* Pairs G₁…G₁₇ = 93 97 57 02 39 37 30 09 76 22 51 55 33 45 11 58 **5** (odd length: the last group is the single digit 5). Sum = a₀·33 + a₁·93 + a₂·97 + … + a₁₇·5 + b = 5849·33 + 1573·93 + 2769·97 + 6170·57 + 2106·2 + 5152·39 + 6831·37 + 4251·30 + 1107·9 + 6609·76 + 5096·22 + 2484·51 + 272·55 + 5425·33 + 7676·45 + 2832·11 + 7115·58 + 6601·5 + 2691 = **3 314 972**.
   Reduce with 10 000 ≡ 27: 3 314 972 → 4 972 + 27·331 = 13 909 → 3 909 + 27·1 = **3 936**. Tag = `3936`.
4. *Device tag (app only):* `0876449745860556196`.
5. *What is posted:* `93975 70239 37300 97622 51553 34511 585 3936` (and, from a device, the nineteen digits).
6. *Receiver:* recomputes the hand tag from the ciphertext with the same keys → 3936 ✔; subtracts the pad → m; Table 1 backwards → `MEET 14 NOV NORTH GATE`. Both dissolve page A 03.
7. *Deniability:* for the innocent text `SEE YOU ON SUNDAY LOVE` (also 33 digits) the cover pad is `33996 99964 58052 01977 88372 55898 755`; subtracting it from c gives that text exactly.

**Test vectors (TV-P1…P3)** — pad of 400 digits, 201 multipliers, b = 5726, r = 511 439 929 348 225 566, s = 1 155 085 760 708 103 975 (the full pad and multiplier lists are in the prototype's output and will be the reference file `tv_paper.json`):

| TV | Text | Digits (m) | Ciphertext (c) | Hand tag | Device tag |
|---|---|---|---|---|---|
| P1 | `A` | `2` | `2` | 8424 | 1907924811919414058 |
| P2 | `MEET 14 NOV NORTH GATE` | 33 digits (above) | `779227211647294665543232442615543` | 3638 | 0914769270739007431 |
| P3 | `THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG 0123456789` | 95 digits | 95 digits | 1431 | 0248148865557894449 |

Page checksum (final definition, over the all-digit canonical string of the TV page `7342 A 03`, N = 400, with keys): **703345**; the vector page without hand keys (TV-P5: set `0009`, B 50, N = 200) has checksum **522854**. Both are reproduced by `reference/aska_paper_ref.py` and the `aska-paper` crate (`reference/tv_paper.json`, vectors TV-P1…TV-P7; TV-P6 is a Block-card set, TV-P7 the Toeplitz convention).

---

## 13. Hardening checklist for the implementation (step 2 onwards)

1. Every digit sequence, multiplier, r, s, tag and plaintext in `LockedBuf`; wiped on drop, on close, on timeout, on distress.
2. Constant-time: tag comparison; Mersenne reduction; checkerboard lookup via fixed tables, not branches on secret digits (the digit *values* are secret; the table is public).
3. Rejection sampling with no modulo fallback; the rejection loop bounded (abort after 10⁶ iterations — impossible in practice; a sign of a broken source).
4. The extractor seed drawn once per booklet from `getrandom`; Toeplitz multiplication over the raw sample block in locked memory; raw samples wiped after extraction.
5. No `Display`/`Debug` for secret types (the 1.1 pattern); no logging of any digit.
6. The page raster drawn with an embedded bitmap font into a locked buffer; handed to the printer as PWG raster or PostScript generated in memory; buffer wiped after the job is accepted; the GTK print operation's preview refused, progress off, async off; `GTK_PRINT_BACKENDS=cups`.
7. IPP over the CUPS domain socket only (`/run/cups/cups.sock`); never a TCP connection to a spooler.
8. The camera path reuses `aska-scan`'s mmap buffers (dump-excluded, blanked); LSB extraction into a locked buffer; no frame leaves the process.
9. Keypad for all digit entry; the locked viewer for all digit display; the Send editor residual stated for text entry.
10. Gates: no-file-writes (print run included), memory gate needles (page digits fatal), unbuffered CLI input, QR round trips at the capture resolution, test vectors in two implementations.

---

## 14. Sources used for the new findings

- Dissolving-paper test with laser, copier, inkjet and pen (letters floating; inkjet and pen inks disintegrating): Princeton University Library *Pop Goes the Page*, "Now You See It…" (dissolving-paper tag).
- Printer tracking dots: Wikipedia, *Printer tracking dots*; EFF, *List of printers which do or do not display tracking dots* (and the EFF's advice to assume all colour lasers carry a code).
- Pen-and-paper methods, destruction and ESDA: *Research 06* (this project), §1, §5, §7.

## Change log

- **v0.2 (9 Oct 2026, step 2):** canonical string made all-digit (direction and hand-tag flag as digits) so the page QR is numeric mode; the collision term of the estimate defined as collision entropy (an upper bound) rather than a lower bound that halved every flat source; final checksum definition and the reference test vectors (`tv_paper.json`) recorded in §12. No change to the alphabet, the arithmetic, the tags or any rule.
- **v0.1 (9 Oct 2026):** first issue for approval. New findings against the earlier design: laser toner survives dissolution (F-5 → D-12 amended); the print spool, logs and printer memory as copies (F-1…F-3 → the printing rule); dice cannot supply a pad's entropy (→ assurance labels, camera as the physical source, seeded extractor).
