# Aska — Design Change DC-05: Aska on a phone

- **Version:** 0.1 — 18 October 2026 (first issue, for the owner's approval before any mobile code; step 1 of *Aska 1.3 Plan v0.1*).
- **Scope:** the design of the mobile clients that *Research 08 — Mobile pre-study* (16 October 2026) prepared and whose ten decisions the owner accepted on 16 October ("accept, iPhone deferred"): the shared Rust core exposed through a new `aska-ffi` crate; the lifecycle, memory and crash rules a phone forces; the Android client for **GrapheneOS** (reference platform) and its validation on a **Samsung** phone; Tor through **Orbot**; the paper mode's device path and cards on a phone; distribution, signing and reproducibility of the APK; the mobile gates; brand 2.0 on Android; and the specification deltas. The **iPhone client (1.4) is deferred** by the owner until an Apple developer identity exists (Q-2); this document fixes only what the iPhone client will share (the FFI, the lifecycle rules, the memory tiers) and leaves its screens to a later issue.
- **Does not change:** the Block Format (KDF profile 2, reserved since draft 0.4, becomes the mobile default — no byte of the layout changes), the wire protocol, the relay, the desktop clients, the paper system. A phone opens what a desktop sealed and the other way round.
- **Sibling documents:** *Research 08 — Mobile pre-study v0.1* (the facts, the platform matrix, the forensic view; this document does not repeat its evidence and cites it as R08 §n); *Decision Record and Threat Model v0.6* (D-03, D-16, D-20, D-22, RM-02, T-09, T-15; the deltas of §11 below go into v0.7); *Client Design v0.8* (§2.3 the Session, §3.1 memory rules, §5 screens, §6 hardening — the mobile part becomes its §13 in v0.9); *Block Format draft 0.8* (KDF profiles, §5.3); *DC-01 v0.2* §6a and §9 (the Tor and bridge rules); *DC-04 v0.3* §6–§7 (device path, cards); *ASKA Brand Guidelines 2.0* and *brand kit 2.0* (Android assets).
- **Status:** **proposed.** Owner approves (or amends) before step 2 of the plan. Every "spike" below names a measurement step 0 must make before the design is relied on.

---

## 1. What the examiner would find on a phone, and what this design does about it

R08 §1 and §6 give the picture; the design answers it in five sentences that the rest of this document makes concrete.

A phone is **always after first unlock**, so an attacker with the right tooling reads the memory of running processes and the decrypted file system until the next reboot (T-36). Aska therefore keeps every secret inside its own process in locked memory, **closes the Session when the screen locks** (not only on the idle timer), and tells the user how to shorten the platform's reboot window. A phone **records that Aska is installed and when it ran** and no application can prevent it (T-37); Aska does not pretend otherwise — no disguise, no cover name — and the guide's first paragraph says that on a phone the deniability is about the *messages*, never about the application. Toolkits, keyboards and the app switcher **copy what is on screen** (T-38); Aska crosses its process boundary only with byte arrays it zeroes, draws every secret from Rust buffers onto a canvas, offers its own keypad and keyboard, and sets `FLAG_SECURE` so the platform refuses screenshots, recordings and the recents thumbnail — the first platform in this project where the application can refuse capture. A native crash **writes memory to a file** (T-39); Aska installs its own fatal-signal handler first, wipes, and exits silently. And Android gives an application **64 KiB of locked memory** (T-40); Aska locks keys, seeds, passphrase material, pad digits and plaintext — all small — and marks Blocks and buckets dump-excluded without locking them, and says so on its "This phone" page.

What remains after all of that is stated in the guide, not hidden: the operating system's own record of use; the free text a user types through a platform keyboard; a note on screen at the second of seizure; and, on a stock phone, whatever the vendor's and Google's services keep about the device. On GrapheneOS the honest summary R08 §6 gives — "the subject had Aska installed and used it at these times, and nothing else" — is the design goal met.

---

## 2. Terms

- **BFU / AFU** — before / after first unlock since boot (R08 §1). The design's rules aim at making the AFU window irrelevant for Aska's secrets.
- **Platform Tor** — a Tor the user installs and runs separately from Aska and that Aska connects to as the desktop connects to the system Tor (DC-01 §6a option A). On Android: **Orbot** (Guardian Project).
- **`aska-ffi`** — the new crate: the UniFFI interface over the Session and the paper functions, generating Kotlin (and later Swift) bindings.
- **The budget** — the bytes an application may `mlock`: 64 KiB on Android by `init`'s `RLIMIT_MEMLOCK`.
- **Tier 1 / Tier 2 memory** — tier 1 is locked (`mlock`) and dump-excluded; tier 2 is dump-excluded (`MADV_DONTDUMP`), zeroised on drop, but not locked because the budget is exhausted.
- **Tombstone** — Android's native crash report (`/data/tombstones`), with register values and memory near them.
- **The "This phone" page** — the mobile client's doctor: one screen of findings about the device Aska is running on, each with the platform's own settings path.
- **The lock** — the moment the screen locks (`ACTION_SCREEN_OFF` / keyguard shown). On a phone this is where the AFU question is decided, so it is a Session boundary.

---

## 3. Decisions

The ten questions of R08 §9 were accepted by the owner on 16 October 2026 with their recommendations, except that the iPhone client is deferred. They are recorded here as the decisions this design is built on, and go into the Decision Record as **D-24** (one decision with ten parts, as D-23 records DC-04).

| # | Decision | Consequence in this design |
|---|---|---|
| Q-1 | **Android distribution: release-page APK only in 1.3.** No Play listing, no Google developer registration. | §8: the APK is signed with a project key and published with its certificate fingerprint next to the desktop files; the Samsung guide documents Auto Blocker, Advanced Protection and the 2027 "advanced flow" / `adb` path (R08 §8). The Play question is recorded for after the Samsung validation. |
| Q-2 | **iPhone: deferred** until an Apple developer identity exists; no iOS code before the owner's decision. | §4 fixes what the iPhone client will share (FFI, lifecycle, tiers); nothing else here is iOS. D-20's note gains the sentence that an iOS publisher would be identified (R08 T-41). |
| Q-3 | **Tor on Android: Orbot (option A); no embedded Arti in 1.3.** | §4.6. An Arti spike (in-memory state, memory use) is in plan step 0 as a measurement, not a dependency. |
| Q-4 | Tor on iPhone: Orbot for iOS after the `.onion`-through-tunnel spike. | Deferred with Q-2; recorded. |
| Q-5 | **The Session closes on screen lock.** | §4.3 lifecycle rule L-2; new requirement MOB-03. |
| Q-6 | **No profile on phones in 1.3.** | §5.1: relays are typed or scanned per session; Receiving Keys are not stored; Settings has no profile. Aska Android **writes no file at all** — the write gate has nothing to except. |
| Q-7 | **Note editor: in-app keyboard by default for short notes, platform keyboard as an option** with a one-line warning. | §5.3. |
| Q-8 | **Paper mode on phones: device path and cards only.** No booklet generation, no printing. | §6. |
| Q-9 | **Two phones budgeted:** a Pixel for GrapheneOS (bought for the project; GrapheneOS installed by the owner from the official web installer) and a Samsung phone. | Plan step 0; the GrapheneOS installation is the first chapter of the mobile guide. |
| Q-10 | **Release shape: 1.3 = Android (GrapheneOS reference, Samsung validation); 1.4 = iPhone later.** | This document and *Plan 1.3*. |

Three further decisions are proposed here and need the owner's word (§12): the in-app keyboard's layout (Q-11), the APK signing key's custody (Q-12), and the Pixel model (Q-13).

---

## 4. Architecture

### 4.1 One core, thin clients

`aska-core`, `aska-proto` and `aska-paper` (without `print`) are pure Rust with no C dependency and compile for `aarch64-linux-android` (NDK, **16 KiB page alignment** of the shared library as Android 15+ requires) — R08 §5.1. What does not come along: `aska-scan`'s Video4Linux2 capture (the phone's camera API delivers frames; the pure-Rust **decoder** `aska_scan::decode_luma` does come along), `aska-paper::print`, the doctor's Linux probes (replaced by the "This phone" page), and the Tor control-port client (Orbot exposes none to applications; **circle-key relays are not supported on phones in 1.3**, as on Tails — the Key Card's TLV 0x06 is read and ignored with a message).

The platform side is thin by rule: it captures (camera frames, key presses), draws (glyph runs from Rust buffers), connects (a TCP socket to Orbot's SOCKS port, handed to Rust as a file descriptor or driven by Rust's own SOCKS client over the platform socket), and applies the platform's protections. It holds no secret in any object of its own.

### 4.2 The `aska-ffi` interface

A UniFFI crate using the proc-macro form (the interface stays in Rust; no `.udl` file to drift). Rules, from R08 §5.1, made normative (MOB-01, MOB-02):

1. **Secrets never cross as strings.** Every parameter and return carrying key material, a passphrase, a note, a label, pad digits or Share bytes is `Vec<u8>` (Kotlin `ByteArray`). The Rust side copies into a `LockedBuf` on entry and never retains the FFI buffer; the Kotlin side `fill(0)`s its array in a `finally` block after every call.
2. **The Session is opaque.** One `Session` object (UniFFI interface) with the desktop's states (Idle → Composing → Sealed → HandOver → Posted; Idle → Collecting → Fetched → Opened → Closed; Client Design §2.3). The UI asks it questions and gives it bytes; no Kotlin object mirrors its content.
3. **Rendering pulls from Rust.** `view_line_count()`, `view_line(i) -> Vec<u8>` (UTF-8 of one wrapped line, wrapped by Rust for the width the UI reports) for the note viewer and the pad-row view; the Kotlin side draws the bytes with `Canvas.drawText(CharArray, …)` from a `CharArray` it zeroes after the frame. No `String`, no `TextView` ever holds a secret. Hand-over material likewise: `handover_words(i)`, `handover_card_png()` (a QR raster, bytes), `handover_share(k)`.
4. **Input pushes to Rust.** `compose_append(bytes)`, `compose_backspace(n)`, `passphrase_key(byte)` from the keypad, `camera_frame(luma, w, h) -> ScanResult` for the decoder, `receive_card(bytes)`, `receive_words(bytes)`.
5. **The lifecycle is explicit.** `on_screen_lock()`, `on_background()`, `on_low_memory()`, `close()`, `distress()` — each ends in the Session's close path, which scrubs its secrets and the stack (Client Design §3.1). A `Session` dropped by the garbage collector is also closed (UniFFI's destructor), but the UI never relies on that.
6. **Errors are enums, not messages.** `AskaError` variants mirror the CLI's exit classes (refused, unreachable, nothing found, declined); the UI chooses the wording from its own locale table. No error carries bytes of a secret.
7. **The doctor is a struct.** `phone_findings(input: PhoneFacts) -> Vec<Finding>`: the platform side collects the facts it alone can read (reboot timer setting, USB-while-locked, backup state, keyboard package, Orbot state, OS and patch level, `RLIMIT_MEMLOCK`) into a plain struct; Rust turns them into the same `Finding`s (check, severity, message key) the desktop uses, so the rule "only the Tor path and a non-onion relay refuse" (Client Design §4.1) is shared code.

The crate also exposes the paper functions the device path needs (`page_from_digits`, `page_from_qr`, `encipher`, `decipher`, `tag_check`), the card codecs (`block_from_cards`, `shares_from_cards`), and `verify_self(apk_sha256)` for the "Verify this app" screen (§5.1). What it does **not** expose: anything that writes a file, the booklet generator, the printer path, the relay's control-port client, the profile.

Memory for the UniFFI boundary is measured in step 0 (spike S-9): JNI `GetByteArrayElements` may copy a `ByteArray` into a C heap buffer the Kotlin side cannot zero; if it does, the binding uses `GetByteArrayRegion` into a Rust-owned `LockedBuf` instead (UniFFI's `RustBuffer` path is examined for the same copy), and the mobile memory gate (§9) decides.

### 4.3 Lifecycle rules

| # | Rule | Why |
|---|---|---|
| L-1 | The idle watchdog of the desktop (default 5 min, Client Design §2.3) runs unchanged. | Same Session, same rule. |
| L-2 | **Screen lock closes the Session** (Q-5): on `ACTION_SCREEN_OFF` and when the keyguard appears, the UI calls `on_screen_lock()` → close; the UI returns to Home. A note being composed is lost; a note being read is gone. | The lock is the AFU moment on a phone; a key surviving it is the one thing an examiner needs (T-36). |
| L-3 | **Background with a grace period:** `onStop` starts a 20-second timer; if the app is not foregrounded again the Session closes. The grace covers switching to Orbot or the camera permission dialog. | A phone call or a notification must not destroy a half-typed note; twenty seconds of AFU exposure under `FLAG_SECURE` is the accepted cost. |
| L-4 | `onTrimMemory` at `TRIM_MEMORY_RUNNING_CRITICAL` or worse closes the Session. | The platform about to kill the process must not find secrets in a process it kills without the handler running. |
| L-5 | **The fatal-signal handler** (§4.5) runs before the platform's; it wipes the locked arena and `_exit(0)`s. | T-39. |
| L-6 | Distress (the distress passphrase, Client Design §2.3) destroys key material with timing parity as on the desktop; the UI shows the decoy exactly as a real note. | Unchanged behaviour; stated because the keypad is new code. |
| L-7 | Leaving a paper page (device path) wipes it, as on the desktop (DC-04 §6). | Unchanged. |
| L-8 | The application never runs in the background on its own: no foreground service, no work scheduler, no broadcast receivers other than screen-off, no notifications. | Nothing to record, nothing to wake up; the OS usage record is the only trace (T-37). |

### 4.4 Memory tiers

Android's `RLIMIT_MEMLOCK` of 64 KiB is set by `init` for every application and cannot be raised by the app (R08 §3; spike S-1 confirms the value on GrapheneOS and on the Samsung phone). `LockedBuf` gains a **tier**:

- **Tier 1 — locked and dump-excluded:** the root and labels, Shares, passphrase material and KDF output, Receiving-Key secret material, the plaintext of a note (≤ 64 KiB only for class 3; class 1 and 2 notes fit), pad pages and their keys, the viewer's line buffers. These are allocated first and sum to well under the budget for class 1 and 2 use; when a class 3 note (64 KiB) would exceed it, its plaintext is tier 2 and the UI says so before showing it.
- **Tier 2 — dump-excluded, zeroised, not locked:** sealed Blocks (4–64 KiB), fetched buckets, QR rasters, camera frames. `MADV_DONTDUMP` keeps them out of a tombstone's memory dump; zram swap is RAM-backed on Android, so an unlocked page is not written to flash by the kernel in normal operation. Samsung's **RAM Plus** is checked in step 0 (S-6): if it is storage-backed swap, the "This phone" page warns as the desktop warns about swap, and the Samsung guide says to turn it off.

`LockedBuf::with_capacity` tries `mlock` and records the outcome; the allocation never fails for lack of budget — it falls to tier 2 and the Session's report (shown on "This phone" as "locked: keys and notes; not locked: Blocks — platform limit") counts the bytes in each tier. Requirement MOB-04. The desktop keeps its single tier: nothing changes for Linux.

### 4.5 The crash path

A `sigaction` handler for `SIGSEGV`, `SIGBUS`, `SIGABRT`, `SIGILL`, `SIGFPE` and `SIGTRAP`, installed when the native library loads (`JNI_OnLoad`, before any Session exists), with `SA_ONSTACK` on a pre-allocated alternate stack (so a stack overflow can still be handled) and `SA_NODEFER` off. The handler (a) walks the registry of live `LockedBuf`s (a lock-free list the allocator maintains for this purpose) and zeroes each, (b) zeroes the alternate stack region it did not use, (c) calls `_exit(0)`. Rust's `panic = "abort"` thereby ends in the handler. No tombstone is written because the process ends before `debuggerd` is given the signal; **spike S-3** forces an abort with and without the handler on both phones and reads `/data/tombstones` (rooted test image or emulator) to confirm.

What this costs, stated in the guide and in the Decision Record (T-39 residual): a crash in Aska on a phone is silent — no report, no diagnostic — where the desktop would print a panic. A user who hits a reproducible crash is asked to reproduce it on a desktop build, where reports are safe to collect, or in the emulator.

### 4.6 Tor through Orbot

As the desktop uses the system Tor on port 9050 (D-16, DC-01 §6a option A), Aska Android uses **Orbot's SOCKS port** (`127.0.0.1:9050` by default; Orbot's "apps VPN" mode is not required and not assumed). The same rules as the desktop's: the proxy must be loopback; one circuit per request by per-request SOCKS credentials; `.onion` only; refusal when the proxy is absent or cannot bootstrap. Orbot is detected by package presence (`org.torproject.android`) and status by its broadcast intent API; when Orbot is not installed, "This phone" says so and names Orbot (from the GrapheneOS Apps store, F-Droid or the Guardian Project — Aska never fetches it); when Orbot is installed but not running, the Tor banner offers "Open Orbot" (an explicit intent) and "Check again". Bridges are Orbot's: the guide says "configure bridges in Orbot" exactly as the desktop guide says "use your platform's Tor connection tool". **Aska still never fetches, suggests or embeds a bridge** (DC-01 §9 — the boundary is unchanged on every platform).

Orbot's own state (directory cache, logs) is Orbot's, as the system Tor's is on the desktop, and is stated in the guide as a residual outside Aska. Arti is **not** in 1.3 (Q-3); spike S-8 measures `arti-client` with in-memory state on the Pixel so that the question can be decided for a later release on facts (binary size, memory, on-disk residue, bootstrap time, vanilla-bridge-only reality).

### 4.7 KDF profile 2

A phone seals with **profile 2** (Argon2id t = 3, m = 64 MiB, p = 1; Block Format Table 1), reserved since draft 0.4 for this purpose, and opens profiles 1 and 2 (one extra Argon2id run on the Block whose label matched — a few hundred milliseconds on a current phone, measured in S-10). Desktop clients since 1.0 MAY open profile 2; **1.3 makes it MUST** for both desktop clients so that every desktop opens what a phone sealed (Client Design §3 delta; Block Format draft 0.9 changes the word only — no byte). The profile number travels in the slot-key info string as specified; nothing in the Block says "phone".

---

## 5. The Android client

### 5.1 Screens

The desktop's screens (Client Design §5) reduced to a phone, under brand 2.0 (§5.6). The window title and the launcher entry are **ASKA**; the application id is `org.aska.Aska`; the package name `org.aska.android`.

| Screen | Content | Differences from the desktop |
|---|---|---|
| **Home** | The lockup (mark + name, no tagline); **Send a note**, **Receive a note**, **Shares**, **Paper**; the Tor state (dot + word) and the build fingerprint prefix in the footer; banners from "This phone" above the footer; the gear. No profile action (Q-6). | Identical on every launch — no list of anything. |
| **Send** | Relay address (typed, pasted from the clipboard **with the clipboard cleared after reading**, or scanned from a Key Card / Receiving Key QR); the note editor (§5.3) with the byte counter; protection level (Quick / Guarded k-of-n / Receiving Key); passphrase on the in-app keypad; **Seal and post**. | No profile relays; no decoy editor on the first screen — Guarded's decoy note and distress passphrase are a second step as on the desktop. |
| **Hand-over** | Key Card QR (drawn from Rust bytes onto a canvas), the 24 words (one canvas line each), Shares as QR cards one at a time; the countdown; **Done — forget the key**. | The phone's screen is the courier; brightness is forced to maximum while the QR is shown and restored after. |
| **Receive** | Scan a Key Card with the camera (CameraX frames → `camera_frame`), or type the 24 words / a Share set on the in-app keyboard; **Fetch**. | Camera first — on a phone it is always there. |
| **View** | The locked viewer: Rust-wrapped lines on a canvas; no copy, no share, no select; **Close and burn**; the read countdown. | `FLAG_SECURE` makes the platform refuse capture — the first View page that can. |
| **Paper** | The device path (scan or type a page; encipher / decipher; tags checked first; **Done**) and the cards (read a Block card set or Share cards with the camera; hand a Block to the Session). | No booklet generation, no printing, no worksheet (Q-8; the worksheet is printed from a desktop or the repository). |
| **Shares** | Enter k Shares (keyboard or camera) → the key; the same screen as the desktop's. | — |
| **This phone** (the gear) | The doctor's findings (§5.5); Tor source (Orbot only in 1.3); language; **Verify this app**; the idle timeout; nothing else. | No profile, no printer, no camera device choice (the platform chooses). |

**Verify this app** on a phone shows the APK's signing certificate SHA-256 as the platform reports it (`PackageManager` signing info) and the application's own hash of its native library, next to the values the release record publishes; it says plainly that a phone cannot run `aska verify` as the desktop does and what the user can compare by hand (§8).

### 5.2 Platform protections used

`FLAG_SECURE` on every window (screenshots, recordings and the recents thumbnail are refused by the platform); `android:allowBackup="false"` and empty `dataExtractionRules`; `android:debuggable="false"`; no storage permissions; no exported components; no notifications; no foreground service; no `INTERNET`-using component other than the SOCKS connection to loopback; `IME_FLAG_NO_PERSONALIZED_LEARNING` and `textNoSuggestions` on every text field that may carry a secret; the clipboard read once for a relay address and then cleared; `setRecentsScreenshotEnabled(false)` (API 33+) as belt to `FLAG_SECURE`'s braces; **no third-party library that phones home** (no analytics, no crash reporter, no ads SDK — the dependency rule of OPS-02 applies to Gradle as to Cargo: every dependency pinned, hashed and justified). Requirement MOB-05.

### 5.3 Input

- **Passphrases, digits, Shares: the in-app keypad**, the desktop's (Client Design §5, C-17): shuffled keys by default, no platform IME involved, each key one byte to Rust.
- **The note editor:** by default an **in-app keyboard** (QWERTY, a Swedish layout, digits and the few punctuation marks a note needs; no prediction, no learning, no clipboard), each key one byte to Rust, the text rendered from Rust lines on a canvas — the platform keyboard never sees the note. The user may switch to the **platform keyboard** for a long note; the editor then uses a secure-entry field with the no-learning flags, and a one-line note says that the keyboard application sees what is typed (T-38 residual). Q-7.
- **Relay addresses and public keys** (not secret): a normal field; the clipboard allowed and cleared.

### 5.4 Camera

CameraX in analysis mode delivers luma planes; each frame is copied into a tier-2 buffer, handed to `aska_scan::decode_luma` in Rust, and zeroed; the preview is shown (the user must aim) but **no frame is ever written** and the capture session is closed the moment a code decodes. Key Cards, Receiving Keys, Share cards, Block card sets and pad pages are all read this way — a phone is the card reader the desktop lacks (DC-04 §7). The camera permission is requested at first use with a sentence about what is read; the application works without it (typing).

### 5.5 "This phone" — the doctor on a phone

The desktop's rule holds: only the Tor path and a non-onion relay refuse; everything else warns or informs (Client Design §4.1). Findings, each with the platform's own settings path:

| Finding | GrapheneOS | Stock Android (Samsung) | Severity |
|---|---|---|---|
| Orbot not installed / not running / no circuit | Install from the Apps store; Open Orbot | Same | **Refuse** (Tor path) |
| Auto-reboot: not set, or longer than 18 h | Settings → Security → Auto reboot; recommend the shortest the user can live with | Android 16 Advanced Protection gives 72 h, not shorter; otherwise none — stated | Warn |
| USB while locked not blocked | Default on GrapheneOS; checked | Advanced Protection "USB protection"; Auto Blocker | Warn |
| Duress PIN not set | Settings → Security → Duress password | Not available — stated once, no banner | Info |
| Backups on for this app | None without Seedvault; `allowBackup=false` honoured | Google backup / Samsung Cloud / Smart Switch — `allowBackup=false` honoured by Google's transport; Smart Switch checked in S-7 | Warn if any transport is found to ignore the flag |
| Keyboard with cloud features | AOSP keyboard: fine | Samsung Keyboard / Gboard: the in-app keyboard is the default; the finding names the package | Info |
| Locked-memory budget | "locked: keys and notes; not locked: Blocks (platform limit 64 KiB)" | Same | Info |
| Storage-backed swap (RAM Plus) | — | If S-6 finds it storage-backed: Warn, with the setting | Warn |
| Developer options / USB debugging on | Turn off before use | Same | Warn |
| Device not up to date (patch level older than 90 days) | Update | Same | Warn |
| Screen capture | "This app refuses screenshots and recordings" | Same | Info (the first positive finding in the project) |
| Rooted / unlocked bootloader detected (best effort) | Warn | Warn | Warn |

### 5.6 Brand 2.0 on Android

From *brand kit 2.0*: the adaptive icon (`@color/ic_launcher_background` `#111111`, the vector foreground and the monochrome layer that gives the themed icon on Android 13+ and GrapheneOS), the legacy and round PNGs, and `colors/android` (`values/` and `values-night/colors.xml`). Material 3 components in the Graphite roles: `background`/`surface`, `text`/`text-muted`, the accent as ink (the one filled button per screen), colour only for states; 4 px control corners, 8 px cards; the platform font (Roboto) for the interface and the platform monospace for fingerprints and keys; the lockup (mark + name) on Home, drawn from the kit's vector; the Tor state as a dot followed by the word; every banner starting with its word. No slogan, no tagline (brand guidelines 2.0, "Nothing extra"). The launcher label is **ASKA**.

---

## 6. Paper mode on a phone

The **device path** of DC-04 §6 and the **cards** of §7, unchanged in their arithmetic and rules: a page is scanned (§5.4) or typed on the in-app keypad, its checksum verified; a message is enciphered or deciphered in tier-1 memory with the tags checked first; the digits are shown in the locked viewer; *Done*, leaving the page, close, lock and distress wipe it (L-7). Block cards and Share cards are read with the camera and handed to the Session like a fetched Block or typed Shares.

**Not on a phone** (Q-8): booklet generation — the PHYSICAL pipeline would run on a phone camera, but a booklet that cannot be printed under PAP-07 can only be copied by hand from a small screen, and the project has no measurement of a phone sensor's noise; both are revisited after 1.3. **Printing: never** — mobile print frameworks spool through files and services (R08 §5.4); the printing rule cannot be checked, so the client has no print action at all. The worksheet is public and is printed from a desktop or the repository.

---

## 7. GrapheneOS reference and Samsung validation

**GrapheneOS (Pixel 6a or later; Q-13 names the model to buy).** Installed by the owner with the official web installer; the first chapter of the mobile guide is that installation (R08 Q-9). Orbot from the GrapheneOS Apps store or F-Droid. Recommended settings the guide walks through and "This phone" checks: auto-reboot at the shortest tolerable interval (the platform offers 10 min to 72 h; default 18 h), USB-C port "charging only when locked" or stricter, a duress PIN, no Google services in the profile Aska lives in (a separate user profile for Aska is suggested, not required), and the AOSP keyboard. GrapheneOS has stated it will not enforce Google's developer verification, so the APK installs from the release page with no identity involved. **This is the platform the gates and the smoke tests are run on first**, and the one the guide describes as matching the design.

**Samsung (Galaxy, One UI 7/8).** The same APK. The validation step (plan step 4) measures and documents what the guide must say: Auto Blocker off (Settings → Security and privacy → Auto Blocker) to install; **Advanced Protection and Aska exclude each other** (it blocks all sideloading) — the user chooses; from 2027 (already in four countries) Google's developer verification: an unverified APK installs through the "advanced flow" (Developer options → authenticate → reboot → 24-hour wait → unverified installs allowed) or by `adb install` with no wait; Play Protect's scan; Samsung Keyboard's cloud features (the in-app keyboard default); RAM Plus (S-6); Smart Switch and Samsung Cloud against `allowBackup=false` (S-7); Knox Vault only on flagships — an A-series phone with TEE-only protection gets an honest line in the guide. **The Samsung guide is mostly a list of what to turn off and on**, written from what step 4 finds, not from documentation.

The guide's **border paragraph** (T-15 on a phone): power the phone off before a border or a search when seizure is possible — BFU is the strongest state on every platform; on GrapheneOS the duress PIN is the second line; Aska itself holds nothing to produce.

---

## 8. Distribution, signing, reproducibility

- **The APK** is published on the release page next to the desktop files: `aska-1.3.0-android-arm64.apk`, its `.minisig` (the project's minisign key, as every release file), and its **signing certificate's SHA-256** in `RELEASE-NOTES.txt`, the release record and the fingerprint card. A user verifies as on the desktop (`sha256sum`, `minisign -V`) and additionally `apksigner verify --print-certs` against the published certificate fingerprint; on the phone, **Verify this app** shows the installed certificate's fingerprint for comparison by eye.
- **The APK signing key** (Q-12): a separate key from the minisign release key, generated on the owner's VM, kept in the same place and under the same rules as `~/.minisign/aska-release.key` (never on a shared folder, never in CI). Android's signature scheme v2+ (v3 with rotation prepared). Losing it means a new package identity; the guide says that an APK with a different certificate is **not** an Aska update, exactly as a new minisign key would not be.
- **Reproducible APK:** pinned Gradle wrapper, pinned NDK and Rust toolchain, `cargo-ndk` with the desktop's `--remap-path-prefix`, `SOURCE_DATE_EPOCH`, no build-time timestamps; `release.sh` gains an `--android` stage that builds twice and compares the unsigned APK byte for byte, then signs with `apksigner`. The reproducibility gate (`repro-build.sh`) covers the APK. F-Droid's reproducible-builds programme is the reference; whether the project also submits to F-Droid is a later question (it would require F-Droid to build and sign, or reproducible-builds verification against the project's signature) and is not in 1.3.
- **No updater, no update check** (as today): the user learns of a release from the person they trust, gets the fingerprint, then the file. Obtainium-style tools are the user's, not the project's.
- **Minimum platform:** Android 13 (API 33) — GrapheneOS supports only current Android; Samsung phones from 2022 on; the `setRecentsScreenshotEnabled` API is 33+.

---

## 9. Gates for mobile

Built in plan step 2 before the client exists, run in CI on the Android emulator (a Linux runner with KVM; the emulator image is rooted, so `/proc/PID/mem` and `strace` work) and in step 3–4 on the two phones by the owner with the same scripts over `adb`:

| Gate | What | How |
|---|---|---|
| **FFI memory gate** | After `close()`, no needle (passphrase, words, note, pad digits, labels) in the process memory, including the Kotlin heap and the JNI copies. | The desktop's XOR-masked needle method (`memscan.py`) over `/proc/PID/mem` on the emulator; a test app drives the FFI; threshold 0 hits after close, a positive control while open. |
| **No-file-writes** | The application process opens no file with write intent and creates nothing, across a send → receive and a paper device-path round trip. | `strace -f` of the app process on the emulator (the desktop script generalised); nothing is excepted since Aska Android writes no file at all (Q-6). |
| **Capture gate** | A screenshot attempt fails with the platform's refusal; a screen recording of View is black; the recents thumbnail is blank. | `adb shell screencap` returns a black or refused image while View is on screen; a recording via `screenrecord` is checked for a uniform frame. |
| **Lock gate** | Locking the screen while a note is on View closes the Session: no needle in memory after `input keyevent KEYCODE_POWER`. | Memory scan after the lock event. |
| **Crash gate** | A forced native abort leaves no tombstone containing a needle; the process exits 0. | A debug-only FFI call triggers an abort; `/data/tombstones` is inspected on the emulator. |
| **Reproducibility gate** | Two builds give the same unsigned APK hash. | `release.sh --android` twice. |
| **Orbot gate** | With Orbot stopped the client refuses; with Orbot running (the emulator with Orbot installed, or the desktop's fake SOCKS bound into the emulator) a note goes Pixel → relay → desktop and back. | Scripted over `adb` with the desktop's `fake_socks.py` and the Python relay. |
| **Platform validation** | The owner's smoke tests on the GrapheneOS Pixel and on the Samsung phone. | Checklist in the plan's steps 3 and 4. |

---

## 10. Deliberately not in 1.3

Embedded Arti (spike only); the iPhone client (1.4, after Q-2); a Play Store listing or Google developer registration (Q-1); the profile on phones (Q-6); booklet generation and any printing from a phone (Q-8); circle-key relays on phones (no control port); a disguised application or cover name; any update check; notifications of any kind; a tablet layout; Android Auto, Wear, widgets; F-Droid submission (later question); accessibility beyond the platform's own (the canvas views carry content descriptions that name the element, never its content).

---

## 11. Specification deltas (to be folded at release 1.3.0)

- **Decision Record v0.7:** **D-24** (the mobile design as this document, with the ten parts of §3); **T-36…T-41** as in R08 §2 with the residuals of this design; **AS-12** (the APK signing key); **RM-02** marked built as option A on Android (Orbot) with the embedded-Tor part still open; **D-20** note amended: "published under a pseudonym that is a domain the owner holds; linkable via the registrar's records; an iOS publisher would be identified (Q-2, deferred)"; **D-03** status: desktop Linux first, Android second (1.3); **§14.2 Mobile (MOB)** requirements MOB-01…MOB-12 (secrets as bytes across the FFI; opaque Session; close on lock; two memory tiers with the budget reported; the platform protections of §5.2; the fatal-signal handler; Orbot as the only Tor source with the desktop's SOCKS rules; no file writes at all; the "This phone" findings; the APK's published certificate fingerprint; the reproducible APK; the mobile gates); T-09 note (capture refused on Android); T-15 note (the border paragraph).
- **Client Design v0.9:** a new **Part — §13 The Android client** (this document's §4–§9 in the specification's register); §2.1 workspace: `crates/aska-ffi`, `android/`; §3.1 memory rules: tiers; §3 passphrases: profile 2 MUST be opened by desktop clients; §4.1/§5 the shared `Finding` model; §5.1 and §5.7 brought to brand 2.0 (Home = lockup without tagline, 280 px buttons, banner words, the Tor dot; window title ASKA) — the two 1.2.x folds still pending; §7 gates: the mobile gates.
- **Block Format draft 0.9:** §5.3 wording — "a mobile client seals with profile 2 and opens 1 and 2; desktop clients MUST open profile 2" (was MAY); no byte changes; test vector TV-2 already covers profile 2.
- **DC-01:** no change; §6a is satisfied by option A on Android and the document is cited.
- **User Guide 1.3:** **Part II — Phones**: what a phone records (first paragraph); GrapheneOS installation and settings; Orbot; installing and verifying the APK; the screens; the Samsung chapter (what to turn off and on, the advanced flow, Advanced Protection); the border paragraph; the paper mode on a phone; removal (uninstall is complete — nothing else exists).
- **Release Checklist v0.4:** rows for the APK (hash, certificate fingerprint, `apksigner verify`, reproducibility), the Android smoke tests on both phones, the mobile gates.
- **Publishing Runbook:** the `--android` stage, `apksigner`, the two keys' custody, the eleven release files (ten + APK; twelve with the APK's `.minisig`).

---

## 12. Open questions for the owner, with the recommendation

| # | Question | Recommendation | Why |
|---|---|---|---|
| Q-11 | **In-app keyboard layout:** QWERTY + Swedish (å ä ö) + digits + the note's punctuation, one layout with a shift and a symbols page; or the platform's layout list? | **One fixed layout**, English/Swedish, as described; no layout settings. | Fewer states, nothing to persist; a note is short by design (class 1 is 4 KiB). The platform keyboard stays available for anything else. |
| Q-12 | **APK signing key custody:** same machine and rules as the minisign key, separate key; or sign the APK with a key derived from nothing new (not possible — Android needs an X.509 certificate). | **A separate key, same custody** (owner's VM, never shared, never in CI); fingerprint published; rotation prepared with v3 signing. | A key compromise or loss should not take the desktop releases with it, and the other way round. |
| Q-13 | **Which Pixel:** the cheapest current "a" model GrapheneOS supports, for the longest remaining support window; or a flagship? | **The current "a" model** (Pixel 9a at the time of writing; check GrapheneOS's device list and end-of-life dates on the day of purchase). | The hardware class (Titan M2, MTE) is the same; the project needs support years, not performance. |
| Q-14 | **Emulator in CI:** run the mobile gates on an Android emulator on GitHub's runners (KVM; slower, flaky at times), or on the owner's machines only? | **Emulator in CI** for the FFI memory gate, the write gate and the crash gate; the capture, lock and Orbot gates on the phones by the owner, scripted over `adb`. | The desktop's "every gate in CI" rule is worth keeping where the emulator is faithful (memory, files, signals); capture and lock behaviour is hardware- and build-dependent and belongs on the phones. |

---

## 13. Hardening checklist for the implementation (step 2 onwards)

1. `aska-ffi` compiles with `panic = "abort"`, `-C force-frame-pointers=yes` (for the handler's stack walk), `--remap-path-prefix`, 16 KiB page alignment; no `std::fs` symbol reachable from the mobile build (checked by `nm` in CI).
2. Every `ByteArray` passed to or from Rust is zeroed in a `finally`; a lint (a Kotlin compiler plugin or a grep-based CI check) refuses `String` constructors in the modules that touch secrets.
3. `FLAG_SECURE` set in `onCreate` of the single activity before `setContentView`; a test asserts it on every window including dialogs.
4. The signal handler is the first thing `JNI_OnLoad` does; the alternate stack is 64 KiB of tier-2 memory; the `LockedBuf` registry is lock-free and the handler never allocates.
5. `on_screen_lock()` is wired to both `ACTION_SCREEN_OFF` and `KeyguardManager.isKeyguardLocked` on resume (a lock that happened while the process was stopped).
6. CameraX analysis frames are `ImageProxy` planes copied into a tier-2 buffer and the proxy closed immediately; the analyzer never keeps a reference.
7. No `Log.*` call in release builds (a ProGuard/R8 rule strips them) — a log line with a secret is a file on a phone.
8. The clipboard is read once, by explicit user action, and cleared with `clearPrimaryClip()`; never written.
9. Gradle dependencies: Compose, CameraX, the UniFFI runtime (JNA or the UniFFI-generated JNI), nothing else; every artefact pinned with a hash in `gradle/verification-metadata.xml`.
10. The APK build is reproducible before any gate is run on it; the signed APK's certificate fingerprint is printed by `release.sh` and compared against the record.

---

## 14. Sources

Research 08 §11 is the evidence base for every platform fact in this document and is not repeated. In addition: UniFFI documentation (Mozilla, proc-macro interface definitions, Kotlin bindings); Android Developers — `FLAG_SECURE`, `setRecentsScreenshotEnabled`, `allowBackup` and data-extraction rules, `IME_FLAG_NO_PERSONALIZED_LEARNING`, CameraX image analysis, 16 KiB page sizes, `onTrimMemory`; AOSP `system/core` init (`RLIMIT_MEMLOCK` 64 KB); Android `debuggerd` documentation (tombstones); Guardian Project — Orbot status intents and SOCKS port; GrapheneOS — features (auto-reboot, USB-C port control, duress PIN), web installer, statement on developer verification; Samsung — Auto Blocker, RAM Plus; Google — Advanced Protection for Android, developer verification timeline; F-Droid — reproducible builds; *ASKA Brand Guidelines 2.0* and *brand kit 2.0* (Android icon and colours).

## Change log

- **v0.1 (18 Oct 2026):** first issue, from Research 08 and the owner's decisions of 16 October; for approval before plan step 2.
