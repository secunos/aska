# Aska 1.1 — Plan

## Version 0.1 — 7 October 2026

- **What this is:** the work list for release 1.1, decided by the project owner on 7 October 2026 after 1.0.1: the v1.1 items named in *Decision Record and Threat Model v0.4* §17.3 and *Client Design v0.6*, plus the findings of the specification re-issue of the same day. The owner also decided that the Tails and Qubes checklists and the external security and legal reviews are **not** planned (D-19, D-21 stand).
- **Order of work:** security fixes first, then the core-library items, then the clients, then the release. Each step ends with every gate green and a delivered update; the owner pushes it and the automatic checks run before the next step starts.
- **Compatibility:** nothing in 1.1 changes the Block Format, the wire protocol or the relay's behaviour towards 1.0.x clients. Notes, Key Cards, Shares and Receiving Keys made by 1.0.x open in 1.1 and the other way round. A 1.0.x profile file opens in 1.1; a profile that holds receiving seeds (step 3) opens in 1.0.x without them.

## Steps

| # | Step | What changes | How it is checked |
|---|---|---|---|
| 1 | **Hardening** (this update) | Distress open on the receiving-key path no longer differs from a decoy open in its closing line (both clients). `aska receive --class` is honoured for words and Shares. Circle client-auth keys cleared at `Session::close()` (C-15). CLI profile commands check the path like the GUI does (regular file, exact size, no symlink following — C-14). Profile passphrase normalised without a growing `String` (C-5). CLI `--ttl` accepts only the six TTLs the cover traffic imitates (CLI-06). Relay wipes expired labels, spent challenges and digests in place and refused Block bodies on drop. Installer writes the RAM-only journal configuration before the relay's first start and asserts it. Key Card decoder made strict (B-7) in Rust and the Python reference. Stale text in `deploy/DEPLOY.md`. | New tests: distress-vs-decoy closing lines (fails on the 1.0.1 binary), Key Card strictness (4), TTL set; full suite, gates, reference tests. |
| 2 | **CLI secrets in locked memory** (C-10) and gate needles (C-17) | Passphrases and key material read from the terminal or `--stdin` go straight into `LockedBuf`s, not through `BufReader`/`Stdin` buffers that live for the process. The GUI memory gate gains needles for the 24 words and the passphrase. | Memory scan of the CLI after a send and a receive; GUI memory gate. |
| 3 | **Receiving seeds in the profile** (RM-09) | The encrypted profile can hold receiving seeds, so a user who keeps a long-lived Receiving Key need not type 24 words each time. Profile format extended with a reserved TLV type; 1.0.x ignores it. GUI Settings and Receiving-key pages; CLI `profile` and `receive --receiving-seed` read from it. | Unit tests; CLI end-to-end; owner test on Debian. |
| 4 | **KDE Wayland capture flag** | Request the per-window "do not capture" flag where the compositor offers one and report it in the doctor; otherwise record that no such flag exists and keep "unknown". | Doctor output on GNOME and KDE (owner on Debian; KDE if available). |
| 5 | **Bridges for the session** (RM-08, DC-01 option B) | The user pastes bridge lines they already have; the client applies them to the running Tor through the control port for this session only (`SETCONF`, reverted at close), waits for bootstrap and reports progress. Debian and Qubes only; refused on Tails and Whonix with the existing explanation. The client never fetches bridges and gives no guidance on obtaining them beyond naming Tor's own channels (DC-01 §9 boundary unchanged). GUI Settings section and CLI option. | Control-port tests against a fake Tor; owner test on Debian with the system Tor. |
| 6 | **Portal camera** (C-04) | Scan Key Cards, Shares and Receiving Keys with the desktop-portal camera (PipeWire) and an in-process QR decoder, replacing the `zbarcam` helper where the portal exists; the helper remains the fallback. | Decoder tests on rendered QR images; owner test with a webcam passed through to the VM. |
| 7 | **Read-only note viewer** (C-02) | The View page draws the note from the locked buffer with a custom widget instead of a GTK text view, removing the toolkit's copies of the note. | GUI memory gate (note-text needle must drop to zero after close). |
| 8 | **Release 1.1.0** | Version, guides, release record and announcement; build, sign, Debian smoke test, publish — the 1.0.x runbook. | As for 1.0.x. |

## Not in 1.1

The two doctor D-Bus probes (GNOME screen recorder, AT-SPI) — not planned. The paper mode (RM-01) and the mobile client (RM-02) — later. Rekor entries — if `rekor-cli` is available on the signing machine at release time.

## Change log

- **v0.1 (7 Oct 2026):** first issue, with step 1 delivered.
