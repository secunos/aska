# Aska

Fire-and-forget secure notes: a fixed-size, random-looking **Block** travels through a Tor-only
**Dead Drop** relay; the key travels separately (QR / 24 words / k-of-n Shares); after delivery
nothing remains anywhere. Design documents are in `docs/`; the Python reference implementation and
test vectors are in `reference/`.

## For users and relay operators

- **[User Guide](docs/USER_GUIDE.md)** — requirements, how to check that your copy is real, install, send and receive, the receiving-key path, Tails and Qubes, and what Aska does **not** protect you against. Shipped inside every release tarball as `docs/USER_GUIDE.md`.
- **[Relay Operator Guide](docs/RELAY_OPERATOR_GUIDE.md)** — what a relay is, requirements, install from the signed binary, configuration, upgrade, what running one means. Shipped as `aska-drop-deploy-<version>.tar.gz` beside the relay binary.
- **Releases** (`https://github.com/secunos/aska/releases`) are signed with minisign key `79AD6224AFF176C9` (`release/aska-release.pub`); each release directory carries `SHA256SUMS.txt`, its signature and `RELEASE-NOTES.txt`. Get the fingerprint out of band first, then the files — the User Guide, section 3, says how.
- **Specifications** (re-issued 8 Oct 2026 to match release 1.1.0): `docs/Secure_Notes_Sharing_App_Aska_Decision_Record_and_Threat_Model_v0.5.md`, `docs/Aska_Client_Design_v0.7.md`, `docs/Aska_Block_Format_Specification_v1_draft0.7.md`, `docs/Aska_Dead_Drop_Protocol_Specification_ADP1_draft0.4.md`. Earlier versions stay in `docs/` because older documents refer to them.
- **Releases so far:** 1.0.0 (6 Oct 2026), 1.0.1 (7 Oct), **1.1.0 (8 Oct 2026)** — the 1.1 plan is `docs/Aska_1.1_Plan_v0.3.md`, the release records are in `docs/releases/`.
- **Release status:** 1.1.0 has passed the project's own gates and an internal security pre-review (`docs/Aska_Internal_PreReview_Report_v0.1.md`); it has **not** had an independent security audit or a legal review. The Security Review Package and Legal Review Brief in `docs/` are published so that anyone can conduct one.

Licences: `LICENSE.md`. Reporting a security problem: `SECURITY.md`. The rest of this file is for developers.

**Status:** M0–M5 complete with every gate passed, including the owner's M5 gate (GUI round
trips over Tor against the droplet). **M5c — the receiving-key path (DC-02, D-17) — is
code-complete:** a receiver creates a receiving key once (24 seed words to keep, a public
`askar1…` key to give out by any channel); a sender pastes it into *To* and posts — nothing to
hand over; the receiver enters the seed words and reads the note. X-Wing (ML-KEM-768 + X25519,
draft-11 vector reproduced) with the X25519 half written as an Elligator2 representative, so a
KEM Block looks like any other. CLI and GUI both do it; all gates pass, plus new ones for
uniformity, matching timing and receiving-key memory. **M6 first runs done (Ubuntu stand-in
for Debian; Tails and Qubes checklists still open → release gate), three packaging fixes. M7
release engineering done: signed releases (`docs/RELEASING.md`), `v0.1.0-alpha` owner-signed. M8: Security Review Package, Legal Review Brief and Release Checklist issued; internal pre-review done (2 High, 11 Medium fixed; `docs/Aska_Internal_PreReview_Report_v0.1.md`), Block Format draft 0.5 (`docs/Aska_Security_Review_Package_v0.1.md`, `docs/Aska_Legal_Review_Brief_v0.1.md`, `docs/Aska_Release_Checklist_v0.2.md`). **Aska 1.0.0 released 6 Oct 2026** — signed, verified independently, smoke-tested on Debian 13 (`docs/releases/v1.0.0.md`); external security and legal reviews not done (see `SECURITY.md`).** **Aska 1.0.1 released 7 Oct 2026:** the command-line client stops quietly with status 141 instead of aborting when its output is closed early (`aska verify | head -1`); nothing else changed (`docs/releases/v1.0.1.md`). **Aska 1.1.0 released 8 Oct 2026** — stored receiving keys (RM-09), in-process camera (`aska-scan`, D-22), the word-at-a-time note viewer (C-02), locked CLI input (C-10) and hardening; `docs/releases/v1.1.0.md`.
Plan: `docs/Aska_Prototype_Plan_v0.1.md`.

## Workspace

| Crate | What | Licence | Status |
|---|---|---|---|
| `crates/aska-core` | Block Format v1, keys, Shares, encodings, Tor transport, Dead Drop client, Session (the only place secrets live) | MIT OR Apache-2.0 | **M3 done** |
| `crates/aska-proto` | ADP/1 wire format, PoW, optional async client (`--features client`) | MIT OR Apache-2.0 | **M2 done** |
| `crates/aska` | command-line client: every Table 3 command, terminal QR, split mode, encrypted profile | MIT OR Apache-2.0 | **M4 code done** (owner's Tor gate pending) |
| `crates/aska-gui` | GTK4 / libadwaita graphical client: Home, Send, Hand-over, Receive, View, Settings, Shares, Receiving key | MIT OR Apache-2.0 | **M5 + M5c code done** |
| `crates/aska-drop` | Dead Drop relay: RAM-only store, PoW, no logs, mlock | AGPL-3.0 | **M2 done** |
| `crates/aska-scan` | in-process QR scanning: V4L2 camera capture through `libc` only, pure-Rust decoder (`rqrr`); frames wiped | MIT OR Apache-2.0 | **1.1** |
| `crates/aska-paper` | paper mode (DC-04): one-time pad pages with a hand tag and a device tag, the two-source entropy pipeline (health tests, min-entropy estimate, seeded Toeplitz extractor, mixing with the OS generator), Block and Share cards, the bitmap-font page renderer — in locked memory, nothing written | MIT OR Apache-2.0 | **1.2 (in development)** |

## Running it yourself (Debian 12/13 or Ubuntu 24.04+ in VirtualBox)

```bash
# 1. toolchain (once)
sudo apt update && sudo apt install -y build-essential pkg-config git python3 python3-pip
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# 2. get the code (git clone https://github.com/secunos/aska, or unpack a source archive)
cd aska

# 3. build and run every test (Argon2id at 256 MiB makes the vector tests take ~10 s;
#    the relay's interop tests start the Python reference relay/client — python3 is enough)
cargo test --workspace --release

# 4. the M1 conformance gate on its own
cargo test -p aska-core --release --test vectors

# 5. reproducible-build check (builds twice, compares hashes; static-pie binaries)
./scripts/repro-build.sh && ./scripts/repro-build.sh --compare

# 6. the M2 no-file-writes gate (needs strace)
sudo apt install -y strace && cargo build --release -p aska-drop && ./scripts/no-writes-check.sh

# 7. run the relay locally and poke it with the reference client
cargo run --release -p aska-drop -- serve --port 4567 --insecure-no-mlock &   # non-root VM: memory lock needs the systemd unit
python3 reference/aska_drop.py info --host 127.0.0.1 --port 4567 --socks none

# 8. the Python reference on its own, for comparison
pip install --break-system-packages pynacl argon2-cffi mnemonic   # or use a venv
python3 reference/test_aska.py && python3 reference/test_drop.py && python3 reference/aska_drop.py selftest
```

Expected: `cargo test` reports **118 passing tests** (+2 ignored: the slow timing-parity tests) —
aska-core 69 (33 unit incl. X-Wing vector/round-trip/uniformity, the Receiving Key encoding and
its hash-based check, the D-16 blocked-network finding, control-port discovery and the release
signature vector, 10 property incl. the header permutation, 8 vector, 13 session-e2e incl. the
receiving-key path and distress on both paths, 2 memory-gate, 2 tor-socks/doctor, 1 Mann–Whitney
sanity), aska-proto 11, aska-drop 19, aska 15 (5 unit, 10 CLI end-to-end incl. `key receive` /
`send --to` / `receive --receiving-seed` and the doctor trigger matrix), aska-gui 4;
`repro-build.sh --compare` prints `REPRODUCIBLE: OK`; `no-writes-check.sh` (relay),
`no-file-writes-client.sh` (core), `no-file-writes-cli.sh` (the `aska` binary, a whole send and
receive) and `no-file-writes-gui.sh` (the graphical client through a whole Send *and* Receive)
all print `OK`; `timing-parity.sh` prints `TIMING-PARITY: OK` (decoy vs distress opens, and
seed matching with vs without a match, Mann–Whitney p ≥ 0.01); `memory-gate-gui.sh` (root, as
it reads `/proc/PID/mem`) prints `MEMORY-GATE (GUI): OK`.

The graphical client needs the GTK development libraries to build:
`sudo apt install -y libgtk-4-dev libadwaita-1-dev pkg-config` (GTK ≥ 4.14, libadwaita ≥ 1.5 —
Debian 13, Ubuntu 24.04+, Tails 7). Run it with `cargo run --release -p aska-gui`.

## Trying the client end to end

Against an in-process relay, no Tor (also the T-10 file-writes gate):

```bash
cargo run --release -p aska-core --example local_e2e -- --verbose   # prints LOCAL E2E OK
./scripts/no-file-writes-client.sh                                   # core; needs strace
./scripts/no-file-writes-cli.sh                                      # the aska binary; needs strace + python3
```

Against the live droplet relay over real Tor (run in the VM, Tor listening on 127.0.0.1:9050):

```bash
cargo run --release -p aska-core --example live_e2e -- <onion-address>   # M3 gate: LIVE E2E OK
```

**The M5 gate (owner, in the VM against the droplet):** `cargo run --release -p aska-gui`, then
in one window *Send a note* → paste the onion address in *Relays* → *Seal and post* → the
Hand-over screen; in a second `aska-gui` (or the same one after *Done*) *Receive a note* → paste
the Key Card text (or read the 24 words off the first window) → *Check the drop* → the note on
the View screen → *Close and burn*. Repeat with a passphrase set on Send and entered on the
Receive keypad. Then Settings → *Check reachability*, create a profile, close and reopen the app,
open the profile, and send again without typing the relay.

**The M5c gate (owner):** on the receiving client, Shares → *Create a receiving key…* (relay =
the droplet) → note the check, keep the 24 words (write them down), copy the `askar1…` key.
On the sending client (or the same one after *Done*), Send → paste the key into *To* → note →
*Seal and post* → the Posted screen must show the **same check**. Then Receive → *I have a
receiving seed* → type the 24 words → *Add* → relay → *Check the drop* → the note. CLI
equivalent: `aska --relay ONION key receive`, `aska send --to askar1…`, `aska --relay ONION
receive --receiving-seed`.

## The `aska` command-line client (M4)

`aska --help` is the reference; `aska <command> --help` for each. The shape, from Client Design
Table 3:

```
aska doctor                                  environment checks (exit 0 clean, 2 warnings, 6 refusals)
aska send   [--level quick|guarded] [--shares 2of3] [--class N] [--ttl 24h] [--passphrase]
            [--decoy] [--distress] [--for NAME]… [--out-keycard FILE]
aska receive [--class N] [--view-seconds 300] [--attempts 3] [--interval 30]
aska share split --k 2 --n 3 [--for NAME]…  |  aska share combine [--check-only]
aska key words | aska key card [--auth-key]
aska seal --out BLOCK.bin …   /   aska post BLOCK.bin      Qubes split mode, sender side
aska drop get ONION --class N --out BUCKET.bin  /  aska open BUCKET.bin   receiver side
aska drop info|put|get ONION                 raw ADP/1 for operators and tests
aska key receive [--from-words]              new receiving key: 24 seed words + public askar1… key + check
aska send --to ASKAR …                       seal for a receiving key (nothing to hand over)
aska receive --receiving-seed                receive with the 24 seed words (DC-02)
aska verify                                  own SHA-256, release tag + key id, signed SHA256SUMS check (no network)
aska profile create|open|forget --file FILE  optional encrypted profile (relays + circle key, C-07)
aska paper generate [--source camera|dice|typing] [--pages 10] [--digits 400] [--no-hand-tag]
            (--rows | --ps | --pbm | --print PRINTER --i-have-read-the-rules)     one-time pad booklet (1.2, DC-04)
aska paper encipher|decipher|check-page [--page-from camera|typed]   a message with a pad page; tags checked first
aska paper worksheet                         the table, the arithmetic, the hand tag, the rules (not secret)
aska paper cover --set-code N --direction A|B --number N …   a cover page for a ciphertext and an innocent text
aska paper seal-cards … / aska paper open-cards   a Block as QR cards instead of a relay (classes 1–2)
aska paper share-cards                       Shares as cards, one per sheet
```

**Paper mode (1.2, in development; `docs/Aska_Design_Change_DC-04_Paper_Mode_v0.2.md`).** A pad
is printed only when the print spool is on volatile storage (tmpfs/ramfs) and the printer is
reached over USB — otherwise the client refuses and shows the page row by row for copying by
hand; `--ps`/`--pbm` write the sheets to standard output for an operator who knows where they go.
Every booklet is labelled PHYSICAL (camera noise through the seeded extractor met the entropy
budget) or SEEDED (dice or typing seeded the generator — computational, not a pad with a proof).
Block cards are read with the built-in camera only (the helper cannot carry bytes).

Global options: `--relay ONION` (repeatable), `--profile FILE`, `--socks HOST:PORT`
(default 127.0.0.1:9050, loopback only) or `--tor-browser` (Tor Browser's Tor on 127.0.0.1:9150),
`--control HOST:PORT` with `--control-cookie FILE` or
`--control-password` (only for circle-key relays), `-y/--yes` (acknowledge doctor warnings; a
success then exits 2), `--accept-unlocked-memory`, `--qr half|ascii|none`, `--idle SECONDS`,
`--scan-cmd CMD` (camera helper, used when no camera can be read in-process; default `zbarcam` from zbar-tools), `--scan-helper` (always use the helper), `--fast` (skip the
0–90 s cover delay; tests only), `--stdin` (scripting: every input from standard input, no
prompts — the order is in `aska --help`).

Rules the binary keeps: secrets are never taken from the command line or the environment —
only from the terminal (echo off), a camera helper, or `--stdin`; nothing is written to disk
unless you name a file (`--out`, `--out-keycard`, `profile create`), and never over an existing
one; hand-over material and notes are shown on the alternate screen with a countdown and the
screen is cleared afterwards; every command runs `doctor` first. Exit codes: 0 success ·
2 success after acknowledged warnings · 3 you declined · 4 relay unreachable or full ·
5 nothing found or opened · 6 refused (not through Tor, non-onion relay) · 1 other error.

A Quick hand-over from the terminal, sender and receiver:

```bash
aska --relay <onion> send --passphrase --ttl 48h      # type the note, end with a lone "." line;
                                                       # Key Card QR + 24 words appear until a key is pressed
aska receive                                           # paste the Key Card (or the words, or "scan"),
                                                       # enter the passphrase, read, any key burns it
```

Guarded: `aska --relay <onion> send --shares 2of3 --for Anna --for Bo` shows Share 1 of 3, then 2,
then 3, one at a time; each trustee later runs `aska --relay <onion> share combine` and pastes
their Shares (the relay address travels separately — Shares do not carry it).

**When the network blocks Tor (D-16, `docs/Aska_Design_Change_DC-01_Networks_that_Block_Tor_v0.2.md`):**
Aska is Tor-only and never configures Tor, so it cannot work around a blocking network by
itself — and must not fall back to anything else. What it does: with a control port configured,
`doctor` reports a Tor that runs but has not bootstrapped (`GETINFO status/bootstrap-phase` below
100 %) and names the platform's own connection tool (Tails: Tor Connection; Whonix: Anon
Connection Wizard; elsewhere Tor Browser's connection settings); without one, a `send` or
`receive` whose every attempt fails the way a blocked network fails ends with the same advice
and exit 4. A Tor Browser connected through a bridge serves as Aska's Tor with `--tor-browser`.
Session-scoped bridges via the control port are a v1.1 item; automatic bridge acquisition is
rejected by design.

**The M4 network gate (owner):** in the VM with Tor bootstrapped and the droplet relay up, run the
two commands above (Quick with `--passphrase --decoy`, then Guarded 2-of-3 with `share combine`)
between two Sessions — two terminals, or two machines — using only the CLI, and note the exit
codes; then the refusals: `aska --relay example.com send` must exit 6 before anything else, and
with Tor stopped `aska --relay <onion> receive` must exit 6 at the doctor. The Qubes split-mode
walkthrough (`seal` → `post` / `drop get --out` → `open`) is the M6 platform run.

## The graphical client (M5)

`aska-gui` is a GTK4/libadwaita application over the same core, the six screens of Client
Design §5 plus Shares:

- **Home** — identical on every launch: three buttons, the build fingerprint prefix and Tor state
  in the footer, doctor findings as banners with their actions (including "Use Tor Browser's Tor",
  D-16), the profile button and the settings gear.
- **Send** — the editor with a live byte counter and automatic Block size, the three protection
  cards, decoy/distress/TTL/relay options, the in-app shuffled passphrase keypad (§6.3), "Seal
  and post" with the Session sealed and posted on worker threads; a failed post keeps the Block
  and offers another relay.
- **Hand-over** — the Key Card as a QR drawn by the app, the 24 words, the CLI-14 banner, "Done —
  forget the key" with the five-minute countdown; Guarded shows one Share at a time.
- **Receive** — paste or type a Key Card, the 24 words or Shares one at a time ("Share accepted —
  1 of 2"), or scan with the camera (since 1.1 in-process: `aska-scan` reads the camera through
  V4L2 and decodes the QR code itself, with a viewfinder; the `zbarcam` helper is the fallback
  when no camera can be read, e.g. one that offers only MJPEG); relays as a fallback for key material that
  names none; the passphrase on the in-app keypad; **Check the drop** fetches the whole bucket from
  every relay on a worker thread, matches locally, opens across the KDF profiles and shows the
  note — or "Nothing found — the note may not be posted yet, or the drop may have expired".
- **View** — the note in a read-only, non-selectable label straight from the Session's locked
  buffer; countdown (default five minutes, Settings); **Close and burn**; a footer that says
  what this system does about screenshots (X11: cannot be prevented; Wayland: detected, not
  blocked); decoy, real and distress slots pass through the same code with nothing looking at
  which one opened.
- **Settings** — the environment checks with explanations and "Check again"; relays for this run
  with a reachability check (one INFO per relay over Tor) and the circle-key indicator; Tor source
  (system Tor / Tor Browser's Tor); cover-traffic level (off / modest / high, default modest, a
  scheduler that follows the relays and Tor state); the two timers (C-05); language (English,
  Svenska — rebuilds the screens); **Verify this app** (own SHA-256, embedded fingerprint, Rekor
  entry, how to compare out of band); the **encrypted profile** (C-07) — create, open, forget — at
  a typed path (no toolkit file chooser: GTK's records every chosen file in
  `~/.local/share/recently-used.xbel`, which the memory/file gates caught).
- **Shares** — split a key you hold whole (24 words or a Key Card) into 2-of-3 or 3-of-5 fresh
  Shares shown one at a time (the recovery drill), or go and combine Shares.

- **Receiving key** (DC-02, from Shares or Receive) — creates a receiving key: the 24 seed
  words to keep, the public `askar1…` key as text (copyable — it is public) and QR, and the
  eight-character **check** to confirm with the sender by another channel; or shows the public
  key for an existing seed. Send has a *To (receiving key)* field: with it filled, Guarded is
  off and the flow ends on a **Posted — nothing to hand over** screen showing the check. Receive
  has *I have a receiving seed*: the 24 words instead of a Key Card, then *Check the drop* tries
  every Block on the relays against the seed (same work per Block, matched or not).

Strings are externalised (`crates/aska-gui/locale/en.txt`, `sv.txt`, ~280 keys); the language
follows the system locale with English as the fallback (C-06) and can be switched in Settings.

Behaviours from §5.7 that are in place: the window title is always "aska"; there are no
notifications; the editors allow paste but not copy or cut and keep no undo history; an idle
Session closes itself and the app returns to Home; leaving Hand-over, Receive or View forgets the
key and burns the note. Text that passed through GTK widgets (the note in the editor and the
View label, the Key Card in the Hand-over label and the Receive field) is overwritten with a
same-length filler before it is cleared, so the allocator's recycled chunk is scrubbed — the
C-02 residual, measured rather than assumed: `scripts/memory-gate-gui.sh` drives a full round
trip and scans the live process from outside (`/proc/PID/mem`) after "Close and burn"; it finds
no root, no label, no note text and no Key Card text. The client also switches off the two
things the toolkit stack would otherwise write to disk — Mesa's shader cache and dconf's runtime
file — which is what `scripts/no-file-writes-gui.sh` verifies (Xvfb, xdotool, strace; with
zbarimg and ImageMagick it drives the Receive half too).

Two findings from those gates changed the core in M5b: `[u8; 32]` secrets that lived inline in
structs that get *moved* (the Session's label, the jobs' label, relays' circle key) left copies
behind at every move and are now boxed (`drop::Secret32`); and the private `*_inner` functions
that `scrub_stack` relies on are marked `#[inline(never)]`, because release builds inlined them
into the very frame the scrub cannot reach.

## Packaging and platform validation (M6)

`scripts/package-gui.sh [VERSION]` builds the release GUI and CLI and produces
`dist/aska-gui-VERSION-linux-x86_64.tar.gz`: `bin/aska-gui`, `bin/aska`, the desktop entry
and icon (`deploy/gui/`), a user-local `install.sh` (to `~/.local`, nothing else) and
`SHA256SUMS`. The GUI links the system GTK 4 / libadwaita; the CLI is static-pie.

Platform notes: on a **Whonix Workstation** (Qubes simple mode) the client detects Whonix and
uses the gateway's Tor at `10.152.152.10:9050` by default — the one non-loopback proxy it will
ever accept; circle-authorised relays are unusable there as on Tails (C-03: the control port
is filtered). The M6 checklists — Debian 13, Tails 7, Qubes simple and split mode, the doctor
trigger matrix and a recording template — are `docs/Aska_Platform_Validation_Checklists_M6_v0.2.md`.
The environment-derived doctor triggers are also checked in CI
(`doctor_findings_fire_on_their_triggers_and_stay_silent_otherwise`).

## Signed releases (M7)

`scripts/release.sh <tag>` builds a release candidate (clean tree at the tag, `REPRODUCIBLE: OK`,
the tarball directory with the project's minisign **public key** and the tag embedded, the
static relay, release notes) — reproducibly in the Debian 13 container of `release/Dockerfile`
(`RELEASE_CONTAINER=1`), the oldest supported glibc so the GUI runs everywhere.
`scripts/release.sh <tag> --sign` is run by the release owner where the secret key lives: it
signs `SHA256SUMS` inside the tarball directory, makes the deterministic tarball, signs the
tarball, the relay and `SHA256SUMS.txt`, and finally runs the shipped `bin/aska verify`, which
must say `MATCH`. `--rekor` records the tarball signature in the transparency log.

`aska verify` (and Settings → *Verify this app* in the GUI) hashes the running binary, finds
`SHA256SUMS` + `SHA256SUMS.minisig` beside it, one directory up, or in `~/.local/share/aska/`
(where `install.sh` copies them), checks the signature with the embedded key and checks that
the list names this binary — offline. A tampered list or a binary that is not in the list is a
`MISMATCH` and a doctor warning. Public key: `release/aska-release.pub` (the alpha key is to be
rotated by the owner before the first public release). Procedure: `docs/RELEASING.md`.

## Relay configuration (the whole surface)

`aska-drop serve [--port 4567] [--max-ttl-hours 168] [--cap-1 2000] [--cap-2 800] [--cap-3 200] [--pow-base 0]`.
Set a cap to 0 to stop serving that class. There is no data directory, no log level and no
admin port. The relay locks its memory and disables core dumps at start and refuses to run if it
cannot (exit code 3). Because everything it maps must then fit in `RLIMIT_MEMLOCK`, it also
refuses to start (exit 3, with the numbers) when that hard limit is smaller than the configured
caps need — about 98 MiB for the defaults; the systemd unit sets `LimitMEMLOCK=infinity`. The
hidden `--insecure-no-mlock` flag exists for development in an unprivileged VM only. Deploying
on a server, and upgrading a relay installed before 2026-09-29: `deploy/DEPLOY.md`.

## Toolchain pin

`rust-toolchain.toml` pins **Rust 1.95.0** literally (`channel = "1.95.0"`), and so does the
release container (`release/Dockerfile`); `release.sh` refuses any other compiler. The
CLI and the relay are static-pie (glibc `crt-static`); the GUI is dynamically linked against the
system GTK 4 / libadwaita and built on Debian 13 for release, so it runs on every supported
platform. A `musl` CLI target remains an option for later.

## Layout

```
Cargo.toml            workspace, pinned dependency versions, release profile
rust-toolchain.toml   toolchain pin
deny.toml             licence / advisory policy (cargo deny)
scripts/              repro-build.sh, no-writes-check.sh / no-file-writes-*.sh (strace gates), soak.py, fake_socks.py
crates/               Rust crates (see table)
reference/            Python reference implementation + test_vectors.json (the oracle)
deploy/               DEPLOY.md walkthrough, torrc, hardened systemd unit, Debian install script
docs/                 all design documents (Markdown twins of the Word files)
```
