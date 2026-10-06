# Aska — Platform Validation Checklists (Milestone M6)

## Version 0.2 — 1 October 2026 (§1 refresh/build steps; A2/A5 corrected; §8 records of the first runs; §9 packaging findings)

- **Purpose:** the M6 gate of the Prototype Plan: "the Tails checklist passes with zero deviations; the Qubes split-mode checklist passes; every doctor finding fires on its trigger and stays silent otherwise." These are the checklists, one per platform, plus the doctor trigger matrix and a recording template. The tester is the project owner; the developer (Claude) fixes deviations and re-issues the build.
- **Build under test:** the `aska-gui-<version>-linux-x86_64.tar.gz` made by `scripts/package-gui.sh` (GUI + CLI + desktop entry + icon + `install.sh` + `SHA256SUMS`), commit noted in the record. Record the SHA-256 of both binaries as `aska verify` prints them.
- **Relay:** the droplet relay over Tor (the onion address is held by the owner; not written here). A second, disposable relay is not needed.
- **What "pass" means:** every numbered line behaves as written. Anything else is a **deviation**: record it verbatim (message, screenshot), do not work around it, continue with the next line where possible.

---

# 1. Preparation (any machine)

1. **Refresh the source on the build machine** so the build under test is the latest commit (the one in the record; the code under test is `3d4453b`, "M6 preparation" — later documentation-only commits do not change the binaries). In the owner's VM, where the repository arrives through the shared folder:

   ```sh
   cp -r /media/sf_askacode/aska ~/aska-new && rm -rf ~/aska && mv ~/aska-new ~/aska
   cd ~/aska && source ~/.cargo/env
   ls crates/aska-gui/src/ui/rxkey.rs deploy/gui/install.sh scripts/package-gui.sh   # all three must exist
   ```

   If any of the three files is missing, the shared folder is stale: unpack the latest `aska-code-*.zip` from `Code\` instead and repeat the check. A build from an older tree is **not** the build under test, whatever it reports.
2. **Build the tarball** on the refreshed tree: `scripts/package-gui.sh` (it runs `cargo build --release --locked -p aska-gui -p aska` itself — about five minutes in the VM — and prints the tarball's SHA-256; the tarball lands in `dist/`). Optionally first `scripts/repro-build.sh && scripts/repro-build.sh --compare` → `REPRODUCIBLE: OK`. Write the three SHA-256 values (tarball, `bin/aska`, `bin/aska-gui` from `dist/aska-gui-*/SHA256SUMS`) on paper. They are the fingerprints every platform compares against **before** running anything.

   *Variant — test from the build tree instead of the tarball.* If the VM that built is also the Debian test machine (Checklist A), the just-built binaries may be tested in place: `./deploy/gui/install.sh` needs the tarball layout, so either run `scripts/package-gui.sh` and `cd dist/aska-gui-*` (A1 and A2 then apply literally), or skip the installer and run `target/release/aska` / `target/release/aska-gui` directly — in that case A1 and A2 are replaced by `sha256sum target/release/aska target/release/aska-gui` written on paper, A4 compares against those, and A5 is started from a terminal (no Activities icon, no `build` line change). Everything from A3 on is the same. Checklists B, C and D always use the tarball, because the Tails and Qubes machines do not build.

   *Variant — the developer's tarball.* The developer builds the same commit in a container with glibc 2.39 (Ubuntu 24.04) and delivers it as `Code\aska-gui-<version>-linux-x86_64.tar.gz` (from 2026-10-01 named `…-dev.tar.gz`, so it cannot overwrite an owner build of the same name in the shared folder). Its CLI is static-pie and its GUI is linked against glibc 2.39, so it runs on Debian 13 / Tails 7 and newer. A tarball built on a newer distribution (Ubuntu 26.04 in the owner's VM) may refuse to start on Tails or Debian with `version 'GLIBC_2.4x' not found`: that is a packaging finding (§9 item 6), not a product deviation — record it and use the developer's tarball. Whichever tarball is used, its three SHA-256 values are the paper values for that run.
3. Put the tarball on a USB stick (Tails), or transfer it into the qube (Qubes: `qvm-copy`), or download it (Debian). Do not put anything else on the stick.
4. Have ready: the droplet onion address (on paper), a second Aska on another machine or VM to send to / receive from, and a phone or webcam if QR scanning is to be tested.
5. Before Checklist A, run the **M5c gate** on the same refreshed build (Shares → *Create a receiving key…* → Send → *To* → *Posted* with the same check → Receive with the seed). A10–A12 repeat it as part of the checklist, so a pass there counts for both.

# 2. Checklist A — Debian 13, GNOME on Wayland (§8.3: supported, baseline)

Environment: Debian 13 with `tor` installed and running (`systemctl status tor`), GNOME Wayland session, swap as installed by default (on).

| # | Step | Expected | Result |
|---|---|---|---|
| A1 | `sha256sum aska-gui-*.tar.gz` | Matches the paper value. | |
| A2 | `touch /tmp/m6-marker; tar xzf …; cd aska-gui-*; sha256sum bin/aska bin/aska-gui`; `./install.sh`; `find ~ -newer /tmp/m6-marker -type f` | Both match; installer reports the three paths. The `find` lists the extracted tarball, the two binaries, the desktop entry, the icon and `~/.local/share/applications/mimeinfo.cache` (written by `update-desktop-database`, which the installer calls) — nothing else from Aska. Desktop indexers (`~/.cache/tracker3/…`) may also appear; they are not Aska. (A marker file is used because a tarball built without `.git` carries 1970 timestamps.) | |
| A3 | `aska doctor` | `[WARN] Swap is enabled…` (default Debian has swap); no X11 warning; no Tor finding; exit 2. Disable swap (`sudo swapoff -a`) → run again → no swap line, exit 0. | |
| A4 | `aska verify` | Shows this binary's SHA-256 (= paper value), "none — development build" for embedded fingerprint and Rekor (until M7), "unverifiable" status. | |
| A5 | Start `aska-gui` from the Activities grid (icon and name "Aska") | Home: three buttons, footer `build <12 hex>` = first 12 of the SHA-256, `Tor: connected`; banners only for the swap warning if still on. Window title "aska" in the top bar. (Installers before commit 8e02af2 wrote `Exec=aska-gui` without a path; on a desktop whose session PATH did not yet include `~/.local/bin` the icon then did nothing until the next login. The installer now writes the absolute path.) | |
| A6 | Send a note (Quick, no options) to the droplet | Hand-over: QR, 24 words, relay line; countdown 05:00 running. | |
| A7 | Second Aska: Receive with the Key Card → *Check the drop* | Note on View within ~2 minutes; countdown; *Close and burn* → Home with toast. | |
| A8 | Repeat A6/A7 with a passphrase on the keypad, decoy on, distress on: open with the real, the decoy and the distress passphrase (three receives) | Real note; decoy text; distress shows the decoy text and afterwards the Session is gone (a second attempt in the same Receive says nothing opened / start over). Timing of the three opens indistinguishable to the eye. | |
| A9 | Send Guarded 2-of-3 with names → Hand-over shows Share 1 of 3 … Next … Done | Never two Shares on screen; back arrow forgets. Receive: Shares → *Combine Shares…* → two Shares → key reconstructed → note. A third, foreign Share is rejected with the "different set" message. | |
| A10 | Shares → *Create a receiving key…* (relay = droplet) | 24 words, check (8 chars), QR, `askar1…` text, *Copy the key* works (paste into a text editor and delete it). | |
| A11 | Send → *To* = the key → post | **Posted — nothing to hand over** with the **same check**. Protection cards greyed out while *To* is filled. | |
| A12 | Receive → *I have a receiving seed* → words → relay → *Check the drop* | Note; after burn the toast says the key has been used. | |
| A13 | Settings: *Check reachability* on the droplet | `reachable — classes 1,2,3, max TTL 168 h, PoW 0 bits`. | |
| A14 | Settings: profile at `~/aska.profile`, passphrase, *Create…*; quit; start; *Open…* | Relays pre-filled on Send. `ls -la ~/aska.profile` = 4096 bytes. *Forget…* → confirm → file gone. `find ~ -newer <marker> -type f` shows nothing else written by Aska during the whole session (create the marker file before starting the GUI). | |
| A15 | Settings: language → Svenska | Every screen in Swedish; back to English. | |
| A16 | Leave a Send half-typed for 5 minutes | Idle: nothing happens on Send (no Session yet); leave a Hand-over for 5 minutes → returns Home with "session ended". | |
| A17 | Log in to an **X11** session (GDM gear icon) and start `aska-gui` | Home banner "X11 session: screenshots cannot be prevented"; View footer "Screenshots cannot be prevented on X11." | |
| A18 | Back on Wayland, start `gnome-screen-recorder`/OBS (or press Ctrl+Shift+Alt+R) and run `aska doctor` | `[WARN] Screen is being shared or recorded.` (process-name detection; see §6 for the portal gap). | |
| A19 | `aska --socks 127.0.0.1:9 doctor` | `[REFUSE] Not connected through Tor…`, exit 6; GUI with Tor stopped (`sudo systemctl stop tor`) shows the red banner and disabled Send. | |
| A20 | Tor Browser open and connected; `sudo systemctl stop tor`; GUI | Banner offers *Use Tor Browser's Tor*; after choosing it, footer "Tor: connected via Tor Browser"; a send works. CLI: `aska --tor-browser doctor` exit 0. | |
| A21 | Measure: `time aska --relay ONION --fast --stdin --yes send <<< "timing"` on this hardware | Note the elapsed seconds (Argon2id 256 MiB dominates sealing; expect 1–3 s). | |

# 3. Checklist B — Tails 7 from a fresh USB stick (§8.1: the amnesic reference)

Environment: Tails 7 booted from a stick written by the Tails installer; Persistent Storage **not** unlocked (first run); Tor Connection completed (plain or with a bridge, per the network).

| # | Step | Expected | Result |
|---|---|---|---|
| B1 | Insert the tarball stick; `sha256sum` it | Matches the paper value. | |
| B2 | `mkdir ~/aska && tar xzf …tar.gz -C ~/aska` (home is RAM on Tails); `sha256sum` both binaries | Match. Do **not** run `install.sh` (it would write to `~/.local`, which is also RAM but the desktop entry is pointless on Tails). | |
| B3 | `~/aska/*/bin/aska doctor` | Expected findings on Tails: **none** for swap (Tails has none), mlock OK or a warning "Cannot lock memory" if `ulimit -l` is 8 MiB (record which — if it warns, `--accept-unlocked-memory` is needed and this is a deviation to fix in packaging/documentation), no X11 warning (Tails 7 is Wayland), Tor at 127.0.0.1:9050 OK. If Persistent Storage is unlocked: `[INFO] Persistent Storage is unlocked…`. | |
| B4 | `~/aska/*/bin/aska-gui` | Starts (Tails 7 ships GTK 4.14 / libadwaita 1.5). Record the start-up warnings, if any. Footer "Tor: connected". Tails' Tor control port is filtered by onion-grater: the GUI must **not** show a bootstrap warning and must not fail on it. | |
| B5 | Send a note to the droplet; receive it on the other machine | Works. Note the time from *Seal and post* to Hand-over (cover delay + Argon2id + Tor; record it). | |
| B6 | Receive on Tails with the Key Card from the other machine | Works; View; burn. | |
| B7 | Receiving key on Tails: create, send to it from the other machine, receive with the words on Tails | Works; the check matches on both sides. | |
| B8 | C-03: on the other machine, `aska --relay ONION key card --auth-key` with a made-up 64-hex key → a Key Card whose relay requires a circle key; paste it into Receive on Tails | Tails: "every relay needs a circle key, which cannot be installed on Tails or Whonix (C-03)" — refused before any network step, with the explanation. CLI `receive` exits 6. | |
| B9 | Tails screenshot (PrtSc) while a note is on View | The screenshot is taken (Tails cannot prevent it); the View footer says "Screen capture can be detected but not blocked on this system." — honest. | |
| B10 | Argon2id time on this hardware: `time aska --fast --stdin --yes seal --out /tmp/t.bin <<< "t"` (then `rm /tmp/t.bin`; or time a GUI seal) | Record seconds. The reference figure goes into the Client Design (§6.2 KDF profile note). | |
| B11 | Profile on Tails: Settings → *Create…* at `~/aska.profile` | Works (RAM). Explain in the record that only Persistent Storage would survive a reboot, and only for the profile. | |
| B12 | Close Aska; `ls -la ~/.local/share ~/.cache ~/.config 2>/dev/null` | Nothing created by Aska (compare with a listing taken before starting it). | |
| B13 | Shut down Tails; boot again; check `~/aska` | Gone (amnesia). | |

# 4. Checklist C — Qubes OS 4.3, simple mode (§8.2)

Environment: a **disposable Whonix-Workstation** qube (netvm `sys-whonix`), Qubes 4.3. Tor runs in the gateway: the SOCKS proxy is `10.152.152.10:9050`, which the client accepts **only** when it detects Whonix (this is the one non-loopback proxy address it will ever use).

| # | Step | Expected | Result |
|---|---|---|---|
| C1 | `qvm-copy` the tarball into the disposable; `sha256sum` | Matches. | |
| C2 | `aska doctor` | Uses `10.152.152.10:9050` by default (`aska doctor --help` shows the platform default); no Tor finding; no swap (Whonix templates have none by default — record if it warns); Wayland or X11 per the qube's session (Qubes 4.3 GUI domains are X11 to the qube: expect the X11 warning and record it — the qube's screenshots are taken by dom0, which the client cannot see). | |
| C3 | `aska --socks 127.0.0.1:9050 doctor` | `[REFUSE]` (no Tor there), exit 6 — proves the default was needed and that the client still refuses unknown proxies. | |
| C4 | GUI: Send to the droplet, receive on another machine | Works. Footer "Tor: connected". | |
| C5 | C-03 on Whonix: the auth-key Key Card of B8 | Same refusal text as Tails ("Tails or Whonix"). | |
| C6 | Close the disposable | Gone; nothing to check. | |

# 5. Checklist D — Qubes OS 4.3, split mode (§8.2, highest assurance)

Environment: an offline **vault** qube (no netvm) with the CLI copied in, and a disposable Whonix-Workstation ("net") for the network steps. Everything that touches a key happens in the vault; everything that touches Tor happens in net.

| # | Step | Expected | Result |
|---|---|---|---|
| D1 | vault: `aska --stdin --yes seal --level guarded --shares 2of3 --out block.bin <<< "split-mode note"` (or interactively) | Prints Sealed; shows Shares one at a time (interactive) or SHARE lines (`--stdin`); `block.bin` is 4 096 bytes of noise (`hexdump -C block.bin \| head`). No network was possible. | |
| D2 | `qvm-copy block.bin` to net; net: `aska post block.bin --relay ONION` | Posted (relay stored). | |
| D3 | net: `aska drop get ONION --class 1 --out bucket.bin` | Bucket file with N records (the whole class-1 bucket, including other people's Blocks). | |
| D4 | `qvm-copy bucket.bin` to vault; vault: `aska open bucket.bin` with two Shares | Label matched offline; the note is shown; burned. | |
| D5 | **KEM Blocks in split mode:** vault: `aska key receive` → words + `askar1…`; another machine sends to that key (any mode); net: `aska drop get … --out bucket2.bin`; vault: `aska open bucket2.bin --receiving-seed` with the words | The note opens offline by decapsulating every record of the bucket. | |
| D6 | vault: `find ~ -newer block.bin -type f` | Only the files you named (`block.bin`, `bucket*.bin`) and nothing else. | |

# 6. Doctor trigger matrix (Client Design Table 4; gate: fires on trigger, silent otherwise)

The environment-derived rows are also checked automatically in CI (`doctor_findings_fire_on_their_triggers_and_stay_silent_otherwise`). The platform rows are checked here.

| Check | Trigger on the test machine | Must show | Must be silent when |
|---|---|---|---|
| Swap | Debian default (swap on) | `[WARN] Swap is enabled…` | `swapoff -a`; Tails; Whonix template |
| Memory lock | `ulimit -l 1024` in the shell before `aska doctor` | `[WARN] Cannot lock memory…` | default limits (record the value: `ulimit -l`) |
| Screen capture (X11) | X11 session | `X11 session: screenshots cannot be prevented` | Wayland |
| Screen capture (recorder) | start OBS / wf-recorder / Kooha | `Screen is being shared or recorded.` | recorder closed. **Known gap:** the PipeWire ScreenCast-portal probe (GNOME's own recorder, Ctrl+Shift+Alt+R) is not implemented — record whether it fires; it will not, and this is an M6 fix item |
| Remote desktop | `SSH_CONNECTION=x DISPLAY=:0 aska doctor`, or GNOME Remote Desktop / x11vnc running | `A remote session is active.` | plain SSH without a display; no VNC |
| Accessibility | `GNOME_ACCESSIBILITY=1 aska doctor`, or Orca running | `An accessibility service could read notes.` | Orca off. **Known gap:** the AT-SPI registry client probe is not implemented (only Orca by name and the env variable) |
| Tor not reachable | `--socks 127.0.0.1:9`; `systemctl stop tor` | `[REFUSE] Not connected through Tor…` exit 6 | Tor running |
| Tor cannot reach the network | with `--control 127.0.0.1:9051` and a Tor stuck bootstrapping (block its guards with a firewall rule, or a network that blocks Tor) | `[WARN] Tor is running but has not reached the Tor network (bootstrap N %)…` with the platform's direction | bootstrap 100 %; no control port |
| Non-onion relay | `--relay example.com` | `Only .onion relays are allowed` refuse, exit 6 | valid onion |
| Fingerprint | (only with an embedded release fingerprint, M7) | `This build does not match its release fingerprint` | matching build |
| Core dumps | `ulimit -c unlimited` and `sudo sysctl kernel.core_pattern=core` | `[WARN] Crash dumps enabled…` (record whether the client's own `PR_SET_DUMPABLE` clearing suppresses it — expected: the client clears dumpable, so the warning appears only if that failed) | default |
| Tails persistence | Tails with Persistent Storage unlocked | `[INFO] Persistent Storage is unlocked…` | locked / not Tails |

# 7. GUI behaviours to confirm visually (§5.7)

- Window title is "aska" on every screen (top bar / overview thumbnail).
- No notification ever appears (GNOME notification list stays empty after a full session).
- In the note editor: Ctrl+C / Ctrl+X do nothing (the clipboard is emptied); Ctrl+V works. The Key Card text on Hand-over cannot be selected; the fingerprint in the footer and the relay addresses in Settings can.
- Keypad: shuffles after every key when *Shuffle keys* is on; the physical-keyboard fallback shows its warning.
- Leaving Hand-over, Receive or View by the back arrow forgets the key / burns the note (toast).
- The View countdown and the idle countdown run down and act.

# 8. Recording template

For each checklist copy this header and fill one line per step:

```
Platform: Debian 13 / Tails 7.x / Qubes 4.3 simple / Qubes 4.3 split
Date:                Tester:              Build commit:
Tarball SHA-256:
bin/aska SHA-256:                          bin/aska-gui SHA-256:
Hardware (CPU, RAM):                       Argon2id seal time (s):
Step  Result (pass / DEVIATION)  Note / screenshot file
A1    pass
A3    DEVIATION  "…exact message…"  shot-A3.png
```

**Records so far (1 October 2026):**

```
Platform: Ubuntu 26.04.1 in VirtualBox, GNOME Wayland (stand-in for Debian 13; Checklist A)
Date: 2026-10-01   Tester: owner   Build commit: 3d4453b (owner build, package-gui.sh in the VM)
Tarball SHA-256: owner's paper value   bin/aska: e1d92b1f…4ff060   bin/aska-gui: df530e20…817f02
A1    pass
A2    pass   mimeinfo.cache (installer) and ~/.cache/tracker3/* (GNOME indexer) also listed — see A2 note
A5    FINDING (packaging)  desktop entry Exec without path; fixed in 8e02af2 (install.sh writes the absolute path)
A3–A21  owner reports the run completed; no deviations were reported; per-line results were not recorded
A17   not testable on Ubuntu 26.04 (no Xorg session); XWayland approximation only
Platform: Tails 7 on a USB stick (Checklist B)
Date: 2026-10-01   Tester: owner   Build: owner tarball + developer tarball (glibc 2.39) on a FAT32 stick
B1–B2  reached (stick had to be reformatted from exFAT to FAT32: Tails did not mount exFAT)
B3–B13 NOT RUN — owner discontinued the run for lack of time and decided (2026-10-01) to proceed on the
       assumption that Tails works; B, C and D remain OPEN gate items to be completed before release.
Platform: Qubes 4.3 simple / split (Checklists C, D) — NOT RUN.
Platform: Debian 13 (Checklist A, baseline) — NOT RUN; the Ubuntu run stands in until then.
```

**Gate status:** M6 is **not** passed. The M6 gate as written ("Tails checklist zero deviations; split-mode checklist passes; doctor matrix") stays open and moves to the release checklist (M8). What is established: the build installs and runs on a current GNOME/Wayland desktop with every flow exercised once by the owner, and the packaging produced three findings, all fixed (§9).

Deviations go to the developer as they are found; the checklist is re-run from the failing step on the fixed build. The gate is met when the Tails checklist has zero deviations, the split-mode checklist passes, and every row of §6 behaves as written or is recorded as one of the two known gaps (portal screencast probe, AT-SPI probe) with a fix scheduled.

# 9. Known gaps going into M6 (so they are not rediscovered)

1. Doctor: the ScreenCast-portal and AT-SPI D-Bus probes of Table 4 are not implemented; detection is by process name and environment only.
2. GUI: the desktop-portal camera (C-04) is not built; QR scanning uses the external `zbarcam` helper (`zbar-tools`).
3. GUI: KDE Wayland's per-window capture flag is not requested; the View footer therefore says "detected but not blocked" on every Wayland desktop.
4. Whonix: `10.152.152.10` is accepted as the proxy only when Whonix is detected (`/etc/whonix_version`, `/usr/share/whonix`, or `os-release`); a Whonix template that renames these would fall back to refusing — record if seen.
5. Tails: the `RLIMIT_MEMLOCK` default (8 MiB) may be below what the client wants for a class-3 fetch; the doctor will warn and the user must accept unlocked memory. Whether this happens on Tails 7 is exactly what B3 records.
6. Packaging (found 2026-10-01): (a) `install.sh` wrote `Exec=aska-gui` without a path → icon inert until re-login (fixed 8e02af2); (b) `package-gui.sh` built the CLI dynamically although the tarball claimed static → fixed 68bc609 (crt-static, own target dir); (c) the GUI is dynamically linked against the build machine's glibc, so release tarballs must be built on the oldest supported glibc (Debian 13 / glibc 2.41 or older) — M7 release engineering builds in a Debian 13 container; (d) the first `find -newer bin/aska` check in A2 was wrong for `.git`-less trees (1970 timestamps) → marker file.
7. Tails did not mount an exFAT stick (Windows' default for sticks > 32 GB); the tarball stick must be FAT32. To be written into the user documentation.
