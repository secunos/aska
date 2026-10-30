# Aska 1.2.3

A small release: **brand 3.0.** The identity of 1.2.2 is replaced by the **Perforerad mark** — a perforated plate whose holes shrink away toward the upper right — with the name **ASKA** set below it; black and white, with one signal colour, yellow, that marks the brand and nothing else; colour otherwise only where it says something (connected, warning, refused); no slogan. The app icon is now the mark on a yellow tile, the Home screen shows the mark with the name under it, the main button is ink with a yellow label (yellow with an ink label in the dark style), warnings are orange, and buttons are sharper rectangles.

Nothing else changed in Aska's own code: no behaviour, no format, no rule. Two dependencies were updated for advisories published after 1.2.2 — `ctutils` (used inside the ML-KEM implementation; its constant-time masks could branch on some platforms) and `tokio` (an unsound API Aska does not use) — with the known-answer tests unchanged; the release record has the details. Everything from 1.2.0 works exactly as before, and notes, keys, pad pages and profiles are unaffected. Relay operators may upgrade `aska-drop` to pick up the `tokio` fix; they need not.

## Still true

This release, like every one before it, **has not been independently audited** and has had no legal review. Read section 9 of the User Guide before relying on Aska. **Never install an update because software told you one exists.** Aska never does. Get the new fingerprint from the person you trust, then the files.

## Get it

```
Tarball        aska-gui-1.2.3-linux-x86_64.tar.gz
SHA-256        TBD
Relay binary   aska-drop-1.2.3-linux-x86_64
SHA-256        TBD
Signing key    79AD6224AFF176C9   (unchanged)
Public key     RWTJdvGvJGKtecwP4zEITLdIK5yvwDp8+PyjmaoWPMHPLJxHDbGs+Oox
Rekor entry    none for this release
```

Then: `sha256sum` the tarball and compare; `minisign -V -P <public key> -m <tarball>`; unpack; `./bin/aska verify` must say MATCH; `./install.sh` (it replaces 1.2.2 and installs the new icon). Full procedure: User Guide §3. Release record: `docs/releases/v1.2.3.md`.

## Reporting problems

A report must never contain a note, a key, a Key Card, a passphrase, a pad page or a relay address. Security issues: privately, through *Security → Report a vulnerability* (see `SECURITY.md`). Everything else: https://github.com/secunos/aska/issues.
