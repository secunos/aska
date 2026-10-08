# Aska 1.1.0

The first feature release after 1.0. Everything from 1.0 still works the same way, and notes, keys and profiles made by 1.0 open in 1.1 and the other way round.

## New

- **Keep a receiving key in the profile.** If people write to you at a long-lived Receiving Key, you can store its seed in the encrypted profile and pick the key by its twelve-character check instead of typing 24 words each time — in the app and on the command line. Up to eight keys; the profile stays one small file of random-looking bytes. Keep the words on paper as a backup.
- **Camera in Aska itself.** *Scan with camera…* now opens a viewfinder and reads the QR code in-process; the picture is wiped as soon as the code is read. On Debian and Ubuntu your user must be in the `video` group. The `zbarcam` helper remains the fallback. **This path has not yet been tried on a real camera** — the project's machines have none — so if you have one, please report how it goes.
- **A note viewer of Aska's own.** The note is drawn word by word from locked memory and never passes through a toolkit text box; it cannot be selected or copied, and accessibility tools cannot read it.

## Hardened

- The command-line client reads everything you type straight into locked memory, one byte at a time, instead of through standard input buffers.
- On the receiving-key path a distress open and a decoy open now end with exactly the same words on screen (1.0 differed in one closing line).
- The command-line `--ttl` accepts only the six expiry times the cover traffic imitates.
- The relay wipes expired labels, spent challenges and refused uploads in memory as it frees them; the installer sets up the RAM-only journal before the relay first starts.
- Stricter Key Card decoding; circle keys cleared when a session closes; profile files checked before they are read.

## About screen capture

No application on Wayland can hide its own window from screenshots or recordings — on KDE or anywhere else. KDE Plasma 6.6 and later offer it as a **user** action (title bar → More Actions → *Hide from Screencast*); Aska now points you to it on those systems. Elsewhere capture is detected, not blocked, as before.

## Still true

This release, like 1.0, **has not been independently audited** and has had no legal review; the owner has decided neither is planned. Read section 9 of the User Guide before relying on Aska. Tested on the signed release: Debian 13. Tails 7 and Qubes OS were not re-tested.

**Never install an update because software told you one exists.** Aska never does. Get the new fingerprint from the person you trust, then the files.

## Get it

Before you download, obtain these from a source you trust that is not the download site:

```
Tarball        aska-gui-1.1.0-linux-x86_64.tar.gz
SHA-256        deafa6629dfb593c8c2d35b0091b55ab63f1ec9e09ac48ba01fd6446f53ad34f
Relay binary   aska-drop-1.1.0-linux-x86_64
SHA-256        a5db77e858cd1b1bc069f3fff92decde4ef6e8a5e126a8ff92ff25a14774f4e2
Signing key    79AD6224AFF176C9   (unchanged)
Public key     RWTJdvGvJGKtecwP4zEITLdIK5yvwDp8+PyjmaoWPMHPLJxHDbGs+Oox
Rekor entry    none for this release
```

Then: `sha256sum` the tarball and compare; `minisign -V -P <public key> -m <tarball>`; unpack; `./bin/aska verify` must say MATCH; `./install.sh` (it replaces 1.0.x). Full procedure: User Guide §3 (`docs/USER_GUIDE.md` inside the tarball). Relay operators: the wire protocol is unchanged and upgrading is optional; the Relay Operator Guide is in `aska-drop-deploy-1.1.0.tar.gz`. Release record: `docs/releases/v1.1.0.md`.

## Reporting problems

A report must never contain a note, a key, a Key Card, a passphrase or a relay address. Security issues: privately, through *Security → Report a vulnerability* on the repository (see `SECURITY.md`). Everything else: https://github.com/secunos/aska/issues.
