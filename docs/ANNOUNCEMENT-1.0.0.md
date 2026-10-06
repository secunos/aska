# Aska 1.0.0 — release announcement

**Aska** sends a short note to one person or a small group in a way that leaves nothing behind. The note is encrypted on your computer with quantum-resistant cryptography, parked as unreadable noise on a relay reachable only through Tor, fetched by the receiver, shown once, and gone. There is no account, no history, no contacts, no log, and nothing is written to disk.

This is the first release. Linux x86-64 only: Debian 13, Ubuntu 24.04+, Tails 7, Qubes OS 4.3 (Whonix). **Tested on the signed release:** Debian 13 (install, self-verification, send and receive over Tor with and without a passphrase). Tails 7 and Qubes OS are supported by design and were exercised on development builds, but **not re-tested on this signed release** — please report how it goes.

## What is in it

- A graphical client (GTK 4) and a command-line client with the same behaviour.
- Three ways to pass the key: a Key Card (QR / text) or 24 words for people who can meet or call; k-of-n Shares for people who might be pressured, so that no single person can open the note; and a public **Receiving Key** for people who have never met, with a twelve-character check to confirm it was not swapped.
- Optional passphrase, decoy note and distress passphrase (shows the decoy and destroys the real note's key on the device).
- Environment checks before every use (Tor, swap, memory locking, screen recording, X11, …), cover traffic while the app is open, an encrypted profile for your circle's relays as the only thing ever written.
- The relay (`aska-drop`): RAM only, no logs, Tor onion service, a static binary and a one-shot installer for a Debian server.
- Reproducible builds, signed releases, and `aska verify` so the app can check itself against the signed hash list offline.

## What it does not promise

Please read section 9 of the User Guide before relying on Aska. In short:

- Aska protects the message and the trail. It cannot protect you from the person you send to, from a camera pointed at the screen, or from a computer that is already compromised.
- It cannot make Tor work on a network that blocks Tor, and it will not try. Use your platform's own tool to connect Tor through a bridge; Aska then uses that Tor.
- A note passes through the toolkit's text widgets and the compositor; Aska overwrites what it can and measures the result, but Tails (no swap, RAM wiped at shutdown) is the only configuration in which we consider the residual negligible.
- The built-in GNOME screen recorder and accessibility clients are not detected (known gap); common recorders are detected by process name only.
- The decoy and distress features have **not** been reviewed by a lawyer. In some jurisdictions destroying material under compulsion is itself an offence. Decide with that in mind.
- A very large sample of Blocks from one relay could in principle reveal what fraction were sent to Receiving Keys — never which ones, never their contents.
- **This release has not been independently audited.** It has passed the project's own gates and an internal security pre-review whose report is published with the source (two High and eleven Medium findings, all fixed before this release). The Security Review Package and the Legal Review Brief are published so that anyone qualified can conduct a review; we will publish any such report with the next release.

**Never install an update because software told you one exists.** Aska never does, and a message claiming to be from Aska that does is a lie. Get the new fingerprint from the person you trust, then the files.

## Get it

Release page: https://github.com/secunos/aska/releases/tag/v1.0.0 — source and documents: https://github.com/secunos/aska

Before you download, obtain these from a source you trust that is not the download site, and write them down:

```
Tarball        aska-gui-1.0.0-linux-x86_64.tar.gz
SHA-256        53ca86eda671a36206b9a7fc4959acd3cd414bc1676323c5ebbb1ce17e2cade0
Relay binary   aska-drop-1.0.0-linux-x86_64
SHA-256        2e36b4cc315681594667b4385851836da77dcc887bda160c1bc36d86febcd088
Signing key    79AD6224AFF176C9
Public key     RWTJdvGvJGKtecwP4zEITLdIK5yvwDp8+PyjmaoWPMHPLJxHDbGs+Oox
Rekor entry    none for this release
```

Then: `sha256sum` the tarball and compare; `minisign -V -P <public key> -m <tarball>`; unpack; `./bin/aska verify` must say MATCH; `./install.sh`. The User Guide (`docs/USER_GUIDE.md` inside the tarball) has the full procedure, and the Relay Operator Guide is in `aska-drop-deploy-1.0.0.tar.gz`.

## Reporting problems

A report must never contain a note, a key, a Key Card, a passphrase or a relay address; the output of `aska doctor` and the exact error text are enough. Security issues: privately, through *Security → Report a vulnerability* on the repository (see `SECURITY.md`). Everything else: https://github.com/secunos/aska/issues.

## Licence

Core and clients: MIT or Apache-2.0, at your choice. Relay: AGPL-3.0. No warranty of any kind.
