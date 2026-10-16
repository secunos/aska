# Aska 1.2.0

The paper release. Everything from 1.0 and 1.1 works as before, and notes, keys, Receiving Keys and profiles made by earlier versions open in 1.2 and the other way round. Nothing on the relay changed; operators need not upgrade.

## New: the paper mode

For the moment when there is no computer you trust — or none at all.

- **A one-time pad booklet on paper.** Aska makes a booklet of pages of random digits — from your camera's sensor noise, measured with health tests and compressed with a safety margin (**PHYSICAL**), or from die rolls or keyboard timing seeding a generator (**SEEDED**; every page says which) — and the two of you each keep a copy. A message becomes digits by a small public table, is added to the page's digits by hand, and is sent as digits over any channel at all. The receiver subtracts with the matching page. The cipher has a proof; its rules do not: one page, one message; write on glass; never photograph; dissolve the page and stir.
- **Two checks on every message.** A four-digit **hand tag** a person computes with pencil in about a quarter of an hour, and a nineteen-digit **device tag** the app checks — so a changed digit or the wrong page is caught before anything is read.
- **The booklet leaves the computer two ways.** Copied by hand from a row-by-row view in Aska's locked viewer (recommended: no printer, no spool, no toner), or printed — **only** when the print spool is in memory, the printer is on USB and you have ticked the rules, through Aska's own print path (the desktop's print dialog writes a temporary file; it is not used).
- **The same page on a trusted device.** Scan or type a page, encipher or decipher in locked memory, press *Done* and the page is gone from the device; the paper is the only record.
- **A printable worksheet** — the table, the arithmetic, the tag, the rules, a complete worked example to check your own arithmetic against, and blank working grids. It is not secret; print it anywhere.
- **Block cards and Share cards.** An ordinary sealed Block can be shown or printed as QR cards instead of posted to a relay, and read back by camera on the other side; Shares can be printed as cards for the people who hold them.

Read **chapter 11 of the User Guide** before the first booklet — it is a list of handling rules, and the rules are the security.

## What to know

- **Laser printers.** If you must print a pad, know that laser toner does not dissolve: it floats off the dissolving paper as a film that stays legible. Break it up, sieve or flush it, never leave the glass standing. A water-soluble pen on soluble paper, written on glass, has none of these problems.
- **The camera path is still unvalidated on hardware.** As in 1.1, no machine of the project has a webcam, so both the QR scanning and the pad's PHYSICAL source have run only against synthetic input. If you have a camera, your first booklet is a test — please report whether it reached the PHYSICAL label, and with which camera. Dice work without any camera.
- **Printing leaves records** that Aska cannot remove: the print system's logs and the printer's own counter. The guide says how to clear what can be cleared.

## Still true

This release, like 1.0 and 1.1, **has not been independently audited** and has had no legal review; the owner has decided neither is planned. The code added since 1.0 — the camera layer, the note viewer, the paper mode — has had the project's tests and gates, not a review pass. Read section 9 of the User Guide before relying on Aska. Tested on the signed release: Debian 13. Tails 7 and Qubes OS were not re-tested.

**Never install an update because software told you one exists.** Aska never does. Get the new fingerprint from the person you trust, then the files.

## Get it

Before you download, obtain these from a source you trust that is not the download site:

```
Tarball        aska-gui-1.2.0-linux-x86_64.tar.gz
SHA-256        b36ccd08af0d1881c6f3c21baa3061f2bc3697116488c1e642788a3825143992
Relay binary   aska-drop-1.2.0-linux-x86_64
SHA-256        eb1c7a381ca7303a241e3c299799dc799e109aa03b968a22933343e84fdfa670
Signing key    79AD6224AFF176C9   (unchanged)
Public key     RWTJdvGvJGKtecwP4zEITLdIK5yvwDp8+PyjmaoWPMHPLJxHDbGs+Oox
Rekor entry    none for this release
```

Then: `sha256sum` the tarball and compare; `minisign -V -P <public key> -m <tarball>`; unpack; `./bin/aska verify` must say MATCH; `./install.sh` (it replaces 1.1.0). Full procedure: User Guide §3 (`docs/USER_GUIDE.md` inside the tarball). Relay operators: the relay is unchanged since 1.1.0 and upgrading is optional; the Relay Operator Guide 1.1 is in `aska-drop-deploy-1.2.0.tar.gz`. Release record: `docs/releases/v1.2.0.md`.

## Reporting problems

A report must never contain a note, a key, a Key Card, a passphrase, a pad page or a relay address. Security issues: privately, through *Security → Report a vulnerability* on the repository (see `SECURITY.md`). Everything else: https://github.com/secunos/aska/issues.
