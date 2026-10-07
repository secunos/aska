# Aska 1.0.1

A small fix on top of 1.0.0. **Only the command-line client changes:** when the program reading its output goes away early — `aska verify | head -1`, or a script's `grep -q` — `aska` now stops quietly with exit status 141 instead of aborting with a "Broken pipe" message. Everything is still wiped on the way out, as before.

Nothing else changed: same graphical client, same cryptography and formats, same relay code (only its version number), same installer and Tor configuration, same dependencies. Notes sent with 1.0.0 open with 1.0.1 and the other way round.

**Do I need it?** If you script the command-line client, yes. Otherwise 1.0.1 behaves exactly like 1.0.0; upgrade when convenient. Relay operators do not need to upgrade.

This release, like 1.0.0, **has not been independently audited** — please read section 9 of the User Guide before relying on Aska. Tested on the signed release: Debian 13 (install, self-verification, send and receive over Tor with a passphrase). Tails 7 and Qubes OS were not re-tested.

**Never install an update because software told you one exists.** Aska never does. Get the new fingerprint from the person you trust, then the files.

## Get it

Before you download, obtain these from a source you trust that is not the download site:

```
Tarball        aska-gui-1.0.1-linux-x86_64.tar.gz
SHA-256        09c80237397b884a978152c64c9c6d15f3cf703c2b0cb9f8e72ccee82c3b1dba
Relay binary   aska-drop-1.0.1-linux-x86_64
SHA-256        f55def3215b956223543ec022335cb93d53f3815d66972a459aa7060c3b2a0e4
Signing key    79AD6224AFF176C9   (unchanged)
Public key     RWTJdvGvJGKtecwP4zEITLdIK5yvwDp8+PyjmaoWPMHPLJxHDbGs+Oox
Rekor entry    none for this release
```

Then: `sha256sum` the tarball and compare; `minisign -V -P <public key> -m <tarball>`; unpack; `./bin/aska verify` must say MATCH; `./install.sh` (it replaces 1.0.0). Full procedure: User Guide §3 (`docs/USER_GUIDE.md` inside the tarball). Release record: `docs/releases/v1.0.1.md`.

## Reporting problems

A report must never contain a note, a key, a Key Card, a passphrase or a relay address. Security issues: privately, through *Security → Report a vulnerability* on the repository (see `SECURITY.md`). Everything else: https://github.com/secunos/aska/issues.
