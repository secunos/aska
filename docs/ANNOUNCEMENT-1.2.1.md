# Aska 1.2.1

A small release: **Aska has a face.** The Glow mark — an ember with a ring of heat — is the app icon; the client wears the Nordic calm palette, ash greys with one ember accent, in light and dark; the Home screen carries the lockup. *Notes that leave no trace.*

Nothing else changed: no behaviour, no format, no rule. Everything from 1.2.0 works exactly as before, and notes, keys, pad pages and profiles are unaffected. Relay operators need not upgrade.

## Still true

This release, like every one before it, **has not been independently audited** and has had no legal review. Read section 9 of the User Guide before relying on Aska. **Never install an update because software told you one exists.** Aska never does. Get the new fingerprint from the person you trust, then the files.

## Get it

```
Tarball        aska-gui-1.2.1-linux-x86_64.tar.gz
SHA-256        (filled at signing)
Relay binary   aska-drop-1.2.1-linux-x86_64
SHA-256        (filled at signing)
Signing key    79AD6224AFF176C9   (unchanged)
Public key     RWTJdvGvJGKtecwP4zEITLdIK5yvwDp8+PyjmaoWPMHPLJxHDbGs+Oox
Rekor entry    none for this release
```

Then: `sha256sum` the tarball and compare; `minisign -V -P <public key> -m <tarball>`; unpack; `./bin/aska verify` must say MATCH; `./install.sh` (it replaces 1.2.0 and installs the new icon). Full procedure: User Guide §3. Release record: `docs/releases/v1.2.1.md`.

## Reporting problems

A report must never contain a note, a key, a Key Card, a passphrase, a pad page or a relay address. Security issues: privately, through *Security → Report a vulnerability* (see `SECURITY.md`). Everything else: https://github.com/secunos/aska/issues.
