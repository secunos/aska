#!/bin/sh
# Build the graphical client tarball (Prototype Plan M5 deliverable): release aska-gui + aska,
# desktop entry, icon, user-local installer, SHA256SUMS. The GUI links the system GTK 4 /
# libadwaita (≥ 4.14 / 1.5: Debian 13, Ubuntu 24.04+, Tails 7); the CLI is static-pie.
# Usage: scripts/package-gui.sh [VERSION] [SUFFIX]  → dist/aska-gui-VERSION-linux-x86_64SUFFIX.tar.gz
#   (SUFFIX, e.g. "-dev", names a developer build so it cannot overwrite an owner build)
set -eu
cd "$(dirname "$0")/.."
VERSION="${1:-$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')}"
NAME="aska-gui-$VERSION-linux-x86_64"
SUFFIX="${2:-}"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct 2>/dev/null || echo 0)}"
case "$SOURCE_DATE_EPOCH" in ''|*[!0-9]*) SOURCE_DATE_EPOCH=0;; esac   # no git: epoch 0, never garbage
cargo build --release --locked -p aska-gui
# The CLI is built static-pie (crt-static) in its own target directory so that it runs on any
# glibc or musl system; RUSTFLAGS with an explicit --target applies to the crate, not to
# build scripts, and does not disturb the GUI build above.
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$PWD=/src --remap-path-prefix=$CARGO_HOME_DIR=/cargo --remap-path-prefix=$HOME=/home -C target-feature=+crt-static" \
  cargo build --release --locked -p aska --target x86_64-unknown-linux-gnu
rm -rf "dist/$NAME" && mkdir -p "dist/$NAME/bin" "dist/$NAME/share/applications" "dist/$NAME/share/icons/hicolor/scalable/apps"
cp target/release/aska-gui "dist/$NAME/bin/"
cp target/x86_64-unknown-linux-gnu/release/aska "dist/$NAME/bin/"
cp deploy/gui/org.aska.Aska.desktop "dist/$NAME/share/applications/"
cp deploy/gui/org.aska.Aska.svg "dist/$NAME/share/icons/hicolor/scalable/apps/"
cp deploy/gui/install.sh "dist/$NAME/"
mkdir -p "dist/$NAME/docs" && cp docs/USER_GUIDE.md docs/RELAY_OPERATOR_GUIDE.md "dist/$NAME/docs/"
cat > "dist/$NAME/README.txt" <<TXT
Aska $VERSION — secure notes that leave nothing behind. Graphical and command-line client, Linux x86_64.

READ FIRST: docs/USER_GUIDE.md (what Aska protects, what it does not, how to use it).

Requirements
  Debian 13, Ubuntu 24.04 or later, Tails 7, or Qubes OS 4.3 (Whonix). 1 GB of free RAM.
  Graphical client: GTK 4 >= 4.14 and libadwaita >= 1.5  (Debian/Ubuntu: sudo apt install libgtk-4-1 libadwaita-1-0).
  A Tor on this computer: the system tor package (port 9050) or Tor Browser (port 9150; choose it in Settings).
  The .onion address of an Aska relay from your circle (none is built in).

Before you install — check that this copy is real (User Guide, section 3)
  1. Get the release fingerprint (SHA-256 of the tarball) from someone you trust, NOT from the download site.
  2. sha256sum the tarball and compare. Then, in this directory:  sha256sum -c SHA256SUMS
  3. ./bin/aska verify   — must say MATCH (a signed release carries SHA256SUMS.minisig).

Install for your user (no root):  ./install.sh        — or run bin/aska-gui in place.
On Tails: do NOT run install.sh; unpack into ~/aska and run bin/aska-gui from there.

Aska keeps no history, no contacts, no log, and writes nothing to disk except an encrypted
profile at a path you name. Never install an update because software told you one exists.

Relay operators: docs/RELAY_OPERATOR_GUIDE.md.  Source, design and review documents: https://github.com/secunos/aska
TXT
( cd "dist/$NAME" && sha256sum bin/aska bin/aska-gui > SHA256SUMS )
# A release signs SHA256SUMS first and makes the tarball itself (scripts/release.sh --sign).
if [ "${ASKA_NO_TAR:-0}" = "1" ]; then
  echo "dist/$NAME (not tarred: ASKA_NO_TAR=1)"
  exit 0
fi
( cd dist && tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner -cf - "$NAME" | gzip -n > "$NAME$SUFFIX.tar.gz" )
sha256sum "dist/$NAME$SUFFIX.tar.gz"
