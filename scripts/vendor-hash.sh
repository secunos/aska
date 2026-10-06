#!/bin/sh
# Deterministic hash of the vendored dependency tree (release checklist row 1.10, OPS-04).
# Runs `cargo vendor` into a temporary directory and prints one SHA-256 over every file's
# path and content. Two machines with the same Cargo.lock print the same value; the release
# record carries it so that anyone can check the dependencies they build from are the ones
# the release was built from. Nothing is written into the repository.
# Usage: scripts/vendor-hash.sh [--keep DIR]   (--keep leaves the vendored tree in DIR)
set -eu
cd "$(dirname "$0")/.."
KEEP=""
[ "${1:-}" = "--keep" ] && KEEP="${2:?--keep needs a directory}"
DIR="${KEEP:-$(mktemp -d)}"
cargo vendor --locked "$DIR" >/dev/null 2>&1 || cargo vendor "$DIR" >/dev/null
HASH="$(cd "$DIR" && find . -type f | LC_ALL=C sort | xargs sha256sum | sha256sum | cut -d' ' -f1)"
N="$(find "$DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)"
[ -n "$KEEP" ] || rm -rf "$DIR"
echo "VENDOR-HASH: $HASH ($N crates, Cargo.lock $(sha256sum Cargo.lock | cut -c1-16)…)"
