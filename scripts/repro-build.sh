#!/bin/sh
# Build the static CLI + relay twice in clean dirs and compare hashes (M0 gate, OPS-02).
# An explicit --target makes RUSTFLAGS apply to the target artefacts only, so proc-macro crates
# (clap_derive, tokio-macros) are still built dynamically for the host.
set -eu
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct 2>/dev/null || echo 0)}"
TARGET="${TARGET:-$(rustc -vV | sed -n 's/^host: //p')}"
# Remap every absolute path that ends up in the binary (panic locations, debug info): the
# repository, the Cargo registry/git checkouts and the home directory. Two builds on the same
# machine are then identical; two builds on different machines are identical when the
# toolchain AND the C library are identical, i.e. inside the same release container
# (release/Dockerfile) — crt-static links glibc into the binary, so the glibc version matters.
CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="--remap-path-prefix=$PWD=/src --remap-path-prefix=$CARGO_HOME_DIR=/cargo --remap-path-prefix=$HOME=/home -C target-feature=+crt-static"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target-repro}"
if [ "${1:-}" = "--compare" ]; then
  cp "$CARGO_TARGET_DIR/SHA256SUMS" /tmp/aska-build1.sums
  rm -rf "$CARGO_TARGET_DIR"
fi
cargo build --release --locked --target "$TARGET" -p aska -p aska-drop
( cd "$CARGO_TARGET_DIR/$TARGET/release" && sha256sum aska aska-drop > ../../SHA256SUMS )
cat "$CARGO_TARGET_DIR/SHA256SUMS"
if [ "${1:-}" = "--compare" ]; then
  # A mismatch must fail the script (a bare `diff && echo` under set -e does not).
  if diff /tmp/aska-build1.sums "$CARGO_TARGET_DIR/SHA256SUMS"; then
    echo "REPRODUCIBLE: OK"
  else
    echo "REPRODUCIBLE: FAIL — the two builds differ"; exit 1
  fi
fi
echo "binaries: $CARGO_TARGET_DIR/$TARGET/release/{aska,aska-drop}"
