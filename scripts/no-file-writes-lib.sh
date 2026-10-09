#!/bin/sh
# 1.2 gate (DC-04 §8.4): a library crate's test binary — which exercises the whole crate —
# must not open any file with write intent, create, rename or unlink anything.
# Usage: scripts/no-file-writes-lib.sh <crate>   (needs strace; run as root so strace can
# read the process — the crates do not make themselves non-dumpable, but the gates are run
# uniformly as root in CI)
set -eu
CRATE="${1:?crate name}"
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
BIN="$(cargo test -p "$CRATE" --lib --locked --no-run 2>&1 | grep -oE "target/debug/deps/$(echo "$CRATE" | tr - _)-[0-9a-f]+" | head -1)"
[ -n "$BIN" ] || { echo "NO-FILE-WRITES-LIB: cannot find the test binary for $CRATE"; exit 1; }
strace -f -e trace=%file -o "$LOG" "./$BIN" --test-threads=1 >/dev/null
# Opened with write intent (the OS random device and /dev/null excepted)?
if grep -E 'O_(WRONLY|RDWR|CREAT|APPEND)' "$LOG" | grep -v -E '/dev/null|/dev/urandom|/dev/video'; then
  echo "NO-FILE-WRITES-LIB: FAIL ($CRATE opened a file with write intent)"; exit 1
fi
if grep -E '(creat|rename|unlink|mkdir|symlink|link)\(' "$LOG"; then
  echo "NO-FILE-WRITES-LIB: FAIL ($CRATE created, renamed or removed a file)"; exit 1
fi
echo "NO-FILE-WRITES-LIB: OK ($CRATE; $(wc -l < "$LOG") file syscalls, none with write intent)"
