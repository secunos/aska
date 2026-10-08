#!/bin/bash
# C-10 gate (Client Design §10.1): the CLI reads its standard input one byte at a time into
# locked memory — never through a buffered reader that would keep passphrases and key material
# for the life of the process. Traces the read(2) calls of one `--stdin` run and fails if any
# read on the input descriptor asks for more than one byte. Usage: scripts/cli-input-unbuffered.sh [path/to/aska]
set -eu
cd "$(dirname "$0")/.."
BIN="${1:-target/release/aska}"
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
# A seed is generated without input, then fed back on stdin (24 words + newline).
SEED="$("$BIN" --stdin --yes --accept-unlocked-memory --socks 127.0.0.1:9 key receive 2>/dev/null | sed -n 's/^SEED //p')"
[ -n "$SEED" ] || { echo "C-10 GATE: could not generate a seed"; exit 1; }
printf '%s\n' "$SEED" | strace -f -e trace=dup,read -o "$LOG" \
  "$BIN" --stdin --yes --accept-unlocked-memory --socks 127.0.0.1:9 key receive --from-words >/dev/null 2>&1 || true
FD="$(grep -oE 'dup\(0\) += [0-9]+' "$LOG" | head -1 | grep -oE '[0-9]+$' || true)"
if [ -z "$FD" ]; then
  if grep -qE 'read\(0, .*, [0-9]{2,}\) += [1-9]' "$LOG"; then
    echo "CLI-INPUT-UNBUFFERED: FAIL — standard input read through a buffer:"; grep -E 'read\(0, ' "$LOG" | head -3; exit 1
  fi
  echo "C-10 GATE: INCONCLUSIVE — no dup(0) seen (strace could not trace the process? run as root)"; exit 1
fi
# Only reads after the dup count: the same descriptor number served the loader earlier.
AFTER="$(mktemp)"; trap 'rm -f "$LOG" "$AFTER"' EXIT
awk -v fd="$FD" 'f && $0 ~ ("read\\(" fd ", ") {print} /dup\(0\)/ {f=1}' "$LOG" > "$AFTER"
READS="$(grep -vcE '= 0$' "$AFTER" || true)"
BIG="$(grep -vcE ', 1\) += [01]$' "$AFTER" || true)"
echo "C-10: $READS reads on the input descriptor (fd $FD), $BIG of them larger than one byte"
if [ "$READS" -lt 50 ] || [ "$BIG" -ne 0 ]; then
  echo "CLI-INPUT-UNBUFFERED: FAIL"; grep -vE ', 1\) += [01]$' "$AFTER" | head -5; exit 1
fi
# io::stdin()'s own buffer would show as read(0, …, 8192): it must never be touched.
if grep -qE 'read\(0, ' "$LOG"; then echo "CLI-INPUT-UNBUFFERED: FAIL — read on fd 0 (buffered io::stdin?)"; exit 1; fi
echo "CLI-INPUT-UNBUFFERED: OK"
