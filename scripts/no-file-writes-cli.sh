#!/bin/bash
# M4 file gate (T-10, Client Design §3.1): a complete `aska send` and `aska receive` — the real
# binary, in --stdin mode, through a SOCKS port to a relay — must create or write no file
# anywhere. Both runs go under strace; afterwards nothing may have been opened for writing and
# nothing written to a descriptor that is not a socket, a pipe or a terminal.
# Needs strace and python3 (the reference relay and scripts/fake_socks.py stand in for the
# droplet and Tor). Usage: scripts/no-file-writes-cli.sh
set -eu
cd "$(dirname "$0")/.."
cargo build --release -p aska >/dev/null 2>&1
BIN=target/release/aska
ONION=2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion
LOG="$(mktemp)"; SEND_OUT="$(mktemp)"; RECV_OUT="$(mktemp)"; SOCKS_OUT="$(mktemp)"
RELAY_PORT=4597
python3 reference/aska_drop.py serve --port $RELAY_PORT >/dev/null 2>&1 &
RELAY=$!
python3 scripts/fake_socks.py --target 127.0.0.1:$RELAY_PORT >"$SOCKS_OUT" 2>/dev/null &
SOCKS=$!
trap 'kill $RELAY $SOCKS 2>/dev/null; rm -f "$LOG" "$SEND_OUT" "$RECV_OUT" "$SOCKS_OUT"' EXIT
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [ -s "$SOCKS_OUT" ] && break; sleep 0.3
done
SOCKS_PORT="$(head -n1 "$SOCKS_OUT")"
sleep 0.5

COMMON="--socks 127.0.0.1:$SOCKS_PORT --stdin --yes --fast --accept-unlocked-memory --relay $ONION"
TRACE="strace -f -yy -e trace=%file,write,writev,pwrite64,pwritev,sendto,sendmsg -o"

# Exit 0 or 2 (warnings acknowledged) is success for the client.
ok() { [ "$1" -eq 0 ] || [ "$1" -eq 2 ]; }

# stdout goes through a pipe (as a terminal or a script would give it), never straight to a file:
# the client's own hand-over lines must not count as the client writing a file.
# shellcheck disable=SC2086
$TRACE "$LOG" "$BIN" $COMMON send --passphrase --decoy 2>/dev/null <<EOF | cat >"$SEND_OUT"
gate-pass
milk please
milk
file gate: the north gate, 14 Nov
EOF
rc=${PIPESTATUS[0]}
ok "$rc" || { echo "GATE FAIL: aska send exited $rc"; exit 1; }
CARD="$(sed -n 's/^KEYCARD //p' "$SEND_OUT")"
[ -n "$CARD" ] || { echo "GATE FAIL: no Key Card printed"; exit 1; }

# shellcheck disable=SC2086
$TRACE "$LOG.recv" "$BIN" $COMMON receive 2>/dev/null <<EOF | cat >"$RECV_OUT"
$CARD

gate-pass
EOF
rc=${PIPESTATUS[0]}
ok "$rc" || { echo "GATE FAIL: aska receive exited $rc"; exit 1; }
grep -q "north gate" "$RECV_OUT" || { echo "GATE FAIL: the note did not come back"; exit 1; }
cat "$LOG.recv" >>"$LOG"; rm -f "$LOG.recv"

# Files opened for writing anywhere in either run? (/dev/null, /proc reads and the tty are not files.)
if grep -E 'openat\(.*O_(WRONLY|RDWR|CREAT|APPEND)' "$LOG" | grep -vE '/dev/null|/dev/tty|/proc/'; then
  echo "NO-FILE-WRITES (CLI): FAIL (a file was opened for writing)"; exit 1
fi
# Writes to anything that is not a socket, a pipe (stdout/stderr) or a terminal?
if grep -E '^[0-9]+ +(write|writev|pwrite64|pwritev|sendto|sendmsg)\(' "$LOG" | grep -vE 'TCP:\[|UNIX:\[|pipe:\[|/dev/pts/|/dev/tty|/dev/null|<\.\.\. [a-z0-9_]+ resumed>'; then
  echo "NO-FILE-WRITES (CLI): FAIL (write to a non-socket descriptor)"; exit 1
fi
echo "NO-FILE-WRITES (CLI): OK"
