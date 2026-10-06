#!/bin/sh
# M3 file gate (T-10): a full send-and-receive through the Session must create or write no file
# anywhere. Runs the local_e2e example under strace and checks that nothing was opened for
# writing and nothing was written to a non-socket fd after the loader finished.
# Needs strace. Usage: scripts/no-file-writes-client.sh
set -eu
cd "$(dirname "$0")/.."
BIN="${1:-}"   # a prebuilt binary (CI builds as the normal user, runs the gate as root)
if [ -z "$BIN" ]; then
  cargo build --release -p aska-core --example local_e2e >/dev/null 2>&1
  BIN=target/release/examples/local_e2e
fi
LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT

# stdout to /dev/null so the example's own success print is never a file write; exit code is truth.
if ! strace -f -yy -e trace=%file,write,writev,pwrite64,pwritev,sendto,sendmsg -o "$LOG" "$BIN" >/dev/null 2>/dev/null; then
  echo "GATE FAIL: example did not complete"; exit 1
fi

# strace must have been able to read the traced process. Aska makes itself non-dumpable at
# start (no core dumps, no other process in its memory), so a tracer that is not root sees bare
# descriptor numbers and raw buffer addresses instead of labels and paths — and every check
# below would be blind (a real file write could then pass unseen). Run the gate as root.
if ! grep -qE '^[0-9]+ +[a-z0-9_]+\([0-9]+<' "$LOG"; then
  echo "NO-FILE-WRITES: INCONCLUSIVE (strace could not read the traced process — run this gate as root)"; exit 1
fi
# Files opened for writing anywhere in the run?
if grep -E 'openat\(.*O_(WRONLY|RDWR|CREAT|APPEND)' "$LOG" | grep -vE '/dev/null|/proc/'; then
  echo "NO-FILE-WRITES: FAIL (a file was opened for writing)"; exit 1
fi
# Writes to anything that is not a socket or tokio's eventfd?
if grep -E '(write|writev|pwrite|send)' "$LOG" | grep -vE 'TCP:\[|UNIX:\[|anon_inode:\[eventfd\]|/dev/null|<\.\.\. [a-z0-9_]+ resumed>'; then
  echo "NO-FILE-WRITES: FAIL (write to a non-socket descriptor)"; exit 1
fi
echo "NO-FILE-WRITES: OK"
