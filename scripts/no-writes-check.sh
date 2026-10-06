#!/bin/sh
# M2 gate: prove the relay writes nothing to disk after start (RLY-04, §5.1).
# Runs the relay under strace, drives the reference client's interop scenario through it,
# then greps the trace for any file opened with write intent or any write to a non-socket fd.
# Usage: scripts/no-writes-check.sh [path/to/aska-drop]   (needs strace and python3)
set -eu
BIN="${1:-target/release/aska-drop}"
PORT=4598
LOG="$(mktemp)"
stop_relay() { pkill -TERM -f "aska-drop serve --port $PORT " 2>/dev/null || true; }
trap 'stop_relay; rm -f "$LOG"' EXIT

strace -f -yy -e trace=%file,write,writev,pwrite64,pwritev,sendto,sendmsg -o "$LOG" \
  "$BIN" serve --port "$PORT" --cap-1 4 --insecure-no-mlock &
STRACE_PID=$!
sleep 1.5
python3 "$(dirname "$0")/../reference/aska_drop.py" remote-test --host 127.0.0.1 --port "$PORT" --socks none
sleep 0.5
# Terminate the relay (not strace: a signalled strace detaches and leaves the tracee running).
stop_relay
wait "$STRACE_PID" 2>/dev/null || true

# Anything opened for writing, at any time?
if grep -E 'openat\(.*O_(WRONLY|RDWR|CREAT|APPEND)' "$LOG"; then
  echo "NO-WRITES: FAIL (file opened with write intent)"; exit 1
fi
# Any write/send to something that is not a TCP socket or tokio's eventfd?
if grep -E '(write|send)' "$LOG" | grep -v -E 'TCP:\[|anon_inode:\[eventfd\]|<\.\.\. [a-z0-9_]+ resumed>'; then
  echo "NO-WRITES: FAIL (write to a non-socket descriptor)"; exit 1
fi
# Any file opened at all after the loader finished (i.e. after /proc/self/maps)?
if sed -n '/proc\/self\/maps/,$p' "$LOG" | tail -n +2 | grep -E 'openat|open\(|creat\(|rename|unlink|mkdir'; then
  echo "NO-WRITES: FAIL (file access after start)"; exit 1
fi
echo "NO-WRITES: OK"
