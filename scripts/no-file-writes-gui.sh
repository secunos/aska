#!/bin/bash
# M5 file gate (T-10, Client Design §3.1) for the graphical client: a complete round trip —
# Home → Send → type a note → relay → Seal and post → Hand-over, then (with the Key Card read
# off the screen by zbarimg) Home → Receive → Add → Check the drop → View — runs under strace
# with a private HOME/XDG tree; afterwards nothing may have been opened for writing anywhere,
# nothing written to a descriptor that is not a socket or a pipe, and the private HOME must be
# empty. Without zbarimg/import the Receive half is skipped (Send-only gate).
#
# Toolkit writes are the point of this gate: GTK's stack wants to write a shader cache and a
# dconf file; aska-gui switches both off in its own environment (main.rs). This checks it stays
# that way. Needs: strace, python3, xdotool, and a display (Xvfb is started when DISPLAY is
# unset). Usage: scripts/no-file-writes-gui.sh [path/to/aska-gui]
set -eu
cd "$(dirname "$0")/.."
BIN="${1:-}"
if [ -z "$BIN" ]; then
  cargo build --release -p aska-gui >/dev/null 2>&1
  BIN=target/release/aska-gui
fi
ONION=2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion
GATEHOME="$(mktemp -d)"
LOG="$(mktemp)"
mkdir -p "$GATEHOME/run"; chmod 700 "$GATEHOME/run"
export HOME="$GATEHOME" XDG_RUNTIME_DIR="$GATEHOME/run" XDG_CACHE_HOME="$GATEHOME/cache" \
       XDG_CONFIG_HOME="$GATEHOME/config" XDG_DATA_HOME="$GATEHOME/data" LANG=C.UTF-8 \
       GSK_RENDERER="${GSK_RENDERER:-cairo}" GDK_BACKEND=x11

XVFB_PID=""
if [ -z "${DISPLAY:-}" ]; then
  Xvfb :97 -screen 0 1280x960x24 >/dev/null 2>&1 &
  XVFB_PID=$!
  export DISPLAY=:97
  sleep 1
fi
RELAY_PORT=4597
python3 reference/aska_drop.py serve --port $RELAY_PORT --cap-1 50 >/dev/null 2>&1 &
RELAY=$!
python3 scripts/fake_socks.py --target 127.0.0.1:$RELAY_PORT --port 9050 >/dev/null 2>&1 &
SOCKS=$!
cleanup() {
  { pkill -P $$; kill $RELAY $SOCKS ${XVFB_PID:-}; wait; } >/dev/null 2>&1 || true
  rm -rf "$GATEHOME" "$LOG"
}
trap cleanup EXIT
sleep 1

# stderr to /dev/null: GTK's own warnings are not the client writing a file.
strace -f -yy -e trace=%file,write,writev,pwrite64,pwritev,connect -o "$LOG" "$BIN" >/dev/null 2>/dev/null &
GUI=$!
sleep 9
xdotool mousemove 380 224 click 1; sleep 2                    # Send a note
xdotool mousemove 380 220 click 1; xdotool type --delay 20 -- "file gate: the north gate"; sleep 1
xdotool mousemove 380 400; for _ in 1 2 3 4 5 6; do xdotool click 5; done; sleep 1
xdotool mousemove 380 466 click 1; xdotool type --delay 20 -- "$ONION"; sleep 1
xdotool mousemove 380 597 click 1                              # Seal and post
# Sealing (Argon2id) + the 0–90 s cover delay + posting: wait for the Hand-over to appear.
sleep 150
RECEIVED=0
if command -v zbarimg >/dev/null && command -v import >/dev/null; then
  SHOT="$(mktemp --suffix=.png)"
  import -window root "$SHOT"
  CARD="$(zbarimg -q --raw "$SHOT" 2>/dev/null | head -1 | tr -d '\n')"
  rm -f "$SHOT"
  if [ -n "$CARD" ]; then
    xdotool mousemove 28 27 click 1; sleep 1; xdotool mousemove 28 27 click 1; sleep 1   # back to Home
    xdotool mousemove 380 275 click 1; sleep 1                                        # Receive
    xdotool mousemove 380 170 click 1; xdotool type --delay 10 -- "$CARD"; sleep 1
    xdotool mousemove 80 238 click 1; sleep 1                                         # Add
    xdotool mousemove 380 400; for _ in 1 2 3 4 5 6; do xdotool click 5; done; sleep 1
    xdotool mousemove 380 597 click 1                                                 # Check the drop
    sleep 130                                                                         # delay + fetch + open
    xdotool mousemove 380 566 click 1; sleep 2                                        # Close and burn
    RECEIVED=1
  else
    echo "note: the Key Card QR could not be read from the screen; Receive half skipped"
  fi
else
  echo "note: zbarimg/import not installed; Receive half skipped"
fi
kill $GUI 2>/dev/null || true
sleep 1

FAIL=0
if grep -E 'openat\(.*O_(WRONLY|RDWR|CREAT|APPEND)' "$LOG" | grep -vE '/dev/null|/proc/|/dev/dri|/dev/shm|/dev/udmabuf'; then
  echo "NO-FILE-WRITES (GUI): FAIL (a file was opened for writing)"; FAIL=1
fi
if grep -E '^[0-9]+ +(write|writev|pwrite64|pwritev)\(' "$LOG" | grep -vE 'UNIX(-STREAM)?:\[|TCP:\[|pipe:\[|/dev/pts|/dev/null|anon_inode|eventfd|<\.\.\. [a-z0-9_]+ resumed>'; then
  echo "NO-FILE-WRITES (GUI): FAIL (write to a non-socket descriptor)"; FAIL=1
fi
if [ -n "$(find "$GATEHOME" -type f)" ]; then
  echo "NO-FILE-WRITES (GUI): FAIL (files appeared under the private HOME):"; find "$GATEHOME" -type f; FAIL=1
fi
# The run must at least have sealed (the root's entropy mix opens /dev/hwrng or /dev/urandom).
if ! grep -qE 'openat\(.*"/dev/(hwrng|urandom)"' "$LOG"; then
  echo "GATE FAIL: the flow did not reach sealing (is the display driver working?)"; exit 1
fi
# With the Receive half, the flow must also have fetched (a GET_ALL answered by the relay).
if [ $RECEIVED -eq 1 ] && ! grep -qE 'connect\(.*9050' "$LOG"; then
  echo "GATE FAIL: no SOCKS connection was made"; exit 1
fi
HALF="send"; [ $RECEIVED -eq 1 ] && HALF="send + receive"
[ $FAIL -eq 0 ] && echo "NO-FILE-WRITES (GUI): OK ($HALF)"
exit $FAIL
