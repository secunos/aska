#!/bin/bash
# M5 memory gate (T-08, Client Design §10) for the graphical client: after a complete round
# trip — Send a marker note, Receive it, View it, Close and burn — the GUI process's writable
# memory is scanned from outside (/proc/PID/mem) for
#   (1) the root key R and the label L (must NEVER be found: the Session zeroises them),
#   (2) the note text and the Key Card string (the toolkit's own buffers: C-02 residual).
# (1) fails the gate. (2) is reported: GTK text buffers, labels and Pango caches may keep
# copies until the memory is reused; the custom read-only viewer (C-02, v1.1) removes them.
# Needs: python3, xdotool, zbarimg, import (ImageMagick) and a display (Xvfb :96 is started
# when DISPLAY is unset). Usage: scripts/memory-gate-gui.sh [path/to/aska-gui]
set -eu
cd "$(dirname "$0")/.."
BIN="${1:-target/release/aska-gui}"
ONION=2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion
MARKER="MEMGATE-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')-the-north-gate"
export GSK_RENDERER="${GSK_RENDERER:-cairo}" GDK_BACKEND=x11 LANG=C.UTF-8
XVFB_PID=""
if [ -z "${DISPLAY:-}" ]; then
  Xvfb :96 -screen 0 1280x960x24 >/dev/null 2>&1 &
  XVFB_PID=$!
  export DISPLAY=:96
  sleep 1
fi
RELAY_PORT=4596
python3 reference/aska_drop.py serve --port $RELAY_PORT --cap-1 50 >/dev/null 2>&1 &
RELAY=$!
python3 scripts/fake_socks.py --target 127.0.0.1:$RELAY_PORT --port 9050 >/dev/null 2>&1 &
SOCKS=$!
SHOT="$(mktemp --suffix=.png)"
cleanup() {
  { kill $GUI $RELAY $SOCKS ${XVFB_PID:-}; wait; } >/dev/null 2>&1 || true
  rm -f "$SHOT"
}
trap cleanup EXIT
sleep 1
"$BIN" >/dev/null 2>&1 &
GUI=$!
sleep 9
xdotool mousemove 380 224 click 1; sleep 2                    # Send a note
xdotool mousemove 380 220 click 1; xdotool type --delay 20 -- "$MARKER"; sleep 1
xdotool mousemove 380 400; for _ in 1 2 3 4 5 6; do xdotool click 5; done; sleep 1
xdotool mousemove 380 466 click 1; xdotool type --delay 20 -- "$ONION"; sleep 1
xdotool mousemove 380 597 click 1                              # Seal and post
sleep 150
import -window root "$SHOT"
CARD="$(zbarimg -q --raw "$SHOT" 2>/dev/null | head -1 | tr -d '\n')"
[ -n "$CARD" ] || { echo "GATE FAIL: no Key Card on screen (did the post succeed?)"; exit 1; }
scan() { python3 scripts/memscan.py "$GUI" "$MARKER" "$CARD" "$1" || true; }
scan "1 hand-over on screen"
xdotool mousemove 28 27 click 1; sleep 1; xdotool mousemove 28 27 click 1; sleep 2
scan "2 back on Home (sender key forgotten)"
xdotool mousemove 380 275 click 1; sleep 1                    # Receive
xdotool mousemove 380 170 click 1; xdotool type --delay 10 -- "$CARD"; sleep 1
xdotool mousemove 80 238 click 1; sleep 1                     # Add
xdotool mousemove 380 400; for _ in 1 2 3 4 5 6; do xdotool click 5; done; sleep 1
xdotool mousemove 380 597 click 1                             # Check the drop
sleep 130
scan "3 note on the View screen"
xdotool mousemove 380 566 click 1; sleep 3                    # Close and burn

# Final scan, while the process is alive and back on Home: this one decides the gate.
python3 scripts/memscan.py "$GUI" "$MARKER" "$CARD" "final: 4 after Close and burn"
