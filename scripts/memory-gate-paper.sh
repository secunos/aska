#!/bin/sh
# 1.2 memory gate for the paper mode (DC-04 §8.4): drive the graphical client through a SEEDED
# booklet (die rolls on the digit pad), open the hand-copy view, read the page's QR off the
# screen, and check that after "Forget the booklet" no pad digit and no page payload remains
# in the process's writable memory. Reads /proc/PID/mem: run as root.
# Needs: python3, xdotool, zbarimg, import (ImageMagick), Xvfb unless DISPLAY is set.
# Usage: scripts/memory-gate-paper.sh [path/to/aska-gui]
set -eu
cd "$(dirname "$0")/.."
. scripts/lib-gui-gate.sh
BIN="${1:-}"
if [ -z "$BIN" ]; then
  cargo build --release -p aska-gui >/dev/null 2>&1
  BIN=target/release/aska-gui
fi
export GSK_RENDERER="${GSK_RENDERER:-cairo}" GDK_BACKEND=x11 LANG=C.UTF-8
XVFB_PID=""
if [ -z "${DISPLAY:-}" ]; then
  Xvfb :95 -screen 0 1280x960x24 >/dev/null 2>&1 &
  XVFB_PID=$!
  export DISPLAY=:95
  sleep 1
fi
SHOT="$(mktemp --suffix=.png)"
cleanup() {
  { kill $GUI ${XVFB_PID:-}; wait; } >/dev/null 2>&1 || true
  rm -f "$SHOT"
}
trap cleanup EXIT
"$BIN" >/dev/null 2>&1 &
GUI=$!
wait_for_window 90 || { echo "GATE FAIL: the Aska window did not appear within 90 s"; save_shot memory-gate-paper-no-window; exit 1; }
WID="$(xdotool search --name '^aska$' | head -n1)"
# A fixed window geometry so the coordinates below hold (the Paper page widens the window).
xdotool windowmove "$WID" 0 0; xdotool windowsize "$WID" 1068 720; sleep 1
xdotool mousemove 380 405 click 1; sleep 2                    # Home: Paper (fourth button)
xdotool windowsize "$WID" 1068 720; sleep 1
xdotool mousemove 930 221 click 1; sleep 1                    # Randomness source combo
xdotool mousemove 985 301 click 1; sleep 1                    # Die rolls (SEEDED)
# 102 rolls on the digit pad: keys 1–6 at x = 52 + 50·k, y = 629.
_i=0
while [ "$_i" -lt 17 ]; do
  for _x in 52 102 152 202 252 302; do xdotool mousemove "$_x" 629 click 1; done
  _i=$((_i + 1))
done
sleep 1
xdotool mousemove 533 400; for _ in 1 2 3 4 5 6 7 8; do xdotool click 5; done; sleep 1   # scroll down
xdotool mousemove 533 145 click 1; sleep 4                    # Make the booklet
xdotool mousemove 111 297 click 1; sleep 2                    # Show for copying…
import -window root "$SHOT"
PAYLOAD="$(zbarimg -q --raw "$SHOT" 2>/dev/null | head -1 | tr -d '\n')"
case "$PAYLOAD" in
  1[0-9]*) ;;
  *) echo "GATE FAIL: no page QR on screen"; save_shot memory-gate-paper-no-qr; exit 1 ;;
esac
scan() { python3 scripts/memscan-paper.py "$GUI" "$PAYLOAD" "$1" || true; }
scan "1 hand-copy view open (the booklet and the row texts are live)"
xdotool mousemove 790 633 click 1; sleep 1                    # Next row (a pad row on screen)
scan "2 pad row 1 on screen"
xdotool mousemove 701 291 click 1; sleep 1                    # Close (row screen)
xdotool mousemove 374 297 click 1; sleep 2                    # Forget the booklet
# Final scan: this one decides the gate.
python3 scripts/memscan-paper.py "$GUI" "$PAYLOAD" "final: 3 after Forget the booklet" || { save_shot memory-gate-paper-final; exit 1; }
echo "MEMORY GATE (paper): OK"
