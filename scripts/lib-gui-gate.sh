# Shared by the GUI gates (no-file-writes-gui.sh, memory-gate-gui.sh). Sourced, not run.

# Wait until the Aska window exists (its title is always "aska"), then give it a moment to
# render. Replaces a fixed `sleep 9`, which was too short on a busy CI runner when the GUI
# starts under strace (6 Oct 2026). Usage: wait_for_window SECONDS
wait_for_window() {
  _n=0
  while [ "$_n" -lt "$1" ]; do
    if xdotool search --name '^aska$' >/dev/null 2>&1; then sleep 3; return 0; fi
    sleep 1; _n=$((_n + 1))
  done
  return 1
}

# On a failure, keep a picture of the screen for diagnosis when GATE_SHOT_DIR is set (CI
# uploads that directory). The screen only ever shows test data. Usage: save_shot NAME
save_shot() {
  [ -n "${GATE_SHOT_DIR:-}" ] || return 0
  mkdir -p "$GATE_SHOT_DIR" && import -window root "$GATE_SHOT_DIR/$1.png" 2>/dev/null || true
}

# Press TEXT on the in-app passphrase keypad (crates/aska-gui/src/ui/keypad.rs) once its
# "Shuffle keys" box has been unticked: the 44 keys then sit in their fixed order — a…k, l…v,
# w x y z å ä ö 0 1 2 3, 4 5 6 7 8 9 . , - ! ? — eleven per row, 50 px apart, rows 42 px apart,
# with Shift/Space/Delete/Clear in a fifth row. X0,Y0 is the centre of the first key ("a");
# the space key's centre is 200 px right of it. TEXT may hold a–z, 0–9, the five symbols and
# spaces: no upper case (Shift re-renders the keys) and no å ä ö (the table below is ASCII,
# so a byte index is a character index whatever the locale). Added for C-17 (8 Oct 2026).
# Usage: keypad_type X0 Y0 TEXT
keypad_type() {
  _keys='abcdefghijklmnopqrstuvwxyz___0123456789.,-!?'
  _i=0
  while [ "$_i" -lt "${#3}" ]; do
    _ch="${3:$_i:1}"
    if [ "$_ch" = " " ]; then
      xdotool mousemove $(( $1 + 200 )) $(( $2 + 168 )) click 1
    else
      _rest="${_keys%%"$_ch"*}"; _n=${#_rest}
      xdotool mousemove $(( $1 + 50 * (_n % 11) )) $(( $2 + 42 * (_n / 11) )) click 1
    fi
    sleep 0.1; _i=$((_i + 1))
  done
}
