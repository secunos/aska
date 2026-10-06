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
