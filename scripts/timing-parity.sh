#!/bin/sh
# M5 gate: distress timing parity (Client Design §6.4). Runs the ignored release test that
# opens a decoy slot and a distress slot 150 times each and applies a Mann–Whitney U test;
# passes when the two are not distinguishable at p < 0.01. Usage: scripts/timing-parity.sh
set -eu
cd "$(dirname "$0")/.."
cargo test --release -p aska-core --test timing_parity -- --include-ignored --nocapture 2>&1 | tee /dev/stderr | grep -q "^test result: ok" \
  && echo "TIMING-PARITY: OK" || { echo "TIMING-PARITY: FAIL"; exit 1; }
