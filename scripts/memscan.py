#!/usr/bin/env python3
"""Scan a live process's writable memory for Aska key material and note text.
Usage: memscan.py PID MARKER KEYCARD [STAGE]  — used by memory-gate-gui.sh; exit 1 on key material."""
import sys, re, os
sys.path.insert(0, "reference")
from aska_ref import KeyCard, derive_label
pid, marker, card = sys.argv[1], sys.argv[2], sys.argv[3]
stage = sys.argv[4] if len(sys.argv) > 4 else "final"
kc = KeyCard.decode(card)
R = kc.root
L = derive_label(R)
needles = {"root R": R, "label L": L, "note text": marker.encode(), "Key Card": card.lower().encode(),
           "Key Card (upper)": card.upper().encode()}
hits = {k: 0 for k in needles}
scanned = 0
# Thread stacks: startstack (stat field 28) lies inside the thread's stack mapping.
import os
threads = []
for tid in os.listdir(f"/proc/{pid}/task"):
    try:
        with open(f"/proc/{pid}/task/{tid}/comm") as f: comm = f.read().strip()
        with open(f"/proc/{pid}/task/{tid}/stat") as f: st = f.read()
        fields = st[st.rindex(")") + 2:].split()
        threads.append((comm, int(fields[25])))   # field 28 overall = index 25 after ') '
    except OSError:
        pass
def owner(lo, hi):
    return [c for c, sp in threads if lo <= sp < hi]
with open(f"/proc/{pid}/maps") as maps, open(f"/proc/{pid}/mem", "rb", 0) as mem:
    for line in maps:
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s*(.*)", line)
        if not m: continue
        lo, hi, perms, name = int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4)
        if "w" not in perms or "[vvar]" in name or "[vsyscall]" in name: continue
        try:
            mem.seek(lo); data = mem.read(hi - lo)
        except (OSError, ValueError):
            continue
        scanned += len(data)
        for k, n in needles.items():
            c = data.count(n)
            if c: hits[k] += c
            if c and k in ("root R", "label L"):
                # Where, and what surrounds it: enough to recognise a TLV, a struct or a frame.
                pos = data.find(n)
                while pos != -1:
                    ctx = data[max(0, pos - 48):pos + len(n) + 48]
                    print(f"  ! {k} at {lo + pos:#x} in {perms} {name or '[anon]'} (offset {pos:#x} of {hi - lo:#x}) threads here: {owner(lo, hi)}")
                    print("    context:", ctx.hex())
                    pos = data.find(n, pos + 1)
print(f"[{stage}] scanned {scanned/1048576:.0f} MiB of writable memory of pid {pid}")
for k, c in hits.items():
    print(f"  {k:18} {c} hit(s)")
fatal = hits["root R"] + hits["label L"]
resid = hits["note text"] + hits["Key Card"] + hits["Key Card (upper)"]
if not stage.startswith("final"):
    # Intermediate stages are informational: a live Session legitimately holds R (in its
    # locked page) and L; what matters is what is left once it has been closed.
    print(f"  (stage report only; key material {'present — a Session is live' if fatal else 'absent'})")
    sys.exit(0)
if fatal:
    print("MEMORY-GATE (GUI): FAIL — key material survives in the process"); sys.exit(1)
print("MEMORY-GATE (GUI): OK — no key material in memory" + (f"; {resid} toolkit residual(s) of note/Key Card text (C-02)" if resid else "; no note or Key Card text either"))