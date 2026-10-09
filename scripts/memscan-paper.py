#!/usr/bin/env python3
"""Scan a live process's writable memory for a pad page (paper mode, DC-04): the page's QR
payload read off the screen and the pad digits inside it.
Usage: memscan-paper.py PID PAYLOAD STAGE — exit 1 when any pad material is found at a
"final" stage. The payload is all digits: 1 + set(4) + dir(1) + no(2) + N(3) + pad(N) + …"""
import os, re, sys
pid, payload, stage = sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "final"
n = int(payload[8:11])
pad = payload[11:11 + n]
needles = {
    "pad (whole)": [pad.encode()],
    "pad row 1": [pad[:50].encode()],
    "pad row 1 (grouped)": [" ".join(pad[i:i + 5] for i in range(0, 50, 5)).encode()],
    "page payload": [payload.encode()],
}
hits = {k: 0 for k in needles}
scanned = 0
with open(f"/proc/{pid}/maps") as maps, open(f"/proc/{pid}/mem", "rb", 0) as mem:
    for line in maps:
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s*(.*)", line)
        if not m:
            continue
        lo, hi, perms, name = int(m.group(1), 16), int(m.group(2), 16), m.group(3), m.group(4)
        if "w" not in perms or "[vvar]" in name or "[vsyscall]" in name:
            continue
        try:
            mem.seek(lo)
            data = mem.read(hi - lo)
        except (OSError, ValueError):
            continue
        scanned += len(data)
        for k, ns in needles.items():
            for nd in ns:
                hits[k] += data.count(nd)
print(f"memscan-paper [{stage}]: scanned {scanned // 1024} KiB: " + ", ".join(f"{k}={v}" for k, v in hits.items()))
if stage.startswith("final") and any(hits.values()):
    print("MEMORY GATE (paper): FAIL — pad material survives after Forget")
    sys.exit(1)
