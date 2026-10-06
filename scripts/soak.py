#!/usr/bin/env python3
"""
soak.py — synthetic load for the M2 soak gate ("24 h on the droplet: flat memory, correct expiry").

Posts random Blocks with a short TTL at a steady rate, polls listings, and prints one line per
interval with the live counts it sees and (when run on the relay host) the relay's memory use
from systemd. Uses only the standard library and reference/aska_drop.py's client.

  # on the droplet, against the loopback relay, 24 hours, one 4 KiB Block every 10 s, TTL 1 h:
  python3 scripts/soak.py --host 127.0.0.1 --port 4567 --socks none --hours 24 --interval 10 --ttl 1

  # from another machine over Tor:
  python3 scripts/soak.py --host <onion> --socks 127.0.0.1:9050 --hours 1 --interval 60

Expected: the class-1 count rises for the first TTL hours, then stays flat at about
3600*ttl/interval; MemoryCurrent stops growing once that plateau is reached.
"""
import argparse, asyncio, os, secrets, subprocess, sys, time

# aska_drop.py lives in reference/ in the repo, or next to this file when copied to a relay host.
_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_here, "..", "reference"))
sys.path.insert(0, _here)
try:
    from aska_drop import DropClient, ST_OK, ST_FULL  # noqa: E402
except ImportError:
    sys.exit("soak.py: cannot find aska_drop.py — copy it next to this script or run from the repo")


def mem():
    try:
        out = subprocess.run(["systemctl", "show", "-p", "MemoryCurrent", "--value", "aska-drop"],
                             capture_output=True, text=True, timeout=5).stdout.strip()
        return f"{int(out) // 1024} KiB" if out.isdigit() else "n/a"
    except Exception:
        return "n/a"


async def main(a):
    if a.socks == "none":
        socks = None
    else:
        h, prt = a.socks.rsplit(":", 1)
        socks = (h, int(prt))
    c = DropClient(a.host, a.port, socks=socks)
    print("info:", await c.info(), flush=True)
    end = time.monotonic() + a.hours * 3600
    n_put = n_ok = n_full = n_err = 0
    last_err = ""
    t_report = time.monotonic()
    while time.monotonic() < end:
        # A single failed request (dropped connection, transient relay hiccup) must not end a
        # 24 h run: count it, remember the last one, and keep going. A rising n_err is itself a
        # finding — it points at a real relay problem, not a reason to abort the soak.
        try:
            st = await c.put(secrets.token_bytes(32), secrets.token_bytes(4096), a.ttl)
            n_put += 1
            n_ok += st == ST_OK
            n_full += st == ST_FULL
        except Exception as e:  # noqa: BLE001 — soak must survive any client-side failure
            n_err += 1
            last_err = f"put: {type(e).__name__}: {e}"
        if time.monotonic() - t_report >= a.report:
            try:
                live = len(await c.get_all(1))
            except Exception as e:  # noqa: BLE001
                n_err += 1
                last_err = f"get_all: {type(e).__name__}: {e}"
                live = "?"
            tail = f" err={n_err} last_err={last_err!r}" if n_err else ""
            print(f"{time.strftime('%H:%M:%S')} puts={n_put} ok={n_ok} full={n_full} "
                  f"live_class1={live} mem={mem()}{tail}", flush=True)
            t_report = time.monotonic()
        await asyncio.sleep(a.interval)
    print(f"soak done — puts={n_put} ok={n_ok} full={n_full} errors={n_err}", flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=4567)
    p.add_argument("--socks", default="127.0.0.1:9050", help="host:port of the Tor SOCKS port, or 'none'")
    p.add_argument("--hours", type=float, default=24)
    p.add_argument("--interval", type=float, default=10, help="seconds between PUTs")
    p.add_argument("--ttl", type=int, default=1, help="TTL hours per Block")
    p.add_argument("--report", type=float, default=300, help="seconds between report lines")
    asyncio.run(main(p.parse_args()))
