#!/usr/bin/env python3
"""
fake_socks.py — a stand-in for Tor's SOCKS port for local gates and tests (never for real use).

Speaks just enough SOCKS5 for aska-core's client: username/password method (the per-request
isolation credentials are accepted and discarded), CONNECT with a domain name that must end in
.onion, forwarded to one fixed loopback target. Prints the listening port on stdout and serves
until killed.

  python3 scripts/fake_socks.py --target 127.0.0.1:4567 [--port 0]
"""
import argparse, socket, struct, sys, threading

FAIL = None  # set by --fail: every CONNECT is answered with this SOCKS reply code


def pump(a, b):
    try:
        while True:
            d = a.recv(65536)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def serve(c, target):
    try:
        ver, n = c.recv(2)
        methods = c.recv(n)
        if ver != 5 or 2 not in methods:
            c.sendall(b"\x05\xff"); return
        c.sendall(b"\x05\x02")
        # RFC 1929 username/password: accept anything.
        _, ul = c.recv(2); c.recv(ul); (pl,) = c.recv(1); c.recv(pl)
        c.sendall(b"\x01\x00")
        ver, cmd, _, atyp = c.recv(4)
        if cmd != 1 or atyp != 3:
            c.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6); return
        (hl,) = c.recv(1)
        host = c.recv(hl).decode()
        c.recv(2)
        if not host.endswith(".onion"):
            c.sendall(b"\x05\x04\x00\x01" + b"\x00" * 6); return
        if FAIL is not None:
            # Simulate a network that blocks Tor: the local proxy answers, nothing beyond it
            # does (general failure 0x01 / host unreachable 0x04 — tor::looks_like_blocked_network).
            c.sendall(b"\x05" + bytes([FAIL]) + b"\x00\x01" + b"\x00" * 6); return
        t = socket.create_connection(target, timeout=30)
        c.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        threading.Thread(target=pump, args=(c, t), daemon=True).start()
        pump(t, c)
    except (OSError, ValueError):
        pass
    finally:
        c.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True)
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--fail", type=lambda x: int(x, 0), default=None,
                   help="answer every CONNECT with this SOCKS reply code (1 = general failure, 4 = host unreachable)")
    a = p.parse_args()
    global FAIL
    FAIL = a.fail
    h, prt = a.target.rsplit(":", 1)
    target = (h, int(prt))
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", a.port))
    s.listen(16)
    print(s.getsockname()[1], flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=serve, args=(c, target), daemon=True).start()


if __name__ == "__main__":
    main()
