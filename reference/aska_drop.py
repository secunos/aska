#!/usr/bin/env python3
"""
aska_drop.py — Reference implementation of the Aska Dead Drop Protocol v1 (ADP/1), draft 0.1.

The Dead Drop is a stateless, onion-only relay that stores opaque Blocks under random labels
until their time-to-live expires. It has no accounts, no per-label retrieval and no logs.
This module contains BOTH the relay (server) and the client library so that the wire format
is defined in exactly one place. It is a reference, not a product: it binds to loopback and
expects Tor to forward an onion service to it (see the specification's operator runbook).

Run relay:     python3 aska_drop.py serve [--port 4567] [--cap-1 2000 --cap-2 800 --cap-3 200] [--max-ttl-hours 168] [--pow-base 0]
Smoke test:    python3 aska_drop.py selftest
Interop test:  python3 aska_drop.py remote-test --host 127.0.0.1 --port 4567 --socks none   (relay must have --cap-1 4)
Health check:  python3 aska_drop.py info --host <onion> [--port 4567] [--socks 127.0.0.1:9050]
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# §3  Constants
# ---------------------------------------------------------------------------
MAGIC = b"ASKD"
PROTO_VERSION = 0x01

OP_INFO, OP_PUT, OP_GET_ALL = 0x01, 0x02, 0x03

ST_OK = 0x00
ST_BAD_REQUEST = 0x01        # malformed framing / unknown op / unsupported version
ST_BAD_CLASS = 0x02          # size class not served
ST_BAD_TTL = 0x03            # ttl outside 1..max
ST_BAD_LENGTH = 0x04         # block length != class size
ST_FULL = 0x05               # store cap reached for this class
ST_DUPLICATE = 0x06          # label exists with different content
ST_POW_REQUIRED = 0x07       # response carries a challenge; client must retry with a solution
ST_POW_INVALID = 0x08        # solution did not verify

SIZE_CLASSES = {1: 4096, 2: 16384, 3: 65536}   # from the Block Format Specification
DEFAULT_MAX_TTL_HOURS = 168                       # 7 days (D-05)
DEFAULT_TTL_HOURS = 24
LABEL_LEN = 32
MAX_REQUEST_HEADER = 4 + 1 + 1                    # magic | version | op
CHALLENGE_LEN = 16
POW_DOMAIN = b"aska/adp1/pow"

# Default capacity per class (Blocks). 200 × 64 KiB ≈ 12.8 MB — fits the RAM-only model.
DEFAULT_CAPS = {1: 2000, 2: 800, 3: 200}


# ---------------------------------------------------------------------------
# §6  Proof-of-work (identifier-free rate limiting, RLY-09)
#     solution: 8-byte nonce such that SHA-256(POW_DOMAIN ‖ challenge ‖ label ‖ nonce) has
#     `difficulty` leading zero bits.
# ---------------------------------------------------------------------------
def pow_check(challenge: bytes, label: bytes, nonce: bytes, difficulty: int) -> bool:
    h = hashlib.sha256(POW_DOMAIN + challenge + label + nonce).digest()
    v = int.from_bytes(h, "big")
    return v >> (256 - difficulty) == 0 if difficulty > 0 else True


def pow_solve(challenge: bytes, label: bytes, difficulty: int) -> bytes:
    n = 0
    while True:
        nonce = n.to_bytes(8, "big")
        if pow_check(challenge, label, nonce, difficulty):
            return nonce
        n += 1


# ---------------------------------------------------------------------------
# §5  Store (RAM only, monotonic deadlines, no timestamps)
# ---------------------------------------------------------------------------
@dataclass
class _Entry:
    block: bytes
    deadline: float          # time.monotonic() at which the Block is deleted
    digest: bytes            # SHA-256 of block, for idempotent duplicate detection


@dataclass
class Store:
    caps: Dict[int, int] = field(default_factory=lambda: dict(DEFAULT_CAPS))
    max_ttl_hours: int = DEFAULT_MAX_TTL_HOURS
    _data: Dict[int, Dict[bytes, _Entry]] = field(default_factory=lambda: {c: {} for c in SIZE_CLASSES})
    # PoW policy: difficulty 0 = off. The relay raises difficulty as a class approaches its cap.
    pow_base_difficulty: int = 0
    _challenges: Dict[bytes, float] = field(default_factory=dict)   # challenge -> expiry (monotonic)
    _clock=time.monotonic

    def expire(self) -> None:
        now = self._clock()
        for c, d in self._data.items():
            for label in [l for l, e in d.items() if e.deadline <= now]:
                del d[label]
        for ch in [c for c, t in self._challenges.items() if t <= now]:
            del self._challenges[ch]

    def difficulty_for(self, size_class: int) -> int:
        """Adaptive: base difficulty, +1 bit per 12.5% of capacity used above 50% (max +4)."""
        d = self._data[size_class]
        fill = len(d) / max(1, self.caps[size_class])
        extra = 0 if fill < 0.5 else min(4, int((fill - 0.5) / 0.125) + 1)
        return self.pow_base_difficulty + extra

    def new_challenge(self) -> bytes:
        ch = secrets.token_bytes(CHALLENGE_LEN)
        self._challenges[ch] = self._clock() + 120.0   # valid two minutes
        return ch

    def consume_challenge(self, ch: bytes) -> bool:
        # Single-use AND within its 120 s validity, as the Rust relay enforces (review D-3).
        exp = self._challenges.pop(ch, None)
        return exp is not None and exp > self._clock()

    def serves(self, size_class: int) -> bool:
        # A class with cap 0 is not served: INFO omits it and PUT/GET_ALL answer BAD_CLASS,
        # as the Rust relay does (review D-2).
        return size_class in SIZE_CLASSES and self.caps.get(size_class, 0) > 0

    def put(self, size_class: int, ttl_hours: int, label: bytes, block: bytes) -> int:
        self.expire()
        if size_class not in SIZE_CLASSES:
            return ST_BAD_CLASS
        if not (1 <= ttl_hours <= self.max_ttl_hours):
            return ST_BAD_TTL
        if len(block) != SIZE_CLASSES[size_class] or len(label) != LABEL_LEN:
            return ST_BAD_LENGTH
        d = self._data[size_class]
        digest = hashlib.sha256(block).digest()
        if label in d:
            return ST_OK if d[label].digest == digest else ST_DUPLICATE   # idempotent retry
        if len(d) >= self.caps[size_class]:
            return ST_FULL
        d[label] = _Entry(block, self._clock() + ttl_hours * 3600.0, digest)
        return ST_OK

    def get_all(self, size_class: int) -> List[Tuple[bytes, bytes]]:
        """All live (label, block) pairs of a class, in RANDOM order (never insertion order)."""
        self.expire()
        items = [(l, e.block) for l, e in self._data[size_class].items()]
        # Fisher–Yates with a CSPRNG
        for i in range(len(items) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            items[i], items[j] = items[j], items[i]
        return items

    def counts(self) -> Dict[int, int]:
        self.expire()
        return {c: len(d) for c, d in self._data.items()}


# ---------------------------------------------------------------------------
# §4  Wire format
#   Request  = MAGIC(4) ‖ version(1) ‖ op(1) ‖ body
#   Response = MAGIC(4) ‖ version(1) ‖ status(1) ‖ body
#   INFO     body: —                     → resp body: max_ttl_hours(2) ‖ classes_bitmap(1) ‖ pow_difficulty(1)
#   PUT      body: class(1) ‖ ttl_hours(2) ‖ label(32) ‖ pow_challenge(16) ‖ pow_nonce(8) ‖ block(class size)
#                                        → resp body: (ST_POW_REQUIRED: challenge(16) ‖ difficulty(1)) else empty
#   GET_ALL  body: class(1)              → resp body: count(4) ‖ count × ( label(32) ‖ block(class size) )
#   Exactly one request per connection. The relay closes after responding.
# ---------------------------------------------------------------------------
def _resp(status: int, body: bytes = b"") -> bytes:
    return MAGIC + bytes([PROTO_VERSION, status]) + body


async def _read_exact(reader: asyncio.StreamReader, n: int, timeout: float) -> Optional[bytes]:
    try:
        return await asyncio.wait_for(reader.readexactly(n), timeout)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError):
        return None


async def handle_connection(store: Store, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                            timeout: float = 30.0) -> None:
    try:
        hdr = await _read_exact(reader, MAX_REQUEST_HEADER, timeout)
        if hdr is None or hdr[:4] != MAGIC or hdr[4] != PROTO_VERSION:
            writer.write(_resp(ST_BAD_REQUEST)); return
        op = hdr[5]
        if op == OP_INFO:
            bitmap = sum(1 << (c - 1) for c in SIZE_CLASSES if store.serves(c))
            writer.write(_resp(ST_OK, struct.pack(">HBB", store.max_ttl_hours, bitmap, store.pow_base_difficulty)))
        elif op == OP_PUT:
            fixed = await _read_exact(reader, 1 + 2 + LABEL_LEN + CHALLENGE_LEN + 8, timeout)
            if fixed is None:
                writer.write(_resp(ST_BAD_REQUEST)); return
            size_class, ttl = fixed[0], struct.unpack(">H", fixed[1:3])[0]
            label = fixed[3:3 + LABEL_LEN]
            challenge = fixed[3 + LABEL_LEN:3 + LABEL_LEN + CHALLENGE_LEN]
            nonce = fixed[3 + LABEL_LEN + CHALLENGE_LEN:]
            if not store.serves(size_class):
                writer.write(_resp(ST_BAD_CLASS)); return
            block = await _read_exact(reader, SIZE_CLASSES[size_class], timeout)
            if block is None:
                writer.write(_resp(ST_BAD_LENGTH)); return
            difficulty = store.difficulty_for(size_class)
            if difficulty > 0:
                if challenge == b"\x00" * CHALLENGE_LEN:
                    ch = store.new_challenge()
                    writer.write(_resp(ST_POW_REQUIRED, ch + bytes([difficulty]))); return
                if not store.consume_challenge(challenge) or not pow_check(challenge, label, nonce, difficulty):
                    writer.write(_resp(ST_POW_INVALID)); return
            writer.write(_resp(store.put(size_class, ttl, label, block)))
        elif op == OP_GET_ALL:
            b = await _read_exact(reader, 1, timeout)
            if b is None or not store.serves(b[0]):
                writer.write(_resp(ST_BAD_CLASS)); return
            items = store.get_all(b[0])
            writer.write(_resp(ST_OK, struct.pack(">I", len(items))))
            for label, block in items:
                writer.write(label + block)
        else:
            writer.write(_resp(ST_BAD_REQUEST))
        await writer.drain()
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def serve(store: Store, host: str = "127.0.0.1", port: int = 4567) -> asyncio.AbstractServer:
    async def _h(r, w):
        await handle_connection(store, r, w)
    server = await asyncio.start_server(_h, host, port, limit=2 ** 20)
    return server


# ---------------------------------------------------------------------------
# Client library (talks to a relay through a SOCKS5 proxy = local Tor, or directly for tests)
# ---------------------------------------------------------------------------
async def _open(host: str, port: int, socks: Optional[Tuple[str, int]]):
    if socks is None:
        return await asyncio.open_connection(host, port)
    # Minimal SOCKS5 CONNECT with domain-name addressing (works for .onion via Tor)
    reader, writer = await asyncio.open_connection(*socks)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    if (await reader.readexactly(2)) != b"\x05\x00":
        raise ConnectionError("SOCKS5 handshake failed")
    hb = host.encode()
    writer.write(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", port))
    await writer.drain()
    resp = await reader.readexactly(4)
    if resp[1] != 0x00:
        raise ConnectionError(f"SOCKS5 connect failed: {resp[1]}")
    atyp = resp[3]
    if atyp == 1:
        await reader.readexactly(4 + 2)
    elif atyp == 3:
        n = (await reader.readexactly(1))[0]; await reader.readexactly(n + 2)
    elif atyp == 4:
        await reader.readexactly(16 + 2)
    return reader, writer


async def _request(host: str, port: int, socks, payload: bytes, timeout: float = 120.0) -> Tuple[int, asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await _open(host, port, socks)
    writer.write(payload)
    await writer.drain()
    hdr = await asyncio.wait_for(reader.readexactly(6), timeout)
    if hdr[:4] != MAGIC or hdr[4] != PROTO_VERSION:
        raise ValueError("bad response header")
    return hdr[5], reader, writer


class DropClient:
    def __init__(self, host: str, port: int = 4567, socks: Optional[Tuple[str, int]] = ("127.0.0.1", 9050)):
        self.host, self.port, self.socks = host, port, socks

    async def info(self) -> dict:
        st, r, w = await _request(self.host, self.port, self.socks, MAGIC + bytes([PROTO_VERSION, OP_INFO]))
        body = await r.readexactly(4); w.close()
        max_ttl, bitmap, diff = struct.unpack(">HBB", body)
        return {"status": st, "max_ttl_hours": max_ttl, "classes": [c for c in range(1, 9) if bitmap >> (c - 1) & 1], "pow_difficulty": diff}

    async def put(self, label: bytes, block: bytes, ttl_hours: int = DEFAULT_TTL_HOURS) -> int:
        size_class = {v: k for k, v in SIZE_CLASSES.items()}[len(block)]
        challenge, nonce = b"\x00" * CHALLENGE_LEN, b"\x00" * 8
        for _ in range(2):   # first attempt may return a PoW challenge
            body = bytes([size_class]) + struct.pack(">H", ttl_hours) + label + challenge + nonce + block
            st, r, w = await _request(self.host, self.port, self.socks, MAGIC + bytes([PROTO_VERSION, OP_PUT]) + body)
            if st == ST_POW_REQUIRED:
                extra = await r.readexactly(CHALLENGE_LEN + 1); w.close()
                challenge, difficulty = extra[:CHALLENGE_LEN], extra[CHALLENGE_LEN]
                nonce = pow_solve(challenge, label, difficulty)
                continue
            w.close()
            return st
        return st

    async def get_all(self, size_class: int) -> List[Tuple[bytes, bytes]]:
        st, r, w = await _request(self.host, self.port, self.socks, MAGIC + bytes([PROTO_VERSION, OP_GET_ALL, size_class]))
        if st != ST_OK:
            w.close(); raise ValueError(f"status {st}")
        n = struct.unpack(">I", await r.readexactly(4))[0]
        size = SIZE_CLASSES[size_class]
        out = []
        for _ in range(n):
            rec = await r.readexactly(LABEL_LEN + size)
            out.append((rec[:LABEL_LEN], rec[LABEL_LEN:]))
        w.close()
        return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
async def _selftest():
    store = Store(caps={1: 4, 2: 800, 3: 200})
    srv = await serve(store, port=0)
    port = srv.sockets[0].getsockname()[1]
    c = DropClient("127.0.0.1", port, socks=None)
    info = await c.info(); assert info["max_ttl_hours"] == 168 and info["classes"] == [1, 2, 3], info
    labels = [secrets.token_bytes(32) for _ in range(3)]
    blocks = [secrets.token_bytes(4096) for _ in range(3)]
    for l, b in zip(labels, blocks):
        assert await c.put(l, b, 1) == ST_OK
    assert await c.put(labels[0], blocks[0], 1) == ST_OK            # idempotent
    assert await c.put(labels[0], secrets.token_bytes(4096), 1) == ST_DUPLICATE
    assert await c.put(secrets.token_bytes(32), secrets.token_bytes(4096), 0) == ST_BAD_TTL
    assert await c.put(secrets.token_bytes(32), secrets.token_bytes(4096), 169) == ST_BAD_TTL
    got = await c.get_all(1)
    assert sorted(got) == sorted(zip(labels, blocks))
    # PoW kicks in above 50% fill (3/4 = 75% → +3 bits), fourth put must still succeed via challenge
    assert store.difficulty_for(1) == 3
    assert await c.put(secrets.token_bytes(32), secrets.token_bytes(4096), 1) == ST_OK
    assert await c.put(secrets.token_bytes(32), secrets.token_bytes(4096), 1) == ST_FULL
    # expiry
    store._clock = lambda: time.monotonic() + 2 * 3600
    assert await c.get_all(1) == []
    srv.close(); await srv.wait_closed()
    print("ADP/1 self-test OK")


async def _remote_test(host: str, port: int, socks):
    """The selftest scenario against a RUNNING relay whose class-1 cap is 4 (interop with the
    Rust relay, M2 gate). Expiry cannot be forced remotely, so it is not checked here."""
    c = DropClient(host, port, socks=socks)
    info = await c.info(); assert info["max_ttl_hours"] == 168 and info["classes"] == [1, 2, 3], info
    labels = [secrets.token_bytes(32) for _ in range(3)]
    blocks = [secrets.token_bytes(4096) for _ in range(3)]
    for l, b in zip(labels, blocks):
        assert await c.put(l, b, 1) == ST_OK
    assert await c.put(labels[0], blocks[0], 1) == ST_OK            # idempotent
    assert await c.put(labels[0], secrets.token_bytes(4096), 1) == ST_DUPLICATE
    assert await c.put(secrets.token_bytes(32), secrets.token_bytes(4096), 0) == ST_BAD_TTL
    assert await c.put(secrets.token_bytes(32), secrets.token_bytes(4096), 169) == ST_BAD_TTL
    got = await c.get_all(1)
    assert sorted(got) == sorted(zip(labels, blocks)), "listing differs"
    # 3/4 full → PoW challenge path; the fourth put must still succeed, the fifth is FULL
    assert await c.put(secrets.token_bytes(32), secrets.token_bytes(4096), 1) == ST_OK
    assert await c.put(secrets.token_bytes(32), secrets.token_bytes(4096), 1) == ST_FULL
    assert len(await c.get_all(1)) == 4
    assert await c.get_all(2) == []
    # a wrong-class PUT and an unknown op are answered as specified
    r, w = await _open(host, port, socks)
    w.write(MAGIC + bytes([PROTO_VERSION, OP_GET_ALL, 9])); await w.drain()
    assert (await r.readexactly(6))[5] == ST_BAD_CLASS; w.close()
    r, w = await _open(host, port, socks)
    w.write(MAGIC + bytes([PROTO_VERSION, 0x09])); await w.drain()
    assert (await r.readexactly(6))[5] == ST_BAD_REQUEST; w.close()
    print("REMOTE TEST OK")


def _opt(argv, name, default):
    return argv[argv.index(name) + 1] if name in argv else default


def _socks_opt(argv):
    s = _opt(argv, "--socks", "127.0.0.1:9050")
    if s == "none":
        return None
    h, p = s.rsplit(":", 1)
    return (h, int(p))


def main(argv):
    cmd = argv[1] if len(argv) >= 2 else ""
    if cmd == "serve":
        port = int(_opt(argv, "--port", 4567))
        caps = {1: int(_opt(argv, "--cap-1", 2000)), 2: int(_opt(argv, "--cap-2", 800)), 3: int(_opt(argv, "--cap-3", 200))}
        async def run():
            store = Store(caps=caps, max_ttl_hours=int(_opt(argv, "--max-ttl-hours", 168)),
                          pow_base_difficulty=int(_opt(argv, "--pow-base", 0)))
            srv = await serve(store, port=port)
            async with srv:
                await srv.serve_forever()
        asyncio.run(run())
    elif cmd == "selftest":
        asyncio.run(_selftest())
    elif cmd == "remote-test":
        # python3 aska_drop.py remote-test --host 127.0.0.1 --port 4567 --socks none
        asyncio.run(_remote_test(_opt(argv, "--host", "127.0.0.1"), int(_opt(argv, "--port", 4567)), _socks_opt(argv)))
    elif cmd == "info":
        # python3 aska_drop.py info --host <onion> [--port 4567] [--socks 127.0.0.1:9050]  (operator health check, §9.5)
        async def run():
            c = DropClient(_opt(argv, "--host", "127.0.0.1"), int(_opt(argv, "--port", 4567)), socks=_socks_opt(argv))
            print(await c.info())
        asyncio.run(run())
    else:
        print(__doc__)


if __name__ == "__main__":
    main(sys.argv)
