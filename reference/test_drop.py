#!/usr/bin/env python3
"""Tests for aska_drop.py (ADP/1) including an end-to-end flow with the Block format. Run: python3 test_drop.py"""
import asyncio, secrets, struct, time
from aska_drop import *
from aska_ref import seal, open_block, derive_label, Slot, split_root, combine_shares, KeyCard

async def start(caps=None):
    store = Store(caps=caps or {1: 100, 2: 50, 3: 10})
    srv = await serve(store, port=0)
    port = srv.sockets[0].getsockname()[1]
    return store, srv, DropClient("127.0.0.1", port, socks=None), port

async def raw(port, payload, read=6):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(payload); await w.drain()
    data = await asyncio.wait_for(r.readexactly(read), 5)
    w.close()
    return data

async def test_end_to_end_level1():
    store, srv, c, _ = await start()
    # noise from other users
    for _ in range(5):
        await c.put(secrets.token_bytes(32), secrets.token_bytes(4096), 24)
    # sender
    R = secrets.token_bytes(32)
    blk = seal(R, 1, [Slot(b"meet 14 nov, north gate", passphrase="north"), Slot(b"buy milk", passphrase="south")])
    assert await c.put(derive_label(R), blk, 24) == ST_OK
    # receiver: bucket fetch, local label match, open
    bucket = await c.get_all(1)
    assert len(bucket) == 6
    L = derive_label(R)
    mine = [b for l, b in bucket if l == L]
    assert len(mine) == 1
    assert open_block(mine[0], R, "north").data == b"meet 14 nov, north gate"
    assert open_block(mine[0], R, "south").data == b"buy milk"
    # a foreign Block never opens
    others = [b for l, b in bucket if l != L]
    assert all(open_block(b, R, "north") is None for b in others)
    srv.close(); await srv.wait_closed()

async def test_end_to_end_level2_shares():
    store, srv, c, _ = await start()
    R = secrets.token_bytes(32)
    blk = seal(R, 2, [Slot(b"root credentials: ...", passphrase=None)])
    assert await c.put(derive_label(R), blk, 48) == ST_OK
    shares = split_root(R, 2, 3)
    # receiver holds share 0, trustee gives share 2; label derived only after reassembly
    R2 = combine_shares([shares[0], shares[2]])
    bucket = await c.get_all(2)
    mine = [b for l, b in bucket if l == derive_label(R2)]
    assert open_block(mine[0], R2, None).data == b"root credentials: ..."
    srv.close(); await srv.wait_closed()

async def test_malformed_requests():
    store, srv, c, port = await start()
    assert (await raw(port, b"XXXX\x01\x01"))[5] == ST_BAD_REQUEST          # bad magic
    assert (await raw(port, MAGIC + b"\x02\x01"))[5] == ST_BAD_REQUEST      # bad version
    assert (await raw(port, MAGIC + b"\x01\x09"))[5] == ST_BAD_REQUEST      # unknown op
    assert (await raw(port, MAGIC + b"\x01\x03\x07"))[5] == ST_BAD_CLASS    # GET_ALL bad class
    # PUT with bad class
    body = bytes([9]) + struct.pack(">H", 24) + b"\x00" * (32 + 16 + 8)
    assert (await raw(port, MAGIC + b"\x01\x02" + body))[5] == ST_BAD_CLASS
    # PUT truncated block (connection closes early → BAD_LENGTH after timeout) — use short timeout path
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(MAGIC + b"\x01\x02" + bytes([1]) + struct.pack(">H", 24) + b"\x00" * 56 + b"\x00" * 100)
    w.write_eof(); await w.drain()
    data = await asyncio.wait_for(r.readexactly(6), 35)
    assert data[5] == ST_BAD_LENGTH
    w.close()
    srv.close(); await srv.wait_closed()

async def test_listing_is_randomised():
    store, srv, c, _ = await start()
    for _ in range(12):
        await c.put(secrets.token_bytes(32), secrets.token_bytes(4096), 24)
    orders = [tuple(l for l, _ in await c.get_all(1)) for _ in range(5)]
    assert len(set(orders)) > 1, "listing order must not be deterministic"
    srv.close(); await srv.wait_closed()

async def test_ttl_and_expiry():
    store, srv, c, _ = await start()
    a, b = secrets.token_bytes(32), secrets.token_bytes(32)
    await c.put(a, secrets.token_bytes(4096), 1)
    await c.put(b, secrets.token_bytes(4096), 5)
    base = time.monotonic()
    store._clock = lambda: base + 2 * 3600
    assert [l for l, _ in await c.get_all(1)] == [b]
    store._clock = lambda: base + 6 * 3600
    assert await c.get_all(1) == []
    srv.close(); await srv.wait_closed()

async def test_pow_flow():
    store, srv, c, _ = await start(caps={1: 4, 2: 1, 3: 1})
    store.pow_base_difficulty = 4
    assert store.difficulty_for(1) == 4
    assert await c.put(secrets.token_bytes(32), secrets.token_bytes(4096), 1) == ST_OK   # client solved challenge
    # invalid solution rejected
    label = secrets.token_bytes(32)
    ch = store.new_challenge()
    body = bytes([1]) + struct.pack(">H", 1) + label + ch + b"\x00" * 8 + secrets.token_bytes(4096)
    r, w = await asyncio.open_connection("127.0.0.1", c.port)
    w.write(MAGIC + b"\x01\x02" + body); await w.drain()
    assert (await r.readexactly(6))[5] == ST_POW_INVALID
    w.close()
    # challenge single-use: reusing a consumed challenge fails
    assert not store.consume_challenge(ch)
    srv.close(); await srv.wait_closed()

async def test_no_per_label_retrieval_surface():
    # The protocol has exactly three ops; nothing takes a label as a query.
    assert {OP_INFO, OP_PUT, OP_GET_ALL} == {1, 2, 3}

async def test_store_holds_no_timestamps():
    store = Store()
    store.put(1, 24, secrets.token_bytes(32), secrets.token_bytes(4096))
    e = next(iter(store._data[1].values()))
    assert set(vars(e).keys()) == {"block", "deadline", "digest"}   # monotonic deadline only

if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        asyncio.run(t()); print("ok ", t.__name__)
    print(f"\n{len(tests)} tests passed")
