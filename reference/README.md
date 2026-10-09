# Aska reference implementation — Block Format v1 (draft 0.3) and Dead Drop Protocol ADP/1 (draft 0.2)

Companion to *Aska Block Format Specification v1 (draft 0.3)* and *Aska Dead Drop Protocol Specification ADP/1 (draft 0.2)*. This code exists so that the
specification is executable and so that independent implementations can be checked against it.
It is **not** hardened (no memory locking, no zeroisation, no constant-time trial loop) and must
not be used as a product.

## Files

| File | Purpose |
|---|---|
| `aska_ref.py` | Reference implementation: seal / open, key hierarchy, UtC committing AEAD, Shamir shares, BIP-39 words, bech32m, Key Card TLV, onion-address helpers |
| `test_aska.py` | 16 tests: round trips for all size classes, decoy/distress independence, tamper detection, size limits, statistical randomness smoke test, share combine/forgery/mixing, encodings, known-answer bech32m and onion vectors |
| `gen_vectors.py` | Regenerates `test_vectors.json` deterministically |
| `test_vectors.json` | 8 vectors (TV-1 … TV-8) with intermediate values and full Block hex |
| `aska_paper_ref.py` | Paper mode (DC-04, release 1.2): checkerboard, modulo-10 pad, hand tag (mod 9 973), device tag (mod 2⁶¹ − 1), canonical page string and checksum, Block-card framing, Toeplitz convention |
| `test_paper.py` | 7 tests incl. the DC-04 worked example, the hand tag's forgery bound (sampled), page checksum, cards, and reproduction of `tv_paper.json` |
| `gen_paper_vectors.py` | Regenerates `tv_paper.json` (TV-P1 … TV-P7) deterministically |
| `tv_paper.json` | Paper-mode vectors: a 400-digit page with keys, three messages with both tags, the worked-example page, a page without hand keys, a card set, a Toeplitz vector |
| `aska_drop.py` | ADP/1 reference **relay** (asyncio, loopback, RAM-only store, expire-only TTL, adaptive PoW, randomised listing) and **client** library (SOCKS5 → Tor) in one file |
| `test_drop.py` | 8 tests incl. two end-to-end flows (Level 1 with decoy; Level 2 via Shares), malformed requests, randomised listing, expiry, PoW |
| `deploy/torrc.aska-drop` | Tor configuration: onion-only, PoW + intro-DoS defence, no logs |
| `deploy/aska-drop.service` | Hardened systemd unit (dynamic user, read-only FS, loopback-only, mlock, no core dumps, no stdout) |
| `deploy/install-debian.sh` | One-shot install for a fresh Debian VPS / droplet (no swap, drop-all firewall, Tor repo, unit, volatile journald) |

## Running

```bash
pip install pynacl argon2-cffi mnemonic
python3 test_aska.py        # ~6 s (Argon2id at 256 MiB dominates)
python3 gen_vectors.py      # rewrites test_vectors.json and self-checks it
python3 aska_ref.py         # smoke test
python3 test_drop.py        # relay + client tests (~7 s)
python3 aska_drop.py serve --port 4567   # run a relay on loopback (Tor forwards the onion service to it)
python3 aska_drop.py selftest
```

## End-to-end in three lines (local relay, no Tor)

```python
from aska_ref import *; from aska_drop import *; import asyncio, secrets
async def demo():
    store = Store(); srv = await serve(store, port=0); port = srv.sockets[0].getsockname()[1]
    c = DropClient("127.0.0.1", port, socks=None)
    R = new_root(); blk = seal(R, 1, [Slot(b"hello", passphrase="north")])
    await c.put(derive_label(R), blk, ttl_hours=24)                        # sender
    bucket = await c.get_all(1)                                            # receiver downloads everything
    mine = [b for l, b in bucket if l == derive_label(R)][0]               # matches locally
    print(open_block(mine, R, "north").data)                               # b'hello'
asyncio.run(demo())
```

## Quick use (for experimenting only)

```python
from aska_ref import *
R = new_root()
blk = seal(R, 1, [Slot(b"the real note", passphrase="north"),
                  Slot(b"buy milk",      passphrase="south"),
                  Slot(b"buy milk",      passphrase="west", distress=True)])
label = derive_label(R)                    # what the relay stores the Block under
print(root_to_words(R))                    # 24 words to read to the receiver
print(KeyCard(R, [], 1, 24).encode())      # or a Key Card for a QR code
shares = split_root(R, 2, 3)               # Level 2: any two Shares rebuild R
print(open_block(blk, R, "north").data)    # b'the real note'
print(open_block(blk, combine_shares(shares[:2]), "west").distress)   # True
```

## Interop checklist for a second implementation

1. Reproduce TV-1 (label, slot key, UtC commitment) and TV-2 (Argon2id) exactly.
2. Implement the test RNG `SHAKE256(b"aska-test-vectors" + seed)` and the draw order of spec §6.1 step 2;
   regenerate TV-3/4/5 bit-for-bit with the explicit offsets given.
3. Open every Block vector with every listed passphrase; verify index, data, distress; verify the
   listed non-matching passphrases open nothing.
4. Reproduce TV-6 shares, TV-7 Key Card, TV-8 header body.
