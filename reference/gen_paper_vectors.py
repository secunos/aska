#!/usr/bin/env python3
"""Regenerates tv_paper.json deterministically (DC-04 test vectors TV-P1…TV-P6) and self-checks it.
The pad and key material come from SHAKE256 with fixed labels — reproducible, never used for
a real page."""
import json, hashlib
from aska_paper_ref import *

def main():
    vectors = []

    # TV-P1…P3: a 400-digit page with hand keys; three texts.
    pad = shake_digits("TV pad", 400)
    a = shake_ints("TV a", 201, P_HAND, 2, 0x3FFF)
    b = shake_ints("TV b", 1, P_HAND, 2, 0x3FFF)[0]
    r, s = shake_ints("TV rs", 2, P_DEV, 8, (1 << 61) - 1)
    canon = canonical(7342, "A", 3, pad, a + [b], r, s)
    page = dict(set_code=7342, direction="A", number=3, pad=pad, hand_keys=a + [b], r=r, s=s,
                canonical=canon, checksum=checksum(canon),
                pad_row_checks=[row_check(pad[i:i+50]) for i in range(0, 400, 50)])
    for i, text in enumerate(["A", "MEET 14 NOV NORTH GATE",
                              "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG 0123456789"], start=1):
        m = encode(text); c = encipher(m, pad)
        vectors.append(dict(id=f"TV-P{i}", page="P", text=text, digits=m, cipher=c,
                            hand_tag=f"{hand_tag(c, a, b):04d}", device_tag=f"{device_tag(c, r, s):019d}"))

    # TV-P4: the DC-04 worked example page (60 digits — not a valid page length, tags only).
    pad60 = shake_digits("DC-04 example pad", 60)
    a60 = shake_ints("DC-04 example a", 31, P_HAND, 2, 0x3FFF)
    b60 = shake_ints("DC-04 example b", 1, P_HAND, 2, 0x3FFF)[0]
    r60, s60 = shake_ints("DC-04 example rs", 2, P_DEV, 8, (1 << 61) - 1)
    m = encode("MEET 14 NOV NORTH GATE"); c = encipher(m, pad60)
    vectors.append(dict(id="TV-P4", page="example60", pad=pad60, a=a60, b=b60, r=r60, s=s60,
                        text="MEET 14 NOV NORTH GATE", digits=m, cipher=c,
                        hand_tag=f"{hand_tag(c, a60, b60):04d}", device_tag=f"{device_tag(c, r60, s60):019d}",
                        cover_text="SEE YOU ON SUNDAY LOVE", cover_pad=cover_pad(c, encode("SEE YOU ON SUNDAY LOVE"))))

    # TV-P5: a 200-digit page without hand keys, direction B, page 50; canonical + checksum.
    pad200 = shake_digits("TV pad200", 200)
    r2, s2 = shake_ints("TV rs2", 2, P_DEV, 8, (1 << 61) - 1)
    canon2 = canonical(9, "B", 50, pad200, None, r2, s2)
    vectors.append(dict(id="TV-P5", page="P2", set_code=9, direction="B", number=50, pad=pad200, r=r2, s=s2,
                        canonical=canon2, checksum=checksum(canon2), qr_payload=qr_payload(canon2)))

    # TV-P6: Block cards for a deterministic class-1 "Block" (random bytes), set id fixed.
    block = hashlib.shake_256(b"TV block").digest(4096)
    cards = split_block(block, bytes.fromhex("a1b2c3d4"))
    assert join_cards(list(reversed(cards))) == block
    vectors.append(dict(id="TV-P6", block_sha3=hashlib.sha3_256(block).hexdigest(), block_hex=block.hex(),
                        set_id="a1b2c3d4", cards=[c.hex() for c in cards]))

    # TV-P7: Toeplitz convention.
    seed = bytes((i * 73 + 29) & 0xFF for i in range(64))
    inp = bytes([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc])
    vectors.append(dict(id="TV-P7", seed_hex=seed.hex(), input_hex=inp.hex(), m=17,
                        output_hex=toeplitz(seed, inp, 17).hex()))

    doc = dict(spec="Aska paper mode DC-04 v0.1", page=page, vectors=vectors)
    with open("tv_paper.json", "w") as f:
        json.dump(doc, f, indent=1)
    # Self-check: parse back.
    p = parse_with_checksum(qr_payload(canon))
    assert p["pad"] == pad and p["hand_keys"] == a + [b] and p["r"] == r
    print("tv_paper.json written:", len(vectors), "vectors")

if __name__ == "__main__":
    main()
