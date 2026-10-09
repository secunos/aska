#!/usr/bin/env python3
"""Tests for aska_paper_ref.py — run: python3 test_paper.py"""
import json, os, random
from aska_paper_ref import *

def test_checkerboard_round_trip_and_prefix_free():
    alphabet = "ETAOINSRHLDCUMFPGWYBVKXJQZ 0123456789"
    assert from_digits(to_digits(alphabet)) == alphabet
    for ch, code in ENC.items():
        assert (len(code) == 1) == (code in "0123456")
    assert normalise("  Två   öl  tack\n") == "TVAA OEL TACK"
    try:
        normalise("a.b"); assert False
    except ValueError:
        pass

def test_worked_example():
    m = encode("MEET 14 NOV NORTH GATE")
    pad = "279749132099457148372454626642375951480946439196613631751385"
    c = encipher(m, pad)
    assert c == "939757023937300976225155334511585"
    a = [5849, 1573, 2769, 6170, 2106, 5152, 6831, 4251, 1107, 6609, 5096, 2484, 272, 5425, 7676, 2832,
         7115, 6601, 5314, 5029, 8369, 9720, 9153, 768, 658, 7564, 9899, 7707, 5061, 499, 4489]
    assert hand_tag(c, a, 2691) == 3936
    assert reduce_by_hand(3314972) == ([13909, 3936], 3936)
    assert device_tag(c, 1231961752939033616, 1450779715753509526) == 876449745860556196
    k2 = cover_pad(c, encode("SEE YOU ON SUNDAY LOVE"))
    assert from_digits(decipher(c, k2)) == "SEE YOU ON SUNDAY LOVE"

def test_hand_tag_is_a_universal_hash():
    # Forgery probability ≈ 1/9973: random key, random distinct ciphertext pairs of equal length.
    rnd = random.Random(1)
    hits = 0; trials = 20000
    for _ in range(trials):
        a = [rnd.randrange(P_HAND) for _ in range(6)]; b = rnd.randrange(P_HAND)
        c1 = "".join(str(rnd.randrange(10)) for _ in range(9))
        c2 = "".join(str(rnd.randrange(10)) for _ in range(9))
        if c1 != c2 and hand_tag(c1, a, b) == hand_tag(c2, a, b): hits += 1
    assert hits <= 12, hits   # expected ≈ 2

def test_device_tag_binds_length():
    assert device_tag("1", 5, 7) != device_tag("01", 5, 7)
    assert device_tag("1", 5, 7) != device_tag("10", 5, 7)

def test_page_canonical_and_checksum():
    pad = shake_digits("t", 200)
    canon = canonical(1, "B", 7, pad, None, 12345, 67890)
    p = parse_with_checksum(qr_payload(canon))
    assert p["pad"] == pad and p["direction"] == "B" and p["number"] == 7 and p["hand_keys"] is None
    bad = list(qr_payload(canon)); bad[30] = str((int(bad[30]) + 1) % 10)
    try:
        parse_with_checksum("".join(bad)); assert False
    except ValueError:
        pass
    keys = [k % P_HAND for k in range(102)]
    canon = canonical(9999, "A", 50, pad, keys, 1, 2)
    assert parse(canon)["hand_keys"] == keys
    assert len(canon) == 1 + 4 + 1 + 2 + 3 + 200 + 1 + 102 * 4 + 38

def test_block_cards():
    block = bytes(random.Random(2).getrandbits(8) for _ in range(16384))
    cards = split_block(block, b"\x01\x02\x03\x04")
    assert len(cards) == 16 and all(len(c) == 7 + 1024 + 4 for c in cards)
    assert join_cards(cards[::-1]) == block
    try:
        split_block(bytes(65536), b"0000"); assert False
    except ValueError:
        pass

def test_vectors_file_reproduces():
    here = os.path.dirname(os.path.abspath(__file__))
    doc = json.load(open(os.path.join(here, "tv_paper.json")))
    page = doc["page"]
    canon = canonical(page["set_code"], page["direction"], page["number"], page["pad"], page["hand_keys"], page["r"], page["s"])
    assert canon == page["canonical"] and checksum(canon) == page["checksum"]
    for v in doc["vectors"]:
        if v["page"] == "P" if "page" in v else False:
            c = encipher(encode(v["text"]), page["pad"])
            assert c == v["cipher"]
            assert f"{hand_tag(c, page['hand_keys'][:-1], page['hand_keys'][-1]):04d}" == v["hand_tag"]
            assert f"{device_tag(c, page['r'], page['s']):019d}" == v["device_tag"]
        if v["id"] == "TV-P6":
            block = bytes.fromhex(v["block_hex"])
            assert join_cards([bytes.fromhex(c) for c in v["cards"]]) == block
        if v["id"] == "TV-P7":
            assert toeplitz(bytes.fromhex(v["seed_hex"]), bytes.fromhex(v["input_hex"]), v["m"]).hex() == v["output_hex"]

if __name__ == "__main__":
    import sys
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t(); print("ok", t.__name__)
    print(f"{len(tests)} tests passed")
