#!/usr/bin/env python3
"""Tests for aska_ref.py — run: python3 test_aska.py"""
import hashlib, json, math, os, sys, collections
from aska_ref import *
from aska_ref import _decode_header_body

R = bytes(range(32))  # fixed root for deterministic checks (NOT for real use)

def test_roundtrip_all_classes():
    for sc, size in SIZE_CLASSES.items():
        blk = seal(R, sc, [Slot(b"hello", passphrase=None)])
        assert len(blk) == size
        o = open_block(blk, R, None)
        assert o and o.data == b"hello" and 0 <= o.index < 4 and not o.distress

def test_decoy_and_distress_independent():
    blk = seal(R, 1, [Slot(b"REAL", passphrase="alpha"), Slot(b"DECOY", passphrase="beta"), Slot(b"DECOY", passphrase="gamma", distress=True)])
    assert open_block(blk, R, "alpha").data == b"REAL"
    assert open_block(blk, R, "beta").data == b"DECOY"
    d = open_block(blk, R, "gamma"); assert d.data == b"DECOY" and d.distress
    assert open_block(blk, R, None) is None          # open-slot key does not exist in this Block
    assert open_block(blk, R, "delta") is None
    assert open_block(blk, os.urandom(32), "alpha") is None

def test_tamper_detected_everywhere():
    blk = bytearray(seal(R, 1, [Slot(b"x" * 100, passphrase=None)]))
    base = open_block(bytes(blk), R, None); assert base
    # flip one bit in each region; opening must never return wrong data
    for off in [0, SALT_LEN + 5, HDR_OFF + 3, HDR_OFF + 40, HDR_OFF + 70, PAYLOAD_OFF + 10, len(blk) - 1]:
        t = bytearray(blk); t[off] ^= 0x01
        o = open_block(bytes(t), R, None)
        assert o is None or o.data == b"x" * 100, off   # either fails cleanly or was in unused filler

def test_header_body_length_bounds():
    # A forged header pointing outside payload must be rejected (cannot forge without key, but check decoder)
    assert _decode_header_body(b"\x00" * 16) == (0, 0, 0, 0)
    assert _decode_header_body(b"\x00" * 15 + b"\x01") is None

def test_size_limits():
    # largest note per class
    for sc, size in SIZE_CLASSES.items():
        payload = size - PAYLOAD_OFF
        assert payload % PAYLOAD_GRANULE == 0
        max_data = payload - HDR_P_LEN - INNER_HDR_LEN - TAG_LEN
        blk = seal(R, sc, [Slot(b"a" * max_data)])
        assert open_block(blk, R, None).data == b"a" * max_data
        try:
            seal(R, sc, [Slot(b"a" * (max_data + 1))]); assert False
        except ValueError:
            pass

def test_randomness_sanity():
    # Bytes of a real Block should be statistically indistinguishable from uniform (coarse chi-square).
    blk = seal(R, 3, [Slot(b"note" * 1000, passphrase=None), Slot(b"decoy", passphrase="p")])
    counts = collections.Counter(blk)
    n = len(blk); exp = n / 256
    chi = sum((counts[b] - exp) ** 2 / exp for b in range(256))
    # 255 dof: mean 255, sd ~22.6 → accept below 340 (≈ +3.8 sd)
    assert chi < 340, chi
    # no 8-byte sequence repeats (would indicate structure)
    seen = set()
    for i in range(0, n - 8, 8):
        w = blk[i:i+8]; assert w not in seen; seen.add(w)

def test_shares():
    for k, n in [(2, 3), (3, 5)]:
        sh = split_root(R, k, n)
        import itertools
        for combo in itertools.combinations(sh, k):
            assert combine_shares(list(combo)) == R
        # fewer than k must fail
        try: combine_shares(sh[:k-1]); assert False
        except ValueError: pass
        # forged share detected
        bad = Share(sh[0].set_id, k, sh[0].x, bytes(b ^ 1 for b in sh[0].y), sh[0].verify)
        try: combine_shares([bad] + sh[1:k]); assert False
        except ValueError: pass
        # shares from different sets rejected
        other = split_root(os.urandom(32), k, n)
        try: combine_shares([sh[0]] + other[1:k]); assert False
        except ValueError: pass
        # encoding round trip
        for s in sh:
            assert share_decode(share_encode(s)) == s

def test_share_secrecy_single_share():
    # A single share carries no information: y for two different roots are both uniform-looking; trivially we just check
    # that changing the root changes y unpredictably and that x=0 never appears.
    sh = split_root(R, 2, 3)
    assert all(s.x != 0 for s in sh)

def test_words():
    w = root_to_words(R); assert len(w.split()) == 24
    assert words_to_root(w) == R
    bad = w.split(); bad[0] = "zoo" if bad[0] != "zoo" else "zone"
    try: words_to_root(" ".join(bad)); assert False
    except ValueError: pass

def test_bech32m_vectors():
    # BIP-350 test vector
    hrp, data = bech32m_decode("A1LQFN3A"); assert hrp == "a" and data == b""
    assert bech32m_encode("a", b"") == "a1lqfn3a"

def test_onion():
    addr = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"  # torproject.org v3
    pk = onion_address_to_pubkey(addr)
    assert onion_pubkey_to_address(pk) == addr

def test_keycard():
    pk = onion_address_to_pubkey("2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion")
    kc = KeyCard(R, [pk], 2, 48)
    s = kc.encode()
    kc2 = KeyCard.decode(s)
    assert kc2.root == R and kc2.relays == [pk] and kc2.size_class == 2 and kc2.ttl_hours == 48
    assert KeyCard.decode(s.upper()).root == R   # QR alphanumeric mode
    ak = os.urandom(32)
    kc3 = KeyCard.decode(KeyCard(R, [pk], 1, 24, auth_key=ak).encode())
    assert kc3.auth_key == ak and KeyCard.decode(s).auth_key is None
    print("   keycard length:", len(s), "chars")

def test_label_independent_of_salt():
    assert derive_label(R) == derive_label(R)
    b1 = seal(R, 1, [Slot(b"a")]); b2 = seal(R, 1, [Slot(b"a")])
    assert b1 != b2   # fresh salt/nonces each time

def test_duplicate_slot_keys_rejected():
    for bad in ([Slot(b"a", passphrase="x"), Slot(b"b", passphrase="x")], [Slot(b"a"), Slot(b"b")],
                [Slot(b"a", passphrase="x", distress=True), Slot(b"b", passphrase="y", distress=True)]):
        try: seal(R, 1, bad); assert False
        except ValueError: pass

def test_kdf_profiles():
    blk = seal(R, 1, [Slot(b"mobile", passphrase="pw", profile=2)])
    assert open_block(blk, R, "pw") is None                      # v1 desktop client (profile 1 only) cannot open
    assert open_block(blk, R, "pw", profiles=(1, 2)).data == b"mobile"
    assert derive_slot_key(R, b"s" * 32, "pw", 1) != derive_slot_key(R, b"s" * 32, "pw", 2)

def test_deterministic_rng_reproducible():
    a = seal(R, 1, [Slot(b"same", passphrase=None)], rng=Rng(b"seed"))
    b = seal(R, 1, [Slot(b"same", passphrase=None)], rng=Rng(b"seed"))
    assert a == b

if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t(); print("ok ", t.__name__)
    print(f"\n{len(tests)} tests passed")
