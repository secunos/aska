#!/usr/bin/env python3
"""Generate Aska Block Format v1 test vectors (test_vectors.json). Deterministic: all randomness
comes from Rng(seed) = SHAKE256("aska-test-vectors" || seed), drawn in the order defined in seal()."""
import hashlib, json
from aska_ref import *
from aska_ref import _encode_header_body

def H(b): return hashlib.sha256(b).hexdigest()

R1 = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
R2 = bytes.fromhex("aska".encode().hex() * 0 + "5b" * 32)  # 0x5b repeated
vec = {"format_version": FORMAT_VERSION, "note": "All values hex unless stated. Rng = SHAKE256('aska-test-vectors'||seed) XOF, consumed sequentially in the order documented in spec §9.",
       "constants": {"size_classes": SIZE_CLASSES, "salt_off": SALT_OFF, "kem_off": KEM_OFF, "kem_len": KEM_LEN, "hdr_off": HDR_OFF, "hdr_len": HDR_LEN, "n_slots": N_SLOTS,
                     "rsv_off": RSV_OFF, "rsv_len": RSV_LEN, "payload_off": PAYLOAD_OFF, "granule": PAYLOAD_GRANULE,
                     "kdf_profiles": KDF_PROFILES, "argon2_len": ARGON2_LEN}, "vectors": []}

# TV-1: key hierarchy intermediates for R1, open slot
salt = Rng(b"tv1").bytes(32)
kslot_open = derive_slot_key(R1, salt, None)
nonce = bytes(range(24))
enc_key, commit = utc_derive(kslot_open, nonce, INFO_UTC_HDR)
vec["vectors"].append({"id": "TV-1", "title": "Key hierarchy intermediates (open slot)", "root": R1.hex(), "label": derive_label(R1).hex(),
    "block_salt": salt.hex(), "slot_key_open_profile1": kslot_open.hex(), "slot_info_string": (INFO_SLOT_PREFIX + b"\x01").decode(),
    "utc_header_nonce": nonce.hex(), "utc_header_enc_key": enc_key.hex(), "utc_header_commit_P": commit.hex(),
    "share_verify_tag": share_verify_tag(R1).hex(), "words": root_to_words(R1)})

# TV-2: passphrase intermediates
a_p = argon2id_passphrase("correct horse", salt, 1)
a_p2 = argon2id_passphrase("correct horse", salt, 2)
vec["vectors"].append({"id": "TV-2", "title": "Passphrase derivation, profiles 1 and 2", "root": R1.hex(), "block_salt": salt.hex(), "passphrase_utf8": "correct horse",
    "profile1": {"argon2id_A_p": a_p.hex(), "slot_key": derive_slot_key(R1, salt, "correct horse", 1).hex()},
    "profile2": {"argon2id_A_p": a_p2.hex(), "slot_key": derive_slot_key(R1, salt, "correct horse", 2).hex()}})

def hdr_index(blk, root, passphrase):
    """The header index a slot landed on (random per Block since the header permutation, §10.3)."""
    o = open_block(blk, root, passphrase, profiles=(1,))
    assert o is not None
    return o.index

# TV-3: 4 KiB Block, one open text slot
blk = seal(R1, 1, [Slot("meet 14 nov, north gate".encode())], rng=Rng(b"tv3"), offsets=[512])
i3 = hdr_index(blk, R1, None)
vec["vectors"].append({"id": "TV-3", "title": "4 KiB Block, single open slot at payload offset 512", "root": R1.hex(), "size_class": 1, "rng_seed": "tv3",
    "slots": [{"index": i3, "ptype": PTYPE_TEXT, "passphrase": None, "distress": False, "offset": 512, "data_utf8": "meet 14 nov, north gate"}],
    "block_sha256": H(blk), "block_hex": blk.hex(), "opens_with": {"passphrase": None, "expected_index": i3}})

# TV-4: 4 KiB Block, real + decoy + distress
slots = [Slot(b"REAL: account 4471-2210, code 8812", passphrase="north"), Slot(b"Buy milk, eggs, bread", passphrase="south"),
         Slot(b"Buy milk, eggs, bread", passphrase="west", distress=True)]
blk = seal(R1, 1, slots, rng=Rng(b"tv4"), offsets=[1024, 0, 2304])
i4 = [hdr_index(blk, R1, s.passphrase) for s in slots]
vec["vectors"].append({"id": "TV-4", "title": "4 KiB Block, three passphrased slots (real, decoy, distress) at explicit offsets", "root": R1.hex(), "size_class": 1, "rng_seed": "tv4",
    "slots": [{"index": i4[k], "ptype": s.ptype, "passphrase": s.passphrase, "distress": s.distress, "offset": o, "data_utf8": s.data.decode()} for k, (s, o) in enumerate(zip(slots, [1024, 0, 2304]))],
    "block_sha256": H(blk), "block_hex": blk.hex(),
    "expectations": [{"passphrase": "north", "index": i4[0], "distress": False}, {"passphrase": "south", "index": i4[1], "distress": False}, {"passphrase": "west", "index": i4[2], "distress": True}, {"passphrase": None, "index": None}, {"passphrase": "east", "index": None}]})

# TV-5: 16 KiB Block, binary slot, empty note
blob = bytes(range(256)) * 20
blk = seal(R2, 2, [Slot(blob, ptype=PTYPE_BINARY), Slot(b"", passphrase="empty")], rng=Rng(b"tv5"), offsets=[0, 8192])
i5 = [hdr_index(blk, R2, None), hdr_index(blk, R2, "empty")]
vec["vectors"].append({"id": "TV-5", "title": "16 KiB Block, binary open slot + empty passphrased slot", "root": R2.hex(), "size_class": 2, "rng_seed": "tv5",
    "slots": [{"index": i5[0], "ptype": PTYPE_BINARY, "passphrase": None, "offset": 0, "data_sha256": H(blob), "data_len": len(blob)}, {"index": i5[1], "ptype": PTYPE_TEXT, "passphrase": "empty", "offset": 8192, "data_len": 0}],
    "block_sha256": H(blk), "block_hex": blk.hex()})

# TV-6: shares
sh23 = split_root(R1, 2, 3, rng=Rng(b"tv6a")); sh35 = split_root(R1, 3, 5, rng=Rng(b"tv6b"))
vec["vectors"].append({"id": "TV-6", "title": "Shamir shares of R1", "root": R1.hex(), "verify_tag": share_verify_tag(R1).hex(),
    "2of3": {"rng_seed": "tv6a", "shares_hex": [s.to_bytes().hex() for s in sh23], "shares_bech32m": [share_encode(s) for s in sh23]},
    "3of5": {"rng_seed": "tv6b", "shares_hex": [s.to_bytes().hex() for s in sh35], "shares_bech32m": [share_encode(s) for s in sh35]}})

# TV-7: Key Card
pk = onion_address_to_pubkey("2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion")
kc = KeyCard(R1, [pk], 1, 24)
vec["vectors"].append({"id": "TV-7", "title": "Key Card TLV and bech32m", "root": R1.hex(), "relay_onion": "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion",
    "relay_pubkey": pk.hex(), "size_class": 1, "ttl_hours": 24, "tlv_hex": kc.to_bytes().hex(), "bech32m": kc.encode()})

# TV-8: header body encoding
vec["vectors"].append({"id": "TV-8", "title": "Header body encoding", "flags": 1, "offset": 1024, "length": 512, "ptype": 1,
    "body_hex": _encode_header_body(1, 1024, 512, 1).hex()})

json.dump(vec, open("test_vectors.json", "w"), indent=1)
print("wrote test_vectors.json", sum(len(v.get("block_hex", "")) // 2 for v in vec["vectors"]), "bytes of blocks")

# Self-check: re-open every block vector
for v in vec["vectors"]:
    if "block_hex" in v:
        b = bytes.fromhex(v["block_hex"]); root = bytes.fromhex(v["root"])
        for s in v["slots"]:
            o = open_block(b, root, s.get("passphrase"))
            assert o and o.index == s["index"], v["id"]
print("self-check OK")
