#!/usr/bin/env python3
"""
aska_ref.py — Reference implementation of the Aska Block Format v1 (draft 0.1).

This is a *reference*, not a product: it favours readability and exact
correspondence with the specification over performance or hardening
(no memory locking, no zeroisation). It exists so that the specification
is executable and so that independent implementations can be checked
against the test vectors it generates.

Dependencies: pynacl (XChaCha20-Poly1305), argon2-cffi (Argon2id),
mnemonic (BIP-39 English word list). HKDF-SHA-512, Shamir over GF(2^8)
and bech32m are implemented here to keep the format self-contained.

Spec cross-references are given as [§n.n] and requirement IDs as BLK-nn / KEY-nn.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import struct
import unicodedata
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence

import nacl.bindings as sodium
from argon2.low_level import Type as Argon2Type, hash_secret_raw
from mnemonic import Mnemonic

# ---------------------------------------------------------------------------
# §3  Constants
# ---------------------------------------------------------------------------
FORMAT_VERSION = 0x01

SIZE_CLASSES = {1: 4096, 2: 16384, 3: 65536}           # BLK-02

SALT_OFF, SALT_LEN = 0, 32                              # §4.1
KEM_OFF, KEM_LEN = 32, 1120                             # §4.2  X-Wing ciphertext (1088 + 32)
N_SLOTS = 4                                             # §4.3
HDR_NONCE_LEN, HDR_P_LEN, HDR_BODY_LEN, TAG_LEN = 24, 32, 16, 16
HDR_LEN = HDR_NONCE_LEN + HDR_P_LEN + HDR_BODY_LEN + TAG_LEN   # 88
HDR_OFF = KEM_OFF + KEM_LEN                             # 1152
RSV_OFF = HDR_OFF + N_SLOTS * HDR_LEN                   # 1504  §4.4 reserved (random in v1)
RSV_LEN = 32
PAYLOAD_OFF = RSV_OFF + RSV_LEN                         # 1536 = 6 * 256 (granule-aligned)
PAYLOAD_GRANULE = 256                                   # §4.4  slot regions are multiples of this
INNER_HDR_LEN = 1 + 1 + 4                               # §4.5  version | ptype | datalen

FLAG_DISTRESS = 0x01                                    # §4.3 header flags
PTYPE_TEXT, PTYPE_BINARY = 0x01, 0x02

# §5.3  KDF profiles (draft 0.2 decision): the profile number is mixed into the slot-key info string,
# so receivers try each profile they support and no format version bump is needed for new parameters.
KDF_PROFILES = {
    1: dict(t=3, m_kib=256 * 1024, p=1),   # desktop (v1 default)
    2: dict(t=3, m_kib=64 * 1024, p=1),    # reserved for mobile (RM-02); not used by v1 clients
}
DEFAULT_PROFILE = 1
ARGON2_LEN = 32

INFO_LABEL = b"aska/v1/label"
INFO_SLOT_PREFIX = b"aska/v1/slot/p"      # + profile byte
INFO_UTC_HDR = b"aska/v1/utc/header"
INFO_UTC_PAY = b"aska/v1/utc/payload"
INFO_PAY_NONCE = b"aska/v1/payload-nonce"
INFO_SHARE_VERIFY = b"aska/v1/share-verify"
INFO_ROOT_FROM_KEM = b"aska/v1/root-from-kem"
AD_HEADER = b"aska/v1/header"
AD_PAYLOAD = b"aska/v1/payload"

HRP_KEYCARD, HRP_SHARE, HRP_RXKEY = "aska", "askas", "askar"   # §7 encodings

# ---------------------------------------------------------------------------
# §5.1  HKDF-SHA-512 (RFC 5869)
# ---------------------------------------------------------------------------
def hkdf_sha512(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    if not salt:
        salt = b"\x00" * 64
    prk = hmac.new(salt, ikm, hashlib.sha512).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha512).digest()
        out += t
        i += 1
    return out[:length]


def ct_eq(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


# ---------------------------------------------------------------------------
# §5.2  Key hierarchy
# ---------------------------------------------------------------------------
def derive_label(root: bytes) -> bytes:
    """L = HKDF(salt="", ikm=R, info="aska/v1/label")  — the relay storage key. BLK-09."""
    assert len(root) == 32
    return hkdf_sha512(b"", root, INFO_LABEL, 32)


def argon2id_passphrase(passphrase: str, block_salt: bytes, profile: int = DEFAULT_PROFILE) -> bytes:
    """A_p = Argon2id(NFKC(passphrase), salt=block_salt, params of `profile`, 32 bytes). §5.3"""
    pr = KDF_PROFILES[profile]
    pw = unicodedata.normalize("NFKC", passphrase).encode("utf-8")
    return hash_secret_raw(pw, block_salt, time_cost=pr["t"], memory_cost=pr["m_kib"],
                           parallelism=pr["p"], hash_len=ARGON2_LEN, type=Argon2Type.ID)


def derive_slot_key(root: bytes, block_salt: bytes, passphrase: Optional[str], profile: int = DEFAULT_PROFILE) -> bytes:
    """K_slot = HKDF(salt=block_salt, ikm = R || A_p, info = "aska/v1/slot/p" || profile).
    A_p is 32 zero bytes for an open (passphrase-less) slot; open slots always use profile 1. §5.2"""
    if passphrase is None:
        profile = DEFAULT_PROFILE
        a_p = b"\x00" * 32
    else:
        a_p = argon2id_passphrase(passphrase, block_salt, profile)
    return hkdf_sha512(block_salt, root + a_p, INFO_SLOT_PREFIX + bytes([profile]), 32)


# ---------------------------------------------------------------------------
# §5.4  Key-committing AEAD: UtC transform over XChaCha20-Poly1305
#        (L, P) = HKDF(salt=nonce, ikm=K, info); ciphertext = P || AEAD_L(nonce, ad, m)
# ---------------------------------------------------------------------------
def utc_derive(key: bytes, nonce: bytes, info: bytes) -> tuple[bytes, bytes]:
    okm = hkdf_sha512(nonce, key, info, 64)
    return okm[:32], okm[32:]


def utc_seal(key: bytes, nonce: bytes, ad: bytes, msg: bytes, info: bytes) -> bytes:
    enc_key, commit = utc_derive(key, nonce, info)
    ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(msg, ad, nonce, enc_key)
    return commit + ct


def utc_open(key: bytes, nonce: bytes, ad: bytes, blob: bytes, info: bytes) -> Optional[bytes]:
    if len(blob) < HDR_P_LEN + TAG_LEN:
        return None
    enc_key, commit = utc_derive(key, nonce, info)
    if not ct_eq(commit, blob[:HDR_P_LEN]):
        return None
    try:
        return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(blob[HDR_P_LEN:], ad, nonce, enc_key)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# §4  Block structure
# ---------------------------------------------------------------------------
@dataclass
class Slot:
    data: bytes
    ptype: int = PTYPE_TEXT
    passphrase: Optional[str] = None     # None => open slot (opens with R alone)
    distress: bool = False
    profile: int = DEFAULT_PROFILE       # KDF profile for the passphrase (ignored for open slots)


@dataclass
class OpenedSlot:
    index: int
    data: bytes
    ptype: int
    distress: bool


class Rng:
    """Randomness source. Production: os.urandom. Test vectors: SHAKE256 stream (§9)."""
    def __init__(self, seed: Optional[bytes] = None):
        self._xof = hashlib.shake_256(b"aska-test-vectors" + seed) if seed is not None else None
        self._pos = 0

    def bytes(self, n: int) -> bytes:
        if self._xof is None:
            return os.urandom(n)
        out = self._xof.copy().digest(self._pos + n)[self._pos:]
        self._pos += n
        return out


def region_size_for(data_len: int) -> int:
    """Slot region = P(32) + inner(6 + data + pad) + tag(16), rounded up to a 256-byte granule. §4.4"""
    raw = HDR_P_LEN + INNER_HDR_LEN + data_len + TAG_LEN
    return -(-raw // PAYLOAD_GRANULE) * PAYLOAD_GRANULE


def _encode_header_body(flags: int, offset: int, length: int, ptype: int) -> bytes:
    assert offset < 2**24 and length < 2**24
    return bytes([flags]) + offset.to_bytes(3, "big") + length.to_bytes(3, "big") + bytes([ptype]) + b"\x00" * 8


def _decode_header_body(b: bytes):
    flags = b[0]
    offset = int.from_bytes(b[1:4], "big")
    length = int.from_bytes(b[4:7], "big")
    ptype = b[7]
    if b[8:16] != b"\x00" * 8:
        return None
    return flags, offset, length, ptype


def seal(root: bytes, size_class: int, slots: Sequence[Slot], rng: Optional[Rng] = None,
         offsets: Optional[Sequence[int]] = None, kem_region: Optional[bytes] = None) -> bytes:
    """Produce a Block. §6.1
    Randomness draw order (normative for test vectors, §9):
      salt(32) → kem_region(1120, if not supplied) → reserved(32) → header nonce per header 0..3 (24 each)
      → header permutation: three 4-byte draws (Fisher–Yates over the 4 header indices, j = u32 % (i+1)
        for i = 3, 2, 1) → placement start (4 bytes, default placement only)
      → for each occupied slot in order: inner padding → filler for the whole payload region
      → random header bytes (88) for each unoccupied header index, ascending.
    Slot s is written under header index perm[s]; with default placement the regions are laid out
    sequentially in order of increasing header index, so neither the header index nor the region
    order of an opened slot says which slot the sender wrote first (§10.3).
    """
    rng = rng or Rng()
    assert len(root) == 32
    assert 1 <= len(slots) <= N_SLOTS
    size = SIZE_CLASSES[size_class]
    payload_len = size - PAYLOAD_OFF
    # §6.1 step 1: slot keys within one Block MUST be distinct — two slots with the same
    # (passphrase, profile) would share K_slot and the opener could only ever reach one of them.
    ids = [(None if sl.passphrase is None else (unicodedata.normalize("NFKC", sl.passphrase), sl.profile)) for sl in slots]
    if len(set(ids)) != len(ids):
        raise ValueError("two slots share the same passphrase/profile (or two open slots)")
    if sum(1 for sl in slots if sl.distress) > 1:
        raise ValueError("at most one distress slot")

    salt = rng.bytes(SALT_LEN)
    kem = kem_region if kem_region is not None else rng.bytes(KEM_LEN)
    assert len(kem) == KEM_LEN
    reserved = rng.bytes(RSV_LEN)
    nonces = [rng.bytes(HDR_NONCE_LEN) for _ in range(N_SLOTS)]
    # Header permutation (§6.1, §10.3): slot s gets header index perm[s].
    perm = list(range(N_SLOTS))
    for i in range(N_SLOTS - 1, 0, -1):
        j = int.from_bytes(rng.bytes(4), "big") % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    idx_of = perm[:len(slots)]

    # Allocate regions in the payload area.
    sizes = [region_size_for(len(s.data)) for s in slots]
    if sum(sizes) > payload_len:
        raise ValueError("slots do not fit in size class")
    if offsets is None:
        # Default placement: sequential from a random granule-aligned start, in order of
        # increasing header index, wrapping not allowed.
        free = payload_len - sum(sizes)
        start = (int.from_bytes(rng.bytes(4), "big") % (free // PAYLOAD_GRANULE + 1)) * PAYLOAD_GRANULE
        offsets, cur = [None] * len(slots), start
        for s_i in sorted(range(len(slots)), key=lambda k: idx_of[k]):
            offsets[s_i] = cur
            cur += sizes[s_i]
    offsets = list(offsets)
    for o, sz in zip(offsets, sizes):
        assert o % PAYLOAD_GRANULE == 0 and o + sz <= payload_len

    payload = bytearray(payload_len)
    occupied = [False] * payload_len

    headers = [None] * N_SLOTS
    for s_i, (slot, off, sz) in enumerate(zip(slots, offsets, sizes)):
        i = idx_of[s_i]
        k_slot = derive_slot_key(root, salt, slot.passphrase, slot.profile)
        inner_len = sz - HDR_P_LEN - TAG_LEN
        pad_len = inner_len - INNER_HDR_LEN - len(slot.data)
        inner = bytes([FORMAT_VERSION, slot.ptype]) + len(slot.data).to_bytes(4, "big") + slot.data + rng.bytes(pad_len)
        pay_nonce = hkdf_sha512(nonces[i], k_slot, INFO_PAY_NONCE, 24)
        blob = utc_seal(k_slot, pay_nonce, AD_PAYLOAD + bytes([i]) + nonces[i], inner, INFO_UTC_PAY)
        assert len(blob) == sz
        payload[off:off + sz] = blob
        for j in range(off, off + sz):
            occupied[j] = True
        flags = FLAG_DISTRESS if slot.distress else 0
        body = _encode_header_body(flags, off, sz, slot.ptype)
        headers[i] = nonces[i] + utc_seal(k_slot, nonces[i], AD_HEADER + bytes([i]), body, INFO_UTC_HDR)

    filler = rng.bytes(payload_len)
    for j in range(payload_len):
        if not occupied[j]:
            payload[j] = filler[j]

    for i in range(N_SLOTS):
        if headers[i] is None:
            headers[i] = rng.bytes(HDR_LEN)

    block = salt + kem + b"".join(headers) + reserved + bytes(payload)
    assert len(block) == size
    return block


def open_block(block: bytes, root: bytes, passphrase: Optional[str] = None,
               profiles: Sequence[int] = (DEFAULT_PROFILE,)) -> Optional[OpenedSlot]:
    """Try to open a Block with R (and an optional passphrase). §6.2
    For each supported KDF profile, derives K_slot and trial-decrypts the 4 headers;
    returns the first slot that opens, or None. Open slots need only profile 1."""
    if len(block) not in SIZE_CLASSES.values():
        return None
    salt = block[SALT_OFF:SALT_OFF + SALT_LEN]
    for profile in (profiles if passphrase is not None else (DEFAULT_PROFILE,)):
        r = _open_with_key(block, derive_slot_key(root, salt, passphrase, profile))
        if r is not None:
            return r
    return None


def _open_with_key(block: bytes, k_slot: bytes) -> Optional[OpenedSlot]:
    payload = block[PAYLOAD_OFF:]
    for i in range(N_SLOTS):
        h = block[HDR_OFF + i * HDR_LEN: HDR_OFF + (i + 1) * HDR_LEN]
        nonce, blob = h[:HDR_NONCE_LEN], h[HDR_NONCE_LEN:]
        body = utc_open(k_slot, nonce, AD_HEADER + bytes([i]), blob, INFO_UTC_HDR)
        if body is None:
            continue
        dec = _decode_header_body(body)
        if dec is None:
            return None
        flags, off, length, ptype = dec
        if off + length > len(payload):
            return None
        pay_nonce = hkdf_sha512(nonce, k_slot, INFO_PAY_NONCE, 24)
        inner = utc_open(k_slot, pay_nonce, AD_PAYLOAD + bytes([i]) + nonce, payload[off:off + length], INFO_UTC_PAY)
        if inner is None or inner[0] != FORMAT_VERSION or inner[1] != ptype:
            return None
        dlen = int.from_bytes(inner[2:6], "big")
        if INNER_HDR_LEN + dlen > len(inner):
            return None
        return OpenedSlot(i, inner[INNER_HDR_LEN:INNER_HDR_LEN + dlen], ptype, bool(flags & FLAG_DISTRESS))
    return None


# ---------------------------------------------------------------------------
# §8  Shamir secret sharing over GF(2^8), polynomial 0x11b, byte-wise
# ---------------------------------------------------------------------------
def _gf_mul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return r


def _gf_inv(a: int) -> int:
    # a^(254) in GF(2^8)
    r, base, e = 1, a, 254
    while e:
        if e & 1:
            r = _gf_mul(r, base)
        base = _gf_mul(base, base)
        e >>= 1
    return r


@dataclass
class Share:
    set_id: bytes          # 2 bytes, random per split
    k: int
    x: int                 # 1..255, never 0
    y: bytes               # 32 bytes
    verify: bytes          # 4 bytes = HKDF(R, "aska/v1/share-verify")[:4]

    def to_bytes(self) -> bytes:
        return bytes([FORMAT_VERSION]) + self.set_id + bytes([self.k, self.x]) + self.y + self.verify

    @classmethod
    def from_bytes(cls, b: bytes) -> "Share":
        if len(b) != 41 or b[0] != FORMAT_VERSION:
            raise ValueError("bad share")
        return cls(b[1:3], b[3], b[4], b[5:37], b[37:41])


def share_verify_tag(root: bytes) -> bytes:
    return hkdf_sha512(b"", root, INFO_SHARE_VERIFY, 4)


def split_root(root: bytes, k: int, n: int, rng: Optional[Rng] = None) -> List[Share]:
    """Split R into n Shares, any k of which reconstruct it. KEY-02/03.
    Randomness draw order: set_id(2) then, for each byte position 0..31, (k-1) coefficient bytes."""
    rng = rng or Rng()
    assert 2 <= k <= n <= 255 and len(root) == 32
    set_id = rng.bytes(2)
    coeffs = [[root[j]] + list(rng.bytes(k - 1)) for j in range(32)]   # a0 = secret byte
    tag = share_verify_tag(root)
    shares = []
    for x in range(1, n + 1):
        y = bytearray(32)
        for j in range(32):
            acc, xp = 0, 1
            for c in coeffs[j]:
                acc ^= _gf_mul(c, xp)
                xp = _gf_mul(xp, x)
            y[j] = acc
        shares.append(Share(set_id, k, x, bytes(y), tag))
    return shares


def combine_shares(shares: Sequence[Share]) -> bytes:
    """Reconstruct R from >= k Shares; raises if inconsistent or verification fails. KEY-02."""
    if not shares:
        raise ValueError("no shares")
    k, set_id, tag = shares[0].k, shares[0].set_id, shares[0].verify
    if any(s.k != k or s.set_id != set_id or s.verify != tag for s in shares):
        raise ValueError("shares from different sets")
    xs = [s.x for s in shares[:k]]
    if len(set(xs)) < k or 0 in xs:
        raise ValueError("not enough distinct shares")
    root = bytearray(32)
    for j in range(32):
        acc = 0
        for a, s in enumerate(shares[:k]):
            num, den = 1, 1
            for b, t in enumerate(shares[:k]):
                if a != b:
                    num = _gf_mul(num, t.x)
                    den = _gf_mul(den, s.x ^ t.x)
            acc ^= _gf_mul(s.y[j], _gf_mul(num, _gf_inv(den)))
        root[j] = acc
    root = bytes(root)
    if not ct_eq(share_verify_tag(root), tag):
        raise ValueError("share verification failed (corrupt or forged share)")
    return root


# ---------------------------------------------------------------------------
# §7  Encodings: BIP-39 words, bech32m, Key Card TLV
# ---------------------------------------------------------------------------
_MN = Mnemonic("english")


def root_to_words(root: bytes) -> str:
    """24 English BIP-39 words: 256 bits of R + 8-bit SHA-256 checksum. KEY-01."""
    return _MN.to_mnemonic(root)


def words_to_root(words: str) -> bytes:
    if not _MN.check(words):
        raise ValueError("word checksum failed")
    return bytes(_MN.to_entropy(words))


# bech32m (BIP-350) — reference code, generalised length
_B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M_CONST = 0x2BC830A3


def _polymod(values: Iterable[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> List[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data: bytes, frombits: int, tobits: int, pad: bool) -> List[int]:
    acc, bits, ret, maxv = 0, 0, [], (1 << tobits) - 1
    for v in data:
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif not pad and (bits >= frombits or ((acc << (tobits - bits)) & maxv)):
        raise ValueError("bad padding")
    return ret


def bech32m_encode(hrp: str, data: bytes) -> str:
    d = _convertbits(data, 8, 5, True)
    chk = _polymod(_hrp_expand(hrp) + d + [0] * 6) ^ _BECH32M_CONST
    return hrp + "1" + "".join(_B32[x] for x in d) + "".join(_B32[(chk >> (5 * (5 - i))) & 31] for i in range(6))


def bech32m_decode(s: str) -> tuple[str, bytes]:
    if s != s.lower() and s != s.upper():
        raise ValueError("mixed case")
    s = s.lower()
    pos = s.rfind("1")
    hrp, data = s[:pos], s[pos + 1:]
    vals = [_B32.index(c) for c in data]
    if _polymod(_hrp_expand(hrp) + vals) != _BECH32M_CONST:
        raise ValueError("checksum failed")
    return hrp, bytes(_convertbits(vals[:-6], 5, 8, False))


# Key Card TLV (§7.3): 0x01 version | 0x02 root | 0x03 relay onion pubkey (repeatable) | 0x04 size class | 0x05 ttl hours
#                      | 0x06 shared circle Tor client-auth private key (x25519, 32 bytes; ADP/1 P-02)
TLV_VERSION, TLV_ROOT, TLV_RELAY, TLV_CLASS, TLV_TTL, TLV_AUTH = 0x01, 0x02, 0x03, 0x04, 0x05, 0x06


@dataclass
class KeyCard:
    root: bytes
    relays: List[bytes] = field(default_factory=list)   # 32-byte ed25519 onion pubkeys
    size_class: Optional[int] = None
    ttl_hours: Optional[int] = None
    auth_key: Optional[bytes] = None                     # 32-byte x25519 private key shared by the circle (optional)

    def to_bytes(self) -> bytes:
        out = bytes([TLV_VERSION, 1, FORMAT_VERSION, TLV_ROOT, 32]) + self.root
        for r in self.relays:
            out += bytes([TLV_RELAY, 32]) + r
        if self.size_class is not None:
            out += bytes([TLV_CLASS, 1, self.size_class])
        if self.ttl_hours is not None:
            out += bytes([TLV_TTL, 2]) + self.ttl_hours.to_bytes(2, "big")
        if self.auth_key is not None:
            out += bytes([TLV_AUTH, 32]) + self.auth_key
        return out

    @classmethod
    def from_bytes(cls, b: bytes) -> "KeyCard":
        """Strict decoder (Block Format §7.3 Table 5; B-7): version first and exactly
        FORMAT_VERSION; root/class/TTL/auth at most once with their exact lengths; relays
        repeatable; unknown types skipped; declared lengths must fit."""
        i, root, relays, sc, ttl, auth = 0, None, [], None, None, None
        first = True
        while i < len(b):
            if i + 2 > len(b):
                raise ValueError("truncated")
            t, l = b[i], b[i + 1]
            v = b[i + 2:i + 2 + l]
            if len(v) != l:
                raise ValueError("truncated")
            i += 2 + l
            if first:
                if t != TLV_VERSION:
                    raise ValueError("version element must be first")
                if v != bytes([FORMAT_VERSION]):
                    raise ValueError("unsupported version")
                first = False
                continue
            if t == TLV_VERSION:
                raise ValueError("duplicate version")
            elif t == TLV_ROOT:
                if root is not None or len(v) != 32:
                    raise ValueError("bad root")
                root = v
            elif t == TLV_RELAY:
                if len(v) != 32:
                    raise ValueError("bad relay")
                relays.append(v)
            elif t == TLV_CLASS:
                if sc is not None or len(v) != 1 or v[0] not in (1, 2, 3):
                    raise ValueError("bad class")
                sc = v[0]
            elif t == TLV_TTL:
                if ttl is not None or len(v) != 2:
                    raise ValueError("bad ttl")
                ttl = int.from_bytes(v, "big")
            elif t == TLV_AUTH:
                if auth is not None or len(v) != 32:
                    raise ValueError("bad auth")
                auth = v
        if root is None:
            raise ValueError("no root")
        return cls(root, relays, sc, ttl, auth)

    def encode(self) -> str:
        return bech32m_encode(HRP_KEYCARD, self.to_bytes())

    @classmethod
    def decode(cls, s: str) -> "KeyCard":
        hrp, data = bech32m_decode(s)
        if hrp != HRP_KEYCARD:
            raise ValueError("wrong HRP")
        return cls.from_bytes(data)


def onion_pubkey_to_address(pk: bytes) -> str:
    """Tor v3 onion address from its 32-byte ed25519 public key (rend-spec-v3)."""
    import base64
    chk = hashlib.sha3_256(b".onion checksum" + pk + b"\x03").digest()[:2]
    return base64.b32encode(pk + chk + b"\x03").decode().lower() + ".onion"


def onion_address_to_pubkey(addr: str) -> bytes:
    import base64
    raw = base64.b32decode(addr.removesuffix(".onion").upper())
    pk, chk, ver = raw[:32], raw[32:34], raw[34]
    if ver != 3 or hashlib.sha3_256(b".onion checksum" + pk + b"\x03").digest()[:2] != chk:
        raise ValueError("bad onion address")
    return pk


def share_encode(s: Share) -> str:
    return bech32m_encode(HRP_SHARE, s.to_bytes())


def share_decode(t: str) -> Share:
    hrp, data = bech32m_decode(t)
    if hrp != HRP_SHARE:
        raise ValueError("wrong HRP")
    return Share.from_bytes(data)


def new_root() -> bytes:
    return secrets.token_bytes(32)


if __name__ == "__main__":
    # Smoke test
    R = new_root()
    blk = seal(R, 1, [Slot(b"meet 14 nov, north gate", passphrase="real"),
                      Slot(b"buy milk", passphrase="decoy"),
                      Slot(b"buy milk", passphrase="help", distress=True)])
    assert len(blk) == 4096
    assert open_block(blk, R, "real").data == b"meet 14 nov, north gate"
    assert open_block(blk, R, "decoy").data == b"buy milk"
    d = open_block(blk, R, "help"); assert d.distress and d.data == b"buy milk"
    assert open_block(blk, R, "wrong") is None and open_block(blk, R, None) is None
    sh = split_root(R, 2, 3)
    assert combine_shares([sh[0], sh[2]]) == R
    assert words_to_root(root_to_words(R)) == R
    kc = KeyCard(R, [b"\x11" * 32], 1, 24)
    assert KeyCard.decode(kc.encode()).root == R
    print("label", derive_label(R).hex()[:16], "... smoke test OK")
