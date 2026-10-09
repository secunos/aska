#!/usr/bin/env python3
"""Aska paper mode — reference implementation of Design Change DC-04 (release 1.2).

Executable companion to the design document, so that the page format, the checkerboard, the
two one-time tags, the page checksum and the Block-card framing can be checked by an
independent implementation. Like aska_ref.py it is NOT hardened (no locked memory, no wiping,
no constant time) and must not be used as a product. The randomness pipeline (entropy
estimate, Toeplitz extractor, mixing) is implemented in the Rust crate only; a small Toeplitz
test vector is included here so that the matrix convention can be cross-checked.

Run: python3 aska_paper_ref.py  (self-test)      python3 test_paper.py  (tests)
"""
import hashlib, unicodedata, zlib

# --- checkerboard (DC-04 §3.1, Table 1) --------------------------------------------------------
ROW0 = "ETAOINS"        # codes 0..6
ROW7 = "RHLDCUMFPG"     # codes 70..79
ROW8 = "WYBVKXJQZ "     # codes 80..89 (89 = space)
ROW9 = "0123456789"     # codes 90..99
ENC = {}
for i, ch in enumerate(ROW0): ENC[ch] = str(i)
for i, ch in enumerate(ROW7): ENC[ch] = "7" + str(i)
for i, ch in enumerate(ROW8): ENC[ch] = "8" + str(i)
for i, ch in enumerate(ROW9): ENC[ch] = "9" + str(i)
assert len(ENC) == 37
DEC = {v: k for k, v in ENC.items()}

_TRANSLIT = {"Å": "AA", "Ä": "AE", "Æ": "AE", "Ö": "OE", "Ø": "OE", "ß": "SS",
             "À": "A", "Á": "A", "Â": "A", "Ã": "A", "Ç": "C", "È": "E", "É": "E", "Ê": "E", "Ë": "E",
             "Ì": "I", "Í": "I", "Î": "I", "Ï": "I", "Ñ": "N", "Ò": "O", "Ó": "O", "Ô": "O", "Õ": "O",
             "Ù": "U", "Ú": "U", "Û": "U", "Ü": "U", "Ý": "Y", "Ÿ": "Y"}

def normalise(text):
    """NFKC, upper case, transliteration, whitespace collapsed and trimmed; refuses punctuation."""
    out = []
    for c in unicodedata.normalize("NFKC", text):
        if c in "\n\t\r": c = " "
        u = c.upper()
        if u in ENC: out.append(u)
        elif u in _TRANSLIT: out.extend(_TRANSLIT[u])
        elif c == "ÿ": out.append("Y")
        else: raise ValueError(f"not in the paper alphabet: {c!r}")
    s = "".join(out)
    return " ".join(s.split())

def to_digits(symbols):
    return "".join(ENC[ch] for ch in symbols)

def encode(text):
    return to_digits(normalise(text))

def from_digits(d):
    out, i = [], 0
    while i < len(d):
        if d[i] in "0123456":
            out.append(DEC[d[i]]); i += 1
        else:
            if i + 1 >= len(d): raise ValueError("a two-digit code is cut short")
            out.append(DEC[d[i:i+2]]); i += 2
    return "".join(out)

# --- pad arithmetic (§3.2) -----------------------------------------------------------------------
def encipher(m, k):
    if len(m) > len(k): raise ValueError("message longer than the page")
    return "".join(str((int(a) + int(b)) % 10) for a, b in zip(m, k))

def decipher(c, k):
    return "".join(str((int(a) - int(b)) % 10) for a, b in zip(c, k))

def cover_pad(c, innocent_digits):
    if len(c) != len(innocent_digits): raise ValueError("lengths differ")
    return decipher(c, innocent_digits)

# --- hand tag (§3.3) -----------------------------------------------------------------------------
P_HAND = 9973

def groups2(c):
    return [int(c[i:i+2]) for i in range(0, len(c), 2)]   # a lone last digit parses as itself

def hand_tag(c, a, b):
    """a = [a0, a1, ...] (ints < 9973, at least len(groups)+1 of them), b int < 9973."""
    G = groups2(c)
    if len(a) < len(G) + 1: raise ValueError("too few multipliers")
    acc = a[0] * len(c) + sum(a[j] * g for j, g in enumerate(G, start=1)) + b
    return acc % P_HAND

def reduce_by_hand(x):
    steps = []
    while x >= P_HAND:
        q, r = divmod(x, 10000)
        x = x - P_HAND if q == 0 else r + 27 * q
        steps.append(x)
    return steps, x

# --- device tag (§3.4) ---------------------------------------------------------------------------
P_DEV = (1 << 61) - 1
GROUP = 18

def device_tag(c, r, s):
    if not (0 <= r < P_DEV and 0 <= s < P_DEV): raise ValueError("key out of range")
    seq = [len(c)] + [int(c[i:i+GROUP]) for i in range(0, len(c), GROUP)]
    h = 0
    for x in seq:
        h = ((h + x) * r) % P_DEV
    return (h + s) % P_DEV

# --- page (§3.5) ---------------------------------------------------------------------------------
PAD_LENGTHS = (200, 400, 600)
DIR_DIGIT = {"A": "1", "B": "2"}

def canonical(set_code, direction, number, pad, hand_keys=None, r=0, s=0):
    """hand_keys: list of ints [a0 .. a_{N/2}, b] (N/2 + 2 values) or None."""
    N = len(pad)
    if N not in PAD_LENGTHS: raise ValueError("pad length")
    if not (1 <= number <= 50): raise ValueError("page number")
    if hand_keys is not None and len(hand_keys) != N // 2 + 2: raise ValueError("hand keys")
    out = ["1", f"{set_code:04d}", DIR_DIGIT[direction], f"{number:02d}", f"{N:03d}", pad]
    if hand_keys is None:
        out.append("0")
    else:
        out.append("1")
        out.extend(f"{k:04d}" for k in hand_keys)
    out.append(f"{r:019d}"); out.append(f"{s:019d}")
    return "".join(out)

def checksum(canon):
    h = hashlib.sha3_256(canon.encode()).digest()
    return f"{int.from_bytes(h[:8], 'big') % 1_000_000:06d}"

def qr_payload(canon):
    return canon + checksum(canon)

def parse(canon):
    """Return a dict of the page's parts; raises on malformed input."""
    if not canon.isdigit() or canon[0] != "1": raise ValueError("format")
    set_code = int(canon[1:5]); direction = {"1": "A", "2": "B"}[canon[5]]
    number = int(canon[6:8]); N = int(canon[8:11])
    if N not in PAD_LENGTHS: raise ValueError("pad length")
    pad = canon[11:11+N]; flag = canon[11+N]
    pos = 12 + N
    keys = None
    if flag == "1":
        n = N // 2 + 2
        keys = [int(canon[pos + 4*i: pos + 4*i + 4]) for i in range(n)]
        if any(k >= P_HAND for k in keys): raise ValueError("hand key out of range")
        pos += 4 * n
    elif flag != "0":
        raise ValueError("hand-tag flag")
    r = int(canon[pos:pos+19]); s = int(canon[pos+19:pos+38])
    if pos + 38 != len(canon): raise ValueError("length")
    if r >= P_DEV or s >= P_DEV: raise ValueError("device key out of range")
    return dict(set_code=set_code, direction=direction, number=number, pad=pad, hand_keys=keys, r=r, s=s)

def parse_with_checksum(payload):
    canon, sum6 = payload[:-6], payload[-6:]
    if checksum(canon) != sum6: raise ValueError("checksum")
    return parse(canon)

def row_check(digits):
    return sum(int(d) for d in digits) % 10

# --- Block cards (§7) ----------------------------------------------------------------------------
CHUNK_DATA = 1024
CLASS_LEN = {1: 4096, 2: 16384}

def split_block(block, set_id):
    n = len(block)
    cls = {v: k for k, v in CLASS_LEN.items()}.get(n)
    if cls is None: raise ValueError("not a class-1 or class-2 Block")
    count = n // CHUNK_DATA
    cards = []
    for i in range(count):
        body = set_id + bytes([i, count, cls]) + block[i*CHUNK_DATA:(i+1)*CHUNK_DATA]
        cards.append(body + zlib.crc32(body).to_bytes(4, "big"))
    return cards

def join_cards(cards):
    parts = {}
    sid = None
    for c in cards:
        body, crc = c[:-4], int.from_bytes(c[-4:], "big")
        if zlib.crc32(body) != crc: raise ValueError("crc")
        this_id, idx, count, cls = body[:4], body[4], body[5], body[6]
        if sid is None: sid = (this_id, count, cls)
        elif sid != (this_id, count, cls): raise ValueError("foreign card")
        if CLASS_LEN.get(cls, -1) != count * CHUNK_DATA or idx >= count: raise ValueError("header")
        parts[idx] = body[7:]
    if len(parts) != sid[1]: raise ValueError("incomplete")
    return b"".join(parts[i] for i in range(sid[1]))

# --- Toeplitz extractor convention (§4.3) --------------------------------------------------------
def toeplitz(seed, inp, m):
    """out_i = XOR_j T[i][j] x_j with T[i][j] = seed_bit[i - j + n - 1]; bits MSB-first."""
    n = len(inp) * 8
    bit = lambda bs, p: (bs[p // 8] >> (7 - p % 8)) & 1
    out = bytearray((m + 7) // 8)
    for i in range(m):
        acc = 0
        for j in range(n):
            acc ^= bit(seed, i + n - 1 - j) & bit(inp, j)
        out[i // 8] |= acc << (7 - i % 8)
    return bytes(out)

# --- deterministic material for vectors (NOT for real pads) -------------------------------------
def shake_digits(label, n):
    out, ctr = [], 0
    while len(out) < n:
        for byte in hashlib.shake_256(f"{label}/{ctr}".encode()).digest(64):
            if byte < 250: out.append(str(byte % 10))
        ctr += 1
    return "".join(out[:n])

def shake_ints(label, n, bound, nbytes, mask):
    out, ctr = [], 0
    while len(out) < n:
        blk = hashlib.shake_256(f"{label}/{ctr}".encode()).digest(64 * nbytes)
        for i in range(0, len(blk) - nbytes + 1, nbytes):
            v = int.from_bytes(blk[i:i+nbytes], "big") & mask
            if v < bound: out.append(v)
        ctr += 1
    return out[:n]

if __name__ == "__main__":
    # Smoke test on the DC-04 worked example.
    m = encode("MEET 14 NOV NORTH GATE")
    assert m == "760018991948953838953701718979210"
    pad = "279749132099457148372454626642375951480946439196613631751385"
    c = encipher(m, pad)
    assert c == "939757023937300976225155334511585"
    a = [5849, 1573, 2769, 6170, 2106, 5152, 6831, 4251, 1107, 6609, 5096, 2484, 272, 5425, 7676, 2832,
         7115, 6601, 5314, 5029, 8369, 9720, 9153, 768, 658, 7564, 9899, 7707, 5061, 499, 4489]
    assert hand_tag(c, a, 2691) == 3936
    assert device_tag(c, 1231961752939033616, 1450779715753509526) == 876449745860556196
    assert from_digits(decipher(c, pad)) == "MEET 14 NOV NORTH GATE"
    print("aska_paper_ref: ok")
