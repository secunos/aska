# Aska — Design Change DC-02: The receiving-key path (X-Wing), pulled forward

## Version 0.1 — 30 September 2026

- **Status:** Decided by the project owner on 30 September 2026 (decision **D-17**: "pull the receiving-key path forward and build it right after M5b"). This note settles the six design points that D-17 left open and is the specification for milestone **M5c**.
- **Amends:** *Block Format Specification v1 draft 0.3* (§6.5 promoted from "design level, deferred to v1.1" to normative; §7.5 Receiving Key defined; spec decision S-04 revised); *Decision Record and Threat Model v0.2* (D-17, threats T-27/T-28, requirements KEY-09…KEY-11); *Client Design v0.4* (Send, Receive, a new Receiving-key screen, CLI commands); *Prototype Plan v0.1* (M5c inserted between M5 and M6). These deltas are to be folded into Block Format draft 0.4, Decision Record v0.3 and Client Design v0.5; until then this note is authoritative.
- **Trigger:** owner question, 30 September 2026: "if I want to send a note to someone across the world they cannot be there in person, what do you suggest?" — the symmetric path needs the key to travel by a second channel; the receiving-key path needs nothing secret to travel at all.

---

# 1. What changes for the user

**Today (symmetric path, unchanged):** the sender seals a note under a random key, posts the Block, and hands the key to the receiver as a QR or 24 words through a channel different from the one that announced the note.

**New (receiving-key path):** the *receiver* acts first. Once, they create a **receiving key**: the client shows a **receiving seed** — 24 words to keep (memorised, on paper, or in the encrypted profile) — and a public **Receiving Key**, an `askar1…` string of about 1 950 characters (also as a QR code) that they give to whoever may want to write to them, by any channel: e-mail, a website, a messenger. It is not secret; it only needs to be *authentic*, which the two parties confirm by reading the last eight characters to each other (the **check**), exactly as one confirms a phone number. The sender pastes the Receiving Key into the *To* field of Send, writes, and posts. There is no Hand-over: nothing exists that could be handed over. The receiver enters their 24 seed words on Receive, presses *Check the drop*, and reads the note.

A receiving key is meant for **one note**. The private half is the seed the receiver keeps; anyone who later learns it can read every Block that was ever encapsulated to it and is still within its time-to-live (at most seven days). After a note has opened, the client says so and suggests creating a new key for the next one (KEY-07 applied to receiving keys). The receiver may keep using a key — the client cannot prevent it — but is told the cost.

Everything else is unchanged: decoy and distress slots, passphrases, size classes, TTL, relays, cover traffic. A Block sealed for a receiving key looks, to the relay and to anyone who copies it, exactly like any other Block (§4).

# 2. Cryptography (normative; Block Format §6.5 and §7.5)

## 2.1 The KEM

X-Wing as specified in *draft-connolly-cfrg-xwing-kem-11* (23 September 2026): ML-KEM-768 (FIPS 203) combined with X25519 through SHA3-256.

- **Decapsulation key** `sk`: 32 uniformly random bytes — the **receiving seed**. `expandDecapsulationKey(sk)`: `expanded = SHAKE256(sk, 96 bytes)`; `(pk_M, sk_M) = ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])`; `sk_X = expanded[64:96]`; `pk_X = X25519(sk_X, BASE)`.
- **Encapsulation key** `pk = pk_M ‖ pk_X` (1 184 + 32 = 1 216 bytes).
- **Encapsulate**: `(ss_M, ct_M) = ML-KEM-768.Encaps(pk_M)` (1 088-byte ciphertext); an X25519 ephemeral `ek_X` giving `ct_X` (see 2.2) and `ss_X = X25519(ek_X, pk_X)`; `ss = SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)` with `XWingLabel = 5c 2e 2f 2f 5e 5c` (`\.//^\`).
- **Decapsulate**: `ss_M = ML-KEM-768.Decaps(ct_M, sk_M)`; `ss_X = X25519(sk_X, ct_X)`; same combiner.

The implementation is Aska's own composition of the RustCrypto `ml-kem` crate (FIPS 203), `x25519-dalek` and `sha3`, so that the X25519 ephemeral is under Aska's control (2.2). It reproduces test vector 1 of draft-11 exactly (`sk = 7f9c2ba4…ef26`, `eseed = 3cb1eea9…85b2` → `ss = d2df0522…e384`, with the published `pk` and `ct` prefixes); this vector is a unit test.

## 2.2 Uniform encoding of the X25519 half (Elligator2, torsion-dirty)

An X25519 public key is not a random string: its u-coordinate satisfies a quadratic-residuosity test that a random 32-byte string fails half the time. The KEM region of a symmetric-path Block is random, so a raw `ct_X` at a fixed offset would mark KEM-path Blocks. Therefore:

1. The sender generates the ephemeral as a **torsion-dirty, Elligator2-representable** point: `ek_X` random; the published point is `E = clamp(ek_X)·B + T` with `T` a uniformly chosen point of order dividing 8; the pair is re-drawn until `E` has an Elligator2 preimage (about half of all points do; the retry count depends only on discarded candidates). `ct_X` **is the u-coordinate of the dirty point `E`**, and it is `ct_X` — not the clean point — that enters the combiner and the X25519 computation on both sides. Because every clamped X25519 scalar is a multiple of 8 and `8·T = O`, `X25519(sk_X, E) = X25519(sk_X, clamp(ek_X)·B)`: the shared secret is unaffected; only the encoding is.
2. The KEM region of the Block carries `ct_M ‖ rep_X` where `rep_X` is the Elligator2 representative of `E` with its two unused high bits filled from the sender's CSPRNG (1 088 + 32 = 1 120 bytes, the reserved size).
3. The receiver decodes `rep_X` → `ct_X` (the map is total: every 32-byte string decodes to some point, so a random-fill KEM region decodes to *something* and is simply not a match), reassembles `ct = ct_M ‖ ct_X`, and decapsulates.

This is X-Wing with a different way of choosing `ek_X` and of writing `ct_X` on the wire; the ML-KEM half, the combiner and the shared secret are standard. Interoperability with other X-Wing implementations is not a goal (Aska only talks to Aska).

## 2.3 From shared secret to Block

`R = HKDF-SHA-512(salt = "", IKM = ss, info = "aska/v1/root-from-kem", L = 32)` (Block Format §6.5, unchanged). From `R` on, the Block is sealed exactly as on the symmetric path (§6.1): label `L`, slot keys, decoy and distress slots, passphrases, padding. The only difference in the finished Block is the content of the KEM region.

## 2.4 Receiving-side matching (Block Format §6.4, KEM case)

A receiver holding a seed fetches whole buckets of every size class from every relay (as today), then for **every** Block: decode `rep_X`, decapsulate, derive `R` and `L`, and compare `L` with the Block's label in constant time. The work per Block is the same whether or not it matches (one ML-KEM decapsulation, one X25519, one SHA3, one HKDF — well under a millisecond), and all Blocks are processed even after a match, so neither the relay nor a local observer learns which Block, if any, was the receiver's. A match continues with §6.2 exactly as on the symmetric path (passphrase, KDF profiles, decoy/distress). The receiver's configured relays (`--relay`, the profile, or the Receiving Key's own relay hints) are the ones polled; there is no Key Card to name them.

## 2.5 The Receiving Key encoding (Block Format §7.5)

bech32m (§7.2) with HRP `askar`. Payload: `version(1) = 0x01 ‖ pk_M(1 184) ‖ pk_X(32) ‖ TLVs`, where the TLVs use the Key Card's types: `0x03` relay onion public key (repeatable), `0x04` size class hint, `0x05` TTL hint. The fixed-size public key comes first because the TLV length byte cannot hold 1 216. Typical length with one relay: 1 217 + 34 = 1 251 bytes → about 2 010 characters; the QR (alphanumeric, upper-cased, EC-M) is version 37 or smaller. The bech32m *checksum* is computed exactly as in BIP-350, but the 1 023-character code-length limit of bech32m is not applied (the `bech32` crate's `Bech32m` type enforces it; Aska uses an identical checksum type without the limit): beyond 1 023 characters the checksum is a 30-bit integrity check rather than a guaranteed 3-error detector, which is what a pasted or scanned key needs. The **check** shown to the user is the last eight characters of the string: they cover the checksum, so they change with every bit of the key.

The **receiving seed** is shown as 24 BIP-39 words with the same encoder as a root (§7.1). The words are the decapsulation key; the client re-derives everything else from them whenever the user enters them. Nothing about a receiving key is ever written to disk by the client; the user may keep the words in the encrypted profile (C-07) in a later revision — v1 shows them once and expects the user to keep them as they would a note key.

# 3. Decision D-17 and spec decision S-04 (revised)

**D-17.** The KEM path is a v1 feature, built in milestone M5c directly after M5. **S-04 (revised):** "KEM path deferred to v1.1" becomes "KEM path as in DC-02 §2; version-1 clients that do not implement it fill the region with random bytes (unchanged); implementations that do MUST follow §2.2 for the X25519 half". No change to the Block layout.

**Rationale.** The remote case (Option C document UC2, source → journalist; the owner's "across the world") is the one the symmetric path serves worst: the key has to travel by voice or by a disappearing-message channel. With a receiving key, nothing secret travels: the public key can be published anywhere, and a captured Block is useless without the seed that never left the receiver's device or head. X-Wing is the CFRG's general-purpose hybrid and is already in libsodium and in TLS; ML-KEM-768 alone is not used anywhere (hybrid is mandatory by every European authority the research report cites).

**Accepted residual (review flag 1 of draft 0.3).** ML-KEM ciphertexts are pseudorandom under MLWE (Maram & Xagawa, PKC 2023) up to the small bias that compression with `q = 3329` introduces. With one Block an observer cannot tell a KEM-path Block from a random-fill one; with a large sample of Blocks from one relay a statistical test could in principle estimate the fraction that carry ML-KEM ciphertexts — never which ones. This is recorded as T-28 and accepted for v1; it is exactly the kind of question the external review (OPS-05) should look at.

# 4. Threat model deltas

| Field | T-27 — Substituted Receiving Key | T-28 — KEM-region distinguishability |
|---|---|---|
| **Adversary** | Anyone who can alter the channel over which the public Receiving Key travels (A-6 network observer with write access, a compromised website or messenger account). | A relay operator or anyone who copies buckets (A-3, A-6). |
| **Threat** | The sender encapsulates to the adversary's key; the adversary reads the note, and can re-seal it to the real key to hide the substitution. | Statistical estimate of how many Blocks in a bucket carry an ML-KEM ciphertext (§3). |
| **Impact** | Confidentiality of that note. Same class as giving someone a wrong phone number for the voice hand-over. | Reveals that the KEM path is in use on this relay; reveals nothing about any single Block, sender or receiver. |
| **Mitigation** | The eight-character check, confirmed over a second channel before the first note; the client shows it prominently on both sides. A receiving key published in several places (site, profile, signed message) is harder to substitute everywhere. | Elligator2 for the X25519 half (§2.2) removes the decisive tell; ML-KEM's bias is small and needs many samples. |
| **Residual** | A sender who skips the check has no protection against substitution — as on the symmetric path a sender who reads the words over the wrong channel has none. | Accepted for v1; review item. |

**Seed compromise (KEY-07 applied).** A leaked receiving seed opens every Block encapsulated to it that is still on a relay or was captured. Mitigation: one key per note (the client says so after each open), short TTLs, and the seed never written by the client.

# 5. Requirements

- **KEY-09** The client SHALL generate receiving keys from 32 bytes of CSPRNG output, show the seed as 24 words and the public key as `askar1…` text and QR with its eight-character check, and SHALL NOT store either except as the user directs (encrypted profile, later revision).
- **KEY-10** When a Receiving Key is given, the client SHALL seal with the KEM path of §2 and SHALL NOT display, encode or hand over the derived root in any form; the sender's Session SHALL forget the root when the Block has been posted.
- **KEY-11** Receiving-side matching SHALL perform the same work for every Block in every fetched bucket regardless of match, and SHALL process all Blocks even after a match.
- **KEY-12** The X25519 half of a KEM-path Block SHALL be written as an Elligator2 representative of a torsion-dirty point with randomised high bits (§2.2); the receiver SHALL decode it before decapsulation.

# 6. Client deltas (for Client Design v0.5)

**CLI (Table 3):** `aska key receive` — new receiving key: prints the 24 seed words (hidden until Enter, as the hand-over), the `askar1…` public key, its QR and the check; `aska key receive --from-words` — re-derives and prints the public key from an existing seed. `aska send --to ASKAR` — KEM-path send; no hand-over output, prints "Posted; nothing to hand over" and the check of the key it sealed for. `aska receive --receiving-seed` — prompts for the 24 seed words instead of key material, fetches with `--relay`/`--profile` relays.

**GUI:** Send gains a *To (receiving key)* field in the Options; when filled, the protection cards are disabled (Guarded and Shares do not apply to a key the sender never holds), and *Seal and post* ends on a **Posted** screen (relays reached, the key's check, "nothing to hand over") instead of Hand-over. Receive gains a toggle *I have a receiving seed*: the key-material field then takes 24 seed words and the status reads "Receiving seed accepted". A new **Receiving key** screen (from Home's Shares/keys area and from Receive) creates a key: seed words in the words grid, the `askar1…` text, a QR, the check in large type, and the instruction "Give the key to the sender by any channel; confirm the check with them by another. Keep the words. One note per key."

**Session (core):** `Session::new_receiving_key() -> words`, `Session::receiving_key_public(words) -> askar`, `compose_for(askar)` (sets the target; `seal()` then uses the KEM path), `add_receiving_seed(words)` (Collecting state, KEM mode), fetch and match as §2.4 inside `accept_fetch`/`accept_bucket`.

# 7. Milestone M5c — plan and gates

Build order: core `xwing` module with the draft-11 vector test and Elligator2 round-trip tests → Block Format KEM path in `block.rs`/`session.rs` with the new e2e tests (KEM send → seed receive; decoy and distress on a KEM Block; random-fill Blocks do not match; every Block processed) → encodings (`askar`, check) → CLI → GUI → gates.

Gates: (a) X-Wing vector reproduced; (b) `is_montgomery_u` on the 32-byte `rep_X` of 2 000 sealed Blocks passes about half the time (uniformity, the crate's own distinguisher run against Aska's output) and the ML-KEM ciphertext bytes show no byte-value outliers beyond the known compression bias; (c) receive-side timing: per-Block matching time independent of match (same Mann–Whitney method as the distress gate); (d) the memory gates (core and GUI) extended with the seed and the X-Wing private key as needles; (e) the owner's gate over Tor: create a key on one client, send to it from another, receive with the words.

**Dependencies added (pinned, vendored):** `ml-kem 0.3.2` (RustCrypto, FIPS 203), `x25519-dalek 3.0`, `sha3 0.11`, `elligator2 0.1.0` (fiat-crypto field arithmetic, formally verified constant-time; differentially tested by its author against the Tor Project's `curve25519-elligator2`). `elligator2` is a young crate and is a named item for the external review; its role is confined to one 32-byte encode/decode per Block.

# 8. Change log

- **v0.1 (30 Sep 2026):** first version; decided (D-17). Implemented the same day as M5c (long-form bech32m checksum noted in §2.5).
