# Aska — Internal Pre-Review Report

## Version 0.1 — 5 October 2026 (Milestone M8, before the independent review)

- **What this is:** the result of an internal code audit run against the Security Review Package v0.1 items, performed on 5 October 2026 by four independent review passes (format and symmetric cryptography; receiving-key path and encodings; client secret handling, Tor and doctor; relay and protocol), each reading the code without having written it and confirming every finding by test or experiment before reporting. The developer then triaged and fixed. It is a *pre*-review: it reduces what the external reviewer will find, it does not replace them — the external review is still the M8 gate.
- **Code under audit:** commit `35f708b` (M8 start). **Fixes:** commits `2f80259` … `5f1e27f`; the specification changes are in *Block Format draft 0.5*.
- **Headline:** 2 High, 11 Medium, 17 Low, 16 Informational findings from the audit, plus one memory-gate regression found and fixed while verifying the fixes. Both High and all Medium findings are fixed, except two Mediums recorded as accepted with rationale (C-11 partially, A-9 reclassified as Informational). Tests after the fixes: 118 passing + 2 ignored; all gates green (see §4).

---

# 1. Findings fixed

| ID | Sev. | Finding (short) | Fix | Commit |
|---|---|---|---|---|
| A-1 | High | Header index and region order revealed the slot order: the real note was always header 0 and first in the payload, so a coercer holding the Block and a decoy passphrase could prove a real slot exists — contradicting Block Format §10.3. | Per-Block random permutation of header indices (Fisher–Yates, normative draw order, mirrored in the Python reference); regions laid out in header-index order; test vectors TV-3…TV-5 regenerated; property test. Spec §6.1, §9, §10.3 (draft 0.5). | 2f80259 |
| B-1 | High | The Receiving Key check (last 8 text characters = 2 payload chars + the bech32m checksum) was an affine function of attacker-controlled free fields (extra relay-hint TLVs); a substitute key with the victim's check was forged in 4.8 ms. T-27's only mitigation did not hold. | Check = first 60 bits of SHA3-256("aska/v1/rk-check" ‖ pk_M ‖ pk_X), twelve bech32 symbols in three groups, computed from the decoded public key on both sides. Spec §7.5.3, T-27. | 74d1e7a |
| B-2 | Low | Sender's check computed over a canonical re-encoding, receiver's over the text; non-canonical input made them disagree. | Subsumed by B-1 (check over the decoded key). | 74d1e7a |
| A-2 | Low | After a distress open the root was `None`; a second `open()` returned `WrongState` without Argon2id — distinguishable from the decoy case (`NoSlot` after Argon2id). | Distress replaces the root with fresh random bytes; a follow-on open does identical work and fails with `NoSlot`. Tests updated. | ccf3541 |
| A-3 / C-2 / B-9 | Medium | Distress open did not destroy the receiving seed (KEM path); the seed re-derives the root from the Block still on the relay. | Seed cleared on distress; e2e test asserts `has_receiving_seed() == false`. | ccf3541 |
| A-4 | Low | GF(2⁸) multiply branched on secret bits. | Branch-free, mask-based `gf_mul` (eight fixed rounds). | ccf3541 |
| A-5 | Low | `Root` derived `PartialEq` (non-constant-time comparison of a secret). | Derive removed; `Root::ct_eq` via `subtle`; tests adjusted. | ccf3541 |
| A-6 | Low | The Session accepted an empty passphrase for a slot no receiver could reach. | `EmptyPassphrase` error for set/decoy/distress passphrases (open is unaffected). | ccf3541 |
| B-3 | Low | Long-form decoder accepted non-canonical strings (padding bits); relay hints unbounded (60 000 accepted). | Re-encode-and-compare canonical check; ≤ 8 relay hints. Spec §7.5.2. | ccf3541 |
| B-5 | Low | `accept_bucket`/`accept_fetch` (split mode) ran decapsulation without `scrub_stack`. | Inner functions + scrub, as `check_drops`. | ccf3541 |
| B-6 | Low | An invalid `pk_M` passed `set_recipient` and failed only at seal. | `xwing::validate_public_key` (FIPS 203 modulus check; non-contributory X25519 point rejected) in `set_recipient`. | ccf3541 |
| C-5 | Medium | NFKC normalisation collected into a growing `String`; prefix copies of passphrases stayed in unlocked heap (confirmed 8-byte fragment after close). | Length pass, then chars encoded straight into a `LockedBuf`. | ccf3541 |
| C-11 | Medium (by the letter) | Argon2id working memory neither locked nor zeroised; Client Design §3.1 claimed both. | Caller-owned block memory zeroised after each derivation. **Not locked** (256 MiB cannot be mlock'ed under default limits) — accepted and documented (§3). | ccf3541 |
| C-1 | Medium | GUI moved the whole Session to the worker for post/fetch (minutes), so close/distress/watchdog were unavailable and a closed window left secrets in a detached thread. | Post and fetch run as `PostJob`/`FetchJob` with the Session on the main thread; in-flight job cancelled by `close_session()`/`shutdown()`; only the open step (Argon2id, seconds) borrows the Session. GUI file-write gate re-run: OK. | 2f127e2 |
| C-3 | Medium | Decoy PUTs carried TTL 1–3 h, real ones 24 h by default — the relay (and anyone copying its memory) could filter decoys by TTL/deadline (CLI-06). | Decoy TTL drawn from the real TTL choices (24 h half the time, the others equally). | 2f127e2 |
| C-4 | Medium | "Copy disabled" on secret text views did not disable copy: the clearing handler ran before GTK's copy, and the clipboard ended up holding the text (confirmed under Xvfb). | Signal emission stopped (`signal_stop_emission_by_name`) for copy/cut. Verified: old binary → clipboard holds the note; fixed binary → empty. | 2f127e2 |
| C-6 | Medium | Keypad passphrase in a growing `Zeroizing<String>` (prefix copies in freed chunks). | Fixed-capacity buffers (1 024 bytes = 256 chars × 4) for the field and its `value()` copies. | 2f127e2 |
| C-7 | Medium | Every keystroke extracted the whole note (`TextBuffer::text()`) into an unwiped g_malloc copy for the byte counter. | Byte length computed from the buffer's iterators without extracting text; `wipe_text_view` sizes its filler from `char_count()`. | 2f127e2 |
| C-8 | Medium | CLI: the 24 words built with `join`/`format!` into plain `String`s (fragment found in heap after drop). | `words_block` pre-sized and built without temporaries; notes assembled into pre-sized `Zeroizing<String>`s. | 2f127e2 |
| C-9 | Low | CLI countdown re-`format!`ed the secret body every second. | Frame built once into a pre-sized zeroising buffer; only the digits are replaced in place. | 2f127e2 |
| C-12 | Low | A relay that accepts and stalls (I/O `Timeout`) triggered the blocked-network direction. | `DropError::Timeout` no longer counts as the blocked-network signature; Tor's own verdicts (rendezvous timeout, SOCKS 0x01/0x04) do. | 2f127e2 |
| C-13 | Low | CLI idle watchdog passive at prompts (root/label in memory indefinitely while the user is away). | Prompts poll with the idle timeout; `TimedOut` ends the command, nothing kept. | 5f1e27f |
| C-14 | Low | GUI profile path followed symlinks on Forget/Open and would read a device path until OOM. | `symlink_metadata`, regular-file and exact-size (4 096) checks, `O_NOFOLLOW` on shred. | 2f127e2 |
| D-1 | Medium | Relay GET_ALL had no overall deadline: a paced reader held a connection slot for records × 30 s; new clients queued behind 256 stalled ones. | 300 s per-connection budget; load shedding (`try_acquire`) instead of queueing. | 2f127e2 |
| D-2 | Low | Rust and Python relays disagreed on a cap-0 class (INFO bitmap, PUT → FULL vs BAD_CLASS, GET_ALL → OK vs BAD_CLASS). | Python reference made `serves()`-aware. | 2f127e2 |
| D-3 | Low | Python reference ignored the 120 s challenge validity on consume. | Expiry checked on consume, as the Rust relay does. | 2f127e2 |

# 2. Findings recorded, not fixed (Low / Informational, with disposition)

| ID | Sev. | Finding | Disposition |
|---|---|---|---|
| B-4 | Low | On a seed-matching hit the Session allocates a `LockedBuf` and derives a label after the loop; a local observer could measure ~0.3 % more time on a hit. | **Accepted:** matching time is not network-observable (no network event follows matching); the local observer is the out-of-scope A-6. Gate wording corrected (§4). |
| A-9 | Info (was Medium) | The timing-parity gate (N = 150, Mann–Whitney p ≥ 0.01) has little power against the microsecond distress delta under Argon2id jitter; p = 0.62 is a sanity check, not a measurement. | **Accepted;** the Review Package §4 item 14 and the Client Design will say "sanity check" rather than present the p-value as evidence of parity. The delta (dropping buffers) is far below human observation. |
| A-7 | Info | `open_profile` returns `BadLength` for a non-class-length file (doc says `NoSlot`); `KeyCard::from_bytes` does not require the version TLV. | Documentation corrected in the next Client Design revision; TLV strictness to be aligned with the spec at draft 0.6 (B-7). |
| A-8 | Info | The Python reference opens less strictly than §6.2 step 4 (no granule-alignment/flags check). | Reference tightened at the next vector regeneration; no product impact. |
| A-10 | Info | `OpenInfo.distress` is handed to front ends (both ignore it). | Kept for the CLI's exit-code semantics; documented as "MUST NOT be displayed". |
| B-7 | Info | Key Card TLV strictness deviates from §7.3 (version not required/first; length ≠ 1 tolerated; duplicates last-wins). | Align at draft 0.6. |
| B-8 | Info | Long-form bech32m: two equal errors exactly 1 023 positions apart are undetected (periodicity of the BCH generator). | Spec §7.5.2 wording to say "detects any single error; otherwise 30-bit". |
| B-10 | Info | Error surfaces on decode are public-input only. | None needed. |
| C-10 | Low | CLI `BufReader` (8 KiB) and `Stdin`'s buffer keep passphrases/key material for the process lifetime. | **Deferred to v1.1:** unbuffered reads into a `LockedBuf`; recorded in the Client Design residuals. |
| C-15 | Info | `Session::close()` leaves circle auth keys in `cfg.relays`. | Clear at close in the next core revision (cosmetic; the Session is dropped right after). |
| C-16 | Info | SOCKS5 reply version bytes unchecked. | Tighten at the next Tor-module revision. |
| C-17 | Low | Gates miss partial copies (whole-needle matching), passphrase/words/seed needles, child-process and socket-mediated writes. | Documented as inherent limits in the Review Package §7 and Client Design §10.1; memscan needles for words and passphrase to be added. |
| C-18 | Info | GUI Send clickable before the first doctor run completes. | Not exploitable (fixed loopback proxy, onion validation); left. |
| C-19 | Info | Fingerprint check is self-consistency only. | By design; documented. |
| C-20 | Info | Terminal echo not restored on abort. | Cosmetic. |
| D-4 | Low | With `pow-base 0` the adaptive PoW is near-free; half of every class is free. | **Accepted (P-03):** record in the runbook; consider a non-zero base for any relay whose address leaves the circle. |
| D-5 | Low | Client listing ceiling hard-coupled to 2× default caps; a larger relay becomes unreachable. | Deferred: derive from a byte budget or advertise caps in INFO (ADP draft 0.3). |
| D-6 | Low | Shipped systemd unit sends stderr to the (volatile) journal; documents say "discarded". | Documents to say "stderr → volatile journal, fatal lines only"; install script to assert the volatile drop-in. |
| D-7 | Info | Outstanding-challenge map not in the locked-memory budget. | Bounded by Tor's intro rate; note in `harden.rs`. |
| D-8 | Info | CSPRNG-failure paths are safe liveness traps. | Comment added at next revision. |
| D-9 | Info | Duplicate-label rule is a label-existence oracle (by design, ADP §11.2). | Add the full-class interaction to §11.2. |

# 3. Owner acceptances arising from this report

1. **Argon2id working memory is zeroised but not locked** (C-11): locking 64–256 MiB is incompatible with default `RLIMIT_MEMLOCK`; the swap warning and the Tails/no-swap guidance remain the mitigation. Client Design §3.1 to be reworded accordingly.
2. **Seed-matching time may differ by a fraction of a percent on a hit** (B-4): not network-observable; accepted.
3. **PoW at the default base provides no meaningful flood cost** (D-4): the cap and Tor are the protection; operators of relays whose address leaves the circle set a non-zero base.

# 4. State after the fixes

`cargo test --workspace --release`: 118 passed, 2 ignored. `cargo clippy -D warnings`, `cargo fmt --check`: clean. Reference tests (`test_aska.py` 16, `test_drop.py` 8, `selftest`): pass; Rust and Python agree bit-for-bit on the regenerated TV-3…TV-5. GUI file-write gate (`no-file-writes-gui.sh`, send + receive): OK after the C-1 refactor. GUI memory gate: a first re-run FAILED (the relay's copy of the label L survived in freed heap — the bucket's record labels were plain arrays), fixed in c6baeda (labels wiped after matching and on `FetchOutcome` drop); second run `MEMORY-GATE (GUI): OK`. Clipboard check under Xvfb: old binary leaks the note to the clipboard, fixed binary does not. `cargo audit`: 168 crates, no advisories (`docs/review/cargo-audit-2026-10-05.txt`). Timing-parity gate: re-run after the distress change (see STATE for the result).

# 5. What the external reviewer should still look at

The items of Security Review Package §4 remain the list; this report closes none of them by itself. In particular items 1–6 (UtC, nonces, indistinguishability, X-Wing composition, `elligator2`, the T-28 number) were *confirmed as implemented as specified* by the internal passes but not proven; the reviewer's independent judgement is what the gate asks for. New since the package: the header permutation (§6.1 draw order — confirm the Fisher–Yates with `u32 mod (i+1)` introduces no exploitable bias for n ≤ 4) and the hash-based check (§7.5.3 — confirm 60 bits is the right trade-off between a readable check and T-27).
