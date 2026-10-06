# Aska — Security Review Package

## Version 0.1 — 5 October 2026 (Milestone M8, for the independent security reviewer; OPS-05)

- **Purpose:** everything an independent reviewer needs to assess Aska version 1 before the v1.0.0-rc1 tag: what the system claims, where the claims are implemented, what the authors already know to be weak or open, and how to build, test and verify the artefacts. The Prototype Plan M8 gate is "all High and Medium findings closed or formally accepted by the owner with rationale".
- **What Aska is, in one paragraph:** a secure notes application for a small circle. A sender writes a note, the client seals it into a fixed-size **Block** that is indistinguishable from random bytes, posts the Block over Tor to a **Dead Drop relay** (an onion service that stores labelled random-looking Blocks for hours and forgets them), and hands the key to the receiver out of band — in person as a QR code or 24 words, as Shamir Shares for several people, or by sealing to a receiver's published post-quantum **Receiving Key** so that nothing needs handing over. The receiver fetches the whole bucket, finds and opens their Block, reads it on screen, and the client leaves nothing behind. Protection levels, a decoy note and a distress passphrase cover coercion. Nothing is stored by the client; the relay stores nothing it can read and nothing after expiry.
- **Status of the code under review:** tag `v0.1.0-alpha` at commit `fb71764` (1 October 2026), owner-signed; subsequent commits to `0c0b14a` change only build tooling and documentation. Code milestones M0–M5c complete; M6 platform validation run once on Ubuntu 26.04 (stand-in for Debian 13) with no deviations reported, Tails and Qubes checklists **open**; M7 release engineering complete.
- **How to read this package:** §1 lists the material. §2 maps the system and its trust boundaries. §3 is the cryptographic inventory. §4 is the consolidated list of review items — the questions the authors want answered, in priority order. §5 lists things in the code a reviewer will notice and should know the reason for. §6 lists known gaps and accepted risks. §7 says how to build, test and verify. §8 is the process: severity scale, triage, how findings are closed. §9 records owner decisions taken during development that bear on the review.

---

# 1. Review material

| Item | Where | Notes |
|---|---|---|
| Source code | `aska-code-M0-M7.zip` (git repository incl. history; HEAD `0c0b14a`, tag `v0.1.0-alpha` = `fb71764`) | Rust workspace: `crates/aska-core` (format, keys, Session, Tor client, Dead Drop client), `aska-proto` (ADP/1 wire protocol), `aska-drop` (relay, AGPL-3.0), `aska` (CLI), `aska-gui` (GTK 4). Python reference implementation under `reference/` (format and relay, used for interoperability tests). |
| Signed alpha | `release/v0.1.0-alpha/`: tarball `311ed693…1df5d`, relay `554f0d9d…cc6f0`, `bin/aska` `e781d45d…a9eb`, `bin/aska-gui` `714c3e7b…a0e6`, minisign key `79AD6224AFF176C9` | Built by the owner on Ubuntu 26.04 (not yet from the Debian 13 release container — see §6). |
| Decision Record and Threat Model v0.3 | `Design/Secure_Notes_Sharing_App_Aska_Decision_Record_and_Threat_Model_v0.3` | Decisions D-01…D-17, assets, adversaries A-1…A-9, threats T-01…T-28, requirements BLK/KEY/RLY/CLI/OPS/RM. **The normative statement of what is claimed.** |
| Block Format Specification v1 draft 0.4 | `Design/Aska_Block_Format_Specification_v1_draft0.4` | Container, key hierarchy, UtC AEAD, Shares, encodings, X-Wing receiving-key path, test vectors TV-1…TV-9, §12.2 review items. |
| Dead Drop Protocol ADP/1 draft 0.2 | `Design/Aska_Dead_Drop_Protocol_Specification_ADP1_draft0.2` | Wire protocol, relay behaviour, PoW, expiry, §13.2 review items. |
| Client Design v0.5 | `Design/Aska_Client_Design_v0.5` | Core library, CLI, GUI, doctor checks, memory rules, platform procedures, build and release, §7 residual risks, §10 gates. |
| Design changes DC-01 v0.2, DC-02 v0.1 | `Design/` | Networks that block Tor (D-16); the receiving-key path (D-17). Folded into the three documents above; kept for the rationale. |
| Platform Validation Checklists M6 v0.2 | `Design/Aska_Platform_Validation_Checklists_M6_v0.2` | Checklists A–D, doctor trigger matrix, §8 records of the first runs, §9 known gaps. |
| Release engineering | `docs/RELEASING.md`, `docs/releases/v0.1.0-alpha.md`, `release/`, `scripts/release.sh` | Signing, verification, reproducibility, the alpha's recorded deviations. |
| Research | `Research/` (report v0.1 and seven topic files) | Background: post-quantum state of the art, deniability and coercion resistance, anonymity and metadata, commercial landscape, forensic lessons. Not normative. |
| Dependency lists | `deps-aska-core.txt`, `deps-aska-drop.txt`, `deps-aska-gui.txt` (this package) | `cargo tree --edges normal`, one crate per line: 88 (core), 45 (relay), 158 (GUI, mostly GTK bindings). |

Sizes (lines of Rust, `wc -l`): aska-core 6 049 + 2 084 test; aska-proto 958; aska-drop 916 + 571 test; aska 2 516 + 906 test; aska-gui 4 348. Tests: 116 passing + 2 ignored slow (timing parity), plus the gate scripts of §7.

# 2. System map and trust boundaries

**Components.** The **client** (`aska`, `aska-gui`) runs on the member's machine; everything secret happens inside one object, the `Session` (`aska-core/src/session.rs`), which is the only place a root key, label, passphrase, plaintext or receiving seed exists. The **relay** (`aska-drop`) is a Tor onion service storing `(label, Block, deadline)` triples in locked memory, serving whole buckets by size class, with proof-of-work and caps; it has no accounts, no log, no disk. **Tor** is the system's: the client talks SOCKS5 to a loopback Tor (or Tor Browser's; or, on Whonix, the gateway) and configures nothing.

**What crosses each boundary.**

| Boundary | What crosses | What must hold |
|---|---|---|
| Client → relay (over Tor) | `POST (class, ttl, label, Block)`; `GET class → bucket`; `INFO`; PoW challenge/response | Block is uniform random to anyone without the key (BLK-01…BLK-03); label is 32 random bytes derived from the root; no identifier, timestamp or signature (BLK-08); the client fetches whole buckets so the relay learns nothing about which Block interests whom (RLY). |
| Client → network | Only SOCKS5 to loopback (or the Whonix gateway when Whonix is detected); only `.onion` destinations; no DNS, HTTP, update check, telemetry | `tor.rs` is the only network code; `require_loopback`, `normalise_onion` enforce it; the doctor refuses network work otherwise (CLI-15). |
| Sender → receiver, out of band | Key Card (`aska1…`, QR), 24 words, Shares (`askas1…`), or nothing (receiving-key path, where the receiver's `askar1…` key travels the other way, in public) | The design assumes this channel is the users'; the material is the key. The eight-character check binds a Receiving Key against substitution (T-27). |
| Client → operating system | Memory locking (`mlock`), core-dump disabling, zeroisation, stack scrubbing; reads of `/proc` (own exe hash, process names), `/run/tor/control.authcookie` (read-only, if readable); spawning `zbarcam` for QR scanning; an encrypted profile file only at a path the user names | Nothing else is written, ever (gates `no-file-writes-*`); no secret survives `Session::close()` (memory gates). |
| Build → user | Signed tarball, `SHA256SUMS` + `.minisig`, embedded public key and tag | `aska verify` checks the signed list offline; out-of-band fingerprint first (§9.4 of the Client Design). |

**Adversaries considered** (Decision Record §8): the relay operator (A-1), the local network observer (A-2), someone who copies buckets or the relay's memory (A-3), a coercer with access to a user (A-4), a court or authority (A-5), endpoint malware (A-6), the Tor network (A-7), a malicious circle member (A-8), an on-path censor (A-9). What is explicitly **not** claimed: protection against a compromised endpoint reading the screen; protection of the act of using the tool; protection against a user who keeps material they were told to destroy (§6 of the Decision Record, §7 of the Client Design).

# 3. Cryptographic inventory

| Purpose | Construction | Crate (version) | Where | Verified by |
|---|---|---|---|---|
| Root → label and slot keys | HKDF-SHA-512 with fixed `info` strings (`consts.rs`) | `hkdf 0.12.4`, `sha2 0.10.9` | `kdf.rs`, `keys.rs` | TV-1…TV-3, Python reference interop |
| Passphrase → slot key | Argon2id, profiles P1/P2 (256 MiB / 64 MiB) | `argon2 0.5.3` | `kdf.rs` | TV-4; timing-parity gate |
| Slot and payload encryption | XChaCha20-Poly1305 made key-committing by the UtC transform (HKDF-SHA-512 as the committing PRF over (K, nonce)) | `chacha20poly1305 0.10.1` | `utc.rs`, `block.rs` | TV-5; §4 item 1 |
| Shares | Shamir over GF(2⁸), 2-of-3 / 3-of-5, 4-byte verification tag | own code | `shares.rs` | TV-6; property tests |
| Receiving-key KEM | X-Wing (ML-KEM-768 + X25519 + SHA3-256, draft-connolly-cfrg-xwing-kem-11), composed in Aska | `ml-kem 0.3.2` (hazmat), `x25519-dalek 3.0.0`, `curve25519-dalek 5.0.0`, `sha3 0.10.9` | `xwing.rs` | TV-9 = draft-11 vector 1 (reproduced); round trip; §4 item 4 |
| Uniform encoding of the X25519 half | Elligator2 representative of a torsion-dirty point | `elligator2 0.1.0` (fiat-crypto 0.3.0 field arithmetic) | `xwing.rs` | uniformity test (400 samples); §4 item 5 |
| KEM shared secret → root | HKDF-SHA-512(salt "", ss, "aska/v1/root-from-kem") | `hkdf` | `xwing.rs` | round trip, e2e tests |
| Encodings | bech32m (BIP-350) with HRPs `aska`/`askas`/`askar`; long-form checksum for the Receiving Key (code length unbounded) | `bech32 0.11.1` + own `Bech32mLong` | `encodings.rs` | TV-7, TV-8, encoding tests; §4 item 7 |
| Words | BIP-39 English, 24 words for 32 bytes | `bip39 2.2.2` | `keys.rs` | round trip |
| Randomness | OS CSPRNG (`getrandom`) only; no user-space PRNG state | `getrandom 0.2.17`, `rand_core 0.6/0.10` adapters | `rng.rs` | §4 item 9 |
| Constant time | `subtle` for label comparison and tag checks | `subtle 2.6.1` | `session.rs`, `shares.rs` | timing-parity gates |
| Zeroisation | `zeroize` on every secret type; `LockedBuf` (mlock, page-aligned, zeroised on drop); `scrub_stack` | `zeroize 1.9.0`, libc via `secret.rs` | `secret.rs` | memory gates (core and GUI, external `/proc/PID/mem` scan) |
| Release signatures | minisign (Ed25519, Blake2b-512 prehash) | `minisign-verify 0.3.0` | `fingerprint.rs` | test vector; release self-check |
| Relay PoW | SHA-256, label-bound, relay-specific single-use challenge | `sha2` | `aska-drop`, `aska-proto` | relay tests; §4 item 11 |

No cryptographic primitive is implemented by hand except Shamir sharing, the UtC transform, the X-Wing composition and the long-form bech32m checksum; those four are the places where a reviewer's attention is most valuable.

# 4. Review items (consolidated, in priority order)

Each item names its source. "Confirm" means the authors believe it holds and want it checked; "assess" means the authors do not know.

1. **UtC instantiation** (Block Format §12.2). Confirm that HKDF-SHA-512 as the committing PRF over (K, nonce), with the derived key fed to XChaCha20-Poly1305, satisfies the assumptions of Bellare–Hoang's UtC key-commitment proof, and that the commitment tag length chosen gives the claimed 2⁻¹²⁸ binding.
2. **Nonce derivation** (Block Format §12.2). Confirm that deriving the payload nonce from the header nonce under K_slot opens no nonce-reuse path when the same passphrase protects two slots of one Block (forbidden by §6.1 step 1 and rejected by the implementation — check the rejection is complete).
3. **Indistinguishability of Blocks** (Block Format §12.2, §10.1). Assess statistically, beyond the smoke test in `reference/test_aska.py`, that Blocks of each size class are indistinguishable from uniform random, including the KEM region on both paths (random fill on the symmetric path, `ct_M ‖ rep_X` on the KEM path).
4. **X-Wing composition** (DC-02 §4, Decision Record D-17). Confirm Aska's composition against draft-11 beyond test vector 1: `expandDecapsulationKey` (SHAKE256 → ML-KEM seed ‖ X25519 secret), the combiner order `ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label`, the handling of a malformed ciphertext (implicit rejection must be total and constant-time), and the root derivation from the shared secret.
5. **`elligator2` crate and the torsion-dirty construction** (Block Format §12.2; the authors' highest-uncertainty item). The crate is at version 0.1.0; its field arithmetic is fiat-crypto (formally verified constant-time) and its author reports differential testing against the Tor Project's `curve25519-elligator2`. Assess: correctness of representative generation and decoding; that the "dirty" point (random low-order component) gives a representative uniform over 32 bytes, including the high bits; that `x25519-dalek`'s decapsulation of a torsion-dirty public point yields the same shared secret as the encapsulator's (the implementation relies on this); constant-time behaviour of encode/decode.
6. **T-28 bias and sample size** (Decision Record T-28). Assess the statistical distinguishability of ML-KEM-768 ciphertexts (compression with q = 3329) from uniform bytes and estimate how many Blocks an observer needs before KEM-path Blocks in a bucket become detectable with meaningful confidence. The design accepts a small bias for v1; the number matters for the guidance given to users.
7. **Long-form bech32m checksum** (Block Format §7.5.2). Confirm that applying the BIP-350 checksum to a ~2 000-character string with the code-length limit removed still detects the error classes the Receiving Key needs (single substitutions; burst errors from a misread QR line), and that the eight-character "check" shown to users is an adequate anti-substitution token against T-27 (an attacker who can publish a substitute key must match 40 bits).
8. **Label derivation and matching** (Block Format §5.2, §6.4). Confirm that the label leaks nothing about the root (HKDF one-wayness), that constant-time comparison is used throughout (`subtle`), and that receiving-side matching by decapsulation does the same work for every record (timing-parity gate `seed_matching_time_does_not_depend_on_a_match`, p = 0.78 at N = 60 — assess whether the sample size is adequate).
9. **Randomness** (`rng.rs`). Confirm that every random value — salts, nonces, labels, roots, seeds, KEM randomness, Elligator2 point — comes from `getrandom` through one path with no fallback, and that the `rand_core 0.10` adapter for `elligator2` cannot be miswired.
10. **Memory handling** (Client Design §3.1). Confirm the claims the gates make: no secret survives `Session::close()`, including the GTK text buffers (filler-wipe technique), the Key Card text, labels and roots moved between threads (`Secret32` boxing), stack residue (`scrub_stack` 128 KiB below the caller). The external gate scans `/proc/PID/mem` for known needles; assess what the needles miss.
11. **Relay PoW** (ADP §13.2). Confirm that the SHA-256 PoW with label binding and a relay-specific single-use challenge cannot be outsourced or amortised across relays or across posts.
12. **Relay resource exhaustion** (ADP §13.2). Review the 30-second read timeout and one-Block-per-connection memory against Tor's concurrent-circuit behaviour for slow-loris resistance; review the caps and the behaviour when a class is full.
13. **Relay expiry ordering** (ADP §13.2). Confirm that randomised listing plus monotonic-only deadlines leaves no ordering leak through the expiry process.
14. **Distress semantics** (Block Format §6.3, Client Design §6.4). Confirm that opening with the distress passphrase is indistinguishable in time and in output from opening the decoy (gate `decoy_and_distress_opens_are_indistinguishable_in_time`, p = 0.62 at N = 150) and that the destruction it triggers is complete (no cached root, label or plaintext).
15. **Receiving-key lifetime** (KEY-07 as revised, KEY-10). Confirm KEY-10 (the sender's Session forgets the root immediately after sealing to a Receiving Key and refuses every hand-over form), and assess the consequences of KEY-07 being advice: a reused seed is a persistent key (T-15 note) — is the guidance adequate?
16. **Encrypted profile** (`profile.rs`). Confirm the profile format (Argon2id + the same AEAD; 4 096-byte fixed size; random-looking) leaks nothing about relays or the circle key to someone who holds the file, and that a wrong passphrase is indistinguishable from a non-profile file.
17. **Tor usage** (`tor.rs`). Confirm: stream isolation per request (random SOCKS credentials); `.onion`-only destinations enforced before any connection; the Whonix gateway exception is reachable only when Whonix is detected (`platform.rs`); the control-port use is read-only (`GETINFO`) and the cookie file is only read; `client_auth_add` refuses on Tails/Whonix. Assess whether the blocked-network signature (`looks_like_blocked_network`) can be induced by an attacker to steer a user toward Tor Browser's Tor.
18. **Doctor and front ends** (Client Design §6). Confirm that no doctor finding is advisory where it should refuse (Table 4) and that the GUI's filler-wipe and no-file-chooser decisions hold (the gates cover a whole Send and Receive).
19. **Dependency review** (OPS-04). The three dependency lists; the crates that touch secrets are in §3. Assess: supply-chain posture (no vendoring yet — see §6), `cargo audit` not yet run (no advisory database reachable from the development environment), build-script and proc-macro surface.
20. **Build and release** (`docs/RELEASING.md`, §7). Confirm the release process and `aska verify`'s logic (`fingerprint.rs`): a valid signature over a list that does not name the binary is a MISMATCH; the embedded key makes a self-consistency check, not a trust anchor; the out-of-band fingerprint remains first.

# 5. Things in the code a reviewer will notice — and why they are there

None of these is a backdoor; each is documented, and each is listed here so that it is examined rather than discovered.

- **A non-loopback proxy address is accepted:** `10.152.152.10:9050`, the Whonix gateway, only when `platform::is_whonix()` is true (`/etc/whonix_version`, `/usr/share/whonix` or `os-release`). Everywhere else the client refuses any proxy that is not on loopback (CLI-15). Client Design §2.4.
- **The doctor reads Tor's control cookie:** `tor::with_discovered_control` opens `/run/tor/control.authcookie` for reading only when it is readable by the user and no control port was configured, to ask `GETINFO status/bootstrap-phase` (D-16). It writes nothing and issues no `SETCONF`. Skipped on Tails and Whonix.
- **The doctor reads `/proc`:** `/proc/self/exe` (own hash), `/proc/*/comm` (process names for the capture, remote-desktop and accessibility checks), `/proc/swaps`, resource limits. Read-only, local, Table 4 of the Client Design.
- **The GUI spawns an external program:** `zbarcam` (zbar-tools) for QR scanning (the desktop-portal camera, C-04, is not built). The decoded text comes back on a pipe; nothing is passed to the helper.
- **A public key is embedded in release builds:** the project's minisign key (`release/aska-release.pub`), used only to verify the signed hash list that ships beside the binary (§4 item 20). Development builds embed none and say so.
- **The client accepts hand-over material with a recognisable prefix:** `aska1…`, `askas1…`, `askar1…` (bech32m HRPs, Block Format §7.2). Hand-over material never touches the network or the relay; the prefix is visible only on the out-of-band channel. The owner reviewed this on 5 October 2026 and decided to keep it (§9); the 24-word form is the unmarked alternative for key material.
- **`unsafe` appears in four files**, each with `#![allow(unsafe_code)]` under a crate-level `deny`: `aska-core/src/secret.rs` (page-aligned allocation, `mlock`/`munlock`), `aska-core/src/platform.rs` (`prctl`, `setrlimit`), `aska-drop/src/harden.rs` (`mlockall`, `setrlimit`), `aska/src/term.rs` (termios and `poll` for the terminal). Everything else is `#![deny(unsafe_code)]` or `#![forbid(unsafe_code)]`.
- **The relay is AGPL-3.0; the client crates are MIT OR Apache-2.0** (D-12). The relay's licence is the mechanism that keeps relay modifications public.
- **Two timing-parity tests are `#[ignore]`** because they take minutes (Argon2id); `scripts/timing-parity.sh` and CI run them.

# 6. Known gaps and accepted risks (as of this package)

| # | Item | Status | Where recorded |
|---|---|---|---|
| 1 | Doctor probes for the ScreenCast portal (GNOME's own recorder) and for AT-SPI clients are not implemented; detection is by process name and environment only | Open; an attempt on 1 Oct 2026 was abandoned | Checklists §9, Client Design §6.1.1, STATE |
| 2 | Desktop-portal camera (C-04) not built; `zbarcam` helper instead | Open (v1.1) | Checklists §9 |
| 3 | KDE Wayland per-window capture flag not requested; View footer says "detected but not blocked" on every Wayland desktop | Open (v1.1) | Checklists §9 |
| 4 | ML-KEM compression bias (T-28) | **Accepted for v1** by D-17; §4 item 6 asks for the number | Decision Record T-28 |
| 5 | Single use of a receiving seed is advice (KEY-07 revised) | **Accepted** | Decision Record §12, Client Design §7 |
| 6 | GTK text buffers cannot be zeroised with certainty (C-02); compositor and GPU buffers; camera frames | **Accepted** — mitigated by filler wipes, swap warnings, Tails guidance | Client Design §7 |
| 7 | Platform gate open: Tails Checklist B, Qubes C and D, Debian 13 A not yet run on a signed tarball; A run on Ubuntu 26.04 without per-line record | Open — release-checklist gate | Checklists §8, Release Checklist |
| 8 | The alpha was not built in the Debian 13 release container and with `rustc 1.98.1` instead of the pinned 1.95.0; the GUI may not start on Debian 13 / Tails 7 | Fixed in tooling after the tag; next cut from the container | `docs/releases/v0.1.0-alpha.md` |
| 9 | No Rekor transparency entry yet (no `rekor-cli` on the signing machine) | Open — release-checklist gate | RELEASING §5 |
| 10 | Dependencies not vendored; `cargo audit`/`cargo deny` not run | Open — M8 | Client Design §9.3 |
| 11 | Receiving seeds cannot be kept in the encrypted profile (RM-09) | Roadmap v1.1 | Decision Record §16 |
| 12 | Session-scoped bridge configuration through the control port (RM-08) | Roadmap v1.1 | Decision Record §16 |
| 13 | Whonix detection relies on three markers; a template that renames them falls back to refusing | Open — observe at Checklist C | Checklists §9 |
| 14 | Tails `RLIMIT_MEMLOCK` default may force "accept unlocked memory" for class-3 fetches | Unknown — Checklist B3 records it | Checklists §9 |

# 7. How to build, test and verify

**Toolchain.** Rust 1.95.0 (pinned in `rust-toolchain.toml`); GTK 4 ≥ 4.14 and libadwaita ≥ 1.5 development packages for the GUI; Python 3 for the reference tests; `strace`, `xdotool`, `Xvfb`, `imagemagick`, `zbar-tools` for the GUI gates; root for the GUI memory gate (it reads `/proc/PID/mem`).

**Build and unit tests.** `cargo build --release --locked --workspace`; `cargo test --workspace --release` → 116 passed, 2 ignored. `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check` are clean.

**Gates** (`scripts/`): `repro-build.sh && repro-build.sh --compare` → `REPRODUCIBLE: OK` (two clean static builds identical); `no-writes-check.sh` (relay), `no-file-writes-client.sh` (core), `no-file-writes-cli.sh` (a whole send and receive), `no-file-writes-gui.sh` (GUI, a whole Send and Receive under `strace`) → `OK`; `timing-parity.sh` → `TIMING-PARITY: OK` (decoy vs distress; seed matching hit vs miss; Mann–Whitney p ≥ 0.01); `memory-gate-gui.sh` (external scan of the GUI process at four stages for root, label, note and Key Card text needles) → `MEMORY-GATE (GUI): OK`. The core memory gate is a unit test (`crates/aska-core/tests/memory_gate.rs`). The doctor trigger matrix is a CI test (`doctor_findings_fire_on_their_triggers_and_stay_silent_otherwise`).

**Interoperability.** `python3 reference/test_aska.py` and `reference/test_drop.py` exercise the Python reference implementation; the Rust vector tests (`crates/aska-core/tests/vectors.rs`) consume the same TV-1…TV-9 values, so a Block sealed by one implementation opens in the other.

**Release verification** (as a member would do it). Compare the tarball's SHA-256 with the fingerprint received out of band; unpack; `sha256sum -c SHA256SUMS`; `minisign -V -p aska-release.pub -m SHA256SUMS`; `./bin/aska verify` → `status: MATCH`. The developer performed this independently on the owner-signed alpha on 1 October 2026 (`docs/releases/v0.1.0-alpha.md`).

**Reproducing the release.** `RELEASE_CONTAINER=1 scripts/release.sh v0.1.0-alpha` builds in the Debian 13 image; two builds in the same image are byte-identical. Builds on different machines differ (glibc is linked into the static binaries) — `docs/RELEASING.md` §3.

# 8. Process

**Severity.** *High*: a confidentiality, anonymity or deniability property stated in the Decision Record can be broken by an adversary in §2 without endpoint compromise. *Medium*: a stated property is weakened (reduced margin, a detectable tell, a leak requiring unusual conditions), or a robustness property (zeroisation, no-write, refusal) fails in a reachable case. *Low*: hardening, defence in depth, documentation gaps. *Informational*: observations.

**Triage.** Findings are filed against a document section or a source location, with a reproduction where possible. The developer answers each within the review period with one of: fixed (commit, test added, gate updated); accepted (owner's rationale recorded in the Decision Record as a numbered decision); disputed (with evidence; escalated to the reviewer for a second look). The M8 gate: every High and Medium finding fixed or accepted with recorded rationale; the Decision Record and the specifications re-issued (v0.4 / draft 0.5 / v0.6) with the changes; then `v1.0.0-rc1`.

**What the authors ask the reviewer to prioritise**, if time is limited: items 1–6 of §4 (the AEAD, nonces, indistinguishability, the X-Wing composition, the `elligator2` crate, the T-28 number), then 10 (memory), 14 (distress), 17 (Tor usage).

# 9. Owner decisions relevant to the review (log)

| Date | Decision | Where |
|---|---|---|
| 25 Sept 2026 | D-01…D-15: the v1 baseline (Blocks, relay, Tor-only, levels, distress, licences, legal review) | Decision Record §3 |
| 30 Sept 2026 | D-16 networks that block Tor — detect and direct; the client acquires no bridges and probes no network | DC-01, Decision Record |
| 30 Sept 2026 | D-17 the X-Wing receiving-key path pulled into v1 | DC-02, Decision Record |
| 1 Oct 2026 | M6 gate not passed; proceed to M7/M8 with Tails/Qubes checklists as release gates | Checklists §8, STATE |
| 1 Oct 2026 | Release key rotated to the owner's key `79AD6224AFF176C9`; bootstrap key retired; alpha signed by the owner | `release/README.md`, `docs/releases/v0.1.0-alpha.md` |
| 5 Oct 2026 | **Hand-over encodings keep their bech32m prefixes** (`aska`, `askas`, `askar`). The owner raised the point that the prefix identifies hand-over material as Aska's to whoever sees it; the developer's analysis: the prefix never reaches the network or the relay, the Key Card and Shares are the key itself and must be treated as such, the 24 words are the unmarked form, and the Receiving Key is public by design (comparable to a PGP key's banner); a prefix-free "bare" encoding was offered as DC-03 and **declined** for v1 — the reviewer is invited to weigh in (§4 item 7 touches the same encoding). | This document; STATE |

---

*Prepared by the developer for the owner and the independent reviewer. Questions about any item go to the project owner, who holds the release key and the final say on acceptance.*
