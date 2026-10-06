# Aska Dead Drop Protocol Specification

## ADP/1, draft 0.2 — relay wire protocol, storage model, DoS defences and operator runbook

- **Status:** Draft 0.2 — the six open issues of draft 0.1 were decided on 25 September 2026 (§13, P-01…P-06) and are incorporated. Executable: the reference relay and client in `aska_drop.py` implement every normative statement; `test_drop.py` (8 tests) includes two end-to-end flows with the Block Format reference; `deploy/` holds the torrc, hardened systemd unit and Debian install script referenced by the runbook.
- **Satisfies:** RLY-01…RLY-10 of *Aska — Decision Record and Threat Model v0.2*; consumes (label, Block, TTL) exactly as defined in *Aska Block Format Specification v1 draft 0.3*.
- **Depends on decisions:** D-05 (expire-only, TTL default 24 h / max 7 days), D-06 (Tor onion only, self/friend-hosted, no public list), D-10 (modest cover traffic).
- **Not in this document:** client polling policy and cover-traffic schedule beyond conformance minimums (Client Design), mixnet transport (RM-05).
- **Notation:** as in the Block Format Specification; all integers big-endian; sizes in bytes.

---

# 1. Scope and conformance

This specification defines the **Aska Dead Drop Protocol, version 1 (ADP/1)**: the wire protocol between an Aska client and a Dead Drop relay, the relay's storage and expiry semantics, its identifier-free defences against flooding, the Tor configuration that exposes it, and the procedure for operating one on a small Linux server. It answers the question the Block Format left open — how a sealed Block travels from sender to receiver — while keeping the relay incapable, by construction, of learning who posted, who collected, or which Block a visitor wanted.

A relay **conforms** if it implements the three operations of §4 exactly, enforces the storage rules of §5 and the rejection rules of §4.5, exposes itself only as a Tor onion service (§7), and keeps no record of any kind beyond the live store (§5.4). A client conforms if it speaks §4, reaches relays only through Tor, and meets the minimums of §8. MUST, SHOULD and MAY are used as in RFC 2119.

## 1.1 Design goals (from the requirements)

| Goal | Requirement | How ADP/1 meets it |
|---|---|---|
| Onion-only reachability | RLY-01 | The relay binds to loopback; Tor forwards a v3 onion service to it. No clearnet listener exists (§7). |
| Exactly two data operations, no per-label retrieval | RLY-02 | PUT stores a Block under its label; GET_ALL returns every live Block of a size class. There is no operation that takes a label as a query (§4). |
| Expire-only, TTL 1 h – 7 d, default 24 h | RLY-03, D-05 | Deadlines are monotonic-clock values; deletion happens at expiry only; no read signal exists (§5.2). |
| No logs, architecturally | RLY-04 | The reference has no logging code path; the systemd unit discards stdout/stderr; Tor logs to /dev/null; journald is volatile (§5.4, §9). |
| Size-class enforcement | RLY-05 | PUT rejects any Block whose length is not exactly the declared class size (§4.5). |
| RAM-only storage | RLY-06 | The store is an in-memory map; the unit has no writable filesystem, no swap, memory locked (§5.1, §9). |
| Vanguards and PoW | RLY-07 | torrc enables onion-service PoW and intro-DoS defence; runbook installs vanguards (§7). |
| Single static binary, minimal config | RLY-08 | Configuration is port, TTL limits, per-class caps and PoW base difficulty (§9.3). |
| Identifier-free rate limiting | RLY-09 | Adaptive proof-of-work on PUT, bound to the label; per-class capacity caps; Tor-level PoW (§6). |
| Transport-agnostic semantics | RLY-10 | PUT / GET_ALL / INFO are defined as messages over any reliable byte stream; §10 describes carrying them over a mixnet. |

# 2. Overview

A Dead Drop is a small daemon holding a set of `(label, Block, deadline)` triples in memory. A **sender** connects over Tor to the relay's onion service and issues one PUT containing the size class, the time-to-live in hours, the 32-byte label from the Block Format, and the Block itself. A **receiver** connects the same way and issues one GET_ALL for a size class; the relay streams back *every* live Block of that class in random order, and the receiver picks out its own by label locally (Block Format §6.4). Nothing the receiver sends identifies which Block it wanted, and nothing the relay stores identifies who sent or fetched anything. Blocks disappear when their deadline passes; nothing else ever deletes them, so there is no signal that a Block was collected.

Two features keep the relay usable without identifiers: an adaptive **proof-of-work** requirement on PUT that rises as a size class fills, so flooding costs the flooder more than it costs the relay; and **per-class capacity caps**, so a full class rejects new Blocks rather than evicting old ones — a sender who receives a "full" status simply uses another relay, while a receiver never loses a Block that was accepted.

![Figure 1 — Deployment and the three operations of ADP/1.](drop_deploy.png)

*Figure 1 — Deployment and the three operations of ADP/1.*

# 3. Constants

| Name | Value | Meaning |
|---|---|---|
| MAGIC | `ASKD` (0x41 0x53 0x4B 0x44) | First four bytes of every request and response. |
| PROTO_VERSION | 0x01 | ADP/1. |
| OP_INFO / OP_PUT / OP_GET_ALL | 0x01 / 0x02 / 0x03 | The only operations. |
| SIZE_CLASSES | 1 → 4 096; 2 → 16 384; 3 → 65 536 | From the Block Format Specification; a relay MAY serve a subset. |
| LABEL_LEN | 32 | Block label L. |
| TTL | 1 ≤ ttl_hours ≤ max_ttl_hours; default 24; max_ttl_hours ≤ 168 | D-05. |
| CHALLENGE_LEN | 16 | PoW challenge; valid 120 s; single use. |
| POW_DOMAIN | `aska/adp1/pow` | Domain separator for the PoW hash. |
| Default capacity per class | 2 000 / 800 / 200 Blocks | ≈ 8 MB + 13 MB + 13 MB of RAM; operator-configurable. |
| Connection timeout | 30 s per read on the relay side | A slow or stalled client is dropped without response. |
| Default port | 4567 on 127.0.0.1 | Behind `HiddenServicePort 4567`. |

*Table 1 — Constants.*

# 4. Wire protocol

## 4.1 Framing

Every request begins `MAGIC ‖ PROTO_VERSION ‖ op` (6 bytes) followed by an operation-specific body; every response begins `MAGIC ‖ PROTO_VERSION ‖ status` (6 bytes) followed by an operation-specific body. **Exactly one request is carried per connection**: the relay reads one request, writes one response, and closes. A client that wants to do two things opens two connections — ideally on two Tor circuits (§8). There is no negotiation, no keep-alive, no headers, no timestamps and no client-supplied identifier of any kind. Unknown magic, version or op are answered with `ST_BAD_REQUEST` and the connection is closed.

The choice of a minimal binary framing over HTTP is deliberate: HTTP carries dates, user agents, content types and negotiation that either leak or must be scrubbed, and an HTTP parser is a large attack surface on a machine whose only job is to hold noise. ADP/1 can be parsed with fixed-length reads and no allocation beyond the Block itself.

## 4.2 INFO

| Direction | Layout |
|---|---|
| Request body | — (empty) |
| Response body | `max_ttl_hours(2) ‖ classes_bitmap(1) ‖ pow_base_difficulty(1)`; bit *c−1* of the bitmap is set if size class *c* is served. |

INFO lets a client confirm it is talking to an ADP/1 relay and learn its limits. It reveals nothing about stored content or activity. Operators use it as their only health check (§9.5).

## 4.3 PUT

| Direction | Layout |
|---|---|
| Request body | `class(1) ‖ ttl_hours(2) ‖ label(32) ‖ pow_challenge(16) ‖ pow_nonce(8) ‖ block(SIZE_CLASSES[class])` |
| Response body | Empty, except for `ST_POW_REQUIRED`, whose body is `challenge(16) ‖ difficulty(1)`. |

On a first attempt the client sends all-zero `pow_challenge` and `pow_nonce`. If the relay currently requires work for this class (§6) it answers `ST_POW_REQUIRED` with a fresh challenge and the difficulty; the client solves the puzzle and repeats the PUT with the same label and Block, carrying the challenge and its solution. If no work is required the relay stores the Block directly. A PUT of a label that already exists with **identical** content returns `ST_OK` (idempotent retry after a dropped connection); with different content it returns `ST_DUPLICATE` and stores nothing. The relay reads the entire Block before validating anything except the class byte, so that the time to reject does not depend on content.

## 4.4 GET_ALL

| Direction | Layout |
|---|---|
| Request body | `class(1)` |
| Response body | `count(4) ‖ count × ( label(32) ‖ block(SIZE_CLASSES[class]) )` |

The relay first runs expiry, then returns every live Block of the class **in an order freshly randomised with a CSPRNG for each response**. Insertion order, and therefore posting order, MUST NOT be recoverable from the listing. There is no pagination, no cursor, no "since" parameter and no filter: any of those would let a visitor express interest in a subset, which is exactly the information the relay must never receive. With the default caps a full class-3 listing is about 13 MB, which is acceptable over Tor for a low-volume circle; §10 discusses growth.

## 4.5 Status codes and rejection rules

| Code | Name | When |
|---|---|---|
| 0x00 | ST_OK | Stored (or identical duplicate), or listing follows. |
| 0x01 | ST_BAD_REQUEST | Wrong magic, unsupported version, unknown op, truncated fixed fields. |
| 0x02 | ST_BAD_CLASS | Size class not served by this relay. |
| 0x03 | ST_BAD_TTL | ttl_hours outside 1..max_ttl_hours. |
| 0x04 | ST_BAD_LENGTH | Block shorter than the class size (connection ended early). |
| 0x05 | ST_FULL | Class at capacity; nothing stored, nothing evicted. |
| 0x06 | ST_DUPLICATE | Label exists with different content. |
| 0x07 | ST_POW_REQUIRED | Work required; challenge and difficulty follow. |
| 0x08 | ST_POW_INVALID | Challenge unknown, expired, already used, or nonce does not verify. |

*Table 2 — Status codes. A relay MUST NOT add codes that reveal store contents (e.g. "label not found" cannot exist because no operation looks up a label).*

# 5. Storage model

## 5.1 RAM only

The store is an in-memory map per size class from label to `(block, deadline, digest)`, where `digest` is SHA-256 of the Block used only for idempotent duplicate detection. The relay MUST NOT write Blocks, labels, deadlines or any derived value to persistent storage. The process MUST run with memory locked against swapping and with core dumps disabled; the host SHOULD have no swap. A restart loses all Blocks — accepted, because senders can post to two relays (CLI-12) and because a relay that could survive a restart would have to persist something a seizure could read.

## 5.2 Deadlines and expiry

On PUT the relay records `deadline = monotonic_now + ttl_hours × 3600`. It MUST use a monotonic clock, never wall-clock time, so that no value in memory corresponds to a calendar instant. Expiry runs before every PUT and GET_ALL (and MAY run on a timer): every entry whose deadline has passed is deleted. Nothing else deletes a live entry. In particular there is no delete-on-read (D-05), no operator delete operation, and no eviction when full.

## 5.3 Capacity

Each class has a cap in Blocks. When a class is at its cap, PUT returns `ST_FULL`. Caps SHOULD be set so that total memory stays well inside the systemd `MemoryMax` (default caps use about 35 MB). Because listing is all-or-nothing, caps also bound the receiver's download (§10).

## 5.4 What the relay knows — and does not

| The relay holds | The relay never holds |
|---|---|
| Live Blocks (random-looking bytes) by label | Any key, passphrase or plaintext |
| A monotonic deadline per Block | Wall-clock posting time, or any timestamp |
| A SHA-256 of each Block (duplicate detection) | Client IP addresses (onion service) or any client identifier |
| Outstanding PoW challenges for ≤ 120 s | Which Block a GET_ALL visitor was interested in |
| Per-class caps and PoW settings | Logs, counters over time, access records, crash dumps |

*Table 3 — Knowledge boundary. A forensic image of the running host yields the left column only; of a powered-off host, nothing.*

# 6. Denial-of-service defences without identifiers

A relay cannot rate-limit "per user" because there are no users; it can only make abuse expensive and bound its own exposure. ADP/1 uses three layers.

## 6.1 Tor-level

The onion service enables Tor's introduction-point rate limiting and **onion-service proof-of-work** (`HiddenServicePoWDefensesEnabled 1`), which Tor activates automatically under load and which makes each new rendezvous cost the client CPU time. This protects the *reachability* of the relay.

## 6.2 Application-level adaptive proof-of-work on PUT

The relay computes a difficulty *d* for each class: `d = base + extra`, where `extra` is 0 while the class is below 50 % of its cap and rises by one bit for every further 12.5 % (to a maximum of +4), so that a near-full class costs sixteen times more work per Block than an empty one. When *d* > 0 a PUT without a valid solution receives a 16-byte random challenge (valid 120 s, single use). The client finds an 8-byte nonce such that `SHA-256(POW_DOMAIN ‖ challenge ‖ label ‖ nonce)` has *d* leading zero bits, and retries. Binding the label into the hash means a solution cannot be reused for a different Block; binding the challenge means it cannot be precomputed. At *d* = 20 a solution costs about one second on a laptop and nothing measurable for the relay to verify. Operators SHOULD leave `base = 0` for a friend-hosted relay and raise it if flooding is observed.

## 6.3 Capacity caps and timeouts

Caps bound memory; the 30-second read timeout bounds slow-loris connections; systemd's `MemoryMax` bounds the worst case. Tor itself limits concurrent rendezvous circuits. None of these mechanisms records anything about the client.

# 7. Tor configuration

The relay process binds `127.0.0.1:4567` only. Tor runs on the same host as a client (`SocksPort 0`, `ClientOnly 1` — it never relays for others) with a single v3 onion service forwarding port 4567. The reference `torrc` (in `deploy/`) sets: `Log notice file /dev/null` and `SafeLogging 1`; `AvoidDiskWrites 1`; three introduction points; intro-DoS defence with a rate of 25/s and burst 200; PoW defences with queue rate 250 and burst 2 500. **Vanguards**: tor 0.4.7+ ships vanguards-lite by default; for a long-lived relay the runbook installs the `vanguards` add-on for full layer-2/3 guard protection against guard-discovery attacks of the kind used in the Boystown case. Operators SHOULD rotate the onion address periodically (generate a new service directory, distribute the new address through Key Cards).

## 7.1 Optional client authorisation with a shared circle key (P-02)

Tor v3 client authorisation encrypts the service descriptor so that only holders of an authorised x25519 private key can even discover or reach the relay; outsiders cannot scan, flood or fingerprint it. Tor's native model is one key per client, which would leave a **list of member keys on the relay** — a membership count and pseudonymous identifiers the design otherwise avoids. ADP/1 therefore specifies the variant that fits the threat model: **one shared circle key**. The operator generates a single x25519 key pair, installs the public half as the relay's only `authorized_clients` entry, and the private half travels to members inside Key Cards as TLV type 0x06 (Block Format §7.3, allocated by this specification). The relay holds one key and learns nothing about membership; the client installs the key into its local Tor (via `ONION_CLIENT_AUTH_ADD` on the control port, or `ClientOnionAuthDir`) before connecting. Client authorisation is **off by default** and is an operator option (§9.4). Rotating the circle key is done together with onion-address rotation. Per-member keys MUST NOT be used.

The onion address is the relay's only identity. It is distributed out of band — inside Key Cards (TLV type 0x03 carries the 32-byte ed25519 public key from which the address is reconstructed), spoken, or written — never through a public list (D-06).

# 8. Client conformance minimums

- Clients MUST reach relays only through Tor (a local SOCKS5 proxy with hostname addressing) and MUST refuse to connect to anything but a `.onion` address.
- Clients MUST open a new connection per request and SHOULD request Tor circuit isolation per connection (SOCKS username/password isolation or a fresh `NEWNYM`), so that a PUT and a later GET_ALL do not share a circuit.
- Clients MUST send PUTs with the label computed as Block Format §5.2 and the class matching the Block length; they SHOULD post each Block to two relays when the Key Card lists two.
- Clients MUST randomise the delay between sealing and posting and between polls, and MUST issue decoy PUTs and GET_ALLs on a Poisson schedule at the level chosen in D-10 (default modest). Decoy Blocks are random bytes of a real class with a random label and a short TTL; they are indistinguishable from real ones.
- Clients MUST fetch with GET_ALL and match labels locally; they MUST NOT implement or use any relay operation that narrows a listing.
- Clients MUST treat `ST_FULL` and connection failure as "try another relay or later", never as an error that reveals anything to the user about a particular Block.
- Clients MUST solve PoW challenges transparently and MUST NOT persist challenges, relay addresses (unless the user saves an encrypted profile, CLI-11) or listing contents beyond the session.

# 9. Operator runbook — a relay on a small Linux server

This runbook installs a Dead Drop on a fresh Debian 12/13 virtual server — a DigitalOcean droplet, a Hetzner box, a home Raspberry Pi behind NAT (no port forwarding needed) or a Qubes VM all work identically, because the relay needs **no inbound connectivity at all**. The scripts referenced are in `deploy/` next to this document; read them before running them. Every step exists to satisfy a numbered requirement, noted in brackets.

## 9.1 Choosing and paying for a host

Any 1 vCPU / 1 GB machine is ample; the store uses about 35 MB at default caps and Tor about 100 MB. The provider will see that the machine talks to the Tor network and will hold the operator's payment identity; the design tolerates this (D-06) because an operator who is identified and compelled can produce only what §5.4 lists. Operators who want to minimise even that exposure can pay with a provider that accepts cash-bought vouchers or Monero, or host at home. Prefer a jurisdiction without secret technical-capability notices, but assume seizure anyway — the design does.

## 9.2 Installation (deploy/install-debian.sh)

1. **Base and updates.** `apt dist-upgrade`, install `unattended-upgrades` so Tor and the kernel stay patched without an operator logging in.
2. **No swap** (RLY-06). `swapoff -a`, comment swap out of `/etc/fstab`, `vm.swappiness=0`. A Block in RAM must never reach disk.
3. **Firewall: drop all inbound.** nftables with `input` policy `drop`, loopback and established connections allowed, outbound open. An onion service only makes *outbound* connections to Tor, so nothing needs to be open — not even SSH. Administer through the provider's console, or allow SSH from a single fixed IP if you must.
4. **Tor from deb.torproject.org** (current versions carry PoW and vanguards-lite). Install `deploy/torrc.aska-drop` as `/etc/tor/torrc`. Tor creates `/var/lib/tor/aska-drop/` with the onion keys and `hostname`.
5. **Relay binary.** Install the reproducibly built static `aska-drop` binary (OPS-02/03). **Verify its SHA-256 against the fingerprint obtained out of band before installing** — a poisoned relay binary cannot read Blocks, but it could log connection metadata.
6. **Hardened systemd unit** (`deploy/aska-drop.service`). It runs as a dynamic user with a read-only view of the filesystem, no home, no `/tmp`, no devices, loopback-only networking (`IPAddressDeny=any` + `IPAddressAllow=localhost`), a system-call allow-list, no capabilities, `MemoryLock=infinity`, `LimitCORE=0`, `StandardOutput=null`, `StandardError=null` (RLY-04) and `MemoryMax=512M`.
7. **Volatile journald.** `Storage=volatile` so that even systemd's own unit messages never touch disk.
8. **Read the onion address** from `/var/lib/tor/aska-drop/hostname` and give it to the circle out of band. It goes into Key Cards as the 32-byte public key (Block Format §7.3).

## 9.3 Configuration

| Setting | Default | Notes |
|---|---|---|
| --port | 4567 | Loopback port Tor forwards to. |
| --max-ttl-hours | 168 | Hard ceiling 168 (D-05). Operators MAY lower it. |
| --cap-1 / --cap-2 / --cap-3 | 2000 / 800 / 200 | Per-class Block caps; set 0 to not serve a class. |
| --pow-base | 0 | Base PoW difficulty in bits; adaptive bits are added on top (§6.2). |

*Table 4 — The complete relay configuration surface (RLY-08). There is deliberately nothing else: no data directory, no log level, no admin port.*

## 9.4 Operating

- **There is nothing to back up.** A restart or rebuild loses live Blocks by design; tell the circle to post important Blocks to two relays.
- **Updates.** Unattended upgrades handle Tor and the OS. Relay binary updates are manual: verify the new fingerprint, replace the binary, `systemctl restart aska-drop`.
- **Onion rotation.** Every few months (or after any suspected exposure): stop tor, move `/var/lib/tor/aska-drop/` away and shred it, start tor, distribute the new address. Old Key Cards stop working; that is the point.
- **Client authorisation (optional, closed circles — §7.1).** Generate one x25519 key pair for the circle (e.g. `openssl genpkey -algorithm x25519`), write `descriptor:x25519:<base32 public key>` to `/var/lib/tor/aska-drop/authorized_clients/circle.auth`, reload Tor, and put the private key into the circle's Key Cards (TLV 0x06). Never create per-member `.auth` files. Rotate the circle key whenever the onion address is rotated.
- **Vanguards.** Install the `vanguards` package (or use Arti when it ships onion-service PoW) for full guard-layer protection on a relay that will run for months.
- **Seizure or compromise.** Assume it yields Table 3's left column at most. Rotate the onion address afterwards so the circle stops using the compromised host.

## 9.5 Health check without logs

Because the relay logs nothing, the only health check is functional: from another machine over Tor, run `aska drop info <onion>` (INFO op) and, optionally, post and fetch a decoy Block. The operator learns "up / down / capacity" and nothing about content or usage — the same as any other client.

# 10. Scaling and transport evolution

GET_ALL-of-everything is the right design for a circle and the wrong one for a crowd: a receiver's download is bounded by the class cap, not by their own traffic. For the target user (D-01) this is fine — a circle posting a few dozen Blocks a day stays under a few megabytes per poll. Three evolution paths exist that preserve the anonymity property, and the message semantics of §4 are designed so that any of them can be adopted without changing the Block Format or the client's local matching logic:

- **More relays, smaller circles.** The friend-hosted model scales horizontally by adding relays; a Key Card names the relay, so partitioning is natural and leaks only "this Block is on relay X", which the sender chose.
- **Time-bucketed listing without a "since" parameter.** A relay MAY partition its store into fixed public epochs (e.g. six-hour buckets identified by an epoch number derived from the relay's own uptime, not wall clock) and GET_ALL MAY take an epoch selector. This is a weaker property than v1 (a visitor reveals which epoch it cares about) and is therefore not in ADP/1; it is noted as the first candidate for ADP/2 if volume demands it.
- **Mixnet transport (RM-05).** PUT and GET_ALL are message-oriented and idempotent, so they map directly onto Katzenpost/Echomix Pigeonhole-style storage or Nym mixnet service providers. The blob model (fixed-size random Blocks, random labels) is exactly what those systems store best.

# 11. Security considerations

## 11.1 What a compromised relay learns

A relay adversary (A-1) with full control of the host learns the live set of Blocks and labels, their deadlines, and the timing and size of connections arriving from Tor. It cannot read Blocks (no key ever reaches it), cannot attribute them (no IP, no identifier, no account), cannot tell which Block a visitor fetched (visitors fetch everything), and cannot tell posting order from a listing (randomised). It *can* observe that "something was posted at monotonic time t and something was fetched at t + Δ", which is the timing side channel that cover traffic and random client delays blunt (T-02, T-06). It can withhold or corrupt Blocks (availability only; corruption is detected by the Block's AEAD, T-03).

## 11.2 Label as the only client-supplied identifier

The label is chosen by the sender, is uniform random to everyone without R, and is never reused (Block Format §10.9). A relay that receives the same label twice sees either an idempotent retry or a collision, and treats the latter as a duplicate. A malicious sender who learns a label (e.g. by seeing a Key Card) could pre-emptively PUT garbage under it to block the real Block — mitigated by the duplicate rule (the real Block is then rejected, which the sender notices and can retry on another relay) and by the fact that labels are secret until the Key Card is handed over.

## 11.3 Proof-of-work

PoW is a cost, not an identity; a determined flooder with more CPU than the circle can still fill a class, at which point the class returns `ST_FULL` and honest senders use another relay. Challenges are random, single-use and expire in two minutes, so solutions cannot be hoarded; binding the label prevents reuse across Blocks. Verification is one SHA-256 for the relay.

## 11.4 Denial of receipt

Expire-only means a sender never learns whether a Block was collected — a deliberate property (no read receipts, T-11, T-15) with a usability cost: the receiver must confirm out of band if confirmation matters.

## 11.5 Tor-specific risks

A long-lived onion service is a guard-discovery target; vanguards and rotation address this (T-07). Tor circuits are not post-quantum; a recorded Tor stream reveals, at most, connection metadata to a future quantum adversary, never Block contents, which are protected inside the Block (T-21). Client-side: Tor use from a small monitored network is itself observable (T-05); the client warns.

## 11.6 Operator exposure

The operator is identifiable to the hosting provider and can be compelled. The design's answer is that compliance is empty: the operator can hand over a running machine and the adversary obtains Table 3. An operator MUST NOT modify the relay to log, and the reproducible-build fingerprint lets the circle check that the binary on the relay is the published one only if the operator cooperates — which is why the *client* never trusts the relay with anything.

# 12. Requirements traceability

| Requirement | Where satisfied |
|---|---|
| RLY-01 | §7 (loopback bind, onion service only, `IPAddressDeny=any` in the unit). |
| RLY-02 | §4.3, §4.4 — PUT and GET_ALL only; INFO is metadata-free; no per-label retrieval surface (verified by `test_no_per_label_retrieval_surface`). |
| RLY-03 | §5.2 — monotonic deadlines, expire-only, max 168 h, default 24 h. |
| RLY-04 | §5.4, §9.2 steps 6–7 — no logging code path; stdout/stderr discarded; volatile journald; Tor log to /dev/null. |
| RLY-05 | §4.3, §4.5 — exact class length required. |
| RLY-06 | §5.1, §9.2 step 2, unit `MemoryLock`/`LimitCORE`, no swap. |
| RLY-07 | §7 — PoW, intro-DoS, vanguards, rotation. |
| RLY-08 | §9.3 — four settings; single binary; systemd unit provided. |
| RLY-09 | §6 — adaptive label-bound PoW, caps, timeouts; no identifier. |
| RLY-10 | §4 message semantics; §10 mixnet mapping. |

*Table 5 — Traceability.*

# 13. Design decisions taken in draft 0.2

The six open issues of draft 0.1 were decided by the project owner on 25 September 2026 and are incorporated in this draft. Recorded as P-01…P-06 (protocol-level, subordinate to D-01…D-15).

| ID | Issue | Decision | Effect on this document |
|---|---|---|---|
| P-01 | Listing cost vs receiver anonymity | **All-or-nothing GET_ALL in ADP/1.** Uptime-epoch buckets noted as the first ADP/2 candidate only if volume ever requires it. | §4.4, §10 unchanged. |
| P-02 | Tor client authorisation | **Optional, off by default, one shared circle key** carried in Key Cards (TLV 0x06). Per-member keys forbidden. | §7.1 added; runbook §9.4 updated; Block Format Key Card TLV 0x06 allocated (BFS draft 0.3). |
| P-03 | PoW base difficulty | **0 by default** (friend-hosted relays); adaptive bits still apply. Raise (e.g. 8) for any relay whose address is shared beyond the circle. | §6.2, §9.3 unchanged. |
| P-04 | Idempotent duplicate rule | **ST_OK for an identical re-PUT** (retry-friendly). Only a party already holding label and Block can trigger it. | §4.3 unchanged. |
| P-05 | Production implementation language | **Rust** for the production relay and client core (static, reproducible builds; mlock; zeroising buffers). Python remains the reference. | Feeds the Client Design / prototype plan. |
| P-06 | Tor implementation | **C Tor in v1.** Revisit Arti when it ships onion-service PoW and vanguards. | §7 unchanged. |

*Table 6 — Protocol-level decisions.*

## 13.1 Change log

- **Draft 0.2 (25 Sep 2026):** decisions P-01…P-06 incorporated; §7.1 shared circle client-auth added; runbook updated; reference Key Card gains TLV 0x06 (tests updated).
- **Draft 0.1 (25 Sep 2026):** first complete draft with reference relay/client, tests and deploy scripts.

## 13.2 Remaining review items (for the security reviewer)

- Confirm that the SHA-256 PoW with label binding cannot be outsourced or amortised across relays (the challenge is relay-specific and single-use, so it should not).
- Review the 30-second read timeout and per-connection memory (one Block buffer) against Tor's concurrent-circuit limits for slow-loris resistance.
- Confirm that randomised listing plus monotonic-only deadlines leaves no ordering leak through the expiry process (e.g. deletion order within one expiry pass is irrelevant because nothing observes it).

Next deliverable: *Aska Client Design v0.1* (CLI-01…CLI-14, OPS-01…OPS-07), covering the command-line core, the Send/Receive/Shares flows, memory handling, warnings, Tails and Qubes procedures and the reproducible build and release pipeline — followed by the prototype plan.
