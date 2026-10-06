# Aska — Design Change DC-01: Networks that block Tor

## Version 0.2 — 30 September 2026

- **Status:** Decided by the project owner on 30 September 2026 (option A). Implemented the same day in the `aska` workspace (commit noted in `STATE.md`).
- **Amends:** *Decision Record and Threat Model v0.2* (adds decision **D-16**, threat **T-26**, requirement **CLI-15**); *Client Design v0.4* (§2.4 Tor integration, Table 3 CLI options, Table 4 doctor checks); *Prototype Plan v0.1* (M4 addendum, M6 test item). These deltas are to be folded into the next revisions of those documents (Decision Record v0.3, Client Design v0.5); until then this note is authoritative for the change.
- **Trigger:** owner requirement, 30 September 2026: "implement a solution for when normal Tor traffic is blocked or not allowed in the client environment; suggestion: Tor bridges via obfs4 as a fallback once normal Tor attempts have been made."

---

# 1. The requirement and what it means for Aska

Everything Aska sends or receives goes through Tor and only through Tor (decision P-06, requirement RLY-01): the relay is an onion service, and the client refuses any destination that is not a `.onion` address and any proxy that is not on the loopback interface. When the local network blocks connections to the Tor network, the client therefore has no traffic at all — and that is the correct failure. A fallback to a non-Tor path would break the anonymity property silently, which is worse than not working. The fallback the requirement asks for must consequently happen *inside* Tor. That is exactly what Tor bridges with a pluggable transport are: the same Tor circuit, entered through a relay that a censor does not recognise as one. obfs4 (now distributed as the "lyrebird" transport) is the transport in general use.

The design constraint that shapes the answer is that Aska uses the **system Tor** and **never writes a file** (Client Design §3.1). Bridges are Tor configuration, and Tor configuration can be changed in two ways: by editing `torrc`, a root-owned file — excluded for a client that must write nothing, and impossible on Tails in any case; or through the control port's `SETCONF`, which is runtime-only, persists nothing, and is the mechanism Tor Browser itself uses. On Tails the control port is filtered by onion-grater, so `SETCONF` would be available on Debian and Qubes but not on Tails — the same situation as circle client-authorisation (C-03).

# 2. Options considered

| Option | What the client does | Platforms | New attack surface | Verdict |
|--------------|--------------------------------|------------|------------------------------|--------------|
| **A — Detect and direct** | The doctor tells "Tor is not running" (refuse) from "Tor runs but cannot reach the network" (warn) and names the platform's own bridge tool. Every failed network attempt with the blocked-network signature ends with the same direction. A `--tor-browser` option uses Tor Browser's Tor, which the user has already connected through a bridge. | All, including Tails | None: two control-port `GETINFO` queries and text. | **Adopted for v1.** |
| **B — Bridges for the session** | The user pastes bridge lines they obtained through Tor's normal distribution channels; the client applies `UseBridges` and the lines with `SETCONF` for the running session, then waits for bootstrap. The client never fetches bridges itself. Needs the transport package installed. | Debian, Qubes; refused on Tails with an explanation (as C-03) | Control-port writes; a new input that is Tor configuration | **Scheduled for v1.1**, after M5 so the graphical client gets the same settings pane. |
| **C — Automatic fallback** | The client tries plain Tor, then applies bridges on its own. | — | Requires bridge lines from somewhere: a distribution service (a non-`.onion` connection, forbidden by RLY-01) or a shipped list (which is itself a fingerprint of the client). Duplicates infrastructure Tor Browser, Tails and Whonix already provide at the OS level. | **Rejected for v1.** |

# 3. Decision D-16 — Networks that block Tor

**Decision.** Aska does not configure Tor and does not fall back to any non-Tor path. When the local network blocks Tor, the client (a) detects the condition where it can and says so plainly, (b) directs the user to the platform's own Tor connection tool, which knows how to connect through a bridge, and (c) can use Tor Browser's Tor once that has connected. Session-scoped bridge configuration through the control port (option B) is a v1.1 feature. Automatic bridge acquisition (option C) is rejected.

**Rationale.** The Tor-only invariant is the anonymity property; every option that preserves it keeps the client's network surface at "loopback SOCKS and control port, `.onion` destinations only". Option A costs two `GETINFO` queries and adds no new input. Option B adds a configuration input and a control-port write, which is acceptable but deserves the review and the GUI pane together. Option C would need the client to contact something that is not an onion service, or to ship a list that identifies it — both contrary to the design — and would replicate what Tails' Tor Connection, Whonix's Anon Connection Wizard and Tor Browser's connection assistant already do better.

**Revisit triggers.** Arti gaining pluggable-transport support with a stable API (the embedded-Tor roadmap item), which would let the client own its Tor without touching system configuration; or field evidence from the circle alpha that the direction in option A is not followed in practice.

# 4. Threat model addition — T-26: the local network blocks Tor

| Field | Content |
|------------|----------------------------------------------------------------------------------------|
| **Adversary** | A network operator or national censor between the client and the Tor network (a new position, "on-path censor"; overlaps A-6 network observer in capability but with the goal of denial rather than observation). |
| **Threat** | The client cannot reach any Tor relay; no Block can be posted or fetched. |
| **Impact** | Availability only. Nothing is disclosed: the client sends nothing outside Tor, and a failed attempt reveals to the local network only that Tor was attempted — which the attempt to connect to Tor already revealed. |
| **Mitigation** | D-16: detection with the platform's bridge tool named (A); session-scoped bridges via the control port (B, v1.1); the client never falls back to a clearnet path. |
| **Residual** | Bridge distribution and blocking is an arms race the Tor Project runs; Aska inherits its state. A user who cannot reach Tor at all cannot use Aska — by design. The Tor connection attempt itself is visible to the local network. |

# 5. Requirement CLI-15

The client SHALL, when a control port is available, distinguish a Tor that is not running or not on loopback (refuse network operations, Table 4) from a Tor that runs but has not reached the network (warn, and direct the user to the platform's bridge tool). When no control port is available, the client SHALL give the same direction when every network attempt of an operation fails with the signature of a blocked network (the local Tor answered; nothing beyond it did). The client SHALL be able to use Tor Browser's SOCKS port. The client SHALL NOT edit Tor configuration files, SHALL NOT obtain bridge lines from any source, and SHALL NOT fall back to any non-Tor path.

# 6. Client Design deltas (for v0.5)

**§2.4 Tor integration — add:** "When the local network blocks Tor, Aska cannot work around it by itself: it uses the system Tor and writes no configuration. The doctor reports a Tor that runs but has not bootstrapped (control port `GETINFO status/bootstrap-phase` below 100 %) as a warning naming the platform's own connection tool — Tor Connection on Tails, the Anon Connection Wizard on Whonix, Tor Browser's connection settings elsewhere — and every network operation that fails the way a blocked network fails ends with the same advice. A `--tor-browser` option points the client at Tor Browser's SOCKS port (127.0.0.1:9150), so a Tor Browser connected through a bridge serves as Aska's Tor. Session-scoped bridge configuration through the control port is planned for v1.1 (D-16)."

**Table 3 — global options, add:** `--tor-browser` — use Tor Browser's Tor (127.0.0.1:9150); conflicts with `--socks`.

**Table 4 — add row:**

| Check | How it is detected on Linux | Warning shown | Refuses? |
|----------------|----------------------------|----------------------------------------|----------------|
| Tor cannot reach the network | Control port: `GETINFO status/bootstrap-phase` reports PROGRESS below 100 | "Tor is running but has not reached the Tor network (bootstrap N %); nothing can be sent or fetched until it does. If this network blocks Tor: …" (platform-specific direction) | No — warn and direct; the operation would only time out |

**§6.1 note:** without a control port the condition cannot be told from a slow start at doctor time; the same direction is then given when the operation fails (`looks_like_blocked_network`).

**§5 graphical client — D-16 behaviour (for M5).** The command-line flag is the CLI's shape of a decision the GUI takes on screen. On Home, the amber doctor banner for "Tor cannot reach the network" carries the platform direction *and an action*, "Use Tor Browser's Tor instead", which switches the session's SOCKS port to 127.0.0.1:9150 and re-runs the check; if that Tor has circuits the banner clears and the user continues. Screen 6 (Settings) gains a "Tor" section — *System Tor (9050)* / *Tor Browser (9150)* / *custom loopback port* — showing the current bootstrap and circuit state. At start the GUI probes both well-known ports and, when the system Tor is absent or stuck but Tor Browser's Tor has circuits, uses the latter and says so in the footer ("via Tor Browser"). The choice lives in the session or in the encrypted profile, never in a plain settings file. A desktop launcher may pass `--tor-browser`; that is a convenience, not the design.

**§8 platform procedures — add to each:** where the platform's bridge tool is (Tails: Tor Connection at start-up; Qubes/Whonix: Anon Connection Wizard in sys-whonix; Debian: Tor Browser's connection settings, then `--tor-browser`).

# 6a. Mobile and Windows implications (for RM-02 and any Windows port)

The principle — detect, direct to the platform's Tor tool, use that Tor, never configure it from Aska, never fall back to a non-Tor path — carries to every platform, but "the platform's Tor" differs, and that decides how much lands on Aska:

| Platform | The platform's Tor | Option A there | Consequence |
|--------------|------------------------------------|--------------------------------|------------------------------------------|
| Linux desktop (Tails, Qubes, Debian) | System `tor` or Tor Browser | As built | — |
| Windows | Tor Browser's Tor (9150) or the Expert Bundle; no daemon by default | Works via `--tor-browser`; direction names Tor Browser | A Windows platform layer (`VirtualLock`, crash-dump control, console I/O) and doctor warnings for the hibernation file and swap; Windows ranks with plain Debian, not Tails |
| Android | Orbot (separate app with its own bridge settings) or Tor embedded in the app | With Orbot: direct to Orbot's bridge settings | With embedded Tor there is no external tool to direct to: **option B is mandatory** |
| iPhone | None an app can rely on; Tor is embedded (or Orbot iOS as a system VPN, which the app cannot verify) | Not applicable | **Option B is mandatory**; memory guarantees need a fresh look (no app-controlled `mlock`, background snapshots, keyboard memory) |

**Requirement for RM-02 (mobile):** on a platform without an external Tor the client MUST provide in-app bridge configuration (option B) from its first release, as the ordinary way its Tor is configured — not as a fallback shown after failures. "Tor cannot be reached, try later" is acceptable only when bridges fail as well; on a censoring network "later" does not come.

# 7. Implementation (done 30 September 2026)

`aska-core`: `tor::bootstrap_progress` and `tor::parse_bootstrap_progress` (control-port query and parser); `tor::looks_like_blocked_network` (rendezvous timeout, SOCKS "general failure" 0x01 and "host unreachable" 0x04 count; a refused loopback connection or a bad address does not); `tor::blocked_network_guidance` (platform-specific text); `platform::is_whonix`; doctor `Check::TorNetwork` (Warn) issued when the control port reports bootstrap below 100 %, falling back to the existing circuit check otherwise; an old Tor without the field raises nothing. `aska` CLI: `--tor-browser` global option; `send`/`post` and `receive` print the guidance once when every attempt failed with the blocked signature, then exit 4 as before; long help explains the behaviour. Tests: parser and classifier unit tests; a doctor integration test with a scripted control port at 5 %, 100 % and "field absent"; a CLI test against a SOCKS port whose Tor cannot reach anything (exit 4, guidance shown, one CONNECT per attempt), a negative check that an ordinary failure prints no bridge advice, and the `--tor-browser` selection and its conflict with `--socks`. Workspace: 98 tests, clippy clean.

# 8. Verification at M6 (platform validation)

In the Debian test VM, block outbound Tor with a local firewall rule for the duration of the test (test-only, on the tester's own machine) and confirm: with a control port configured, `aska doctor` shows the TorNetwork warning with the Debian direction; without one, `aska --relay <onion> receive` ends with the guidance after its attempts and exit 4; with Tor Browser connected through a bridge and left open, `aska --tor-browser --relay <onion> receive` fetches normally. On Tails and Whonix, confirm the direction names the tool that exists on that platform.

# 9. Boundaries

Aska's guidance addresses networks that censor Tor — the environment its users are designed for, and a standard, documented Tor use case. The client does not acquire bridges, does not probe or fingerprint the network it is on, and does not attempt to defeat any particular network's policy. On a network whose owner forbids Tor, such as an employer's, the correct response is to use another network; the client's messages do not suggest otherwise.

## Change log

- **v0.2 (30 Sep 2026):** added §5 GUI behaviour for D-16 (banner action, Settings → Tor, start-up probe) and §6a mobile/Windows implications with the RM-02 requirement (in-app bridge configuration mandatory where no external Tor exists).
- **v0.1 (30 Sep 2026):** first version; decision D-16 taken (option A), implementation and tests complete.
