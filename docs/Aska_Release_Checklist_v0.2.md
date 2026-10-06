# Aska — Release Checklist

## Version 0.2 — 6 October 2026 (Milestone M8 → `v1.0.0`; then every release)

- **Purpose:** the single list that must be complete before a release is given to anyone outside the development pair. It gathers the gates scattered across the Prototype Plan (M6, M7, M8), the Decision Record (OPS-01…OPS-07, D-13), the Platform Validation Checklists (§8 records) and `docs/RELEASING.md`, and it records who did what, when. A release candidate (`-rc`) must pass §1–§5; a final release additionally §6.
- **How to use:** copy this file to `docs/releases/<tag>-checklist.md`, fill the *Result* column with pass / fail / n/a and a date and initials, attach evidence where the row asks for it. A row marked **GATE** blocks the release when it fails; other rows are recorded and may be accepted by the owner with a written rationale.
- **State at v0.2 (for `v1.0.0`):** rows already satisfied are marked ✔ with their evidence. **Owner decision 2026-10-06:** the first public release is `v1.0.0`, without the external security review (§4.1–4.6) and the legal review (§5) — those gates are **waived for 1.0.0 by the owner** and stay in this list as open rows for the next release; the README, `SECURITY.md`, the User Guide and the announcement state the absence of both reviews. The developer's recorded recommendation was a 0.2.0 labelled "not independently reviewed". Releasing is done in five steps, each finished before the next: (1) documentation ✔ 6 Oct, (2) release metadata ✔ 6 Oct, (3) signed build by the owner, (4) platform gate A + B on the signed tarball, (5) publication on GitHub (`https://github.com/secunos/aska`).

---

# 1. Code and tests (every release) — owner or developer

| # | Item | Gate | Evidence | Result |
|---|---|---|---|---|
| 1.1 | Working tree clean at the tag; tag annotated; `git describe` prints the tag | GATE | `release.sh` refuses otherwise | ✔ alpha |
| 1.2 | `cargo test --workspace --release` all green (116 + 2 ignored at alpha; record the counts) | GATE | test output | ✔ alpha |
| 1.3 | `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check` clean | GATE | CI | ✔ alpha |
| 1.4 | `repro-build.sh && repro-build.sh --compare` → `REPRODUCIBLE: OK` on the build machine | GATE | `release.sh` output | ✔ alpha |
| 1.5 | `no-writes-check.sh`, `no-file-writes-client.sh`, `no-file-writes-cli.sh`, `no-file-writes-gui.sh` → OK | GATE | CI / local run | ✔ alpha (CI) |
| 1.6 | `timing-parity.sh` → `TIMING-PARITY: OK` (both ignored tests; record the p-values) | GATE | output | ✔ alpha (p = 0.62 / 0.78) |
| 1.7 | `memory-gate-gui.sh` → `MEMORY-GATE (GUI): OK`; core memory gate in the test run | GATE | output | ✔ alpha |
| 1.8 | Doctor trigger matrix CI test green (`doctor_findings_fire_on_their_triggers_and_stay_silent_otherwise`) | GATE | CI | ✔ alpha |
| 1.9 | `cargo audit` (RustSec) and `cargo deny` run; no unaddressed advisory on a crate in the Security Review Package §3 | GATE | report in `docs/review/` | ✔ `cargo audit` 5 Oct 2026: 168 crates, no advisories (`docs/review/cargo-audit-2026-10-05.txt`); ✔ `cargo deny check` 6 Oct 2026: advisories, bans, licences, sources all ok (`docs/review/cargo-deny-2026-10-06.txt`, policy `deny.toml`); both in CI (`supply-chain` job) |
| 1.10 | Dependencies vendored (`cargo vendor`) and the vendored tree hashed in the release record (OPS-04) | — | `VENDOR-HASH` line | ✔ `scripts/vendor-hash.sh` (deterministic SHA-256 over the vendored tree, 163 crates); printed into `RELEASE-NOTES.txt` by `release.sh` and run in CI; the tree itself is not committed |
| 1.11 | Version bumped in `Cargo.toml` (workspace) to the release version; `aska --version`, GUI footer and `README.txt` agree | — | diff | ✔ 1.0.0 (6 Oct 2026); `repository = https://github.com/secunos/aska`; crates `publish = false` |
| 1.12 | README status paragraph and `docs/` versions current; the three specifications at the versions the Decision Record names | — | docs | ✔ README user section, `LICENSE.md`, `SECURITY.md`, User Guide v1.0, Relay Operator Guide v1.0 (6 Oct). ☐ The Decision Record still names Block Format draft 0.4: DR v0.4 / Client Design v0.6 / ADP draft 0.3 are deferred to after 1.0.0 by the owner's decision (the normative changes are in draft 0.5 and the Pre-Review Report) |

# 2. Build and signing (every release) — build: anyone; signing: owner

| # | Item | Gate | Evidence | Result |
|---|---|---|---|---|
| 2.1 | Built in the Debian 13 release container (`RELEASE_CONTAINER=1 scripts/release.sh <tag>`), toolchain exactly `rust-toolchain.toml` (1.95.0) | GATE | `RELEASE-NOTES.txt` toolchain line | ✔ v1.0.0 with rustc 1.95.0 on native Debian 13 (the container's distribution), not in the container — recorded deviation (`docs/releases/v1.0.0.md`) |
| 2.2 | A second build in the same container image by a different person matches `SHA256SUMS` byte for byte (independent rebuilder, Prototype Plan §1) | GATE for final; record for rc | rebuilder's `SHA256SUMS` | ☐ open |
| 2.3 | Signed by the owner's release key (`79AD6224AFF176C9`) on the owner's machine; secret key never on a shared folder or in CI | GATE | `release.sh --sign` output; key id in notes | ✔ v1.0.0 (6 Oct) |
| 2.4 | `release.sh --sign` ended with `aska verify → MATCH` | GATE | output | ✔ v1.0.0 |
| 2.5 | Independent verification with the public key only, on another machine: `sha256sum -c`, `minisign -V` × 4, `SHA256SUMS` inside the tarball, `bin/aska verify` → MATCH; no build-machine paths in the binaries | GATE | `docs/releases/<tag>.md` | ✔ v1.0.0 (developer, 6 Oct) |
| 2.6 | Rekor transparency entry recorded for the tarball signature (`release.sh --rekor`) and written into `RELEASE-NOTES.txt` | GATE from rc1 (OPS-03) | `REKOR.txt` | ☐ open — none for v1.0.0 (no `rekor-cli`); recorded in the release record |
| 2.7 | `RELEASE-NOTES.txt` complete: commit, toolchain, epoch, key id, file list, Rekor entry, verification instructions | GATE | file | ✔ v1.0.0 (commit 48e34b3, epoch, vendor hash, key id; Rekor "(filled in by --rekor)") |
| 2.8 | Release record `docs/releases/<tag>.md` written: hashes, who built, who signed, who verified, deviations | — | file | ✔ v1.0.0 |

# 3. Platform gate (rc1 and every release that changes `crates/`) — owner

All on the **signed tarball of this release**, following `Aska_Platform_Validation_Checklists_M6_v0.2`; record per-line results in `docs/releases/<tag>-platforms.md` using the §8 template.

| # | Item | Gate | Result |
|---|---|---|---|
| 3.1 | Checklist A on **Debian 13** (GNOME Wayland), A1–A21 including the real A17 (Xorg session) | GATE | ☐ not run on v1.0.0 — Debian 13 smoke test only (owner decision 6 Oct): install, verify MATCH, GUI send/receive, wrong passphrase, reachability ✔ |
| 3.2 | Checklist B on **Tails 7** from a USB stick, B1–B13, **zero deviations** (Prototype Plan M6 gate) | GATE | ☐ not run on v1.0.0 (owner decision 6 Oct) |
| 3.3 | Checklist C on **Qubes 4.3 simple mode** (disposable Whonix-Workstation), C1–C6 | GATE | ☐ not run on v1.0.0 (owner decision 6 Oct) |
| 3.4 | Checklist D on **Qubes 4.3 split mode** incl. KEM Blocks offline (`aska open … --receiving-seed`), D1–D6 | GATE | ☐ not run on v1.0.0 (owner decision 6 Oct) |
| 3.5 | Doctor trigger matrix (Checklists §6) walked on at least one platform; the two known-gap rows (portal recorder, AT-SPI) recorded as such | GATE | ☐ open |
| 3.6 | GUI visual checks (Checklists §7) | — | ☐ open |
| 3.7 | Findings from the runs fixed or accepted with rationale; the checklist document updated (§8 records, §9 gaps) | GATE | ☐ |

# 4. Security review — owner with the reviewer (**waived for 1.0.0 by owner decision 2026-10-06; open for the next release**)

| # | Item | Gate | Result |
|---|---|---|---|
| 4.0 | Internal pre-review run and its findings fixed or accepted (`Aska_Internal_PreReview_Report_v0.1`): 2 High + 11 Medium fixed, 3 owner acceptances recorded | — | ✔ 5 Oct 2026 (commits 2f80259…39d57bf) |
| 4.1 | Security Review Package v0.1 handed to the independent reviewer (OPS-05) with the material of its §1, plus the pre-review report | GATE | ☐ |
| 4.2 | Every **High** and **Medium** finding fixed (commit + test/gate) or accepted by the owner with a written rationale in the Decision Record | GATE | ☐ |
| 4.3 | Low and Informational findings answered (fixed, accepted, or scheduled with a version) | — | ☐ |
| 4.4 | The reviewer's report published with the release (redactions only for unfixed items, by agreement) | — | ☐ |
| 4.5 | Specifications re-issued with the review's changes: Decision Record v0.4, Block Format draft 0.5 (or v1.0 if frozen), ADP/1 draft 0.3, Client Design v0.6 | GATE | ☐ |
| 4.6 | The five highest-uncertainty items (Review Package §4 items 1–6) each have an explicit "confirmed / changed / accepted" line | GATE | ☐ |

# 5. Legal review — owner with the legal reviewer (**waived for 1.0.0 by owner decision 2026-10-06; open for the next release**)

| # | Item | Gate | Result |
|---|---|---|---|
| 5.1 | Legal Review Brief v0.1 handed to the reviewer(s) for Sweden, EU, UK and US (OPS-06, D-13) | GATE | ☐ |
| 5.2 | Sign-off on the **distress function** per jurisdiction (Brief §4.2) | GATE | ☐ |
| 5.3 | Sign-off on **Tor-only operation and relay hosting** (Brief §4.3) | GATE | ☐ |
| 5.4 | Sign-off on **possession and distribution**, incl. export/import notifications done if required (Brief §4.4) | GATE | ☐ |
| 5.5 | Required warnings written into the user documentation in the reviewer's words; required notices added to the repository | GATE | ☐ |
| 5.6 | Answers recorded in the Decision Record v0.4 (D-13 closure) | GATE | ☐ |

# 6. Final release only (`v1.0.0`) — owner

| # | Item | Gate | Result |
|---|---|---|---|
| 6.1 | All rc findings closed; no code change since the last full platform gate, or the gate re-run | GATE | ☐ |
| 6.2 | Fingerprints (tarball, `bin/aska-gui`), key id and Rekor entry handed to the circle **out of band** before the files are made available (Client Design §9.4) | GATE | ☐ |
| 6.3 | The relay operator(s) upgraded per `deploy/DEPLOY.md`; the onion address rotated if it was ever written down where it should not have been | — | ☐ |
| 6.4 | Hosting chosen and `repository` in `Cargo.toml` set; the release published as `dist/release/<tag>/` unchanged | — | ✔ GitHub `secunos/aska`; release page at publication |
| 6.5 | Announcement states what the release does **not** promise: residual risks (Client Design §7), known gaps (Review Package §6), "never install an update because software told you one exists", and the absence of independent security and legal review | — | ✔ draft `docs/ANNOUNCEMENT-1.0.0.md` (fingerprints filled at signing) |

# 7. Record

```
Release:            Tag:                Commit:
Built by / where:                         Toolchain:
Signed by (key id):                       Rekor:
Verified independently by / date:
Platform gate (A/B/C/D) dates and record files:
Security review: reviewer, report date, High/Medium open: 0
Legal review: reviewer(s), sign-off dates (distress / Tor / possession):
Owner's acceptances (Decision Record entries):
Signature of the owner:                                   Date:
```
