# Aska — Legal Review Brief

## Version 0.1 — 5 October 2026 (Milestone M8; decision D-13, requirement OPS-06)

- **Purpose:** the questions the project needs answered by an independent legal reviewer before any release outside the circle, with an accurate description of what the software does and does not do, so that the answers rest on facts rather than on the project's own characterisation. Jurisdictions, per D-13: Sweden, the European Union, the United Kingdom and the United States (the owner's and the circle's situations).
- **What this brief is not:** it is not legal advice and it draws no conclusions. It was prepared by the developer (an AI system working under the owner's direction) and the owner; neither is a lawyer. Where it names a statute or doctrine it does so to point the reviewer at the question, not to answer it.
- **Gate (Prototype Plan M8):** legal sign-off on the distress function, Tor-only operation and possession risk per jurisdiction, before `v1.0.0-rc1`.

---

# 1. What the software does

**Aska** is a program a person runs on their own Linux computer to send a short note to another person so that it cannot be read by anyone else, cannot be traced to either of them, and leaves no copy anywhere afterwards.

1. The sender types a note. The program encrypts it into a fixed-size block of bytes that is indistinguishable from random data (4, 16 or 64 KiB). The encryption key is generated at random on the sender's machine and exists only in that program's memory.
2. The program sends the block, over the Tor anonymity network, to a **relay** — a small server program, run by the circle itself, reachable only as a Tor onion service. The relay stores the block in memory under a random 32-byte label for a period the sender chooses (one hour to seven days) and then deletes it. The relay keeps no log, writes nothing to disk, has no user accounts, and cannot decrypt anything it stores.
3. The sender gives the receiver the key by a channel of their own choosing: in person as a QR code or 24 English words; split into pieces for several people so that no single person can read the note (Shamir secret sharing); or — the "receiving key" path — the receiver has earlier published a public key, the sender encrypts to it, and nothing has to be handed over.
4. The receiver's program fetches the relay's whole store for that size class (so that the relay cannot tell which block interests whom), finds the block that opens with the key, shows the note on screen for a limited time, and then erases it. No file is written at any point; the program's memory is locked and wiped.
5. Optionally, the sender can require a passphrase to open the note, can add a **decoy** note that opens with a different passphrase, and can set a **distress passphrase**: a passphrase that, when entered, opens the decoy and at the same time destroys the key to the real note inside the receiver's program, so that the real note can no longer be read by anyone.

The circle is small and private: the relay is the circle's own server; there is no public service, no account, no company operating anything, no payment, no advertising, no analytics.

# 2. What the software does not do

- It does **not** store anything on the user's computer except, optionally, one encrypted settings file (relay addresses) at a path the user chooses. No history, no contacts, no keys, no cache, no log.
- It does **not** use the network except through Tor to onion addresses. It does not contact the developer or anyone else, does not check for updates, and sends no telemetry.
- It does **not** circumvent any network's policy: when a network blocks Tor, the program says so and points the user to the platform's own Tor connection tool; it does not obtain or configure Tor bridges itself and has no non-Tor fallback (D-16).
- The relay does **not** know who posts or fetches (Tor), cannot read what it stores, and keeps nothing after expiry. It is open source (AGPL-3.0) so that anyone running a modified relay must publish the modification.
- The distress function does **not** destroy anything on the relay or on anyone else's machine. It destroys a key inside the receiver's own running program, in the receiver's own memory, at the receiver's own choice to enter that passphrase. Before that moment the receiver could have read the note; after it, no one can. The relay's block expires on its own as it always would.
- The program does **not** hide its own existence. Its binary is identifiable; the hand-over material carries a recognisable prefix (`aska1…`); a user who wants to deny using it cannot rely on the software for that.

# 3. Cryptography facts the reviewer may need

Encryption is XChaCha20-Poly1305 with a key-committing construction; passphrases are stretched with Argon2id; the receiving-key path uses X-Wing, a hybrid of ML-KEM-768 (FIPS 203, the NIST post-quantum standard) and X25519. All algorithms are public, standardised or in IETF draft, implemented from open-source Rust libraries, and documented in the Block Format Specification. There is no key escrow, no recovery mechanism and no master key; the project cannot decrypt anything for anyone.

# 4. Questions for the reviewer

## 4.1 Compelled decryption and key disclosure

1. In each jurisdiction, can a user be compelled to produce a key or passphrase for an Aska note, and what are the consequences of inability to comply? Relevant facts: after a note has been read and closed, no key exists anywhere; before it is read, the receiver may hold a key they can produce; with Shares, no single person can produce the key alone; with a receiving key, the receiver's 24-word seed is a persistent key as long as they keep it (the program advises creating a new one for every note).
2. Does the existence of a **decoy** note change the analysis — in particular, is presenting a decoy under compulsion a distinct offence (false statement, obstruction, perverting the course of justice) in any of the four jurisdictions, and does it matter that the software makes decoy and real notes indistinguishable to a third party?
3. (UK specifically) How do RIPA 2000 Part III notices interact with a system in which the key genuinely no longer exists, and with a receiver who holds Shares insufficient to reconstruct it?

## 4.2 The distress function

4. If a user enters the distress passphrase while under legal compulsion to decrypt, is that act — destroying a key in their own program's memory — exposed to charges of destruction of evidence, obstruction, tampering or contempt in each jurisdiction? Does it matter whether a proceeding is already pending, anticipated, or neither?
5. Does **providing** software with such a function expose the author or distributor to liability (aiding, facilitating, "designed for" provisions), in any of the four jurisdictions? Relevant facts: the function acts only on the user's own ephemeral memory; it is documented; it is one of several protection levels; the software is distributed free, as open source, to a private circle.
6. Should the user documentation carry a specific warning about the legal position of using the distress function, and in what terms?

## 4.3 Tor-only operation and relay hosting

7. Is running a Tor onion service that stores encrypted blocks it cannot read, with no logs and no retention beyond expiry, lawful for a private individual or small group in each jurisdiction, and are there retention, registration or "intermediary" obligations (e.g. EU DSA scope for a private, non-commercial relay; UK Online Safety Act scope; Swedish BBS-lagen or equivalent) that could attach to the relay operator?
8. What liability does a relay operator bear for content they cannot read, posted by members of their own circle, and does the answer change if the relay is accidentally reachable by outsiders (the relay accepts posts from anyone who knows its onion address and can solve a proof of work)?
9. Is the use of Tor itself, or the fact that the software refuses to work without Tor, legally significant in any of the four jurisdictions (e.g. as an aggravating circumstance, as an indicator relied on in investigations, or under any anti-anonymity provision)?

## 4.4 Possession, distribution and export

10. Is possessing or using the software lawful for a private individual in each jurisdiction, and are there circumstances (e.g. certain employments, border crossings, bail or licence conditions) where possession of a tool of this kind carries risk the documentation should warn about?
11. Export and import controls: the software implements strong cryptography and is published as open source. The project's understanding — to be confirmed — is that publicly available open-source cryptographic software falls under the EU dual-use regulation's and the US EAR's publicly-available / published-source provisions (US: 15 CFR 742.15(b) notification for ECCN 5D002 source); the reviewer is asked to state what, if anything, must be done (notifications, notices in the repository) before public release, for each jurisdiction.
12. Does distributing the software to a circle that includes people in the US and in Sweden/EU change anything in 10–11?

## 4.5 Data protection

13. Does the GDPR (or UK GDPR) apply to the relay or to the client, given that the relay processes only random labels and ciphertext it cannot read and retains nothing, and that no natural person is identifiable to the operator? If it does, what are the minimal obligations?
14. The receiving key is public and may be published by a user alongside their name. Does the software's design create any obligation for the project (as opposed to the user) in that respect?

## 4.6 Licences and attribution

15. The client crates are MIT OR Apache-2.0; the relay is AGPL-3.0; dependencies carry their own licences (lists in the review package). Please confirm the combination is coherent, that the AGPL on the relay achieves the intended effect (a modified relay offered as a network service must publish its source), and that the chosen licence texts and notices are complete for distribution.

## 4.7 Residual

16. Anything in §1–§3 that, in the reviewer's judgement, creates a legal exposure the project has not asked about.

# 5. Material

The Decision Record and Threat Model v0.3 (what is claimed and against whom), the Client Design v0.5 §7 (residual risks) and §8 (platform procedures), the Research Report v0.1 §3.2 (the project's own early survey of the legal landscape, which this brief supersedes as the statement of questions), and the Security Review Package v0.1 for the technical facts.

# 6. How the answers are used

Each answer is recorded as a numbered decision or constraint in the Decision Record v0.4 (D-13 closure). Where the answer requires a change — a warning in the documentation, a change of default, a notification before publication — it becomes a release-checklist item (Release Checklist v0.1 §3). Where the answer is "lawful but with risk", the risk is stated in the user documentation in the reviewer's words.
