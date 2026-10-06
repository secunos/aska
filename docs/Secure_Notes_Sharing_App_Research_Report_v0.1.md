# Secure Notes Sharing App

## Research Report: How to design the most secure fire-and-forget information exchange (2026 state of the art)

- **Version:** 0.1 — research phase complete, design phase not started
- **Date:** 25 September 2026
- **Prepared for:** the project owner
- **Prepared by:** Claude (seven parallel research streams; ~600 tool calls against primary sources)
- **Status:** Working document. Claims flagged *[unverified]* rest on secondary sources or could not be confirmed and should be checked before being relied on.
- **Companion material:** the seven full research reports (Markdown) and STATE.md are saved next to this file in the project folder under *Research/*.

---

# 1. Executive summary

This report summarises an extensive research pass over the current (September 2026) state of the art in secure information exchange, carried out as the first step of the Secure Notes Sharing App project. The goal was to answer one question before any design work starts: **what does it actually take, in 2026, to exchange a note so that it is unbreakable (including against state-funded quantum computers), deniable, coercion-resistant, anonymous and untraceable once delivered?** Seven parallel research streams covered post-quantum cryptography, plausible deniability and coercion resistance, anonymity and metadata resistance, the commercial and open-source product landscape, forensic and law-enforcement case findings, pen-and-paper methods, and the four inspiration links plus endpoint security.

The single most important finding is that **in no documented case in the last decade was modern cryptography itself broken**. EncroChat, Sky ECC, ANOM, Ghost, MATRIX, the Cuban and Russian spy rings, Silk Road, the Boystown Tor case and the 2026 *US v. Sharp* Signal case were all won by attacking the endpoint, the operator or supply chain, metadata and timing, residual data the user believed was gone, or human error. The consequence for this project is stark: the ciphertext is the easiest part. The hard part is making sure that nothing else exists — on the sender's device, the receiver's device, the server, or the paper — before, during or after the exchange.

> **Ten findings that should shape the design**
>
> 1. **Cryptography is a solved problem if we stay symmetric or hybrid.** AES-256 / XChaCha20 with 256-bit random keys is already quantum-safe (Grover gives at best a quadratic speed-up). Where public-key is unavoidable, the 2026 consensus is a *hybrid* KEM (X25519 + ML-KEM-768, e.g. X-Wing, now in libsodium 1.0.22 and age 1.3), never raw ML-KEM alone. BSI, ANSSI, NCSC and the EU roadmap all recommend hybrids; NIST IR 8547 deprecates RSA/ECC in 2030 and disallows them in 2035.
>
> 2. **The quantum threat has moved closer in 2026.** Gidney (May 2025) cut RSA-2048 to under 1 million noisy qubits; Google (March 2026) estimates 256-bit ECC key recovery with under 500 k physical qubits in about 9 minutes; expert surveys give a 28–49 % probability of a cryptographically relevant quantum computer within ten years. ECC is now cheaper to break than RSA, so X25519-only key agreement is the first thing to retire. "Harvest now, decrypt later" means anything transmitted today with classical key exchange should be assumed readable in the 2030s.
>
> 3. **One-time pads and Shamir secret sharing are the only unconditionally secure tools** — their security does not rest on any computational assumption and is therefore immune to quantum computers by construction. Both are practical on paper. Everything else that can be done by hand (Solitaire, LC4, VIC, book ciphers) only *looks* secure.
>
> 4. **Cryptographic deniability is weaker than it sounds; structural deniability is stronger.** Canetti-style deniable encryption has a proven polynomial security ceiling and no implementations. Anamorphic encryption (2022–2026) is the most promising modern primitive but has no audited library. Hidden volumes (VeraCrypt, Shufflecake) are single-snapshot only and routinely defeated by OS leakage. What works in practice is *absence*: no accounts, no logs, no persistent keys, ciphertext indistinguishable from random, fixed-size blocks with decoy slots (the Superbacked/Blockcrypt pattern), and a server that holds nothing tying a blob to a person.
>
> 5. **The post-quantum transition is eroding deniability in messaging.** Signal's PQXDH signs its KEM prekey and thereby loses the deniability X3DH had (Fiedler–Janson 2024; Katsumata et al. USENIX Security 2025). Deniable PQ handshakes exist in the literature (K-Waay split-KEM, USENIX Security 2024; Sparrow-KEM 2025) but are not deployed. Rule for this project: **no long-term signatures anywhere on the wire**; authenticate with KEM-derived or symmetric MACs.
>
> 6. **Coercion resistance comes from making compliance impossible, not from bravery.** Two mechanisms do this: (a) k-of-n threshold custody of the key so no single person can decrypt, ideally threshold *decryption* so the key is never reassembled; and (b) "nothing to give" — per-note ephemeral keys destroyed at read time, so after delivery nobody, including the sender, can decrypt. Deniable secret sharing (TCC 2025) shows a lone coerced share-holder cannot fake a share; only a qualified majority can lie coherently. Duress PINs (GrapheneOS) and auto-reboot to before-first-unlock are the strongest shipped endpoint defences.
>
> 7. **The law is the binding constraint, not the mathematics.** UK RIPA s.49 jails people for refusing to decrypt (2–5 years); US courts split on compelled biometrics (Payne 9th Cir. 2024 vs Brown D.C. Cir. 2025); Sweden's bill Ju2024/02286 would compel messaging providers to hand over E2EE content; EU "chat control 1.0" was extended to April 2028 (currently excluding E2EE). Courts in the UK, Germany, the Netherlands and the CJEU (C-670/22) have all admitted evidence obtained by hacking. A design only survives all of this if no single human — sender, receiver or operator — retains anything that could be surrendered.
>
> 8. **Anonymity at scale is still research-grade; the practical sweet spot is a dead drop with broadcast-style retrieval.** Tor is the only mature low-latency system but does not resist a global passive adversary doing timing correlation, and long-lived onion identities are guard-discovery targets. Mixnets (Nym, Katzenpost/Echomix) are slow and not yet public at scale. A fixed-size encrypted blob posted under a random ID via Tor, retrieved by downloading the whole recent bucket, gives receiver anonymity by construction and is deployable today.
>
> 9. **Web-delivered JavaScript cannot be the trust root.** A coerced or compromised server, CDN or phishing clone (the Privnote clone case) can serve malicious code to one user with no audit trail. Signal refuses to ship a web client for this reason. The app must be native-first with reproducible, publicly logged builds; any web front end is a convenience layer, not the security boundary.
>
> 10. **The endpoint is where designs die.** Signal messages were recovered in 2026 from Apple's notification cache after deletion and uninstall; Cellebrite extracts most After-First-Unlock phones; Paragon Graphite and the 2026 Coruna/DarkSword kits compromise phones with zero clicks. The only devices that consistently resist forensic extraction are GrapheneOS Pixels and iPhones in Lockdown Mode with auto-reboot to BFU and a long alphanumeric passcode. The app must render plaintext in memory only, never write it to disk, exclude itself from backups, block screenshots and notifications, and treat "disappearing" as a UX promise unless creation of copies is prevented.

On the basis of these findings, Section 5 proposes three candidate architectures — a paper-first information-theoretic design, a digital fire-and-forget dead drop, and a layered hybrid that combines them — and Section 6 lists the decisions needed before design work starts. The preliminary recommendation is the **layered hybrid**: a digital dead-drop core using hybrid post-quantum encryption and threshold key custody, with an optional paper path (printed one-time pad or Shamir key shares) for the highest-threat scenarios, all wrapped in a native, reproducibly built, amnesic client. Section 7 lists every claim that could not be verified against a primary source.

# 2. Scope, requirements and threat model

## 2.1 What the project is trying to achieve

The project brief asks for a way to share notes or information "in the most secure way that is possible", with no traceability once the information has been communicated, protected by quantum-safe cryptography, with the ability to deny knowledge of the information or of having taken part in the exchange — "essentially fire and forget". Two additional constraints were added in the research brief: it must be impossible to force a single person to give up the secret under threat, because the logical design must make one person's knowledge insufficient; and it must be very anonymous in nature. Both online and real-world (pen-and-paper) exchange are in scope.

## 2.2 Requirements as understood from the brief

| ID | Requirement | What it means concretely (research interpretation) |
|---|---|---|
| R1 | Unbreakable confidentiality | Content unreadable to anyone but the intended receiver; withstands brute force and state-funded quantum computers for the foreseeable future (assume 30+ years of secrecy). |
| R2 | Integrity | Receiver can detect tampering; an attacker cannot alter a note undetectably (often forgotten in "just encrypt it" designs). |
| R3 | Plausible deniability (content) | A coerced party can produce an innocuous decryption, or the existence of a real note cannot be proven. |
| R4 | Plausible deniability (participation) | No transcript, signature, log or identifier proves that a given person sent or received anything. |
| R5 | Coercion resistance | One person's knowledge is insufficient by design (k-of-n control), and/or after delivery nobody retains anything that can be surrendered. |
| R6 | Untraceability / fire-and-forget | After the exchange there is no residue on server, devices or paper; no timestamps, IPs, accounts or read receipts survive. |
| R7 | Anonymity | No phone numbers, e-mail addresses, accounts or persistent identifiers; network-level unlinkability of sender and receiver. |
| R8 | Offline / paper path | A mode that works with pen and paper (or paper plus an air-gapped device) for when no trusted computer or network exists. |
| R9 | Usability | Usable by non-cryptographers without fatal mistakes; the design, not user discipline, must prevent the classic failures. |

## 2.3 Adversary model used in this research

The research assumed the strongest realistic adversary: a well-funded state actor with (a) a future cryptographically relevant quantum computer and the ability to record all traffic today; (b) lawful and unlawful access to servers, hosting providers and ISPs, including compelled logging and secret notices; (c) commercial forensic tooling (Cellebrite, GrayKey, Magnet) and mercenary spyware (Pegasus, Paragon Graphite, Coruna/DarkSword) against endpoints; (d) the legal power to compel keys and passcodes and to punish refusal; and (e) physical coercion of one participant at a time. What this adversary is *not* assumed to have is the ability to coerce all key holders simultaneously, to break AES-256 or SHA-3, or to have already implanted every participant's device before the exchange. Where a mechanism only holds against a weaker adversary (for example a single-snapshot forensic image), the report says so.

## 2.4 Method

Seven research agents ran in parallel, each with a defined scope, instructed to prefer primary sources (NIST, IETF, IACR ePrint, USENIX/IEEE/ACM proceedings, vendor security documentation, court records, Europol/DOJ releases, Citizen Lab, Amnesty Security Lab) and to flag anything that could not be verified. Roughly 600 searches and page fetches were performed. Each stream produced a 2,500–4,000-word report with a source list; those reports are preserved in full in the project folder and are the basis for this summary. Video content from YouTube could not be retrieved; only titles and channel were confirmed.

# 3. What the research found

## 3.1 Cryptography in 2026: standards, quantum threat and design consequences

### Post-quantum standards and mandates

NIST finalised the first three post-quantum standards in August 2024: **FIPS 203 ML-KEM** (key encapsulation, formerly Kyber), **FIPS 204 ML-DSA** (signatures, formerly Dilithium) and **FIPS 205 SLH-DSA** (hash-based signatures, formerly SPHINCS+). Two more are still in the pipeline: **FN-DSA (Falcon, FIPS 206)** has still not appeared even as a draft as of 25 September 2026, and **HQC-KEM (FIPS 207)**, selected in March 2025 as a code-based backup to ML-KEM, is expected as a draft in 2026 and final in 2027. NIST's additional-signature "on-ramp" advanced nine candidates to Round 3 in May 2026 (HAWK, SQIsign, FAEST, MQOM, SDitH, UOV, MAYO, QR-UOV, SNOVA); no standard is expected before about 2028. NIST SP 800-227 (September 2025) gives the formal guidance on using KEMs and combiners.

On the deprecation side, NIST IR 8547 proposes that RSA-2048 and 112-bit-strength curves be deprecated after 2030 and that **all** quantum-vulnerable public-key algorithms (RSA, ECDSA, EdDSA, ECDH) be disallowed after 2035. NSA's CNSA 2.0 requires ML-KEM-1024, ML-DSA-87, AES-256 and SHA-384/512, with new national-security acquisitions required to comply from 1 January 2027. In Europe, the EU Coordinated Implementation Roadmap (June 2025) wants every Member State transitioning by end 2026 and high-risk systems migrated by 2030; Germany's BSI (TR-02102-1, January 2026) raised its baseline to 120 bits and recommends FrodoKEM, Classic McEliece and ML-KEM, always in hybrid; ANSSI strongly recommends hybrids for anything protecting data beyond 2030; the UK NCSC set milestones of 2028, 2031 and 2035. The practical consensus: **use ML-KEM-768 or -1024 in a hybrid with X25519; nobody objects, and most European authorities require it.**

### Hybrid key exchange has become the default in production

Hybrid post-quantum key exchange is no longer experimental. RFC 10024 (August 2026) standardises X25519MLKEM768 for TLS 1.3; it is on by default in Chrome, Edge, Firefox, Safari (iOS/macOS 26), OpenSSH (since 9.9), Go 1.24 and OpenSSL 3.5, and Cloudflare reported more than 60 % of client traffic using it by early 2026. RFC 9980 (June 2026) brings composite ML-KEM + ECC and ML-DSA + EdDSA keys to OpenPGP and explicitly forbids standalone ML-KEM. **X-Wing** — ML-KEM-768 combined with X25519 through a SHA3-256 combiner, with a 1,216-byte public key and 1,120-byte ciphertext — is the CFRG's general-purpose hybrid KEM and shipped in libsodium 1.0.22 (April 2026), which calls it "the recommended KEM for most applications". Filippo Valsorda's **age** file-encryption tool added native post-quantum recipients in v1.3.0 (December 2025) using HPKE with hybrid ML-KEM-768 — a small, opinionated reference design very close to what a notes app needs.

In messaging, Signal deployed **PQXDH** (2023) for the initial handshake and, on 2 October 2025, the **Sparse Post-Quantum Ratchet (SPQR, "Triple Ratchet")**, which adds an ML-KEM-768 ratchet running alongside the classical Double Ratchet, with erasure-coded key material spread across messages and the whole thing formally verified in ProVerif and F*. Apple's iMessage PQ3 (2024) rekeys with ML-KEM every ~50 messages or 7 days. Tuta and Proton Mail moved e-mail to hybrid ML-KEM in 2026. SimpleX uses sntrup761 in its ratchet. WhatsApp, Threema and Wire have not confirmed PQ in production.

### How close is the quantum threat?

| Date | Work | Result |
|---|---|---|
| 2019 | Gidney & Ekerå | RSA-2048 in 8 hours with ~20 million noisy qubits. |
| May 2025 | Gidney, arXiv 2505.15917 | RSA-2048 in under a week with **fewer than 1 million** noisy qubits (0.1 % gate error). |
| Feb 2026 | Iceberg Quantum "Pinnacle" *[secondary]* | Under 100 k physical qubits using qLDPC codes, but requires non-planar connectivity unproven at scale. |
| Mar 2026 | Chevignard, Fouque, Schrottenloher (Eurocrypt 2026) | P-256 discrete log with ~1,193 logical qubits (down from 2,124). |
| 30 Mar 2026 | Google Quantum AI whitepaper | 256-bit ECC key recovery with **under 500 k physical qubits in ~9 minutes**; circuits withheld, correctness attested by a zero-knowledge proof; not peer-reviewed. |
| Mar 2026 | Global Risk Institute expert survey (26 experts) | Probability of a cryptographically relevant quantum computer: **28–49 % within 10 years, 51–70 % within 15 years**; timeline judged to be accelerating. |

*Table 1 — Quantum resource estimates and timelines as of September 2026.*

Current hardware (Google Willow 105 qubits, Quantinuum Helios 98 ions / 48 logical qubits, IBM Nighthawk 120 qubits, neutral-atom arrays of 3,000–6,000 atoms) remains three to four orders of magnitude below what is needed, but the required qubit count has fallen roughly 20–200× in seven years and **elliptic-curve cryptography is now cheaper to break than RSA**. For this project the conclusion is not subtle: any note whose secrecy must outlast the early 2030s must not depend on X25519 or any other classical public-key primitive alone.

### Symmetric cryptography and information-theoretic security are safe

Grover's algorithm gives at most a quadratic speed-up against symmetric ciphers and hash functions, and NIST notes it "will provide little or no advantage in attacking AES" because it cannot be efficiently parallelised. AES-256, XChaCha20 and 256-bit hashes (SHA-256, SHA3-256, BLAKE2/3) are the conservative choice and are what CNSA 2.0 mandates. More importantly for this project, **the one-time pad and Shamir secret sharing are information-theoretically secure**: their security proofs make no assumption about the attacker's computing power, so they are immune to any quantum or future computer, provided the key material is truly random, never reused and delivered out of band. A design in which a random 256-bit note key is split with Shamir and delivered over separate channels involves no public-key cryptography at all and is quantum-safe by construction.

### Weaknesses, breaks and implementation lessons

Two of NIST's later-round candidates were destroyed by classical mathematics: SIKE (Castryck–Decru, July 2022, broken in ten minutes on one core) and Rainbow (Beullens, 2022, 53 hours on a laptop). This is the strongest argument for hybrids and for diversity of assumptions. Implementation risk is real as well: KyberSlash (2023–24) was a secret-dependent timing leak in the Kyber reference code and derivatives; power-analysis and template attacks on ML-KEM decapsulation were published in 2024–25; liboqs's HQC had a timing flaw (CVE-2025-52473). The lesson is to use **formally verified or heavily reviewed libraries** — libcrux (Cryspen, used by Signal), mlkem-native, BoringSSL/AWS-LC, Go's crypto/mlkem, libsodium 1.0.22 — and to build in **crypto agility** (algorithm identifiers in headers) so that a broken component can be replaced.

Two further details matter for a notes app specifically. First, the common AEADs (AES-GCM, ChaCha20-Poly1305, AES-GCM-SIV) are **not key-committing** (RFC 9771, 2025): a ciphertext can be crafted to decrypt validly under two different keys, which is exactly the property a decoy-secret design touches. Any container that can be opened with more than one passphrase must add explicit key commitment (a hash of the key, or an HMAC-then-encrypt construction). Second, **deniability and post-quantum signatures are in tension**: ML-DSA and SLH-DSA are non-repudiable, and the academic literature (Section 3.2) shows even PQXDH's signed prekey costs deniability. The 2026 recommendation is to authenticate with KEM-derived or symmetric MACs and to never put a long-term signature on the wire.

> **Recommended 2026 cryptographic stack (to be confirmed in design)**
>
> • 256-bit keys throughout; XChaCha20-Poly1305 (192-bit nonce) or AES-256-GCM-SIV as the AEAD, with explicit key commitment.
>
> • HKDF-SHA-512 or SHAKE256 for key derivation; Argon2id (RFC 9106, ≥ 64 MiB–1 GiB memory) for any passphrase.
>
> • X-Wing (X25519 + ML-KEM-768) via libsodium 1.0.22 / libcrux for any online key exchange; a fresh ephemeral key pair per note, zeroised after use.
>
> • No signatures on the wire; implicit (KEM-based) or symmetric-MAC authentication only.
>
> • Optional information-theoretic path: random note key split k-of-n with Shamir and delivered over independent channels or on paper.
>
> • Versioned headers / algorithm identifiers for agility; FN-DSA and HQC treated as "not yet final".

## 3.2 Plausible deniability and coercion resistance

### Deniable encryption: strong in theory, absent in practice

The classical notion of deniable encryption (Canetti, Dwork, Naor, Ostrovsky, CRYPTO 1997) lets a coerced party produce fake randomness or keys that "explain" a ciphertext as any chosen message. Its limits are now well understood: Bendlin et al. (ASIACRYPT 2011) proved that **no non-interactive receiver-deniable scheme can achieve better than polynomial security**; fully deniable schemes need interaction and indistinguishability obfuscation (Canetti, Park, Poburinnaya, CRYPTO 2020). Nothing shippable exists, and nothing is expected to.

The more promising modern line is **anamorphic encryption** (Persiano, Phan, Yung, EUROCRYPT 2022), designed for a "dictator" who can demand your private key and dictate what you encrypt: a ciphertext decrypts to a cover message under the surrendered key and to the real message under a second, pre-shared "double key". The field has matured rapidly — robust definitions (Banfi et al., EUROCRYPT 2024), CCA-secure and multi-message constructions (two CRYPTO 2026 papers), anamorphic signatures, and in 2026 *anamorphic secret-sharing signatures* (Avitabile, Botta, Friolo) that hide threshold shares inside ordinary signatures — which is essentially requirements R3 and R5 in one primitive. The caveats are that the double key must itself be pre-shared and hidden (the problem regresses one level), that generic black-box constructions are impossible (Catalano et al. 2025), that a regulator could mandate "anamorphic-resistant" schemes (Carnemolla et al. 2025), that robust constructions specifically over ML-KEM have not been shown *[unverified]*, and that **no audited implementation exists**. Anamorphic techniques are a candidate for a later iteration, not for version one.

### Hidden volumes and deniable storage: weaker than advertised

TrueCrypt/VeraCrypt hidden volumes and hidden operating systems, and the newer Shufflecake (CCS 2023, Linux), provide deniability only against a *single-snapshot* adversary and only if the rest of the system does not tattle. Czeskis et al. (USENIX HotSec 2008) showed Windows shortcut files, Word auto-recovery files and desktop-search caches all reveal the hidden volume's existence. A June 2026 VeraCrypt advisory (GHSA-jjcr-75w7-58jp) disclosed that versions 1.26.6–1.26.28 wrote zeroed sectors every 128 MiB inside file-hosted hidden volumes, producing a forensically detectable pattern. The PETS 2022 systematisation of deniable storage concludes that no practically efficient construction achieves multi-snapshot deniability, and that even *hiding the fact that a deniability system is installed* remains open. Steganography via generative models (Meteor 2021, Pulsar 2024, LLM-based schemes 2025–26) is provably secure only under strong shared-model assumptions and yields a few bits per token. **Conclusion: do not build deniability on hidden storage on the user's device; build it on absence** — store nothing, and make what is transmitted indistinguishable from random.

### Deniability in messaging is being eroded by the PQ transition

OTR (2004) pioneered deniable authentication by using MACs instead of signatures and publishing MAC keys after use; Signal's X3DH inherited "offline" deniability (a judge who sees only transcripts and long-term keys cannot tell who wrote what). Signal's PQXDH signs its ML-KEM prekey with the long-term identity key, and two independent analyses — Fiedler & Janson (2024) and Katsumata, Niot, Tucker & Wiggers (USENIX Security 2025) — show it **does not** retain X3DH's deniability. The literature already contains fixes: K-Waay (USENIX Security 2024) achieves a deniable post-quantum X3DH from a "split-KEM" without ring signatures, and Sparrow-KEM (AsiaCCS 2025) makes it 40× faster; deniable ring signatures from Falcon and MAYO offer another route. None is deployed. Message franking — deliberately making messages attributable to a moderator — is the anti-pattern and conflicts directly with participation deniability; any abuse-reporting regulation would push in that direction.

### Legal reality: where cryptography stops

| Jurisdiction | Rule | Consequence for design |
|---|---|---|
| United Kingdom | RIPA 2000 s.49/53: a notice compels a key or plaintext; refusal is a crime (2 years; 5 for national security / child cases). Convictions include Drage (2010), Nicholson (2018), Finch (2021, sentence doubled for refusing). | "I refuse" is not a defence. "I never had a key" must be literally true — no persistent key the user could be ordered to produce. |
| United States | Memorised passcodes are generally testimonial (State v. Valdez, Utah 2023). Biometrics split: US v. Payne (9th Cir. 2024) compelled thumbprint is non-testimonial; US v. Brown (D.C. Cir. 2025) compelled fingerprint is testimonial. Supreme Court outcomes *[unverified]*. | Passcode-only unlock, no biometrics; auto-reboot to before-first-unlock so keys are not resident. |
| Sweden | No general key-disclosure duty for suspects reported *[not re-verified]*; covert data reading (hemlig dataavläsning, 2020:62) allows police to implant tools. Bill Ju2024/02286 would compel number-independent messaging services to retain and hand over content incl. E2EE; Signal said it would leave; the Armed Forces opposed it. Outcome after the 2026 election *[unverified]*. | Assume providers can be compelled; the server must have nothing to hand over. Endpoint implants are lawful — the endpoint model must assume compromise. |
| European Union | Regulation (EU) 2026/1881 (in force 31 July 2026) extends voluntary CSAM detection to 3 April 2028 and expressly excludes E2EE and forbids client-side scanning of it; the mandatory "chat control 2.0" CSAR remains in trilogue. ECtHR *Podchasov v. Russia* (2024): weakening E2EE is not necessary in a democratic society. CJEU C-670/22 (2024): EncroChat hacked data admissible. | E2EE is currently protected but the political direction is towards scanning; the design must not have a natural place to insert a scanner (no plaintext on any server, no accounts to attach obligations to). |

*Table 2 — Compelled-decryption and interception law, 2026.*

### What actually resists coercion

The research converges on two mechanisms. The first is **multi-party control**: Shamir k-of-n secret sharing is information-theoretically hiding below the threshold, and threshold *decryption* goes further by never reassembling the key at all. NIST's multi-party threshold call (IR 8214C, 2025) explicitly includes threshold ML-KEM, but no standardised, audited post-quantum threshold library exists yet (expected around 2027); classical threshold decryption is mature. Bitcoin practice offers a useful analogy: m-of-n multisig (keys never combined) is strictly stronger against coercion than secret sharing with reconstruction, and SLIP-39 and codex32 are mature share formats. Deniable secret sharing (Canetti et al., 2025) adds an important negative result: a single coerced share-holder cannot produce a convincing fake share; only a qualified majority can lie coherently. Time can also be a custodian: timelock encryption (drand tlock) or verifiable delay functions can make a note undecryptable by anyone, including the sender, until a chosen time.

The second mechanism is **"nothing to give"**: per-note ephemeral keys, burn-on-read, immediate zeroisation and cryptographic erasure. If the sender never stores the key, the server holds only ciphertext, and the receiver decrypts in memory and the server deletes on first fetch, then after delivery no party can comply with a demand, however forceful. The 2026 systematisation of cryptographic erasure formalises this (Destruction-IND) and notes the one weak point: deletion is only as good as the erasure of every key copy, and flash storage is unreliable for overwriting (Wei et al. 2011 found 4–75 % of "securely erased" data recoverable). The answer is never to write plaintext or keys to persistent storage in the first place, and to bind any wrapped key to a hardware enclave whose destruction is instantaneous.

Deployed duress features complete the picture: GrapheneOS's duress PIN irreversibly wipes the device (including eSIMs), its auto-reboot (default 18 h) returns the phone to before-first-unlock, and USB data is cut while locked; iOS 18.1 added a 72-hour inactivity reboot and Lockdown Mode. Two cautions apply: a wipe is itself evidence of destruction (an obstruction risk in many jurisdictions), and a duress code only helps if the coercer lets you type. A per-note "distress" key that returns a plausible decoy and silently destroys the real note is the note-level equivalent and is worth prototyping.

| Mechanism | Deniability / coercion strength | Usability | Maturity | Verdict for this project |
|---|---|---|---|---|
| Canetti-style deniable PKE | 2 (polynomial ceiling) | 1 | 1 | Not usable. |
| Anamorphic encryption (robust, CCA, 2024–26) | 3 | 2 | 2 | Watch; candidate for later iteration; no audited code. |
| VeraCrypt hidden volume / Shufflecake | 2 | 3 | 3–5 | Do not rely on; single-snapshot, OS leakage. |
| OTR / X3DH offline deniability | 3 | 5 | 5 | Model to emulate: MACs not signatures. |
| K-Waay / Sparrow-KEM deniable PQ AKE | 4 | 3 | 2 | Proven, fast, not deployed; candidate if interactive handshake is needed. |
| Shamir k-of-n custody (SLIP-39, codex32) | 4 (coercion) / 1 (deniability) | 3 | 5 | Core building block; add share verification; reconstruction is a single point. |
| Threshold decryption (classical) | 5 (coercion) | 3 | 4 | Strongest custody model; key never assembled. |
| Threshold ML-KEM | 5 (coercion) | 2 | 1–2 | Await NIST process (~2027). |
| Timelock encryption (drand tlock) | 4 until T | 4 | 4 | Optional; not PQ; trust in beacon network. |
| Ephemeral key + burn-after-read + crypto-erase | 5 ("nothing to give") | 5 | 5 | **Foundation of the design.** |
| Multi-secret decoy container (Blockcrypt-style) | 3–4 | 4 | 3 | Include; document the deniability asymmetry honestly. |
| Duress PIN / auto-reboot to BFU (GrapheneOS, iOS) | 3 | 4 | 5 | Recommend as endpoint hygiene. |
| Oblivious dead drop / mixnet delivery | 4 (unlinkability) | 3 | 2–3 | Tor-based dead drop now; mixnet later. |
| One-time HTTPS link (Privnote model) | 1 | 5 | 5 | Baseline to beat; logs link parties. |

*Table 3 — Deniability and coercion-resistance mechanisms rated 1 (weak) to 5 (strong).*

## 3.3 Anonymity and metadata resistance

### Network layer: Tor, mixnets and broadcast

Tor remains the only mature low-latency anonymity network. Version 3 onion services, the Arti Rust rewrite (2.6.0, September 2026), proof-of-work DoS defence (since 0.4.8) and vanguards against guard discovery are all in place. Its limits are equally clear: Tor does not resist a global passive adversary performing end-to-end timing correlation, and a long-lived onion identity that an adversary can repeatedly poke is a guard-discovery target — this is exactly how German police deanonymised a Boystown operator running an outdated Ricochet client (2021, reported 2024). Tor's own circuit handshakes are still classical, so post-quantum protection must live inside the application layer *[status unverified for late 2026]*. I2P (2.12.0, ~55,000 routers) added hybrid ML-KEM transport encryption in 2.10 but has a smaller audit base and makes every participant a relay.

Mixnets trade latency for resistance to global observers. Nym's own 2026 roadmap concedes the mixnet is "simply too slow for everyday usage"; Katzenpost/Echomix (2025) is the most relevant academic successor, with hybrid-PQ Sphinx packets, unlinkable message boxes (BACAP) and a "Pigeonhole" storage layer whose replicas cannot link a write to a read — the closest published match to a dead-drop note primitive — but its public network has not launched. Academic metadata-private messaging systems (Vuvuzela, Karaoke, Groove, Pung, Talek, Myco 2025) show that cryptographic receiver anonymity is achievable but at 30–60 second latencies and high server cost; the PoPETs 2024 systematisation concludes no system yet combines low latency, asynchrony and horizontal scalability.

| Primitive | Latency | Resists global passive adversary | Receiver anonymity | Real deployments |
|---|---|---|---|---|
| Low-latency onion routing (Tor, I2P) | 0.5–2 s | No (timing correlation) | Yes via onion/rendezvous | Tor, I2P (millions) |
| Mixnet + cover traffic (Nym, Katzenpost) | seconds–minutes | Yes (statistical) | Weak unless mailbox layer | NymVPN; Katzenpost pre-launch |
| DC-nets | rounds | Yes (perfect) | Group only | Research only |
| Broadcast — "everyone downloads everything" | polling interval | Yes for receiver | **Yes, trivially** | Bitmessage, Nostr relays, Hyphanet |
| PIR inbox (Pung, Talek, Myco) | 3–60 s | Yes (cryptographic) | Yes | Research only |

*Table 4 — Anonymity primitives compared.*

The practical verdict is that **a dead drop with broadcast-style retrieval** is the deployable sweet spot for a low-volume notes system: the sender uploads a fixed-size encrypted blob under a random 256-bit identifier through Tor, and receivers download the whole recent bucket rather than asking for a specific blob, so the server cannot tell who a note was for. Fixed-size padding, randomised send delays and client-generated decoy uploads and fetches (Loopix-style Poisson scheduling) remove the remaining size and timing signals. When Katzenpost or a comparable mixnet goes live, the same blob format can move onto it.

### Messengers and identifiers

Of the existing messengers, only **SimpleX Chat, Cwtch, Briar, Ricochet Refresh, OnionShare and Quiet** require no account or server-side identifier at all (the last four use a Tor onion address as identity). Signal still requires a phone number (usernames since 2024 merely hide it from contacts), and delivery-receipt timing can link conversation pairs within about five messages despite sealed sender. Session removed forward secrecy in 2021 and is only now (Protocol V2, announced December 2025) restoring it with ML-KEM; it nearly shut down in 2026. Threema uses random IDs but its server sees the sender–recipient graph. Several projects showed their fragility in 2026: Briar entered maintenance mode (July), Session survived only through emergency donations (June), SimpleX moved under a US parent company and started crowdfunding (August), and Nym admitted its speed problem. Privacy Guides (May 2026) recommends only Signal, SimpleX and Briar. **The design lesson is to depend on no single funded entity: the system should be stateless, open and reproducible so that anyone can host a relay.**

| Messenger | Identifier | Transport anonymity | Post-quantum | Forward secrecy | Deniability | Main metadata leak |
|---|---|---|---|---|---|---|
| Signal | Phone number | None built in | PQXDH + SPQR (ML-KEM) | Yes (+PQ) | Weakened by PQXDH | Registration identity; receipt timing; SGX trust |
| SimpleX | None | 2-hop routing; Tor SOCKS | sntrup761 ratchet | Yes (+PQ) | Yes | Relay sees queue IDs/timing; US parent |
| Cwtch | Onion address | Tor onion end-to-end | No | Per-connection *[unverified]* | Partial | Online status; guard exposure |
| Briar | Onion address | Tor / mesh | No | Yes | Yes | Maintenance mode since Jul 2026 |
| Session | Random ID | Onion requests | Announced (V2) | No until V2 | No | Swarm nodes see ID + timing |
| Threema | Threema ID | None | Roadmap (IBM) | Yes | Partial | Server sees sender/recipient graph |
| Olvid | None (QR/SAS) | None | Designed-for, not deployed | Yes | Partial | Timing side channel (CCS 2026) |
| Ricochet Refresh / OnionShare | Ephemeral onion | Tor | No | Per-session | Partial | Both online; address distribution |
| Telegram | Phone number | None | No | Secret chats only | No | Cloud chats readable by Telegram; IP/phone handed to police since 2024 |

*Table 5 — Messengers relevant to the anonymity requirement (2026).*

### Delivery patterns for untraceable notes

Burn-after-reading services (Privnote, PrivateBin, Yopass, Bitwarden Send, Enclosed, Hemmelig) share one architecture: the browser generates a key, encrypts, uploads only ciphertext and puts the key in the URL fragment, which browsers never send to the server. This protects **content** against a passive operator but not the **relationship**: the server sees creator IP, reader IP and the timing of both. Four field problems recur: corporate link scanners and chat unfurlers "burn" the note before the human opens it (fix: an explicit reveal step, as PrivateBin's `#-` prefix and Password Pusher do); a compromised or coerced server can serve malicious JavaScript to one user (the browser-crypto problem); URLs leak into history, clipboards, proxies and screenshots; and typo-squatted clones — over a thousand Privnote clones rewrote cryptocurrency addresses inside notes (Krebs, 2024). Alternative placements that improve on this include Tor onion-service dead drops, Nostr-style gift-wrapped events scanned in bulk, Hyphanet (store-and-relay deniability), and even Bitcoin OP_RETURN (globally replicated, permanent — hence only for post-quantum ciphertext). A one-way broadcast (the numbers-station model, Section 3.6) is the most untraceable channel of all because the receiver emits nothing.

### Client-side hygiene and the Anonymous Planet guide

The Hitchhiker's Guide to Online Anonymity (anonymousplanet.net, v1.2.5, June 2026) is a 300-page, actively maintained, CC-BY-SA guide aimed at activists and journalists. Its threat model is unusually honest: it tiers adversaries from stalkers to nation-states, and it stresses *behavioural* leaks most technical guides omit — stylometry, keystroke dynamics, OSINT, EXIF and printer dots, Windows device identifiers that survive reinstalls, and mixing identities. Its recommended routes are Tails (amnesic), Whonix (gateway/workstation VM split) and Qubes-Whonix; it recommends Monero for payments and cash-bought burner hardware. Its controversial parts are the Windows-host-plus-VeraCrypt-hidden-OS path (telemetry and RIPA exposure) and Tor-over-VPN advice. For this project it is a strong source of endpoint and operational guidance to reference, not a design blueprint.

### Regulatory pressure and hosting

Beyond the compelled-decryption law in Table 2: the UK served Apple a Technical Capability Notice in 2025 and Apple withdrew Advanced Data Protection for UK users; the Online Safety Act s.121 allows Ofcom to compel "accredited technology"; the US has CLOUD Act reach and gag-order national security letters; Australia's TOLA is why Session relocated to Switzerland; several EU states are reviving IP-retention obligations for providers. The hosting conclusion is not "pick a good jurisdiction" but **assume every host will eventually be compelled or seized and make its logs worthless**: onion-only ingress (no source IPs), no accounts, fixed-size blobs, TTL-based deletion, broadcast retrieval, and a codebase anyone can re-host.

## 3.4 Commercial and open-source products: what best-in-class does

The product survey covered secure messengers, burn-after-reading services, encrypted file and note tools, hardware and paper products, and government-grade concepts. The full comparison table is in the companion report; the condensed view follows.

| Product | Category | Crypto / PQ | Zero-knowledge server | Identifier | Deniability / duress | Audit |
|---|---|---|---|---|---|---|
| Signal | Messenger | PQXDH + SPQR; ML-KEM-768/1024 | Sealed sender; sees recipient/IP | Phone | Disappearing msgs; repudiable | Cryspen formal 2023/25 |
| Threema | Messenger | Ibex (X25519); PQ roadmap | Minimal metadata | Random ID | None | Cure53 2020/23/24 |
| Olvid | Messenger | Out-of-band identities; PQ designed-for | **Yes — no trusted server** | None | Metadata encryption | ANSSI CSPN ×2; CCS 2026 |
| SimpleX | Messenger | sntrup761 double ratchet | No identifiers; IP unless Tor | None | Incognito profiles | Trail of Bits 2022/24 |
| Tuta / Proton Mail | E-mail | Hybrid ML-KEM (2026) | Body only | Account | None | Univ. Wuppertal 2026 (Tuta) |
| PrivateBin | One-time note | PBKDF2 → AES-256-GCM; key in fragment | Yes | None | Burn-after-read; `#-` interstitial | None formal |
| Enclosed / Yopass / Bitwarden Send | One-time note | Client-side AES-256-GCM / OpenPGP | Yes | None (Send: sender account) | Burn, TTL, password | None formal (Bitwarden vault: Cure53) |
| OneTimeSecret / Password Pusher | One-time note | Server-side AES | **No** | None | Expiry, passphrase | None |
| age 1.3 | File encryption | HPKE hybrid ML-KEM-768 + X25519 | n/a | Keys | None | Community |
| Kryptor | File encryption | XChaCha20-Poly1305 with key commitment; Argon2id | n/a | Keys | Random-looking ciphertext | None |
| Picocrypt | File encryption | Argon2id → XChaCha20 (+Serpent); HMAC-SHA3 | n/a | Passphrase | Deniable volumes (no header) | None; upstream slowed |
| VeraCrypt | Volume encryption | AES/Serpent/Twofish XTS; Argon2 | n/a | Passphrase | Hidden volumes/OS (2026 zero-sector bug fixed in 1.26.29) | QuarksLab 2016 |
| Superbacked | Paper/QR Shamir backup | Argon2; Blockcrypt (AES-256-GCM/CBC, HKDF); sss-cli | Offline, no server | None | **Multi-secret deniable blocks**; amnesic Superbacked OS | None public; MIT since Aug 2026 |
| Trezor SLIP-39 / Cypherock X1 | Hardware wallet | Shamir shares; secure elements | n/a | None | Hidden wallets (Trezor) | Several / Keylabs |
| Tails 7 | Amnesic OS | LUKS2 Argon2id; Tor | n/a | None | Amnesia by design | Radically Open Security 2024 |

*Table 6 — Condensed product landscape (full table in companion report 04).*

Several products deserve specific mention. **Olvid** (France) is the only widely deployed messenger whose security does not depend on any trusted server: identities are exchanged out of band by QR or short authentication string, no phone or e-mail is needed, and it carries two ANSSI security visas; a CCS 2026 formal analysis confirmed its core properties while noting a timing side channel. **Superbacked** (Section 3.7) demonstrates the fixed-size, multi-secret, decoy-capable container and the amnesic-OS workflow. **age** shows how small a correct hybrid-PQ encryptor can be. **Kryptor** and **Picocrypt** show ciphertext-indistinguishable-from-random containers with key commitment. **Telegram** is the negative example: cloud chats are not end-to-end encrypted, and after Pavel Durov's 2024 arrest the company disclosed IP addresses and phone numbers for thousands of users.

Government-grade practice adds one principle worth adopting: the NSA's Commercial Solutions for Classified programme protects classified data with **two nested, independent encryption layers** implemented by different codebases, so that a single bug, RNG failure or protocol flaw cannot expose plaintext; its 2026 capability packages now list CNSA 2.0 algorithms. Sweden's approved systems (Tutus Färist, Sectra Tiger, Advenica) follow the same philosophy. For a notes app this translates naturally into a hybrid post-quantum KEM layer plus an independent symmetric layer keyed from a passphrase or pre-shared secret — which is also exactly the pattern of Signal's Triple Ratchet and Picocrypt's paranoid mode.

Where commercial products fail in the field is consistent across the survey: endpoint compromise (Paragon Graphite's WhatsApp zero-click, 2025), forensic extraction of After-First-Unlock phones, cloud backups that silently include message databases, screenshots, notifications and third-party keyboards, phone-number identities that enable contact-graph discovery, hosted JavaScript that can be swapped, and operating-system residue (thumbnail caches, journals, wear-levelled flash, printer spool files) that undermines every deniability claim.

## 3.5 What forensic and law-enforcement cases teach

This stream examined how "secure" communications and secret notes have actually been broken or traced in the last fifteen years, from encrypted-phone takedowns and device forensics to spy cases and paper evidence. The pattern is unambiguous.

| Case | Year | What actually failed | Layer |
|---|---|---|---|
| Phantom Secure | 2018 | CEO incriminated himself to undercover RCMP; FBI then tried to coerce a backdoor. | Human / operator |
| EncroChat | 2020 | French Gendarmerie pushed a malicious "update" (implant) to ~32,000 handsets through the vendor's own update channel; it exfiltrated stored databases (messages, **notes**, images) then streamed live messages and lock passwords. | Endpoint via update supply chain |
| Sky ECC | 2021 | Man-in-the-middle on OVH servers; devices tricked into releasing key material; **no forward secrecy**, so ~1 billion stored messages became retroactively readable. | Server + protocol |
| ANOM / Trojan Shield | 2019–21 | The entire platform was FBI-run; a master key BCC'd every message to law enforcement. Trust came from criminal influencers, not code review. | Supply-chain trust / honeypot |
| Exclu | 2023 | Decryption material seized in an unrelated 2019 raid; police read traffic for ~5 months. | Key seizure |
| Ghost | 2024 | Australian police modified the platform's own software updates; sole developer identified via company ownership and money trail. | Update channel + operator |
| MATRIX | 2024 | Found on a murder suspect's phone; 40 servers accessed; three months of interception. | Infrastructure |
| Boystown (Tor) | 2019–21 | Timing correlation across monitored Tor nodes against an outdated Ricochet client without vanguards; walked back to the entry guard, then subpoenaed the ISP. | Traffic shape / metadata |
| Silk Road | 2013 | Persona contamination (forum handle linked to real e-mail), a leaked VPN IP in source code, laptop seized open mid-session. | Human / OPSEC |
| Russian illegals | 2010 | Steganography + shortwave + one-time pads defeated because a 27-character password was written on paper found in a covert search, and a laptop reused its MAC address. | Human / physical |
| Cuban agents (Montes, Myers) | 2001–09 | One-time pads were never broken; agents were caught because Cuba issued decryption *software* whose swap and temp files survived wiping. | Endpoint residue |
| Reality Winner | 2017 | Colour-laser tracking dots encoded printer serial and time; six printers, one e-mail from work. | Physical / metadata |
| TeleMessage / "Signalgate" | 2025 | An archiving clone of Signal copied plaintext to a server that was breached within minutes (410 GB leaked). Signal's encryption was intact; the linked device leaked. | Archival clone / linked device |
| US v. Sharp | 2026 | FBI recovered "disappeared" Signal messages — after the app was uninstalled — from Apple's **push-notification SQLite store**. | OS cache |

*Table 7 — How secure communications were actually broken. In no case was the cipher attacked.*

The device-forensics picture in 2025–26 sharpens the endpoint requirement. The difference between *Before First Unlock* (keys not in RAM) and *After First Unlock* is decisive: Cellebrite's leaked February 2025 matrix showed most Android devices and AFU iPhones extractable, stock Pixels resistant in BFU only, and **Pixels running GrapheneOS resistant in both states**; an October 2025 leak reportedly showed Cellebrite losing full-file-system support even against unlocked GrapheneOS *[forum-level, unverified]*. The AFU attack surface is USB: Amnesty documented a locked Samsung unlocked in about 16 minutes through emulated USB peripherals and three kernel zero-days. Apple's inactivity reboot and GrapheneOS's auto-reboot work — forensic vendors now advise investigators to image "as soon as possible" — and an FBI filing conceded that a phone in Lockdown Mode could not be extracted. On an unlocked device, however, everything survives: SQLite free lists and write-ahead logs, keyboard caches, screenshots, cloud backups, Signal Desktop's database key in the OS keychain, and Windows Recall's screenshot history.

Paper leaves traces too. Electrostatic detection (ESDA) recovers indented writing several pages deep; ink, fibre, DNA and fingerprints are routine; charred paper is readable under infrared; the 2011 DARPA challenge reassembled five documents shredded into more than 10,000 pieces in 33 days, and Iranian students reassembled strip-shredded CIA files in 1979; thermal paper that has faded can be chemically restored. Cipher notes found at crime scenes — Provenzano's *pizzini* (a Caesar shift), the Zodiac Z340 (solved 2020), the Cuban pads, the Russian password — were found by following people and places, after which home-made ciphers fell.

> **What investigators actually rely on, roughly in order of frequency**
>
> 1. Seized endpoints in After-First-Unlock or unlocked state.
>
> 2. Informants, undercover buyers and turned insiders (Phantom Secure, ANOM, El Chapo's sysadmin).
>
> 3. Compromise of the operator, server or software-update channel (EncroChat, Sky ECC, Ghost).
>
> 4. Metadata: IP addresses, phone numbers, timing, location, printer dots, MAC addresses.
>
> 5. Backups, archives, linked devices and OS caches (TeleMessage, US v. Sharp, Cuban swap files).
>
> 6. Legal coercion of passwords (RIPA) or of providers (Proton compelled to log an activist's IP in 2021).
>
> 7. Cryptanalysis of a modern cipher: **zero documented cases.**

Two further lessons round this off. What has held up: Signal's server-side minimisation (its subpoena responses contain two timestamps), Mullvad's nothing-to-seize architecture (a 2023 police raid left with nothing), Tor with current software and large anonymity sets, strong full-disk encryption against decryption (Simon Finch's VeraCrypt volume was never opened; he was jailed for refusing), and GrapheneOS or Lockdown-Mode iPhones against commercial forensics. And legal challenge to *how* evidence was obtained has failed essentially everywhere in Europe: the UK Court of Appeal, German BGH, Dutch Supreme Court and CJEU all admitted the EncroChat material. **Prevention, not exclusion, is the only defence.**

## 3.6 Pen and paper: what is genuinely secure offline

Only three families of paper-usable techniques are unconditionally secure, and all three are relevant to this project.

**The one-time pad** (Vernam 1919, Shannon 1949) gives perfect secrecy against any computer, quantum or otherwise, provided the key is truly random, at least as long as the message, used once, and destroyed. It also gives content deniability for free: for any ciphertext there exists a "key" that decrypts it to any innocuous plaintext of the same length, so a coerced party can hand over a fake pad. Its four requirements are exactly where history shows it failing: randomness (dice, hardware generators or physical-noise extractors, never a library PRNG), no reuse (VENONA exploited duplicated Soviet pad pages for decades), distribution over a channel at least as secure as the message (microfilm, concealments — the Cuban service still broadcasts five-figure groups by shortwave, and a new Persian-language numbers station appeared in March 2026), and destruction (KGB pads were printed on nitrocellulose flash paper). A one-time pad is malleable, so integrity requires a **Carter–Wegman one-time MAC** drawn from the same pad — also information-theoretically secure and hand-computable with a pre-printed worksheet. For sizing, a 500-character note needs about two pad pages by hand; a 1 kB digital note needs 1 kB of pad, and one QR code holds up to 2,953 bytes.

**Shamir secret sharing** (1979) splits a secret so that any k of n shares reconstruct it while k−1 reveal nothing; it is the natural tool for coercion resistance (2-of-3 with holders in different places, one with a lawyer). Hand-computable variants now exist: Blockstream's **codex32 (BIP-93)** performs Shamir over GF(32) with paper volvelles and a 13-character checksum that catches arithmetic errors (30–60 minutes per operation; still marked "do not use with real money"), Coldcard's **SeedXOR** and Goucher's **Hamming backups** give n-of-n and 2-of-3 splitting with nothing but XOR. Machine formats include Trezor's SLIP-39, Superbacked's blocksets, Parity's Banana Split and cyphar's paperback (which signs every shard so forged shares are detected). The documented pitfalls are implementation bugs (Trail of Bits found six threshold libraries that let a participant recover the secret outright in 2021; HashiCorp Vault had a timing leak in 2023), the absence of share verification in plain Shamir, and dealer trust — whoever splits the secret sees it, so splitting must happen on an air-gapped device that is wiped afterwards.

**Visual cryptography** (Naor–Shamir 1994) is Shamir for images: k random-looking transparencies stacked together reveal a picture with zero computation. It suits short codes and keys rather than long text.

| Genuinely secure on paper | Only looks secure |
|---|---|
| One-time pad with true randomness, single use and physical destruction (confidentiality + deniability) | Every non-OTP hand cipher: Solitaire (keystream bias), LC4 (chosen-plaintext attacks), VIC ("unbroken" for four years in the 1950s), Chaocipher (solved 2016), Playfair/ADFGVX (broken in WWI), book and running-key ciphers |
| Carter–Wegman one-time MAC drawn from the pad (integrity) | Invisible ink, microdots, grilles, null ciphers — modern forensics reveals essentially all inks |
| Shamir / codex32 / SLIP-39 / SeedXOR / Hamming 2-of-3 (coercion resistance; add checksums or signatures) | Tamper-evident seals — all 120 tested by Argonne's Vulnerability Assessment Team were defeated, mean time under 5 minutes, average cost $55 |
| Visual cryptography (k-of-n with no computation) | Strip or P-4/P-5 shredding; thermal-paper fading; "deleting" a photo of a pad |
| One-way broadcast as delivery channel (receiver emits nothing) | Memorised passphrases or brain wallets as the only secret (98 % of studied brain wallets were drained) |
|  | Encrypted QR backups (AES/ChaCha) are computationally secure but not information-theoretic and not deniable without a decoy layer |

*Table 8 — Paper methods: genuinely secure vs. apparently secure.*

Physical practice matters as much as the mathematics. Colour laser printers embed serial numbers and timestamps in yellow micro-dots (this helped identify Reality Winner); use a monochrome laser bought with cash, the DEDA anonymisation toolkit, or hand-copying with stencils. Write only on a single sheet on glass to defeat indented-writing recovery. Destroy with water-soluble paper (dissolves in seconds, legal and silent), flash paper, or a P-7 cross-cut shredder followed by burning and stirring the ash. Never photograph a pad: EXIF, cloud auto-upload, thumbnails and "recently deleted" folders recreate the Cuban failure. If a device must read paper, it should be a stateless, radio-less scanner in the SeedSigner mould. Finally, the survey found **no shipped product that prints a true-random pad plus one-time-MAC keys as QR codes for paper couriers** — Jericho Comms comes closest but stays digital — which is a genuine gap this project could fill.

## 3.7 The four inspiration links

### Superbacked (superbacked.com)

Superbacked is an offline desktop application by Canadian privacy researcher Sun Knudsen that encrypts secrets into fixed-size "blocks" printed as QR codes on index cards, aimed at backup and succession planning for seed phrases, master keys and credentials. It never connects to the internet and needs no account. Three of its design ideas map directly onto this project's requirements. First, **blocksets**: secrets split with Shamir secret sharing (2-of-3, 3-of-5, 4-of-7) so that "no single person can access them alone but together the right group can recover what matters" — requirement R5. Second, **plausible deniability through decoy secrets**: the MIT-licensed Blockcrypt library encrypts up to four secrets, each under its own passphrase, into one block whose encrypted headers, data and random padding are indistinguishable; every block looks identical whether it holds one secret or four, so surrendering passphrase #1 reveals only secret #1 and the existence of the others cannot be proven — requirement R3. Third, **Superbacked OS**: a hardened live operating system that runs air-gapped from RAM, persists nothing, and comes with a guide for proving nothing was written by hashing the drive before and after — the amnesic workflow needed for R6.

The cryptography is conventional: Argon2 for the passphrase (parameters unpublished), HKDF-SHA256 subkeys, AES-256-CBC for headers and AES-256-GCM for data, a 16-byte salt and IV, and random padding to a fixed length. Blockcrypt's own documentation lists two honest weaknesses: the block is not authenticated as a whole (tampering can make secrets unrecoverable), and deniability is asymmetric (revealing a later secret proves earlier ones exist). The project launched as a paid, closed-source product (about US$149), drew criticism on Hacker News and Privacy Guides for price and closed source, became free and source-available, and in v2.0.0-beta.4 (2 August 2026) was **relicensed to MIT**, adding YubiKey protection, BIP39 extraction, a "paranoid" key-derivation mode and air-gapped modes for Superbacked OS. There is no separate hardware device; the "air-gapped" offering is software. No third-party audit was found.

### The two YouTube videos

Video content could not be retrieved, but titles and channel were confirmed via YouTube's oEmbed endpoint. **youtu.be/0rEqaUnWoD0** is *"Superbacked 2 is open source"* (channel Sun Knudsen) and almost certainly announces the MIT relicensing and version-2 features described above. **youtu.be/zR3a2KCO2pY** is *"Superbacked helps the right people recover what matters"* (same channel), matching the site's blockset/succession-planning copy and very likely the product explainer for Shamir threshold recovery. Both summaries are inferred from title and release notes, not from viewing.

### Anonymous Planet — The Hitchhiker's Guide to Online Anonymity

Covered in Section 3.3: a large, actively maintained, community-written operational-security guide whose value for this project is its honest threat tiering and its attention to behavioural and physical leaks (stylometry, OSINT, printer dots, device identifiers, mixing identities). Its recommended routes (Tails, Whonix, Qubes-Whonix), payment advice (Monero) and hardware advice (cash-bought burners) should inform the app's user guidance; its VeraCrypt-hidden-OS-on-Windows deniability path should not, for the reasons in Section 3.2.

## 3.8 Endpoint and device reality

Every stream converged on the endpoint as the decisive layer, so the state of endpoint defence deserves its own summary. On mobile, **GrapheneOS** (Pixel 8–10, September 2026 release) offers a duress PIN that irreversibly wipes the device, auto-reboot to before-first-unlock (default 18 hours), USB data cut while locked, hardware memory tagging, secure-element throttling, per-app clipboard blocking and sandboxed Google Play; leaked Cellebrite matrices indicate it resists extraction in both lock states. **iOS** offers Lockdown Mode (blocks the attachment and link-preview paths that Paragon used), a 72-hour inactivity reboot and Stolen Device Protection, but Advanced Data Protection was withdrawn in the UK in 2025 and the platform cannot block screenshots. **Android 16 Advanced Protection** bundles similar hardening plus tamper-resistant intrusion logging.

For desktop, the amnesic and compartmentalised options are Tails 7 (now part of the Tor Project), Whonix 18 and Qubes OS 4.3 (December 2025), with a "vault qube" that has no network device as the reference pattern. The stateless microcontroller signers of the Bitcoin world (SeedSigner, Krux, Jade) demonstrate the strongest pattern for a paper reader: no storage, no radios, optical input and output only. Faraday bags block radio but help the adversary as much as the defender (they prevent remote wipe).

Key handling on the endpoint must follow known rules: lock secrets in memory and zeroise them (Rust's `zeroize`; never hold secrets in JavaScript strings, which are immutable and garbage-collected by copying); wrap keys in the secure enclave (Apple SEP, Android StrongBox/Titan M2, TPM 2.0) so that deletion is instant key destruction rather than an unreliable overwrite; exclude the app from OS backups; set `FLAG_SECURE` on Android and `WDA_MONITOR` display affinity on Windows to defeat screenshots and Recall; avoid notifications entirely (the *US v. Sharp* lesson); refuse to run with untrusted accessibility services enabled; and use an in-app keypad for passphrases so third-party keyboards never see them.

The **browser-JavaScript problem** is structural, not fixable with configuration: a server, CDN or interceptor can serve different code to one user on any page load with no audit trail, extensions share the origin, XSS is total compromise, and browser storage is not amnesic. Subresource Integrity does not protect the HTML itself; Meta's Code Verify extension is partial; Google's Web Environment Integrity was abandoned. Signal dropped its web client in 2017 for this reason. The credible path is **native applications with reproducible builds** (Signal Android and F-Droid publish byte-for-byte rebuild recipes), release artefacts signed and logged through Sigstore, and pinned builds with out-of-band hashes rather than silent auto-update — the exact channel that destroyed EncroChat and Ghost.

Finally, mercenary spyware has not paused: Paragon Graphite compromised WhatsApp (2025) and iMessage (CVE-2025-43200) with zero clicks; iVerify reported in September 2026 that the leaked "Coruna" exploit kit combined with the "DarkSword" watering-hole kit was present on 5 % of devices it scanned. The design must therefore assume the endpoint may already be compromised and minimise what such a compromise yields: short key lifetimes, no history, no server-side residue, and plaintext that exists only while the note is on screen.

# 4. Synthesis: design principles derived from the research

Pulling the seven streams together, twenty-two principles emerge. Each is traceable to a specific failure or result above; together they form the requirements baseline for the design phase.

### A. Cryptography

1. **Symmetric first, hybrid second, classical never alone.** Random 256-bit note keys with XChaCha20-Poly1305 or AES-256-GCM-SIV are quantum-safe today. Where key agreement is unavoidable, use a hybrid KEM (X-Wing: X25519 + ML-KEM-768) with a fresh key pair per note. No RSA, no ECC-only, anywhere.
2. **Explicit key commitment** on every container, because decoy-secret and multi-passphrase designs are exactly where non-committing AEADs bite.
3. **No long-term signatures on the wire.** Authenticate with KEM-derived or symmetric MACs; publish MAC keys after expiry (the OTR pattern). This is what preserves participation deniability under a post-quantum regime.
4. **Two independent layers** (the CSfC principle): a hybrid PQ layer and an independent symmetric layer keyed from a passphrase, pre-shared secret or Shamir shares, implemented from different codebases.
5. **Formally verified or heavily reviewed libraries only** (libcrux, libsodium 1.0.22, mlkem-native, Go crypto/mlkem), with algorithm identifiers in headers for agility.
6. **Offer an information-theoretic option** — one-time pad plus one-time MAC, or Shamir-split keys over independent channels — for users whose threat model justifies the key-distribution cost.

### B. Deniability and coercion

1. **Structural deniability over cryptographic deniability.** Ciphertext indistinguishable from random; no magic bytes; fixed-size blocks; no server record linking a blob to a person; no "my notes" list, read receipts or delivery confirmations.
2. **Decoy slots in every container** (Blockcrypt pattern), with the deniability asymmetry documented honestly and every block identical in appearance whether it holds one secret or several.
3. **k-of-n control of the note key** so that one person's knowledge is insufficient; prefer threshold decryption (key never reassembled) where the tooling allows, and require share verification.
4. **"Nothing to give" after delivery**: per-note ephemeral keys, burn-on-read, immediate zeroisation, server deletion on first fetch and at expiry; the sender never retains the key.
5. **A per-note distress key** that returns a plausible decoy and destroys the real note, as an optional feature.
6. **Assume the law compels whatever exists.** Design so that no single human — sender, receiver or operator — can comply with a demand even if they want to.

### C. Anonymity and delivery

1. **No accounts, no phone numbers, no e-mail, no push tokens, no device identifiers.** Nothing to subpoena, coerce or arrest.
2. **Dead drop, not mailbox.** Blobs stored under random 256-bit identifiers; retrieval by downloading the whole recent bucket (broadcast model) so the server cannot see who a note is for; onion-only ingress so it never sees source IPs.
3. **Fixed-size padding tiers, randomised timing and client-generated cover traffic** so a passive observer sees a constant rate regardless of real activity.
4. **Explicit reveal step before burn**, so link scanners and unfurlers cannot consume a note, and an unguessable identifier so they cannot enumerate.
5. **Stateless, open, reproducible relay software** that anyone can host, with logging made architecturally impossible rather than promised — because every provider will eventually be compelled or seized.

### D. Endpoint and human factors

1. **Native clients with reproducible, publicly logged builds and pinned updates**; no silent auto-update; a web front end only as a convenience layer that is never the trust root.
2. **Zero plaintext at rest**: render in memory only, zeroise buffers, exclude from backups, block screenshots and screen recording, send no notifications, refuse untrusted accessibility services, use an in-app keypad for secrets.
3. **Guide users to hardened endpoints** — GrapheneOS or iOS Lockdown Mode with auto-reboot and a long alphanumeric passcode, no biometrics — and state plainly that a seized unlocked phone defeats everything.
4. **One-directional, one-shot flows** with no threads, link reuse or linked devices; keys never need to be written down because they are single-use and embedded in the artefact.
5. **Paper path hygiene built into the product**: monochrome or hand-copied output, soluble or flash paper, "write on glass" and "never photograph" guidance, and a stateless optical reader.

# 5. Candidate architectures for discussion

Three candidate architectures follow from the principles. They are presented as options for the design discussion, not as a finished design; each can be built, and they are not mutually exclusive. All three share the same cryptographic stack (Section 3.1) and the same endpoint rules (Section 4D).

## 5.1 Option A — "Paper-first": an information-theoretic generator

In this option the app is primarily an **air-gapped generator and reader**, and the exchange itself happens in the physical world. A stateless device (a phone in airplane mode running the app from a verified build, or a SeedSigner-class single-board computer) mixes two entropy sources to generate a one-time pad and one-time-MAC key material, and prints it as QR codes plus base32 groups on water-soluble or flash paper. The pad booklet is itself split 2-of-3 or 3-of-5 with a hand-computable scheme (codex32 or Hamming-XOR) so that no courier carries a usable key. The sender enciphers the note — by hand with a pre-printed worksheet, or by scanning the pad page into the stateless device — and the ciphertext travels over *any* channel, ideally a one-way broadcast (a public bulletin, a dead-drop blob, or literally a numbers-station-style posting). The receiver decrypts with the matching page, verifies the MAC, and both parties dissolve or burn their pages.

**Strengths:** unconditionally secure against any computer, quantum or otherwise; content deniability is inherent in the pad (a fake page decrypts to anything); coercion resistance via split pads; no server, no account, no network trust; fills a genuine market gap (no such product exists). **Weaknesses:** key distribution requires a prior physical meeting or trusted courier; pad management is where every historical OTP system failed; hand operation is slow and error-prone for anything beyond a few hundred characters; the pad itself is evidence if found (flash paper is incriminating to possess in some places); usability is low for ordinary users.

## 5.2 Option B — "Digital fire-and-forget dead drop"

Here the app is a **native, reproducibly built client plus stateless relay software**. To send, the client pads the note to a fixed-size tier, generates a random 256-bit note key, encrypts with a committing AEAD, and derives the delivery secret in one of two ways: (i) if the receiver has published a one-time hybrid KEM public key (X-Wing) via QR or a prior exchange, the note key is encapsulated to it; (ii) otherwise the note key is carried out of band (QR, spoken words, or a Shamir split across two channels). The ciphertext blob is uploaded under a random identifier through Tor to any relay running the open server software, which stores only opaque blobs with a TTL and no logs, onion-only. The receiver's client periodically downloads the whole recent bucket over Tor (broadcast retrieval), tries its keys against each blob, renders the match in memory only, and the relay deletes the blob on first fetch and at expiry. Coercion resistance comes from k-of-n threshold wrapping of the note key (for example the receiver plus a second device or trustee, or a timelock share) and from the fact that after delivery no party holds anything. Every container carries decoy slots, so a surrendered passphrase can open an innocuous note.

**Strengths:** deployable today with mature components (libsodium X-Wing, Tor onion services, age-style envelope); high usability; nothing to subpoena; post-quantum by construction; anyone can host a relay; the broadcast model gives receiver anonymity without research-grade PIR. **Weaknesses:** Tor does not resist a global passive adversary; the receiver's device is the single point of failure (spyware, seizure while unlocked); broadcast retrieval scales poorly beyond a modest user base and needs cover traffic; threshold post-quantum decryption is not yet standardised, so k-of-n is implemented at the symmetric key-wrapping layer for now.

## 5.3 Option C — "Layered hybrid" (preliminary recommendation)

Option C uses **Option B as the core and Option A as the highest-assurance mode**, sharing one container format. The everyday path is the digital dead drop. For the highest-threat exchanges, the same app prints the note key — or the note itself as a one-time-pad ciphertext with its pad — as Shamir shares on paper, so that the digital blob alone is worthless, the paper alone is worthless, and reconstruction needs k of n independent artefacts held by different people or places. Both modes produce blocks that are indistinguishable from random and identical in size, both carry decoy slots, both use the same committing AEAD, and both are read by the same memory-only renderer. The app also ships an "amnesic mode" recipe (Tails/Qubes or Superbacked-OS-style live boot with a before-and-after drive hash) for users who need to prove nothing persisted.

**Why this is the preliminary recommendation:** it satisfies every requirement in Section 2.2 in at least one mode; it lets the threat level choose the friction rather than forcing all users to the maximum; it avoids betting the design on any single component (Tor, a relay operator, an endpoint, or a courier); and it is the only option that gives unconditional (information-theoretic) security for the cases that truly need it while remaining usable for the rest. Its cost is scope: two delivery paths and a paper workflow to design, test and explain.

| Requirement | A — Paper-first | B — Digital dead drop | C — Layered hybrid |
|---|---|---|---|
| R1 Unbreakable / quantum-safe | Unconditional (OTP) | Computational (AES-256 + hybrid KEM) | Both, per mode |
| R2 Integrity | One-time MAC | Committing AEAD | Both |
| R3 Content deniability | Inherent (fake pad) | Decoy slots; random-looking blob | Both |
| R4 Participation deniability | No transcript exists | No accounts, no signatures, no logs | Both |
| R5 Coercion resistance | Split pads (k-of-n) | Threshold-wrapped key; nothing retained after read | Both, cross-medium |
| R6 Untraceability | Destroyed paper; broadcast ciphertext | Burn-on-read, TTL, onion ingress, broadcast fetch | Both |
| R7 Anonymity | Physical tradecraft | Tor / mixnet; no identifiers | Both |
| R8 Offline / paper path | Native | Only for key transport | Native |
| R9 Usability | Low | High | High by default; low only when chosen |
| Maturity of components | High (but no product exists) | High | High |
| Main residual risk | Pad handling; physical evidence | Compromised or seized endpoint; Tor correlation | Scope and complexity |

*Table 9 — Candidate architectures against the requirements.*

# 6. Decisions needed before design starts

The research resolves most technical questions but leaves a set of product decisions that only the project owner can make. They are listed here so the next session can start with them.

1. **Who is the user and what is the threat level?** A tool for a small trusted circle under nation-state threat looks very different from a broad consumer product; it determines whether Option A's friction is acceptable and how much cover traffic and anonymity-set the system needs.
2. **Which option — A, B or C — and in what order?** The preliminary recommendation is C built incrementally: B first (the container format, client and relay), then the paper mode.
3. **Key transport model for the digital path:** one-time recipient QR keys exchanged in person (Olvid model), out-of-band symmetric key (Privnote model without the URL), Shamir split across two channels, or a mix.
4. **Threshold policy:** which k-of-n schemes to support (2-of-3, 3-of-5), who the trustees are (second device, trusted person, timelock), and whether reconstruction happens on the receiver's device or via threshold decryption.
5. **Deniability posture:** how far to go — decoy slots only, or also anamorphic/steganographic techniques in a later iteration — and how to explain the asymmetry honestly to users.
6. **Transport:** Tor onion services only, or design the blob format now for a future mixnet (Katzenpost/Nym) as well; whether to support a plain-HTTPS fallback at all (the research says no).
7. **Platforms and build discipline:** native Android (GrapheneOS-first) and iOS, desktop (Linux/Qubes/Tails), and how far to go with reproducible builds and Sigstore from day one.
8. **Relay model:** self-host only, a community of volunteer relays, or both; and how to fund and govern without creating a compellable operator.
9. **Paper materials and printing guidance:** which paper (soluble, flash), which printer advice, and whether to ship a stateless reader build for single-board computers.
10. **Legal review:** the design should be checked against Swedish, EU, UK and US law on compelled decryption, data retention and obstruction before launch.

# 7. Claims that could not be verified

The research agents flagged every claim that rests on a secondary source or could not be confirmed. These should be checked before being cited or relied upon in design documents.

- Content of the two YouTube videos (titles and channel confirmed only).
- Superbacked's Argon2 parameters and current pricing; any hardware device named "Superbacked Airgapped" (none found).
- The October 2025 Cellebrite leak claiming loss of full-file-system support against unlocked GrapheneOS (forum-level source).
- EncroChat implant internals (use of CVE-2019-2215 and Frida), Sky ECC's "invisible push message" key release, ANOM's server location, and Sky ECC users' handwritten code sheets (single secondary sources).
- Final publication status of NIST IR 8547; whether Arti's proof-of-work defence and Tor's post-quantum circuit handshake shipped in 2026.
- Outcome of Sweden's bill Ju2024/02286 after the September 2026 election; the UK Investigatory Powers Tribunal ruling on Apple; restoration of Advanced Data Protection in the UK; the Ofcom s.121 report; EDRi's forecast of CSAR adoption in October 2026.
- US Supreme Court disposition of *Payne* and *Valdez* certiorari petitions.
- Whether a robust, CCA-secure anamorphic construction exists specifically over ML-KEM; the claim that one-time-pad deniability survives the addition of a polynomial one-time MAC (plausible, not found in literature).
- Cwtch's per-message forward-secrecy details; Delta Chat post-quantum status; 2026 activity of Lokinet, Berty and VeilidChat; SimpleX's 2025 Trail of Bits results; YubiKey and Nitrokey post-quantum firmware; Session Protocol V2 rollout completion.
- Exact classification levels for Tutus, Sectra and Advenica products; Cryptomator and Notesnook audit dates; Coldcard/SeedSigner current feature details.
- Existence of "Whoaverse" or "OTP Crypto" one-time-pad apps and of a "critical 2024 ssss bug" (none found).

# 8. Where the project stands and how to resume

The research phase is complete and this document is its deliverable. The state is saved in the project folder under *Research/*: this report, the seven full stream reports as Markdown (01–07), the original inspiration links, and a STATE.md file describing what has been done, what was decided, and what comes next. The same summary has been written to the Claude project so that any future session — from any device — can read it before continuing. The next step is a design conversation over the decisions in Section 6, followed by iteration: threat model and requirements document, container format specification, protocol specification for the dead drop and key transport, paper-mode specification, and a prototype plan.

# 9. Selected sources

Full source lists (several hundred URLs) are in the seven companion reports. The primary sources most relied upon in this summary are listed here by topic.

### Standards and cryptography

- NIST Post-Quantum Cryptography project and news — https://csrc.nist.gov/projects/post-quantum-cryptography
- NIST IR 8547 (transition to PQC, deprecation timeline) — https://nvlpubs.nist.gov/nistpubs/ir/2024/NIST.IR.8547.ipd.pdf
- NIST IR 8610, additional signatures Round 3 — https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8610.pdf
- NSA CNSA 2.0 FAQ — https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF
- EU Coordinated Implementation Roadmap for PQC — https://digital-strategy.ec.europa.eu/en/policies/post-quantum-cryptography
- RFC 10024, PQ/T hybrid key agreement for TLS 1.3 — https://www.rfc-editor.org/info/rfc10024/
- RFC 9980, Post-Quantum Cryptography in OpenPGP — https://datatracker.ietf.org/doc/rfc9980/
- X-Wing hybrid KEM (draft and paper) — https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/ ; https://eprint.iacr.org/2024/039
- RFC 9771, properties of AEAD algorithms (key commitment) — https://datatracker.ietf.org/doc/draft-irtf-cfrg-aead-properties/
- Gidney, factoring RSA-2048 with under a million noisy qubits — https://arxiv.org/abs/2505.15917
- Global Risk Institute, Quantum Threat Timeline Report 2025 — https://globalriskinstitute.org/publication/quantum-threat-timeline-report-2025b/
- Signal, SPQR / Triple Ratchet — https://signal.org/blog/spqr/ ; PQXDH — https://signal.org/docs/specifications/pqxdh/
- Apple, iMessage PQ3 — https://security.apple.com/blog/imessage-pq3/
- libsodium 1.0.22 release (ML-KEM, X-Wing) — https://github.com/jedisct1/libsodium/releases
- age v1.3.0 post-quantum recipients — https://github.com/FiloSottile/age/releases/tag/v1.3.0
- Cryspen, verified ML-KEM (libcrux) — https://cryspen.com/post/ml-kem-verification/
- KyberSlash — https://kyberslash.cr.yp.to/ ; Castryck–Decru SIDH break — https://eprint.iacr.org/2022/975

### Deniability and coercion resistance

- Canetti, Dwork, Naor, Ostrovsky, Deniable Encryption — https://eprint.iacr.org/1996/002
- Bendlin, Nielsen, Nordholt, Orlandi, bounds for deniable PKE — https://eprint.iacr.org/2011/046
- Persiano, Phan, Yung, Anamorphic Encryption — https://eprint.iacr.org/2022/639.pdf ; Banfi et al., revisited — https://eprint.iacr.org/2023/249
- Avitabile, Botta, Friolo, Sharing a Secret Anamorphically (2026) — https://eprint.iacr.org/2026/236
- Canetti et al., Deniable Secret Sharing — https://eprint.iacr.org/2025/525
- Czeskis et al., Defeating Encrypted and Deniable File Systems — https://www.usenix.org/legacy/event/hotsec08/tech/full_papers/czeskis/czeskis.pdf
- Chen et al., SoK: Plausibly Deniable Storage (PETS 2022) — https://eprint.iacr.org/2021/1547.pdf
- Shufflecake (CCS 2023) — https://eprint.iacr.org/2023/1529
- Fiedler, Janson, deniability analysis of PQXDH — https://eprint.iacr.org/2024/741
- Katsumata, Niot, Tucker, Wiggers (USENIX Security 2025) — https://www.usenix.org/conference/usenixsecurity25/presentation/katsumata
- Collins et al., K-Waay (USENIX Security 2024) — https://eprint.iacr.org/2024/120 ; Niot, Sparrow-KEM — https://eprint.iacr.org/2025/853
- NIST IR 8214C, multi-party threshold schemes call — https://nvlpubs.nist.gov/nistpubs/ir/2025/NIST.IR.8214C.2pd.pdf
- SoK: Cryptographic Erasure on Public Ledgers (2026) — https://eprint.iacr.org/2026/1109.pdf
- United States v. Payne (9th Cir. 2024) — https://cdn.ca9.uscourts.gov/datastore/opinions/2024/04/17/22-50262.pdf
- RIPA Part III (Open Rights Group wiki) — https://wiki.openrightsgroup.org/wiki/Regulation_of_Investigatory_Powers_Act_2000/Part_III
- Swedish data-storage bill, joint letter — https://www.globalencryption.org/2025/04/joint-letter-on-swedish-data-storage-and-access-to-electronic-information-legislation/
- EU interim CSAM regulation extended to 2028 — https://eucrim.eu/news/interim-rules-on-voluntary-csam-detection-reinstated-until-2028/
- GrapheneOS features (duress, auto-reboot, USB) — https://grapheneos.org/features

### Anonymity and delivery

- Tor Project blog (Arti releases, Boystown response) — https://blog.torproject.org/
- Tor onion-service proof-of-work defence — https://onionservices.torproject.org/technology/security/pow/
- Sasy & Goldberg, SoK: Metadata-Protecting Communication Systems (PoPETs 2024) — https://petsymposium.org/popets/2024/popets-2024-0030.pdf
- Echomix / Katzenpost (2025) — https://pith.science/paper/2501.02933 ; https://katzenpost.network/
- Nym roadmap 2026 — https://nym.com/blog/nym-roadmap-2026
- Myco (IEEE S&P 2025) — https://eprint.iacr.org/2025/687 ; Groove (OSDI 2022) — https://www.usenix.org/system/files/osdi22-barman.pdf
- Improving Signal's Sealed Sender (NDSS 2021) — https://www.ndss-symposium.org/ndss-paper/improving-signals-sealed-sender/
- SimpleX Chat blog (PQ ratchet, consortium, crowdfunding) — https://simplex.chat/blog/
- Briar maintenance mode (July 2026) — https://briarproject.org/news/2026-maintenance-mode/
- Privacy Guides, real-time communication — https://www.privacyguides.org/en/real-time-communication/
- PrivateBin issue #174 (burn-after-reading race) — https://github.com/PrivateBin/PrivateBin/issues/174
- Krebs on Security, Privnote phishing clones — https://krebsonsecurity.com/2024/04/fake-lawsuit-threat-exposes-privnote-phishing-sites/
- Anonymous Planet guide — https://anonymousplanet.net/guide/ ; repository — https://github.com/Anon-Planet/thgtoa

### Products and endpoint

- Superbacked — https://superbacked.com/ ; Blockcrypt technical documentation — https://github.com/superbacked/blockcrypt/blob/main/docs/blockcrypt-technical-documentation.md ; releases — https://github.com/superbacked/superbacked/releases
- Olvid technology and CCS 2026 analysis — https://olvid.io/technology/en/ ; https://eprint.iacr.org/2026/1622
- Threema Ibex security analysis — https://threema.com/assets/6-resources/audits/security_analysis_ibex_2023.pdf
- Telegram data sharing after 2024 — https://techcrunch.com/2025/01/07/telegram-reports-spike-in-sharing-user-data-with-law-enforcement/
- VeraCrypt hidden-volume advisory (June 2026) — https://github.com/veracrypt/VeraCrypt/security/advisories/GHSA-jjcr-75w7-58jp
- Picocrypt internals — https://github.com/Picocrypt/Picocrypt/blob/main/Internals.md ; Kryptor — https://www.kryptor.co.uk/
- NSA Commercial Solutions for Classified — https://www.nsa.gov/Resources/Commercial-Solutions-for-Classified-Program/
- Apple Lockdown Mode — https://support.apple.com/en-us/105120 ; Secure Enclave — https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web
- Google Advanced Protection (Android 16) — https://security.googleblog.com/2025/05/advanced-protection-mobile-devices.html
- Qubes OS 4.3 — https://www.qubes-os.org/news/2025/12/21/qubes-os-4-3-0-has-been-released/ ; Tor and Tails merger — https://blog.torproject.org/tor-tails-join-forces/
- Signal reproducible builds — https://github.com/signalapp/Signal-Android/blob/main/reproducible-builds/README.md ; Meta Code Verify — https://engineering.fb.com/2022/03/10/security/code-verify/
- Citizen Lab, Paragon Graphite — https://citizenlab.ca/2025/03/a-first-look-at-paragons-proliferating-spyware-operations/ ; iVerify, Coruna and DarkSword — https://www.iverify.com/blog/proliferation-of-coruna-and-darksword
- Windows Recall — https://learn.microsoft.com/en-us/windows/ai/recall/

### Forensics, law enforcement and paper

- eucrim, EncroChat judicial chronology — https://eucrim.eu/articles/encrochat-a-judicial-chronology/
- Shutdown of Sky Global — https://en.wikipedia.org/wiki/Shutdown_of_Sky_Global ; Operation Trojan Shield / ANOM — https://www.vice.com/en/article/operation-trojan-shield-anom-fbi-secret-phone-network/
- Ghost takedown — https://www.computerweekly.com/news/366611232/Europol-provides-detail-on-Ghost-encrypted-comms-platform-takedown
- Amnesty Security Lab, Cellebrite zero-day in Serbia — https://securitylab.amnesty.org/latest/2025/02/cellebrite-zero-day-exploit-used-to-target-phone-of-serbian-student-activist/
- 404 Media, leaked Cellebrite capability documents — https://www.404media.co/leaked-docs-show-what-phones-cellebrite-can-and-cant-unlock/
- Magnet Forensics on iOS 18 inactivity reboot — https://www.magnetforensics.com/blog/understanding-the-security-impacts-of-ios-18s-inactivity-reboot/
- RedSec Labs, Signal messages recovered from iOS notification database (US v. Sharp, 2026) — https://www.redseclabs.com/blog/signal-disappearing-messages-fbi-ios-notification-database/
- Tor response to German deanonymisation reports — https://www.bleepingcomputer.com/news/security/tor-says-its-still-safe-amid-reports-of-police-deanonymizing-users/
- Rijmenants, Cuban Agent Communications — https://www.ciphermachinesandcryptology.com/papers/cuban_agent_communications.pdf
- The Register, Russian spy ring blunders (2010) — https://www.theregister.com/2010/07/01/spy_ring_blunders/
- Errata Security, how Reality Winner was identified — https://blog.erratasec.com/2017/06/how-intercept-outed-reality-winner.html
- The Register, Simon Finch RIPA sentence — https://www.theregister.com/2021/03/18/simon_finch_veracrypt_sentence_doubled/
- Signal, Santa Clara subpoena response — https://signal.org/bigbrother/santaclara/ ; Proton, activist case — https://proton.me/blog/climate-activist-arrest
- Crypto Museum, one-time pads — https://www.cryptomuseum.com/crypto/otp/index.htm
- Blockstream, codex32 — https://blog.blockstream.com/codex32-a-shamir-secret-sharing-scheme/ ; BIP-93 — https://bips.dev/93/
- Goucher, Hamming backups (2-of-3 with XOR) — https://cp4space.hatsya.com/2021/09/10/hamming-backups-a-2-of-3-variant-of-seedxor/
- Trail of Bits, Shamir secret-sharing vulnerabilities — https://blog.trailofbits.com/2021/12/21/disclosing-shamirs-secret-sharing-vulnerabilities-and-announcing-zkdocs/
- Naor & Shamir, Visual Cryptography — https://www.wisdom.weizmann.ac.il/~naor/PAPERS/vis.pdf
- Johnston, tamper-indicating seals — https://scienceandglobalsecurity.org/archive/sgs09johnston.pdf
- Jericho Comms one-time-pad system — https://joshua-m-david.github.io/jerichoencryption/information.html
- Printer tracking dots and DEDA — https://en.wikipedia.org/wiki/Printer_tracking_dots ; https://github.com/dfd-tud/deda
- Microtrace, ESDA indented-writing recovery — https://www.microtrace.com/technique/electrostatic-detection-apparatus-esda/
- DARPA Shredder Challenge 2011 — https://en.wikipedia.org/wiki/DARPA_Shredder_Challenge_2011
