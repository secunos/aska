# Aska — User Guide

## Version 1.0.1 — for Aska 1.0.1 (Linux x86-64)

Aska sends a short note to one person, or to a small group, in a way that leaves nothing behind. The note is encrypted on your computer, parked as unreadable noise on a relay that is reachable only through Tor, fetched by the receiver, shown on their screen, and gone. Aska keeps no history, no contacts, no account, no log, and writes nothing to disk unless you ask it to.

This guide tells you what you need, how to check that the copy you have is the real one, how to install it, how to send and receive, and — just as important — what Aska does **not** protect you against. Read the last part even if you skip the rest.

---

# 1. Before you start — what Aska promises and what it does not

**What Aska does.** Encryption that is designed to hold against today's computers and against future quantum computers (XChaCha20-Poly1305 with keys from Argon2id, and for the receiving-key path ML-KEM-768 combined with X25519). Every note travels only over Tor to a relay that is itself a Tor onion service, so neither the relay nor anyone watching the network learns who talks to whom. A relay stores only random-looking blocks for a limited time and has no idea which block is a note, a decoy, or filler. On your computer the note and the key live in locked memory that is wiped when you close the note, and the application writes nothing to disk.

**What Aska cannot do.** It cannot protect a note from the person you send it to, from a camera pointed at the screen, or from a computer that is already compromised by someone else. It cannot stop you from saving a key to a file or reading the words over a channel that is being listened to. It cannot make Tor work on a network that blocks Tor. These limits are spelled out in section 9; the short version is that Aska protects the *message* and the *trail* — the two ends are yours to protect.

**The status of this release.** Aska 1.0.1 has been through the project's own internal security review (its report is published with the source) and the gates listed in the release record. It has **not** been reviewed by an independent security auditor, and it has not had a legal review in any jurisdiction. The owner of the project chose to release it on that basis. If your safety depends on this software, weigh that fact.

---

# 2. What you need

| | Requirement |
|---|---|
| Computer | x86-64 PC. Linux: **Debian 13** or **Ubuntu 24.04 or later** for everyday use; **Tails 7** (from a USB stick) for the best protection; **Qubes OS 4.3** for compartmentalised use. Other Linux distributions work if they provide GTK 4.14 and libadwaita 1.5. There is no Windows, macOS or phone version. |
| Memory | 1 GB of free RAM while Aska runs (the key derivation uses 256 MiB on purpose, to slow down guessing). |
| Libraries (graphical client) | `libgtk-4-1` (GTK ≥ 4.14) and `libadwaita-1-0` (≥ 1.5). On Debian/Ubuntu: `sudo apt install libgtk-4-1 libadwaita-1-0`. Tails 7 has them. The command-line client needs nothing. |
| Tor | A Tor running on your computer. Either the system `tor` package (`sudo apt install tor`, it listens on port 9050) or Tor Browser (its Tor listens on port 9150 while the browser is open). Tails and Whonix provide Tor already. |
| A relay | The `.onion` address of an Aska relay. Your circle runs one or knows one (the Relay Operator Guide explains how to run one). Aska ships with no relay built in. |
| Optional: a camera | To read Key Card QR codes from another screen or from paper. Aska uses the `zbarcam` helper from the `zbar-tools` package. Pasting or typing works without it. |
| Not swap | Swap should be off, or Aska will warn at every start that a note *could* reach the disk. Section 3.4 shows how. Tails has no swap. |

Aska never needs root. It installs into your own home folder and can be removed by deleting a handful of files there (section 12).

---

# 3. Getting Aska and checking it is real

A tool like this is only worth having if the copy you run is the copy the project built. Someone who can hand you a modified Aska can read everything you send with it. The check takes two minutes and must be done **before** the first use, on every machine, for every new version.

## 3.1 Get the fingerprint first, then the files

For a user the release is one tarball, `aska-gui-1.0.1-linux-x86_64.tar.gz`, and three small companion files: `aska-gui-1.0.1-linux-x86_64.tar.gz.minisig` (its signature), `SHA256SUMS.txt` and `SHA256SUMS.txt.minisig`. The release page also carries the public key file, `RELEASE-NOTES.txt`, and — for relay operators — the relay binary `aska-drop-1.0.1-linux-x86_64`, the deploy tarball `aska-drop-deploy-1.0.1.tar.gz` and their signatures.

Before you download anything, obtain the release **fingerprint** — the SHA-256 of the tarball, 64 hexadecimal characters — from a source you trust that is **not** the download site: the person who introduced you to Aska, on paper, read over a call, or exchanged in person. The project also publishes its signing key id, `79AD6224AFF176C9`, and the public key

```
RWTJdvGvJGKtecwP4zEITLdIK5yvwDp8+PyjmaoWPMHPLJxHDbGs+Oox
```

Write those down too, from the same trusted source. A download site can always be made to show you a matching but false pair of file and fingerprint; a friend's piece of paper cannot be rewritten by whoever controls the site.

Then download the four files from the project's release page, `https://github.com/secunos/aska/releases` (any mirror or a USB stick from a friend is equally fine — step 3.2 is what makes it safe).

## 3.2 Check

In a terminal, in the folder with the downloaded files:

```bash
sha256sum aska-gui-1.0.1-linux-x86_64.tar.gz
```

The 64-character value must be **identical** to the fingerprint you obtained out of band. If it is not, stop: delete the file and ask your source again. Do not "try it anyway".

If you have `minisign` installed (`sudo apt install minisign`), also check the signature with the public key from above:

```bash
minisign -V -P RWTJdvGvJGKtecwP4zEITLdIK5yvwDp8+PyjmaoWPMHPLJxHDbGs+Oox -m aska-gui-1.0.1-linux-x86_64.tar.gz
```

It must say `Signature and comment signature verified`. The comment names the release tag.

## 3.3 Unpack and install

```bash
tar -xzf aska-gui-1.0.1-linux-x86_64.tar.gz
cd aska-gui-1.0.1-linux-x86_64
sha256sum -c SHA256SUMS            # both lines: OK
./install.sh
```

`install.sh` copies `aska` and `aska-gui` to `~/.local/bin`, a desktop entry and icon to `~/.local/share`, and the signed hash list to `~/.local/share/aska` so the application can verify itself later, and refreshes your desktop's application cache (`mimeinfo.cache`). It writes nothing else and never asks for a password. To uninstall, delete those files.

**On Tails, do not run `install.sh`.** Unpack into `~/aska` (which is in RAM) and run `~/aska/aska-gui-1.0.1-linux-x86_64/bin/aska-gui` from there; everything disappears at shutdown, which is the point of Tails. The USB stick that carries the tarball to Tails must be formatted **FAT32** — Tails does not mount exFAT, the default for large sticks on Windows.

## 3.4 First start

Start Aska from your desktop's application menu ("Aska"), or with `aska-gui` in a terminal. Every start runs the **environment checks** (section 4) and shows their findings as banners on the Home screen.

Open **Settings** (the gear) → **Verify this app**. It must say

> MATCH — the release's signed hash list is valid and names this binary.

and show a key id of `79AD6224AFF176C9`. Compare the SHA-256 shown there with the one in `SHA256SUMS` and with your paper. Anything else — MISMATCH, "unverifiable", a different key id — means you are not running the release you think you are. Stop and go back to 3.1.

The command-line equivalent is `aska verify`; it contacts nothing and prints the same facts.

If the checks warn about **swap**, turn it off before you use Aska for anything real:

```bash
sudo swapoff -a
sudo sed -i.bak '/\sswap\s/s/^/#/' /etc/fstab
for u in $(systemctl list-units --type=swap --all --no-legend | awk '{print $1}'); do sudo systemctl mask "$u"; done
cat /proc/swaps        # only the header line
```

---

# 4. The environment checks ("doctor")

Aska looks at the computer it runs on before it does anything, and tells you what it finds. Two findings stop network use until fixed; the rest are warnings that you can accept for the session with the **Accept** button (or `--yes` on the command line) — but each one weakens the protection, and the banner says how.

| Finding | What it means | What to do |
|---|---|---|
| **Not connected through Tor** | No Tor answers on the configured port. Aska refuses to send or receive. | Start Tor (`sudo systemctl start tor`) or open Tor Browser and choose *Tor Browser's Tor* in Settings → Tor. |
| **Only .onion relays are allowed** | A relay address is not a valid onion address. Refused. | Check the address with whoever gave it to you. |
| **Tor has not built a circuit yet** | Tor runs but is still connecting. | Wait a minute and press *Check again*. |
| **Tor is running but has not reached the Tor network (bootstrap N %)** | Tor is up but cannot bootstrap — the network you are on probably blocks Tor. Aska can only tell this at start-up when it can talk to Tor's control port; otherwise the same warning appears after a post or fetch has failed. | Aska cannot fix this and will not try. Use your platform's own tool: Tor Connection on Tails, the Anon Connection Wizard on Whonix, Tor Browser's connection settings elsewhere (then *Use Tor Browser's Tor*). |
| **Swap is enabled** | Memory can be written to disk by the operating system. | Section 3.4, or use Tails. |
| **Cannot lock memory** | The system limit on locked memory is too low. | Usually a VM or container setting; accept for the session if you must, knowing secrets may be swapped. |
| **Screen is being shared or recorded** / **remote session active** | A known screen recorder, remote-desktop server or forwarded display was found. | Close it. Aska can detect common tools by name only — see 9. |
| **X11 session: screenshots cannot be prevented** | On X11 every program can read every window. | Prefer a Wayland session (GNOME's default on Debian; Tails is Wayland). |
| **An accessibility service could read notes** | A screen reader or the accessibility bus is active. | Aware of it, decide. |
| **Crash dumps enabled** | A crash could write memory to disk. | Aska disables them for itself; the warning means it could not. |
| **This build does not match its signed release list — do not use it for anything real** | The signed hash list beside the binary does not verify, or does not name it. | Do not use it. Section 3. |
| **Persistent Storage is unlocked** (Tails) | Information only: Aska still saves nothing there. | — |

The footer of the Home screen shows the Tor state at all times ("Tor: connected", "Tor: connected via Tor Browser", "Tor: not reachable", …) and the first characters of the build fingerprint.

---

# 5. Sending a note

Press **Send a note**. The screen has the note editor at the top and the options below.

**The note.** Type or paste it. The counter under the editor shows the size; a Block of 4, 16 or 64 KiB holds roughly 2.5 KB, 14 KB or 62 KB of text (about one, six or twenty-five pages), and Aska picks the smallest that fits. The editor allows paste but not copy or cut, and keeps no undo history — the note exists on this screen and nowhere else until it is sealed.

**Protection level.**

- **Quick** — "you can meet or call them". The key travels whole, as a Key Card (text and QR code) and as the same key spelled out in 24 words. Whoever holds the key before the drop expires can read the note.
- **Guarded** — "they might be pressured". The key is split into Shares (2 of 3, or 3 of 5); each Share goes to a different person, and only enough of them together reconstruct the key. One person's knowledge, or one person's device, is not sufficient. Name the holders in the *for* fields so each Share is labelled.

**Passphrase to open the note.** Optional. The receiver must enter it as well as hold the key. Use it when the key might be seen in transit (a Key Card photographed, words overheard). Passphrases are entered on an in-app keypad whose layout shuffles each time; a physical-keyboard fallback exists behind a toggle. A passphrase is a *second* factor — it does not replace the key.

**Add a decoy note.** A second, harmless note behind its own passphrase. Whoever is forced to open the drop can give the decoy passphrase and show a plausible note. The real note stays hidden — the Block looks identical either way, and nothing on the relay or in the Block reveals that there are two.

**Add a distress passphrase.** A third passphrase that shows the decoy **and destroys the real note's key on the receiving device** the moment it is entered. After it, the real note cannot be opened by anyone from that device, and the device behaves exactly as if the decoy had been opened normally — the timing is identical by design. *Be aware:* in some legal systems destroying material under compulsion can itself be an offence; the project has not had this reviewed. Decide with that in mind.

Each passphrase you set must be different from the others, and none may be empty.

**Keep on the relay for.** 1 hour to 7 days (default 24 hours). After this the relay discards the Block; a receiver who comes later finds nothing. Shorter is safer.

**Relays.** One or more `.onion` addresses, separated by spaces. If a profile is open (section 8), its relays are already there. The Key Card will carry the relay address so the receiver does not have to type it; words and Shares never do.

**To (receiving key).** Leave empty for the normal flow. Section 7 explains this field.

Press **Seal and post**. Aska derives the key (a few seconds — it is deliberately slow), seals the note into a Block with random filler so that every Block looks the same, and posts it over Tor to each relay on a fresh circuit. Posting can take a minute. A real post is delayed by a random 0–90 seconds and mixed with Aska's decoy traffic (section 8) so it does not stand out.

## 5.1 Hand-over — getting the key to the receiver

After posting you see the **Hand-over** screen. This is the only moment the key exists in readable form, and the whole security of a Quick note depends on how you pass it on.

- **Key Card** — a short text beginning `aska1…`, also drawn as a QR code. It contains the key, the Block's size class and the relay address. Show the QR to the receiver's camera, let them photograph it from your screen, or read the text to them.
- **The same key as 24 words** — for reading aloud or writing on paper. Words carry the key only; the receiver also needs the relay address (tell them, or they take it from a Key Card someone else has).
- **Guarded:** one **Share** at a time (`askas1…`), labelled "Share 1 of 3 — for: Anna". Pass each to its person before showing the next. Never two Shares on one screen or in one hand.

A banner reminds you of the Quick rule: whoever holds this key before the drop expires can read the note. The screen closes itself after five minutes. Press **Done — forget the key** as soon as the hand-over is complete; Aska then wipes the key from memory and nothing about this note remains on your computer.

What you must *not* do: save the Key Card to a file, send it over the same channel an adversary would be watching, or send the key and the passphrase over the same channel. The key is for one channel, the passphrase for another, and the relay is a third — that separation is the design.

---

# 6. Receiving a note

Press **Receive a note**.

**Key material.** Paste or type the Key Card (`aska1…`), the 24 words, or Shares one at a time (**Add** after each; the screen says "Share accepted — 1 of 2 (need more)" until enough have arrived and the key is reconstructed on this device). **Scan with camera…** starts the camera helper to read a QR code.

**Relays.** Needed only when the key material names no relay — words and Shares never do, a Key Card usually does.

**Passphrase.** Enter it on the keypad if the sender set one; leave empty otherwise.

Press **Check the drop**. Aska fetches the relay's whole stock of Blocks of the right size over Tor — every receiver downloads everything, so the relay cannot tell which Block was wanted — finds yours locally, derives the key and opens it. Then the **Note** screen shows the text.

**Nothing found** means the note is not posted yet or the drop has expired — ask the sender, and try again; the command-line client retries on its own (three attempts, 30 seconds apart, by default). **Nothing opened with that passphrase** means the Block was found but no passphrase you gave opens anything: a wrong passphrase, and nothing more is revealed than that.

## 6.1 Reading and burning

The note is shown in a read-only field drawn straight from locked memory; it cannot be selected, copied or searched. A countdown runs (five minutes by default, adjustable in Settings → Timers). Press **Close and burn** when you have read it. Aska wipes the note and the key; closing the window or letting the countdown finish does the same. The footer tells you the truth about screenshots on this system: on X11 they cannot be prevented; on Wayland capture can be detected but not blocked.

A note you need to keep is a note you must write down by hand, knowing that the paper is now the weakest point.

If a decoy or distress passphrase was entered, the Note screen looks and behaves exactly the same — by design, nothing on screen shows which note was opened.

---

# 7. The receiving key — notes from someone far away

The Quick and Guarded levels need a hand-over: the receiver must get a key from the sender by a trusted channel. Sometimes there is no such channel — a source and a journalist on different continents who have never met. For that case the **receiver** creates a key pair and publishes the public half; anyone can then send a note that only the receiver can open, and nothing secret ever crosses any channel.

**Receiver:** **Shares** → **Create a receiving key…** (or the same button on the Receive screen). Enter the relay. The screen shows three things:

- the **24 seed words** — the secret. Keep them (on paper, in your head); never type them anywhere but into Aska;
- the **Receiving Key** — public text beginning `askar1…`, also as QR. Give this to whoever may write to you, by any channel at all: e-mail, a web page, a printed card. It is public;
- a **twelve-character check** such as `qpzr-y9x8-gf2t`. It is derived from the key itself (a hash of the public key); a substituted key has a different check, and making one that matches is out of reach in practice.

**Sender:** Send → paste the Receiving Key into **To (receiving key)** → write the note → **Seal and post**. The flow ends on **Posted — nothing to hand over**, showing the **same twelve-character check**.

**The one thing both sides must do:** confirm the check over a second channel — a phone call, a message, in person — before the first note. If the checks differ, someone substituted the key between you; stop. A key published in several places at once is harder to substitute everywhere.

**Receiver, to read:** Receive → **I have a receiving seed** → type the 24 words → **Add** → relay → **Check the drop**. Aska tries every Block on the relay against your seed (the same work for each, matched or not) and opens the one for you.

When you press **Close and burn** (or the countdown ends) Aska reminds you that this key has now been used and that a new one should be created. Anyone who later learns the 24 words can read every note sent to that key that is still on the relay. Aska will not stop you from reusing a key; the advice stands.

---

# 8. Settings, profile and cover traffic

The gear opens **Settings**.

**Environment checks** — the findings of section 4 with explanations, and *Check again*.

**Relays for this run** — the relay list, kept until the application closes. **Check reachability** asks each relay over Tor and reports its classes, maximum TTL and proof-of-work setting. The line "Circle key" says whether the relays you use are open to anyone (the normal case) or restricted to a circle.

**Tor** — *System Tor (port 9050)* or *Tor Browser's Tor (port 9150)*. The second is what you choose when only Tor Browser, connected through a bridge, reaches the Tor network on the network you are on. Aska itself never configures Tor and never tries to get around a network's rules; it only uses a Tor that already works.

**Cover traffic** — while Aska is open it sends decoy requests to your relays at random intervals, carrying random bytes that the relay discards like anything else, so a real post or fetch looks like any other request. *Modest* (default) is a few per relay per day; *High* is about hourly; *Off* is off. There is no background service: cover runs only while the window is open, because a permanently running process would itself be a signal.

**Timers** — the idle timeout (an idle session closes itself and forgets its key) and the note auto-close.

**Language** — English or Svenska; follows the system language by default.

**Verify this app** — section 3.4.

**Encrypted profile** — the one thing Aska can write to disk, and only at a path you type: your circle's relays (and circle key, if any) in a file of random-looking bytes protected by a passphrase. With a profile open you need not type the relay each time. *Create…*, *Open…* and *Forget…* (which overwrites the file with random bytes and deletes it). Nothing else — no notes, no keys, no history — is ever in it. Opening a profile takes a few seconds (Argon2id, 256 MiB).

---

# 9. What Aska does not protect you against — read this

1. **The other end.** The receiver can photograph the screen, write the note down, or be someone other than you think. Aska makes a note disappear from devices, not from people.
2. **A compromised computer.** If malware or a remote operator can see your screen or memory, they see the note. Aska limits the damage — there is no history, no contacts, no stored keys to take — but it cannot protect a note while it is being displayed. Tails from a USB stick, used only for this, is the strongest practical answer.
3. **Cameras and screens.** Someone filming your screen, a screen recorder Aska did not recognise (it knows common recorders by their process names only; GNOME's own built-in recorder is **not** detected — a known gap), or a compositor that keeps the rendered frame in GPU memory. On X11 any program can take screenshots.
4. **Your own channel choice.** Reading the 24 words over a monitored phone, pasting a Key Card into a chat that is being read, or sending the key and the passphrase together, defeats everything. The key, the passphrase and the relay address are meant to travel separately.
5. **Toolkit memory.** The note passes through the graphical toolkit's text widgets and the compositor; Aska overwrites what it can, measures the result and warns about swap, but cannot guarantee that every copy is gone from every buffer. Tails (no swap, memory wiped at shutdown) removes the residual.
6. **A network that blocks Tor.** Aska has no fallback and will not invent one. If Tor cannot connect, use your platform's own tool to connect through a bridge; Aska will tell you so and then use that Tor. The attempt to connect to Tor is itself visible to the local network.
7. **A substituted Receiving Key.** The key is public; the twelve-character check is the only protection against a swap, and only if you compare it over a second channel.
8. **Reused receiving keys.** Whoever learns the seed reads every note still on the relay for that key. Create a new key after each use.
9. **Compelled disclosure.** The decoy and distress features give you a plausible note to show and a way to destroy the real one. Whether using them is lawful where you are has not been reviewed by this project. Destroying evidence can be a crime.
10. **Statistical observation of a relay.** An observer who collects a very large number of Blocks from one relay could, in principle, estimate what fraction were sent to receiving keys — never which ones, and never their contents. Accepted for 1.0 and documented for review.
11. **The 1.0 releases have not been independently audited.** See section 1.

Rules of thumb: use Tails for anything that matters; set short TTLs; use a passphrase when the key crosses a channel you do not fully trust; never save key material; burn the note as soon as you have read it; confirm the check for receiving keys; and **never install an update because software told you one exists** — Aska will never tell you to, and a message claiming to be from Aska that does is a lie. Get the new fingerprint from your trusted source and repeat section 3.

---

# 10. Using Aska on Tails and Qubes

**Tails 7.** Boot from the stick; do not unlock Persistent Storage unless you need the encrypted profile, and understand that only the profile could ever be stored there. Complete Tor Connection *before* starting Aska. Bring the tarball on a FAT32 stick, unpack it into `~/aska`, verify as in section 3, and run `bin/aska-gui` in place. Use Aska; close it; shut down Tails. Everything was in RAM and Tails wipes RAM at shutdown. A circle key (restricted relays) cannot be used on Tails; the receiving-key path works as everywhere.

**Qubes OS 4.3, simple mode.** Run `aska-gui` in a disposable Whonix-Workstation qube. Aska recognises Whonix and uses the gateway's Tor automatically. The qube is destroyed when closed. The X11 warning is expected there — the qube's screenshots are taken by dom0, which Aska cannot see.

**Qubes OS, split mode (highest assurance).** Seal the note in a qube with no network at all, and post it from a disposable with only Tor, using the command-line client:

```bash
# in the offline vault qube
aska seal --level guarded --shares 2of3 --out block.bin       # shows the Shares; block.bin is noise
qvm-copy block.bin                                             # to the disposable
# in the disposable
aska post block.bin --relay <onion>
```

Receiving mirrors it: `aska drop get <onion> --class N --out bucket.bin` in the disposable, `qvm-copy` to the vault, `aska open bucket.bin` there (add `--receiving-seed` for a receiving key). The key never exists in a networked qube.

---

# 11. The command-line client

`aska` does everything the graphical client does, in a terminal, with the same rules: secrets are never taken from the command line or the environment (only typed with echo off, scanned, or piped with `--stdin`), nothing is written unless you name a file, hand-over material and notes are shown on the alternate screen with a countdown and cleared afterwards, and every command runs the environment checks first.

```bash
aska doctor                                   # the environment checks; exit 0 clean, 2 warnings, 6 refusals
aska --relay <onion> send                      # type the note, end with a line containing only "."
aska --relay <onion> send --passphrase --ttl 48h
aska --relay <onion> send --shares 2of3 --for Anna --for Bo    # Guarded: Shares one at a time
aska --relay <onion> send --decoy --distress   # prompts for each passphrase and note
aska receive                                   # paste the Key Card (or words, or "scan"), passphrase, read
aska --relay <onion> share combine             # a Share holder: paste Shares until the key is whole
aska --relay <onion> key receive               # new receiving key: 24 words, askar1… key, check
aska --relay <onion> send --to askar1…         # send to a receiving key
aska --relay <onion> receive --receiving-seed  # receive with the 24 words
aska verify                                    # own hash, release key, signed list check (offline)
aska --relay <onion> profile create --file ~/circle.aska   # the optional encrypted profile (needs ≥ 1 relay)
aska --profile ~/circle.aska send              # use it
```

Global options: `--relay` (repeatable), `--profile FILE`, `--socks HOST:PORT` (default 127.0.0.1:9050) or `--tor-browser` (127.0.0.1:9150), `-y`/`--yes` to acknowledge warnings (a success then exits 2), `--accept-unlocked-memory`, `--qr half|ascii|none`, `--idle SECONDS`, `--scan-cmd CMD`. `aska --help` and `aska <command> --help` are the full reference.

Exit codes: 0 success · 2 success after acknowledged warnings · 3 you declined · 4 relay unreachable or full · 5 nothing found or opened · 6 refused (not through Tor, or a relay that is not a `.onion`) · 141 output closed early, e.g. by `| head` (1.0.1 and later) · 1 other error.

---

# 12. Removing Aska

```bash
rm -f ~/.local/bin/aska ~/.local/bin/aska-gui
rm -f ~/.local/share/applications/org.aska.Aska.desktop ~/.local/share/icons/hicolor/scalable/apps/org.aska.Aska.svg
rm -rf ~/.local/share/aska
update-desktop-database ~/.local/share/applications 2>/dev/null
```

If you created an encrypted profile, *Forget…* it from Settings first (or delete the file; it contains only relay addresses). There is nothing else: Aska kept no history, no cache and no configuration.

---

# 13. Getting help and reporting problems

The source code, the design documents, the internal review report and the release records are at `https://github.com/secunos/aska`. A problem report (the repository's *Issues* page) should never contain a note, a key, a Key Card, a passphrase or a relay address — the output of `aska doctor` and the exact error text are enough. If you believe you have found a security flaw, report it privately first through the repository's *Security → Report a vulnerability* page (see `SECURITY.md`).

*Aska is free software: the core and clients under MIT or Apache-2.0 at your choice, the relay under AGPL-3.0. It comes with no warranty of any kind.*
