# Aska — Relay Operator Guide

## Version 1.0.1 — for `aska-drop` 1.0.1 (Linux x86-64)

An Aska **relay** (the "Dead Drop") is the place where sealed notes wait for their receiver. It is a small program that keeps up to a few thousand fixed-size random-looking Blocks in RAM for up to seven days (3,000 with the default capacities), hands all of them to anyone who asks, and forgets them when they expire. It is reachable only as a Tor onion service. It has no accounts, no logs, no admin interface and no disk store; it does not know which Blocks are notes, which are decoys and which are filler, and it cannot tell senders from receivers.

This guide is for the person who runs one. It covers what you need, how to install from the signed release, how to check it works, how to upgrade, and what running a relay does and does not mean for you.

---

# 1. What a relay is, and is not

**It stores ciphertext for a while.** A client posts a Block of 4, 16 or 64 KiB together with a 32-byte random label and a time to live; the relay keeps it until that time runs out (hard ceiling 168 hours) and then discards it. A client that wants a note fetches the relay's *entire* stock of Blocks of that size and finds its own on its own device. The relay therefore never learns which Block was wanted, and sees every fetch as the same request.

**It has no way to read anything.** Blocks are indistinguishable from random bytes; the key never passes through the relay. Decoy traffic from clients (random Blocks, random fetches) is mixed in with real traffic and the relay cannot tell them apart either.

**It keeps no record.** There is no data directory, no database, no log file and no log level. The process locks its memory so that nothing can be swapped to disk, disables crash dumps, runs under a throw-away system user with a read-only view of the filesystem, and prints nothing while it runs. The only thing it can ever write is a single line to the system journal on a fatal start-up failure, and the journal is configured to live in RAM. A reboot loses every live Block; that is by design and there is nothing to back up.

**It is visible only through Tor.** The relay listens on `127.0.0.1` and Tor forwards an onion service to it. The host has no open ports; inbound traffic is dropped by the firewall. Nobody who does not hold the onion address can find the relay, and the address is passed around inside Aska Key Cards or by word of mouth.

**What you, the operator, hold:** a server with Tor and a 2 MB binary, and the onion address. You do not hold keys, names, notes or any means to obtain them. Destroying the server is the complete decommissioning procedure.

---

# 2. What you need

| | Requirement |
|---|---|
| Host | A Debian 12 or 13 x86-64 machine you control: the smallest VPS (1 vCPU, 1 GB RAM, any disk) is enough; a Raspberry Pi is not (x86-64 only in this release). A fresh install is strongly preferred — the installer hardens the whole host, and a shared host weakens that. |
| Access | Root, over SSH with a **key** (the installer disables password login) or the provider's console. |
| Network | Outbound internet. **No inbound ports** are needed and none are opened — an onion service connects outwards to the Tor network. |
| Memory | The relay must be able to lock about 100 MiB with the default capacities (2000 × 4 KiB, 800 × 16 KiB, 200 × 64 KiB Blocks plus runtime); it locks about 9 MiB when empty and grows as Blocks arrive. The service unit caps it at 512 MiB. |
| Time | About 30 minutes, most of it waiting for `apt` and for Tor to publish the onion service. |
| On your own computer | `sha256sum` and, ideally, `minisign` (`sudo apt install minisign`) to check the files before you put them on the server. |

The relay needs no Rust toolchain, no library and no container on the server: the binary is static and runs on any x86-64 Linux.

---

# 3. Get the files and check them

From the release you need two files, and from the source archive three more:

| File | From | Purpose |
|---|---|---|
| `aska-drop-1.0.1-linux-x86_64` | release (`https://github.com/secunos/aska/releases`) | the relay binary (static) |
| `aska-drop-1.0.1-linux-x86_64.minisig` | release | its signature |
| `deploy/install-debian.sh` | source archive, or `aska-drop-deploy-1.0.1.tar.gz` beside the binary | one-shot installer |
| `deploy/torrc.aska-drop` | same | Tor configuration (onion service, no logs, DoS defences) |
| `deploy/aska-drop.service` | same | hardened systemd unit |

Obtain the **fingerprint** (SHA-256) of the relay binary from a source other than the download site — the release announcement passed to you by someone you trust, or the `SHA256SUMS.txt` of the release checked against its signature. The project's signing key id is `79AD6224AFF176C9` and its public key is

```
RWTJdvGvJGKtecwP4zEITLdIK5yvwDp8+PyjmaoWPMHPLJxHDbGs+Oox
```

On your own computer, in the folder with the files:

```bash
sha256sum aska-drop-1.0.1-linux-x86_64                     # compare with the fingerprint
minisign -V -P RWTJdvGvJGKtecwP4zEITLdIK5yvwDp8+PyjmaoWPMHPLJxHDbGs+Oox -m aska-drop-1.0.1-linux-x86_64
```

The second command must print `Signature and comment signature verified`. Read `install-debian.sh` before you run it: it is about eighty lines and it reconfigures the firewall, SSH, swap and Tor of the machine it runs on. You should know what it will do.

---

# 4. Install

## 4.1 Copy the files — before the firewall goes up

The installer drops **all** inbound traffic, SSH included, unless you tell it to keep SSH open. Copy everything first and run the install from an SSH session you already have:

```bash
scp aska-drop-1.0.1-linux-x86_64 install-debian.sh torrc.aska-drop aska-drop.service root@<server>:/root/
ssh root@<server>
```

## 4.2 Run the installer

On the server:

```bash
cd /root
mv aska-drop-1.0.1-linux-x86_64 aska-drop
sha256sum aska-drop                       # the fingerprint again, now on the server
chmod +x install-debian.sh
SSH_ALLOW=any ./install-debian.sh         # 5–10 minutes
```

`SSH_ALLOW=any` keeps SSH open to key holders from anywhere and disables password login. `SSH_ALLOW=<your public IP>` restricts it to one address; `SSH_ALLOW=none` closes SSH entirely (you will then need the provider's console for everything). The script refuses to run over SSH without one of these, so it cannot lock you out by accident.

What it does, in order: updates the system and turns on unattended security updates; turns swap off for good; installs an nftables firewall that drops all inbound traffic except established connections (and SSH if allowed); installs Tor from the Tor Project's own repository with the supplied `torrc` (an onion service forwarding to port 4567, no SOCKS port, no logs, intro-point and proof-of-work DoS defences on); installs the binary to `/usr/local/bin/aska-drop` and the hardened unit; makes the system journal volatile (RAM only). It ends by printing the **onion address** — 56 characters followed by `.onion`.

That address is the only thing you need to hand out. Give it to your circle by a channel you trust; it will travel inside their Key Cards from then on.

## 4.3 Check

Still on the server:

```bash
systemctl status aska-drop tor --no-pager | grep Active     # both: active (running)
cat /var/lib/tor/aska-drop/hostname                          # the onion address
ss -ltn                                                      # only 127.0.0.1:4567 (and port 22 if SSH was kept open); Tor itself listens on no port
cat /proc/swaps                                              # header line only
grep VmLck /proc/$(systemctl show -p MainPID --value aska-drop)/status   # about 9000 kB when empty
```

Then, from any computer with Tor and the Aska client, after giving Tor a few minutes to publish the service:

```bash
aska drop info <onion-address>
```

The answer — max TTL 168 h, classes 1–3, PoW base 0 — is the complete health check. Nothing else is observable from outside; that is the point.

---

# 5. Configuration

The whole surface is the `ExecStart` line of the unit:

```
aska-drop serve [--port 4567] [--max-ttl-hours 168] [--cap-1 2000] [--cap-2 800] [--cap-3 200] [--pow-base 0]
```

| Option | Meaning | Default |
|---|---|---|
| `--port` | loopback port Tor forwards to (must match `HiddenServicePort` in the torrc) | 4567 |
| `--max-ttl-hours` | longest time a client may ask the relay to keep a Block; hard ceiling 168 | 168 |
| `--cap-1`, `--cap-2`, `--cap-3` | how many Blocks of 4, 16 and 64 KiB the relay holds at most; 0 switches a class off | 2000 / 800 / 200 |
| `--pow-base` | base proof-of-work difficulty, in bits, that a client must solve to post; adaptive bits are added once a class is more than half full (up to +4). Clients refuse more than 24 bits in total, so keep this at 20 or below — in practice a few bits at most | 0 |

To change something: edit `/etc/systemd/system/aska-drop.service`, then `systemctl daemon-reload && systemctl restart aska-drop`. A restart empties the store.

Guidance: the defaults suit a circle of a few dozen people. A relay that is "full" answers posts with FULL; the client posts to every relay the sender gave it, so a note still goes through if any one of them accepted it — capacity is a comfort setting, not a safety one. Raising a cap raises the memory the relay locks (every Block is resident): roughly cap-1 × 4 KiB + cap-2 × 16 KiB + cap-3 × 64 KiB, plus about 64 MiB headroom — adjust `MemoryMax` in the unit accordingly. `--pow-base` above 0 makes posting cost the sender a little CPU; it is a defence against someone trying to fill the relay with junk, at the price of slower posts for everyone. Leave it at 0 unless you see the relay full all the time.

**Restricted ("circle-key") relays.** A relay can be limited to clients that hold a shared Tor client-authorisation key: put one `.auth` file for the whole circle in `/var/lib/tor/aska-drop/authorized_clients/` and distribute the private half inside Key Cards. One key for everyone, never one per member — individual keys would be a membership list. Clients on Tails and Whonix cannot use such relays (their Tor control port is filtered), so a circle that includes them keeps at least one open relay.

---

# 6. Day to day

**Nothing to back up, nothing to rotate on a schedule, nothing to read.** A healthy relay is silent.

**Operating-system and Tor updates** happen on their own (unattended-upgrades). A kernel update needs a reboot now and then; a reboot loses the live Blocks and nothing else.

**Upgrading the relay binary.** Verify the new release as in section 3, copy the new binary (and the new unit file, if the release notes say it changed) to `/root`, then on the server:

```bash
sha256sum /root/aska-drop                                  # the new fingerprint
install -m 0644 /root/aska-drop.service /etc/systemd/system/aska-drop.service   # only if changed
install -m 0755 /root/aska-drop /usr/local/bin/aska-drop
systemctl daemon-reload && systemctl restart aska-drop
systemctl status aska-drop --no-pager | head -3
```

**If the relay restarts on its own**, `journalctl -u aska-drop -n 20 --no-pager` shows the one line it leaves. The relay refuses to start when its locked-memory limit is too small for its caps (exit code 3, with the numbers); the supplied unit sets the limit to unlimited, so this points at an edited unit.

**Rotating the onion address.** Every few months, or whenever you suspect the address has been written down where it should not be:

```bash
systemctl stop tor
shred -u /var/lib/tor/aska-drop/*; rm -rf /var/lib/tor/aska-drop
systemctl start tor
sleep 5; cat /var/lib/tor/aska-drop/hostname               # the new address — hand it out again
```

Every Key Card that carried the old address stops working. That is the point.

**Decommissioning.** Destroy the server. If you keep the host for something else, `systemctl disable --now aska-drop tor`, run the `shred` line above, and `rm /usr/local/bin/aska-drop /etc/systemd/system/aska-drop.service`. Nothing else of Aska is on the disk.

**Locked out after installing?** If SSH stopped answering, the install ran without `SSH_ALLOW` (from a console), with `SSH_ALLOW=none`, or with an IP address that is no longer yours. The fix is to boot the provider's rescue system, mount the disk and add `tcp dport 22 accept;` to the input chain in `/etc/nftables.conf`, then boot normally. The project's deployment notes (`deploy/DEPLOY.md` in the source archive) spell out the steps for DigitalOcean.

---

# 7. What running a relay means for you

**Technically.** You provide storage for other people's ciphertext for up to a week and bandwidth for Tor. You cannot read it, cannot tell who posted or fetched it, and cannot be made to produce more than you have: there are no logs to hand over, no keys to surrender and no user list. The machine holds, at any moment, up to a few thousand Blocks of random-looking bytes and one onion key.

**Legally.** This is a matter of where you are and of the people who use your relay, and this project has not had it reviewed by a lawyer in any jurisdiction. Running a Tor onion service and a store-and-forward relay is lawful in most countries; hosting encrypted content you cannot inspect is the normal situation of every mail and chat provider. But a relay that is used for something unlawful may draw attention to the operator, and some jurisdictions have rules on encryption services or on data retention that could in principle be read to apply. The project's position is simply that the software is honest about what it keeps (nothing) and that an operator should know the rules of their own country before running one. If in doubt, ask someone qualified where you live.

**Practically.** Use a server that is yours and only runs this; pay for it in a way you are comfortable with; keep the onion address off anything that is indexed; do not announce the relay publicly. A relay is for a circle, not for the world.

---

# 8. Reference: the wire protocol in one paragraph

The relay speaks ADP/1, a tiny binary protocol over a single TCP connection per request: INFO (returns max TTL, served classes and base PoW), PUT (a class, a TTL, a 32-byte label, a Block of the class's size; the relay answers OK, FULL, DUPLICATE, BAD_*, POW_REQUIRED with a challenge, or POW_INVALID), and GET_ALL (a class; the relay returns every live label and Block of that class, bounded only by its cap — clients refuse a listing longer than 4096 / 1600 / 400 records). Requests are fixed-length; malformed ones are answered with a status or dropped; every connection has a 30-second read/write timeout and a 300-second overall budget; at most 256 connections are open at once and new ones are shed, not queued. Identical re-posts are acknowledged, not duplicated. The full specification is `docs/Aska_Dead_Drop_Protocol_Specification_ADP1_draft0.3.md` in the source archive, and `reference/aska_drop.py` is a readable Python implementation of the same rules.

*`aska-drop` is free software under the AGPL-3.0. It comes with no warranty of any kind.*
