# Deploying an Aska Dead Drop relay on a DigitalOcean droplet (M2)

This walks the relay from a laptop build to a running onion service. It follows the operator
runbook in the Dead Drop Protocol Specification (§9) and uses the scripts in this directory.
Time: about 30 minutes, most of it waiting for `apt` and for Tor to publish the descriptor.

## 0. What you need

- The Ubuntu VM where `cargo test --workspace --release` already passes (it builds the binary).
- A DigitalOcean account. Create a droplet: **Debian 13 (or 12)**, the smallest size
  (1 vCPU / 1 GB / 25 GB), any region, **SSH key** authentication, no extras. Note its IP.
- Tor on the VM for the health check afterwards: `sudo apt install -y tor` (the Ubuntu package
  is fine on the client side; it listens on `127.0.0.1:9050`).

## 1. Build the static relay binary in the VM

```bash
cd ~/aska
./scripts/repro-build.sh            # prints SHA-256 of aska and aska-drop
./scripts/repro-build.sh --compare  # must print REPRODUCIBLE: OK
sha256sum target-repro/x86_64-unknown-linux-gnu/release/aska-drop   # write this fingerprint down
```

The binary is `static-pie`, so it runs on any x86-64 Linux; Debian on the droplet needs nothing
installed for it. The fingerprint you wrote down is what you compare against on the server
(step 3) — that is the OPS-02 "verify before installing" rule, done by hand for now (M7 adds
signed releases).

## 2. Copy the files to the droplet — *before* the firewall goes up

The install script drops **all** inbound traffic, including SSH, once it has run (§9.2 step 3).
So copy everything first, and do the install from an SSH session you already have open.

```bash
scp target-repro/x86_64-unknown-linux-gnu/release/aska-drop \
    deploy/install-debian.sh deploy/torrc.aska-drop deploy/aska-drop.service \
    root@<droplet-ip>:/root/
ssh root@<droplet-ip>
```

To keep SSH after the install, run the script with `SSH_ALLOW` set to your own public
address (find it with `curl -s https://ifconfig.me` from the VM) or to `any` for key-only SSH
from anywhere; the script then also disables password login. Without `SSH_ALLOW` the firewall
closes SSH too and the DigitalOcean web console ("Access → Launch Droplet Console") is the
only way in, which is the runbook's default. Note that a home connection's address can change;
if you get locked out, the console still works.

## 3. Install

On the droplet, in the SSH session:

```bash
cd /root
sha256sum aska-drop        # must equal the fingerprint from step 1
chmod +x install-debian.sh
SSH_ALLOW=<your-public-ip> ./install-debian.sh   # 5–10 minutes; ends by printing the onion address
# (or SSH_ALLOW=any, or omit it to close SSH and use the web console)
```

What it did: dist-upgrade + unattended-upgrades, swap off, nftables drop-all-inbound, Tor from
deb.torproject.org with our `torrc` (onion service, PoW and intro-DoS defences, no logs),
the binary to `/usr/local/bin/aska-drop`, the hardened systemd unit
(`LimitMEMLOCK=infinity`, `LimitCORE=0`, standard output to null and standard error to the RAM-only journal — the relay prints nothing while serving, only a one-line fatal start-up or abort reason — read-only filesystem view), and a
volatile journal. The relay is now listening on `127.0.0.1:4567` and Tor forwards the onion
service to it.

Checks on the droplet:

```bash
systemctl status aska-drop tor --no-pager   # both active (running)
cat /var/lib/tor/aska-drop/hostname         # the onion address, 56 chars + .onion
ss -ltn                                     # only 127.0.0.1:4567 (and Tor's own loopback ports)
swapon --show                               # prints nothing
free -m                                     # Swap: 0
```

## 4. Health check over Tor from the VM (§9.5)

Tor needs a few minutes after the first start to publish the descriptor. Then, on the VM:

```bash
python3 ~/aska/reference/aska_drop.py info --host <onion-address> --port 4567 --socks 127.0.0.1:9050
# → {'status': 0, 'max_ttl_hours': 168, 'classes': [1, 2, 3], 'pow_difficulty': 0}
```

That is the complete health check: the relay answers, serves three classes, seven-day TTL,
no base PoW. Nothing else is observable from outside — by design.

## 5. The M2 soak gate (24 hours)

On the droplet, as a background job that logs to a file (it survives the console closing and
does not depend on a terminal multiplexer's scrollback, which a 24 h run overflows):

```bash
# copy reference/aska_drop.py and scripts/soak.py to /root first (scp, as in step 2), then:
cd /root
PYTHONPATH=/root nohup python3 /root/soak.py --host 127.0.0.1 --port 4567 --socks none \
    --hours 24 --interval 10 --ttl 1 --report 600 > /root/soak.log 2>&1 &
tail -n 20 /root/soak.log        # any time; the first report line appears after 10 minutes
```

Expected every 10 minutes: a line like
`puts=… ok=… full=0 live_class1=360 mem=…KiB`. The live count climbs for the first hour, then
stays at about 360 (one hour of Blocks at one per 10 s) and `MemoryCurrent` stops growing at
the same time — that is "flat memory and correct expiry". Anything that keeps climbing after the
first hour is a bug; send me the output. A failed request does not end the run: it is counted
and the line grows an `err=N last_err=…` tail. `err` staying at 0 is part of the gate; a
non-zero `err` with the relay still up points at the network path, a non-zero `err` together
with a relay restart in `journalctl -u aska-drop` points at the relay.

`mem` is the *locked* footprint: about 9 MiB for an empty relay (binary, two worker stacks and
the runtime, all resident because of `mlockall`), growing by roughly the size of the live
Blocks. With the default caps a completely full relay locks about 45 MiB.

Optional extra gate on the droplet: `apt-get install -y strace` and run
`scripts/no-writes-check.sh /usr/local/bin/aska-drop` (it starts a second relay instance on
port 4598 for the duration of the check; the production instance is untouched).

## 5a. Upgrading a relay installed before 2026-09-29 (required)

Units installed from earlier revisions contain a mis-spelled directive (`MemoryLock=infinity`,
which systemd ignores with a warning at boot) instead of `LimitMEMLOCK=infinity`. The relay
then runs under the default 8 MiB lock limit, which the empty process already nearly fills:
it works until the store grows, and then the first refused allocation aborts it (`status=6/ABRT`
in the journal, one connection dropped, systemd restarts it five seconds later, live Blocks
lost). The 2026-09-29 relay refuses to start under such a limit instead. To upgrade:

```bash
# on the droplet, with the new deploy/aska-drop.service and the rebuilt aska-drop binary in /root
install -m 0644 /root/aska-drop.service /etc/systemd/system/aska-drop.service
install -m 0755 /root/aska-drop /usr/local/bin/aska-drop
systemctl daemon-reload && systemctl restart aska-drop
systemctl status aska-drop --no-pager | head -5           # active (running), no warning
grep VmLck /proc/$(systemctl show -p MainPID --value aska-drop)/status   # ≈ 9000 kB when empty
```

The unit fix alone (first line, then `daemon-reload` + `restart`) stops the aborts immediately
and can be applied before the binary is rebuilt. The new unit also sends stderr to the journal:
the relay never prints while running, so the only thing that can appear there is the one-line
reason for a fatal start-up failure or an abort — which is exactly the line whose absence made
this fault take a day to find.

## Locked out? (SSH times out after the install)

If the install ran without `SSH_ALLOW` (for example an older copy of the script), the firewall
closed port 22 and your existing session only survived because established connections are
always allowed. Fix it from the DigitalOcean panel without any password:

1. Droplet page → **Recovery** → select *Boot from Recovery ISO* → **Power** → power-cycle.
2. Open the console (Access → Recovery Console). The rescue menu needs no login. Choose **1**
   (mount the disk), then **6** (interactive shell). If `ls /mnt/etc/nftables.conf` fails, run
   `lsblk` and `mount /dev/vda1 /mnt` first.
3. `sed -i 's/ct state established,related accept; }/ct state established,related accept; tcp dport 22 accept; }/' /mnt/etc/nftables.conf && grep -c 'dport 22' /mnt/etc/nftables.conf && sync`
   (the grep must print `1`). Do not bother with `chroot`; editing the file is enough.
4. Recovery → select *Boot from Hard Drive* → Power → power-cycle. SSH works again; Tor and
   the relay start on their own.

The current script refuses to run over SSH without `SSH_ALLOW`, so this cannot recur with an
up-to-date copy.

## 6. Day-to-day

- Nothing to back up; a reboot loses live Blocks by design (D-05).
- Updates: OS and Tor are unattended. A new relay binary: verify its fingerprint, `install -m
  0755 aska-drop /usr/local/bin/aska-drop`, `systemctl restart aska-drop`. If the unit file
  changed too, `install -m 0644 aska-drop.service /etc/systemd/system/` and `systemctl
  daemon-reload` first.
- If the relay ever restarts on its own, `journalctl -u aska-drop -n 50 --no-pager` shows why:
  a `status=6/ABRT` line preceded by `memory allocation of N bytes failed` means the lock limit
  is too small for the caps (see 5a); the current relay refuses to start in that case rather
  than failing later.
- Rotate the onion address every few months: `systemctl stop tor`, `shred -u
  /var/lib/tor/aska-drop/*`, `rm -rf /var/lib/tor/aska-drop`, `systemctl start tor`, read the new
  `hostname`, hand it out again. Old Key Cards stop working — that is the point.
- Closed circle (optional, §7.1): one shared x25519 key in
  `/var/lib/tor/aska-drop/authorized_clients/circle.auth`; the private half goes into Key Cards.
  Never one file per member.
- Destroying the droplet is the complete decommissioning procedure; there is nothing on its disk
  worth wiping except the onion key, which `shred` above handles if you prefer to keep the host.
