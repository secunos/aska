#!/bin/sh
# Aska Dead Drop relay — one-shot install for a fresh Debian 12/13 VPS (e.g. a DigitalOcean droplet).
# Run as root. Review every line before running; this is a reference, not a product.
set -eu

# Refuse to lock the operator out: over SSH, SSH_ALLOW must be set (see step 3).
if [ -z "${SSH_ALLOW:-}" ] && [ -n "${SSH_CONNECTION:-}" ]; then
  echo "!! You are running this over SSH without SSH_ALLOW set. The firewall below would close SSH"
  echo "!! and this session would be your last (only the provider console could get you back in)."
  echo "!! Re-run as:  SSH_ALLOW=any ./install-debian.sh   (key-only SSH from anywhere)"
  echo "!!         or:  SSH_ALLOW=<your-public-ip> ./install-debian.sh"
  echo "!!         or:  SSH_ALLOW=none ./install-debian.sh  to close SSH deliberately."
  exit 1
fi
[ "${SSH_ALLOW:-}" = "none" ] && SSH_ALLOW=""

echo "[1/7] base hardening"
apt-get update && apt-get -y dist-upgrade
apt-get -y install --no-install-recommends ca-certificates curl gnupg apt-transport-https unattended-upgrades nftables
systemctl enable --now unattended-upgrades

echo "[2/7] no swap (RAM-only store must never hit disk)"
swapoff -a || true
sed -i '/ swap / s/^/#/' /etc/fstab
sysctl -w vm.swappiness=0 >/dev/null

echo "[3/7] firewall: drop ALL inbound (onion services need no open ports); allow loopback + outbound"
# SSH_ALLOW: keep SSH reachable from this address/CIDR (e.g. SSH_ALLOW=203.0.113.7 ./install-debian.sh),
# or SSH_ALLOW=any for key-only SSH from anywhere. Unset = SSH is closed too (provider console only).
SSH_RULE=""
case "${SSH_ALLOW:-}" in
  "")   ;;
  any)  SSH_RULE="tcp dport 22 accept;" ;;
  *)    SSH_RULE="ip saddr ${SSH_ALLOW} tcp dport 22 accept;" ;;
esac
cat > /etc/nftables.conf <<NFT
flush ruleset
table inet filter {
  chain input  { type filter hook input priority 0; policy drop; iif lo accept; ct state established,related accept; ${SSH_RULE} }
  chain forward{ type filter hook forward priority 0; policy drop; }
  chain output { type filter hook output priority 0; policy accept; }
}
NFT
systemctl enable --now nftables && nft -f /etc/nftables.conf
if [ -n "$SSH_RULE" ]; then
  # key-only SSH, no root password login, no forwarding
  sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication no/; s/^#\?PermitRootLogin .*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
  systemctl reload ssh || systemctl reload sshd || true
  echo "    SSH stays open from: ${SSH_ALLOW}"
else
  echo "    SSH is now closed; use the provider console."
fi

echo "[4/7] Tor from the Tor Project repository"
. /etc/os-release
curl -fsSL https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --dearmor -o /usr/share/keyrings/tor-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org $VERSION_CODENAME main" > /etc/apt/sources.list.d/tor.list
apt-get update && apt-get -y install tor deb.torproject.org-keyring
install -m 0644 torrc.aska-drop /etc/tor/torrc
systemctl restart tor

echo "[5/7] relay binary"
# Production: a reproducibly built static binary with a published fingerprint (OPS-02/03). Verify BEFORE installing:
#   sha256sum aska-drop && compare with the fingerprint obtained out of band
install -m 0755 aska-drop /usr/local/bin/aska-drop

echo "[6/7] journald: keep nothing on disk (before the relay's first start, so no line of its ever touches the disk)"
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=volatile\nRuntimeMaxUse=16M\n' > /etc/systemd/journald.conf.d/volatile.conf
systemctl restart systemd-journald
# Assert it: a persistent journal directory must not exist, and journald must report volatile storage.
if [ -d /var/log/journal ]; then
  echo "journald: /var/log/journal exists — removing the persistent journal (nothing of the relay is in it yet)"
  rm -rf /var/log/journal && systemctl restart systemd-journald
fi
grep -q '^Storage=volatile' /etc/systemd/journald.conf.d/volatile.conf || { echo "journald drop-in missing"; exit 1; }
[ ! -d /var/log/journal ] || { echo "journald: persistent journal still present"; exit 1; }

echo "[7/7] systemd unit (hardened; no output while serving, a fatal line only to the RAM journal)"
install -m 0644 aska-drop.service /etc/systemd/system/aska-drop.service
systemctl daemon-reload && systemctl enable --now aska-drop

sleep 5
echo "Onion address (hand this to your circle out of band, e.g. inside Key Cards):"
cat /var/lib/tor/aska-drop/hostname
