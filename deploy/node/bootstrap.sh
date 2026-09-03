#!/usr/bin/env bash
#
# Prepare a fresh Ubuntu VM to run a HoneySentinel node.
#
# Written for Oracle Cloud's Always Free Ampere instances, and works unchanged
# on any Debian/Ubuntu box (GCP e2-micro, a spare Pi, a paid VPS).
#
#   sudo bash bootstrap.sh
#
# What it does, in order:
#   1. moves the real SSH daemon to port 22022 BEFORE anything touches port 22
#   2. installs Docker
#   3. redirects the well-known ports at the firewall to the emulators
#   4. persists the rules across reboot
#
# It does NOT start the engine. Fill in .env first, then run
# `docker compose up -d --build` from this directory.

set -euo pipefail

REAL_SSH_PORT="${REAL_SSH_PORT:-22022}"

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo." >&2
  exit 1
fi

echo "==> 1/4  Moving the real SSH daemon to port ${REAL_SSH_PORT}"
if ! grep -qE "^Port ${REAL_SSH_PORT}\b" /etc/ssh/sshd_config; then
  # Keep 22 listening for now so an in-flight session is never cut off. The
  # port-22 redirect added later is what actually hands 22 to the emulator.
  printf '\n# HoneySentinel: real administrative SSH\nPort %s\n' "${REAL_SSH_PORT}" \
    >> /etc/ssh/sshd_config
  systemctl restart ssh 2>/dev/null || systemctl restart sshd
fi

cat <<EOF

  *** OPEN A SECOND TERMINAL NOW AND CONFIRM THIS WORKS: ***

      ssh -p ${REAL_SSH_PORT} <user>@<this-host>

  Do not continue until that succeeds. After the redirect below, port 22
  belongs to the honeypot and will no longer log you in.

EOF
read -r -p "Confirmed you can log in on ${REAL_SSH_PORT}? [yes/NO] " ok
[[ "${ok}" == "yes" ]] || { echo "Aborted; nothing was redirected."; exit 1; }

echo "==> 2/4  Installing Docker"
if ! command -v docker >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl iptables-persistent
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
fi
docker --version

echo "==> 3/4  Redirecting well-known ports to the emulators"
# Oracle's Ubuntu images ship a REJECT rule partway down the INPUT chain, so
# new ACCEPTs have to be inserted above it rather than appended.
for p in 22022 2222 2121 8080 8443; do
  iptables -C INPUT -p tcp --dport "$p" -j ACCEPT 2>/dev/null \
    || iptables -I INPUT 1 -p tcp --dport "$p" -j ACCEPT
done
for pair in "22 2222" "21 2121" "80 8080" "443 8443"; do
  set -- $pair
  iptables -C INPUT -p tcp --dport "$1" -j ACCEPT 2>/dev/null \
    || iptables -I INPUT 1 -p tcp --dport "$1" -j ACCEPT
  iptables -t nat -C PREROUTING -p tcp --dport "$1" -j REDIRECT --to-port "$2" 2>/dev/null \
    || iptables -t nat -A PREROUTING -p tcp --dport "$1" -j REDIRECT --to-port "$2"
done

echo "==> 4/4  Persisting firewall rules"
netfilter-persistent save

cat <<'EOF'

Done. Remaining steps, which this script deliberately does not do for you:

  1. Open the ports in the cloud firewall too. On Oracle that is
     Networking -> Virtual Cloud Networks -> your VCN -> Security Lists ->
     Default Security List -> Add Ingress Rules, source 0.0.0.0/0, for
     TCP 21, 22, 80, 443 (and 22022 for your own SSH).
     The VM firewall alone is not enough; OCI drops it upstream.

  2. cp .env.example .env  and fill in HONEYPOT_INGEST_TOKEN.

  3. docker compose up -d --build && docker compose logs -f

EOF
