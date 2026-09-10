#!/usr/bin/env bash
# Docker Engine install for Ubuntu 22.04/24.04 (Debian-compatible)
# Run as root or via sudo

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run as root: sudo bash install-docker.sh"
  exit 1
fi

echo "[1/5] Remove old Docker packages..."
for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do
  apt-get remove -y "$pkg" 2>/dev/null || true
done

echo "[2/5] Install dependencies..."
apt-get update -q
apt-get install -y ca-certificates curl gnupg lsb-release

echo "[3/5] Add Docker GPG key and repo..."
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" \
  > /etc/apt/sources.list.d/docker.list

echo "[4/5] Install Docker Engine + Compose plugin..."
apt-get update -q
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

echo "[5/5] Enable and start Docker..."
systemctl enable --now docker

# Add current sudo user to docker group (takes effect on next login)
SUDO_USER_NAME="${SUDO_USER:-}"
if [[ -n "$SUDO_USER_NAME" ]]; then
  usermod -aG docker "$SUDO_USER_NAME"
  echo "User '$SUDO_USER_NAME' added to docker group (re-login required)"
fi

docker --version
docker compose version
echo ""
echo "Docker installed successfully."
echo "Next: cp .env.example .env && cp dagobert.env.example dagobert.env"
echo "      Edit both files, then: docker compose up -d"
