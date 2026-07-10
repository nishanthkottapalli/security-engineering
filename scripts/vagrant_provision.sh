#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl gnupg make python3 python3-venv jq
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${UBUNTU_CODENAME:-$VERSION_CODENAME} stable" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
usermod -aG docker vagrant

cd /workspace
if [[ ! -f .env ]]; then cp .env.example .env; fi
mkdir -p lab-output uploads
chown -R vagrant:vagrant lab-output uploads

docker compose up -d --build postgres migrate api worker gateway
if [[ "${RUN_WAZUH:-0}" == "1" ]]; then
  docker compose --profile wazuh run --rm wazuh-logtest
fi

echo 'Lab available at http://localhost:18080 from the host.'
