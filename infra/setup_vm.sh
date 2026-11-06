#!/usr/bin/env bash
# Prepares the Decoy Desk VM: Docker, gVisor (runsc), a syscall-tracing runtime and work dirs.
# Safe to re-run: every step checks whether it is already done.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl gnupg jq git unzip

# Docker, from the official repository
if ! command -v docker >/dev/null; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

# gVisor, from the official apt repository (never hand-copy the binary)
if ! command -v runsc >/dev/null; then
  curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor --yes -o /usr/share/keyrings/gvisor-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
    > /etc/apt/sources.list.d/gvisor.list
  apt-get update -y
  apt-get install -y runsc
fi

# Two Docker runtimes:
#   runsc        the default sandbox
#   runsc-trace  same sandbox, but records the syscalls that matter (files, programs, network) from outside
install -d -m 0750 /var/log/runsc
runsc install
runsc install --runtime=runsc-trace -- \
  --debug --debug-log=/var/log/runsc/ \
  --strace --strace-syscalls=openat,open,execve,connect
systemctl restart docker

# Orchestrator work dirs
install -d -m 0750 /srv/decoy-desk /srv/decoy-desk/jobs

echo "--- docker runtimes ---"
docker info --format '{{json .Runtimes}}' | jq 'keys'
runsc --version | head -1
