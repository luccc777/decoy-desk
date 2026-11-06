#!/usr/bin/env bash
# Asks for a secret without echoing it and stores it in the server's .env.
# Usage (from your machine): ssh -t root@SERVER bash /root/decoy-desk/infra/set_secret.sh VULTR_INFERENCE_KEY
set -euo pipefail

name="${1:?usage: set_secret.sh VAR_NAME}"
env_file=/root/decoy-desk/.env

read -rsp "Paste ${name} and press Enter: " value
echo
[ -n "$value" ] || { echo "Empty value, nothing changed."; exit 1; }

touch "$env_file"
grep -v "^${name}=" "$env_file" > "${env_file}.tmp" || true
printf '%s=%s\n' "$name" "$value" >> "${env_file}.tmp"
mv "${env_file}.tmp" "$env_file"
chmod 600 "$env_file"
echo "Saved ${name} (${#value} characters)."
