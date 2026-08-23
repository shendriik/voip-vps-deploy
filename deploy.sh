#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: run as root"
    exit 1
fi

if [[ -f /root/.voip-vault-pass ]]; then
    VAULT_ARGS=(--vault-password-file /root/.voip-vault-pass)
else
    VAULT_ARGS=(--ask-vault-pass)
fi

exec ansible-playbook \
    -i inventory/production.yml \
    site.yml \
    "${VAULT_ARGS[@]}" \
    "$@"
