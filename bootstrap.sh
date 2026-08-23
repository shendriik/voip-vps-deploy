#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: run as root"
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo "=== Updating apt metadata ==="
apt-get update

echo "=== Installing deployment prerequisites ==="
apt-get install -y \
    git \
    python3 \
    python3-apt \
    ansible-core \
    ca-certificates \
    curl

echo "=== Verifying Ansible ==="
command -v ansible-playbook >/dev/null 2>&1 || {
    echo "ERROR: ansible-playbook was not installed"
    exit 1
}

ansible-playbook --version | head -1

echo
echo "Bootstrap complete."
echo "Next:"
echo "  ./deploy.sh --check --diff"
