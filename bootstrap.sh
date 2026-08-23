#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: run as root"
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

apt-get update

apt-get install -y \
    git \
    ansible-core \
    python3

echo
echo "Bootstrap complete."
echo "Run:"
echo "  ./deploy.sh"
