#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: run as root"
    exit 1
fi

echo "=== Pulling configuration ==="
git pull --ff-only

echo
echo "=== Applying configuration ==="
exec ./deploy.sh
