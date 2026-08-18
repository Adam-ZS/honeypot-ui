#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "Stopping HoneySentinel..."
docker compose down

echo "HoneySentinel stopped. Captured data is preserved in the honeypot_data volume."
echo "To remove it as well: docker compose down -v"
