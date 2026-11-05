#!/usr/bin/env bash
# Local development: run agent + API + dashboard dev server together.
set -euo pipefail
cd "$(dirname "$0")/.."
export SENTINEL_DATA_DIR="${SENTINEL_DATA_DIR:-./data}"
export SENTINEL_API_BOOTSTRAP_ADMIN_USERNAME="${SENTINEL_API_BOOTSTRAP_ADMIN_USERNAME:-admin}"
export SENTINEL_API_BOOTSTRAP_ADMIN_PASSWORD="${SENTINEL_API_BOOTSTRAP_ADMIN_PASSWORD:-admin-dev-password}"

python -m agent init
python -m backend init-keys || true

echo "[*] starting API on :8443, agent, and Vite dev server on :5173"
python -m backend run &
API=$!
python -m agent run &
AGENT=$!
( cd frontend && npm run dev ) &
WEB=$!
trap 'kill $API $AGENT $WEB 2>/dev/null || true' EXIT
wait
