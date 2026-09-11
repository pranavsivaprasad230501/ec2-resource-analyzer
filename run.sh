#!/usr/bin/env bash
# Bootstraps and runs the EC2 Resource Analyzer: creates the venv if missing,
# installs/updates dependencies, then starts the server.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "error: $PYTHON_BIN not found. Install Python 3.9+ and re-run this script." >&2
    exit 1
fi

if [ ! -d venv ]; then
    echo "Creating virtual environment..."
    "$PYTHON_BIN" -m venv venv
fi

# shellcheck disable=SC1091
source venv/bin/activate

pip install --quiet --disable-pip-version-check -r requirements.txt

PORT="${PORT:-8000}"
echo ""
echo "Starting EC2 Resource Analyzer on http://localhost:${PORT}"
echo ""
exec uvicorn app:app --reload --port "$PORT"
