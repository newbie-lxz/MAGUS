#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
REQ_FILE="00_core/requirements.txt"
if [[ ! -f "$REQ_FILE" ]]; then
  echo "[ERROR] Cannot find requirements file: $REQ_FILE"
  exit 1
fi
if grep -Ev '^\s*(#|$)' "$REQ_FILE" >/dev/null; then
  python3 -m venv .venv
  .venv/bin/python -m pip install -r "$REQ_FILE"
else
  python3 -m venv --without-pip .venv
fi
echo "[OK] Python environment is ready."
echo "Next: run ./07_source_api_demo_linux.sh or ./08_source_api_executable_demo_linux.sh"
