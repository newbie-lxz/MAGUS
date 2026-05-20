#!/usr/bin/env bash
set -euo pipefail

FLOW="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$FLOW/.." && pwd)"
WORKSPACE="$(cd "$ROOT/../.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
C_OUT_DIR="$WORKSPACE/c/out"
TARGET_FILE="$FLOW/targets.manual.json"

if [[ ! -d "$C_OUT_DIR" ]]; then
  echo "[ERROR] Cannot find C output directory: $C_OUT_DIR"
  exit 1
fi

if ! compgen -G "$C_OUT_DIR/*.jsonl" > /dev/null; then
  echo "[ERROR] No Stage C *.jsonl files found under: $C_OUT_DIR"
  exit 1
fi

if [[ ! -x "$PYTHON" ]]; then
  echo "[ERROR] Cannot find Python env: $PYTHON"
  echo "Run d/memberD_verifier/01_demo_test/01_setup_linux.sh first."
  exit 1
fi

"$PYTHON" "$ROOT/00_core/gen_targets_from_hypotheses.py" --hypotheses "$C_OUT_DIR" --out "$TARGET_FILE"
echo
echo "[OK] Manual targets file generated:"
echo "  02_run_with_C/targets.manual.json"
echo "Edit repo_path, run_cmd/poc_cmd/test_cmd, and oracle fields if auto mode is not enough."
