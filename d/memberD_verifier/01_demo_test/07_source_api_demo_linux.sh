#!/usr/bin/env bash
set -euo pipefail

DEMO="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DEMO/.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
HYP_FILE="$DEMO/samples/hypotheses.source_api.example.jsonl"
OUT_DIR="$DEMO/out_source_api"
TARGET_FILE="$DEMO/targets.source_api.auto.json"

if [[ ! -x "$PYTHON" ]]; then
  echo "[ERROR] Cannot find Python env: $PYTHON"
  echo "Run d/memberD_verifier/01_demo_test/01_setup_linux.sh first."
  exit 1
fi

"$PYTHON" "$ROOT/00_core/gen_targets_from_hypotheses.py" --hypotheses "$HYP_FILE" --out "$TARGET_FILE" --auto-fill
"$PYTHON" "$ROOT/00_core/verifier.py" --hypotheses "$HYP_FILE" --targets "$TARGET_FILE" --out-dir "$OUT_DIR"
"$PYTHON" "$ROOT/03_tools/validate_outputs.py" --out-dir "$OUT_DIR"

echo
echo "[OK] Source/API misuse demo finished."
echo "Inspect 01_demo_test/out_source_api/verification.failed.jsonl"
