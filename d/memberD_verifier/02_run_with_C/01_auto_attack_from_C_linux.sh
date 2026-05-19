#!/usr/bin/env bash
set -euo pipefail
FLOW="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$FLOW/.." && pwd)"
WORKSPACE="$(cd "$ROOT/../.." && pwd)"
HYP_FILE="$WORKSPACE/c/out/hypotheses.jsonl"
OUT_DIR="$FLOW/output"
TARGET_FILE="$FLOW/targets.auto.json"

if [[ ! -f "$HYP_FILE" ]]; then
  echo "[ERROR] Cannot find C output: $HYP_FILE"
  echo "Run Stage C first so it writes c/out/hypotheses.jsonl."
  exit 1
fi

"$ROOT/.venv/bin/python" "$ROOT/00_core/gen_targets_from_hypotheses.py" --hypotheses "$HYP_FILE" --out "$TARGET_FILE" --auto-fill
"$ROOT/.venv/bin/python" "$ROOT/00_core/verifier.py" --hypotheses "$HYP_FILE" --targets "$TARGET_FILE" --out-dir "$OUT_DIR"
"$ROOT/.venv/bin/python" "$ROOT/03_tools/validate_outputs.py" --out-dir "$OUT_DIR"
echo "[OK] C workflow finished."
