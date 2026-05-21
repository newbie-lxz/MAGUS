#!/usr/bin/env bash
set -euo pipefail

FLOW="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$FLOW/.." && pwd)"
WORKSPACE="$(cd "$ROOT/../.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
C_OUT_DIR="$WORKSPACE/c/out"
TARGET_FILE="$FLOW/targets.manual.json"
OUT_DIR="$FLOW/output_manual"
REPORT_ROOT="$WORKSPACE/report"

if [[ ! -d "$C_OUT_DIR" ]]; then
  echo "[ERROR] Cannot find C output directory: $C_OUT_DIR"
  exit 1
fi

if ! compgen -G "$C_OUT_DIR/*.jsonl" > /dev/null; then
  echo "[ERROR] No Stage C *.jsonl files found under: $C_OUT_DIR"
  exit 1
fi

if [[ ! -f "$TARGET_FILE" ]]; then
  echo "[ERROR] Cannot find targets.manual.json. Run 02_generate_targets_from_C_linux.sh first."
  exit 1
fi

if [[ ! -x "$PYTHON" ]]; then
  echo "[ERROR] Cannot find Python env: $PYTHON"
  echo "Run d/memberD_verifier/01_demo_test/01_setup_linux.sh first."
  exit 1
fi

"$PYTHON" "$ROOT/00_core/verifier.py" --hypotheses "$C_OUT_DIR" --targets "$TARGET_FILE" --out-dir "$OUT_DIR"
"$PYTHON" "$ROOT/03_tools/validate_outputs.py" --out-dir "$OUT_DIR"
REPORT_COMMAND=("$PYTHON" "$WORKSPACE/pipeline.py" report --d-output-dir "$OUT_DIR" --report-root "$REPORT_ROOT")
if [[ -n "${REPORT_RUN_NAME:-}" ]]; then
  REPORT_COMMAND+=(--run-name "$REPORT_RUN_NAME")
fi
"${REPORT_COMMAND[@]}"
echo "[OK] Manual target verification finished."
