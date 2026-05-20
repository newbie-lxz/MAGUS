#!/usr/bin/env bash
set -euo pipefail
FLOW="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$FLOW/.." && pwd)"
WORKSPACE="$(cd "$ROOT/../.." && pwd)"
PYTHON="$ROOT/.venv/bin/python"
C_OUT_DIR="$WORKSPACE/c/out"
OUT_DIR="$FLOW/output"
TARGET_AUTO_FILE="$FLOW/targets.auto.json"
TARGET_BOUND_FILE="$FLOW/targets.executable.json"
CONTEXT_FILE="$FLOW/verification_contexts.jsonl"
TARGET_FILE="$TARGET_AUTO_FILE"

if [[ ! -d "$C_OUT_DIR" ]]; then
  echo "[ERROR] Cannot find C output directory: $C_OUT_DIR"
  echo "Run Stage C first so it writes one or more *.jsonl files under c/out/."
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

"$PYTHON" "$ROOT/00_core/gen_targets_from_hypotheses.py" --hypotheses "$C_OUT_DIR" --out "$TARGET_AUTO_FILE" --auto-fill
if [[ -f "$CONTEXT_FILE" ]]; then
  "$PYTHON" "$FLOW/bind_verification_contexts.py" --hypotheses "$C_OUT_DIR" --targets "$TARGET_AUTO_FILE" --contexts "$CONTEXT_FILE" --out "$TARGET_BOUND_FILE"
  TARGET_FILE="$TARGET_BOUND_FILE"
fi
"$PYTHON" "$ROOT/00_core/verifier.py" --hypotheses "$C_OUT_DIR" --targets "$TARGET_FILE" --out-dir "$OUT_DIR"
"$PYTHON" "$ROOT/03_tools/validate_outputs.py" --out-dir "$OUT_DIR"
echo "[OK] C workflow finished."
