#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List


MIN_EVIDENCE_FIELDS = ["project_id", "sample_id", "route", "file", "line", "evidence_slice"]
FAILURE_CODES = {"NOT_EXPLOITABLE", "ENV_MISSING", "HYPOTHESIS_WRONG", "TIMEOUT", "NON_DETERMINISTIC"}


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8-sig").strip()
    if not text:
        return []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return [data]
    except json.JSONDecodeError:
        pass

    rows: List[Dict[str, Any]] = []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"{path}:{n}: invalid json: {exc}") from exc
    return rows


def missing(row: Dict[str, Any], fields: Iterable[str]) -> List[str]:
    return [field for field in fields if row.get(field) in (None, "", [])]


def validate_confirmed(row: Dict[str, Any]) -> List[str]:
    errors = []
    errors.extend(f"missing {field}" for field in missing(row, MIN_EVIDENCE_FIELDS))
    errors.extend(f"missing {field}" for field in missing(row, ["verify_id", "hypothesis_id", "payload_ref", "repro_steps", "runtime_trace"]))
    if row.get("status") != "confirmed":
        errors.append("status must be confirmed")
    if row.get("severity") != "P0":
        errors.append("confirmed record must set severity=P0")
    return errors


def validate_failed(row: Dict[str, Any]) -> List[str]:
    errors = []
    errors.extend(f"missing {field}" for field in missing(row, MIN_EVIDENCE_FIELDS))
    errors.extend(f"missing {field}" for field in missing(row, ["verify_id", "hypothesis_id", "failure_code"]))
    if row.get("status") != "failed":
        errors.append("status must be failed")
    if row.get("failure_code") not in FAILURE_CODES:
        errors.append(f"unknown failure_code={row.get('failure_code')!r}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate Member D output JSONL files")
    parser.add_argument("--out-dir", default=Path("out"), type=Path)
    args = parser.parse_args()

    confirmed = read_jsonl(args.out_dir / "verification.jsonl")
    failed = read_jsonl(args.out_dir / "verification.failed.jsonl")

    problems: List[str] = []
    for idx, row in enumerate(confirmed, 1):
        for err in validate_confirmed(row):
            problems.append(f"verification.jsonl:{idx}: {err}")
    for idx, row in enumerate(failed, 1):
        for err in validate_failed(row):
            problems.append(f"verification.failed.jsonl:{idx}: {err}")

    if problems:
        print("INVALID")
        for item in problems:
            print("-", item)
        return 1

    print("VALID")
    print(f"confirmed: {len(confirmed)}")
    print(f"failed:    {len(failed)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
