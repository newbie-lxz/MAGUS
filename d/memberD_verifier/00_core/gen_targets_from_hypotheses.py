#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate source/API verification targets from Stage C hypotheses.

In MAGUS, "API" means a C/C++ programming interface or function-call sequence.
This generator does not create HTTP requests, base URLs, bearer tokens, or Web
endpoint cases.
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


DEFAULT_FAILURE_PATTERNS = [
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
    "Segmentation fault",
    "null pointer",
    "heap-use-after-free",
    "stack-buffer-overflow",
    "heap-buffer-overflow",
    "double-free",
]

UNRESOLVED_VALUES = {"AUTO_DETECT_FAILED", "TODO", "待填写", "真实"}
WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
JULIET_API_MISUSE_ROOT = WORKSPACE_ROOT / "srcs" / "juliet-api-misuse"


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    text = path.read_text(encoding="utf-8-sig").strip()
    if not text:
        return []

    try:
        data = json.loads(text)
        if isinstance(data, list):
            if all(isinstance(item, dict) for item in data):
                return data
            raise ValueError(f"{path}: expected JSON objects in array")
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
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON at {path}:{n}: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{n}: expected JSON object")
        rows.append(row)
    return rows


def hypothesis_files(path: Path) -> List[Path]:
    if path.is_dir():
        files = sorted(item for item in path.glob("*.jsonl") if item.is_file())
        if not files:
            raise ValueError(f"{path}: no Stage C *.jsonl files found")
        return files
    if path.is_file():
        return [path]
    raise ValueError(f"{path}: expected Stage C output directory or hypotheses JSONL file")


def read_hypotheses(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen: Dict[Tuple[str, str], str] = {}
    for file_path in hypothesis_files(path):
        for row_no, row in enumerate(read_jsonl(file_path), 1):
            project_id = str(row.get("project_id", "")).strip()
            hypothesis_id = str(row.get("hypothesis_id", "")).strip()
            if project_id and hypothesis_id:
                key = (project_id, hypothesis_id)
                label = f"{file_path}:{row_no}"
                previous = seen.get(key)
                if previous:
                    raise ValueError(
                        f"duplicate hypothesis project_id={project_id!r} hypothesis_id={hypothesis_id!r}: "
                        f"{previous} and {label}"
                    )
                seen[key] = label
            rows.append(row)
    if not rows:
        raise ValueError(f"{path}: no Stage C hypothesis records found")
    return rows


def dump_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return " ".join(as_text(v) for v in value)
    if isinstance(value, dict):
        return " ".join(f"{k} {as_text(v)}" for k, v in value.items())
    return str(value)


def classify_attack(hyp: Dict[str, Any]) -> str:
    text = as_text(
        [
            hyp.get("claim"),
            hyp.get("cwe_candidates") or hyp.get("CWE_candidates") or hyp.get("cwe_list"),
            hyp.get("preconditions"),
            hyp.get("attack_path"),
            hyp.get("rebuttal"),
        ]
    ).lower()

    if "cwe-476" in text or "null pointer" in text or "空指针" in text:
        return "null_deref"
    if "cwe-416" in text or "use after free" in text or "uaf" in text:
        return "use_after_free"
    if "cwe-401" in text or "memory leak" in text or "内存泄漏" in text:
        return "memory_leak"
    if "cwe-190" in text or "integer overflow" in text or "integer underflow" in text or "整数溢出" in text:
        return "integer_overflow"
    if "cwe-78" in text or "command injection" in text or "命令注入" in text:
        return "command_injection"
    if "cwe-22" in text or "path traversal" in text or "目录遍历" in text:
        return "path_traversal"
    if "cwe-89" in text or "sql injection" in text or "sql注入" in text:
        return "sql_injection"
    if (
        "cwe-120" in text
        or "cwe-121" in text
        or "cwe-122" in text
        or "cwe-787" in text
        or "buffer overflow" in text
        or "缓冲区溢出" in text
    ):
        return "buffer_overflow"
    return "generic"


def marker_for(hyp: Dict[str, Any]) -> str:
    return f"memberD_source_api_probe_{hyp.get('hypothesis_id', 'hyp')}"


def path_entry_text(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("function", "entry_symbol", "name", "code", "loc"):
            raw = value.get(key)
            if raw not in (None, "", []):
                return str(raw)
        return ""
    return str(value or "")


def normalize_entry_symbol(raw: Any) -> str:
    symbol = " ".join(str(raw or "").split())
    if not symbol:
        return ""
    if " @ " in symbol:
        symbol = symbol.split(" @ ", 1)[0].strip()
    if "::" in symbol:
        symbol = symbol.rsplit("::", 1)[-1].strip()
    if "->" in symbol:
        symbol = symbol.split("->", 1)[0].strip()
    if symbol.startswith("call:"):
        symbol = symbol[len("call:") :].strip()
    if "(" in symbol:
        symbol = symbol.split("(", 1)[0].strip()
    symbol = symbol.strip(" .,:;")
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)$", symbol)
    if match:
        return match.group(1)
    return symbol


def entry_symbol(hyp: Dict[str, Any]) -> str:
    verification_context = hyp.get("verification_context")
    if isinstance(verification_context, dict):
        for key in ("entry_function", "entrypoint", "func_name", "function"):
            value = verification_context.get(key)
            if isinstance(value, str) and value:
                return normalize_entry_symbol(value)

    for key in ("func_name", "entry_function", "entrypoint", "function", "api"):
        value = hyp.get(key)
        if isinstance(value, str) and value:
            return normalize_entry_symbol(value)
        if isinstance(value, dict):
            for subkey in ("handler", "function", "name"):
                if value.get(subkey):
                    return normalize_entry_symbol(value[subkey])

    route_symbol = normalize_entry_symbol(hyp.get("route"))
    if route_symbol:
        return route_symbol

    attack_path = hyp.get("attack_path")
    if isinstance(attack_path, list):
        for item in attack_path:
            candidate = normalize_entry_symbol(path_entry_text(item))
            if candidate:
                return candidate
    elif attack_path:
        candidate = normalize_entry_symbol(path_entry_text(attack_path))
        if candidate:
            return candidate

    return "unknown_entry"


def infer_poc_language(hyp: Dict[str, Any]) -> str:
    text = as_text([hyp.get("language"), hyp.get("file"), hyp.get("filepath")]).lower()
    if text.endswith(".c") or text.endswith(".h") or text == "c":
        return "c"
    if text.endswith(".cpp") or text.endswith(".cc") or text.endswith(".cxx") or "c++" in text or "cpp" in text:
        return "cpp"
    if text.endswith(".rs") or "rust" in text:
        return "rust"
    if text.endswith(".go") or "golang" in text or text == "go":
        return "go"
    if text.endswith(".java") or "java" in text:
        return "java"
    if text.endswith(".py") or "python" in text:
        return "python"
    return "unknown"


def first_value(source: Dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        value = source.get(key)
        if value not in (None, "", []):
            return value
    return None


def resolve_candidate_source_path(source_file: Any) -> Path | None:
    if source_file in (None, "", []):
        return None
    raw = Path(str(source_file))
    candidates = [raw] if raw.is_absolute() else [
        WORKSPACE_ROOT / raw,
        JULIET_API_MISUSE_ROOT / raw,
        WORKSPACE_ROOT / "srcs" / raw,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return None


def is_juliet_api_misuse_hypothesis(hyp: Dict[str, Any], source_file: Any) -> bool:
    text = as_text([source_file, hyp.get("project_id"), hyp.get("sample_id")]).lower()
    if "juliet-api-misuse" in text:
        return True
    resolved = resolve_candidate_source_path(source_file)
    if resolved is None:
        return False
    try:
        resolved.relative_to(JULIET_API_MISUSE_ROOT.resolve())
        return True
    except ValueError:
        return False


def juliet_win32_test_cmd(source_file: Any, symbol: str, route: Any) -> str:
    return " ".join(
        [
            "${PYTHON}",
            "tools/juliet_win_shim/run_juliet_win_case.py",
            "--source-file",
            shlex.quote(str(source_file)),
            "--entry-symbol",
            shlex.quote(symbol),
            "--route",
            shlex.quote(str(route or "")),
        ]
    )


def juliet_win32_execution_context(source_file: Any, symbol: str, route: Any) -> Dict[str, Any]:
    return {
        "repo_path": str(WORKSPACE_ROOT),
        "test_cmd": juliet_win32_test_cmd(source_file, symbol, route),
    }


def juliet_win32_oracle() -> Dict[str, Any]:
    return {
        "accepted_evidence": [
            "Juliet bad/good main banner proves the selected route executed",
            "MAGUS_JULIET_ROUTE_CONFIRMED proves a tainted Win32/API sink or point-flaw marker was reached",
        ],
        "failure_patterns": ["MAGUS_JULIET_ROUTE_CONFIRMED"],
        "required_patterns": ["MAGUS_JULIET_ROUTE_EXECUTED"],
        "failure_code_patterns": {
            "NOT_ROUTE_BOUND": ["MAGUS_JULIET_NOT_ROUTE_BOUND"],
            "ENV_MISSING": ["MAGUS_JULIET_BUILD_FAILED", "MAGUS_JULIET_RUNNER_ERROR"],
            "NOT_EXPLOITABLE": ["MAGUS_JULIET_NOT_CONFIRMED"],
        },
        "expect_nonzero_exit": False,
    }


def has_unresolved_marker(value: Any) -> bool:
    if value in (None, "", []):
        return False
    text = as_text(value)
    return any(marker.lower() in text.lower() for marker in UNRESOLVED_VALUES)


def collect_execution(hyp: Dict[str, Any]) -> Dict[str, Any]:
    execution: Dict[str, Any] = {}
    sources: List[Dict[str, Any]] = [hyp]
    verification_context = hyp.get("verification_context")
    if isinstance(verification_context, dict):
        sources.insert(0, verification_context)

    key_map = {
        "repo_path": ("repo_path", "repository_path", "source_root", "project_root"),
        "config_cmd": ("config_cmd", "configure_cmd"),
        "build_cmd": ("build_cmd", "compile_cmd"),
        "run_cmd": ("run_cmd", "harness_cmd", "trigger_cmd"),
        "poc_cmd": ("poc_cmd",),
        "test_cmd": ("test_cmd",),
        "docker_image": ("docker_image", "container_image"),
        "timeout_sec": ("timeout_sec", "timeout"),
    }
    for out_key, in_keys in key_map.items():
        for source in sources:
            value = first_value(source, in_keys)
            if value not in (None, "", []) and not has_unresolved_marker(value):
                execution[out_key] = value
                break
    return execution


def seed_inputs_for_attack(attack_type: str) -> List[str]:
    if attack_type == "null_deref":
        return ["empty input", "malformed serialized bytes", "allocation failure path"]
    if attack_type == "integer_overflow":
        return ["-1", "0", "INT_MAX", "SIZE_MAX boundary value"]
    if attack_type == "use_after_free":
        return ["release-before-use API sequence", "double release sequence", "dangling handle reuse"]
    if attack_type == "buffer_overflow":
        return ["boundary-sized buffer", "oversized buffer", "unterminated byte string"]
    if attack_type == "path_traversal":
        return ["../ traversal path", "absolute path", "encoded traversal path"]
    if attack_type == "command_injection":
        return ["shell metacharacter payload", "argument separator payload", "environment-controlled command"]
    if attack_type == "sql_injection":
        return ["quote-breaking SQL string", "boolean tautology", "union-select probe"]
    return [
        "boundary-sized input",
        "null/zero/negative argument where type permits",
        "malformed serialized bytes",
        "state-transition sequence that violates inferred API pattern",
    ]


def make_source_api_case(hyp: Dict[str, Any], auto_fill: bool) -> Dict[str, Any]:
    attack_type = classify_attack(hyp)
    symbol = entry_symbol(hyp)
    language = infer_poc_language(hyp)
    source_file = hyp.get("file") or hyp.get("filepath")
    cwe = hyp.get("cwe_candidates") or hyp.get("CWE_candidates") or hyp.get("cwe_list") or []

    verification_context = hyp.get("verification_context")
    seed_inputs = seed_inputs_for_attack(attack_type)
    input_source = None
    if isinstance(verification_context, dict):
        if isinstance(verification_context.get("seed_inputs"), list) and verification_context.get("seed_inputs"):
            seed_inputs = verification_context["seed_inputs"]
        input_source = verification_context.get("input_source")

    explicit_oracle: Dict[str, Any] = {}
    if isinstance(hyp.get("oracle"), dict):
        explicit_oracle.update(hyp["oracle"])
    if isinstance(verification_context, dict) and isinstance(verification_context.get("oracle"), dict):
        explicit_oracle.update(verification_context["oracle"])

    case: Dict[str, Any] = {
        "name": f"auto_{attack_type}" if auto_fill else "source_api_misuse",
        "target_type": "source_api",
        "attack_type": attack_type,
        "auto_generated": auto_fill,
        "payload_kind": "api_misuse_plan",
        "poc_language": language,
        "source_file": source_file,
        "entry_symbol": symbol,
        "api_sequence": hyp.get("api_sequence") or hyp.get("attack_path") or [],
        "poc_plan": [
            f"Build or load project containing {source_file or 'the target source file'}",
            f"Construct or locate a harness that reaches {symbol}",
            f"Drive the API sequence with misuse-oriented inputs for {', '.join(cwe) if cwe else attack_type}",
            "Run under sanitizer/test oracle and collect crash, error-code, assertion, or differential evidence",
        ],
        "payload": {
            "marker": marker_for(hyp),
            "entry_symbol": symbol,
            "input_source": input_source,
            "seed_inputs": seed_inputs,
        },
        "oracle": {
            "accepted_evidence": [
                "ASan/UBSan crash",
                "non-zero test exit caused by crafted source/API input",
                "unexpected success on invalid API state",
                "differential behavior between vulnerable and fixed revision",
            ],
            "failure_patterns": DEFAULT_FAILURE_PATTERNS,
            "expect_nonzero_exit": True,
        },
    }

    execution = collect_execution(hyp)
    if execution:
        case["execution"] = execution
    if hyp.get("poc_code") or hyp.get("harness_code"):
        case["harness_code"] = hyp.get("poc_code") or hyp.get("harness_code")
    case["oracle"].update(explicit_oracle)
    if auto_fill and is_juliet_api_misuse_hypothesis(hyp, source_file):
        case["name"] = "juliet_win32_source_api"
        case["payload_kind"] = "juliet_win32_dynamic_case"
        case["execution"] = juliet_win32_execution_context(source_file, symbol, hyp.get("route"))
        if execution:
            case["execution"].update(execution)
        case["oracle"] = juliet_win32_oracle()
        case["oracle"].update(explicit_oracle)
    return case


def make_native_case(hyp: Dict[str, Any], auto_fill: bool) -> Dict[str, Any]:
    return make_source_api_case(hyp, auto_fill)


def build_targets(hypotheses: Iterable[Dict[str, Any]], auto_fill: bool = False) -> Dict[str, Any]:
    targets_by_project: Dict[str, Dict[str, Any]] = {}

    for hyp in hypotheses:
        project_id = hyp.get("project_id")
        hypothesis_id = hyp.get("hypothesis_id")
        route = hyp.get("route")

        if not project_id or not hypothesis_id or not route:
            raise ValueError(
                f"hypothesis missing project_id/hypothesis_id/route: "
                f"project_id={project_id}, hypothesis_id={hypothesis_id}, route={route}"
            )

        target = targets_by_project.setdefault(
            str(project_id),
            {
                "project_id": str(project_id),
                "target_type": "source_api",
                "env_profile": "source_repository",
                "cases": {},
            },
        )
        target["cases"][str(hypothesis_id)] = make_source_api_case(hyp, auto_fill)

    return {"targets": list(targets_by_project.values())}


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate source/API targets.json from Stage C hypotheses")
    parser.add_argument("--hypotheses", required=True, type=Path, help="C stage output directory or hypotheses JSONL file")
    parser.add_argument("--out", default=Path("targets.json"), type=Path, help="Output targets.json")
    parser.add_argument("--auto-fill", action="store_true", help="Generate best-effort source/API payload plans")
    args = parser.parse_args()

    hypotheses = read_hypotheses(args.hypotheses)
    targets = build_targets(hypotheses=hypotheses, auto_fill=args.auto_fill)
    dump_json(args.out, targets)

    total_cases = sum(len(t["cases"]) for t in targets["targets"])
    print(f"generated: {args.out}")
    print(f"projects:  {len(targets['targets'])}")
    print(f"cases:     {total_cases}")
    print("next: run verifier.py; Juliet api-misuse targets include runner/oracle automatically; other projects require execution context")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
