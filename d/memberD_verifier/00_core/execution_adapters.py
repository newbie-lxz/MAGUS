#!/usr/bin/env python3
"""
Project and environment execution adapters for Stage D.

Adapters know how to execute a project family. They do not select vulnerability
semantics; oracle_profiles owns that generic API/behavior decision.
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any, Dict, Iterable


WORKSPACE_ROOT = Path(__file__).resolve().parents[3]
JULIET_API_MISUSE_ROOT = WORKSPACE_ROOT / "srcs" / "juliet-api-misuse"
SANITIZED_SOURCE_ROOT = WORKSPACE_ROOT / "srcs_sanitized"
SANITIZED_JULIET_API_MISUSE_ROOT = SANITIZED_SOURCE_ROOT / "juliet-api-misuse"


def as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return " ".join(as_text(item) for item in value)
    if isinstance(value, dict):
        return " ".join(f"{key} {as_text(item)}" for key, item in value.items())
    return str(value)


def resolve_candidate_source_path(source_file: Any) -> Path | None:
    if source_file in (None, "", []):
        return None
    raw = Path(str(source_file))
    candidates = [raw] if raw.is_absolute() else [
        WORKSPACE_ROOT / raw,
        SANITIZED_SOURCE_ROOT / raw,
        SANITIZED_JULIET_API_MISUSE_ROOT / raw,
        JULIET_API_MISUSE_ROOT / raw,
        WORKSPACE_ROOT / "srcs" / raw,
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return None


def is_juliet_api_misuse_hypothesis(hypothesis: Dict[str, Any], source_file: Any) -> bool:
    text = as_text([source_file, hypothesis.get("project_id"), hypothesis.get("sample_id")]).lower()
    if "juliet-api-misuse" in text:
        return True
    resolved = resolve_candidate_source_path(source_file)
    if resolved is None:
        return False
    for root in (SANITIZED_JULIET_API_MISUSE_ROOT, JULIET_API_MISUSE_ROOT):
        try:
            resolved.relative_to(root.resolve())
            return True
        except ValueError:
            continue
    return False


def shell_join(parts: Iterable[Any]) -> str:
    return " ".join(shlex.quote(str(part)) for part in parts)


def juliet_win32_test_cmd(source_file: Any, symbol: str, route: Any, oracle_profile: Dict[str, Any]) -> str:
    command = [
        "${PYTHON}",
        "tools/juliet_win_shim/run_juliet_win_case.py",
        "--source-file",
        source_file,
        "--entry-symbol",
        symbol,
        "--route",
        route or "",
        "--oracle-profile-id",
        oracle_profile.get("profile_id") or "",
    ]
    for pattern in oracle_profile.get("confirm_patterns") or []:
        command.extend(["--confirm-pattern", pattern])
    return shell_join(command)


def juliet_win32_execution_context(source_file: Any, symbol: str, route: Any, oracle_profile: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "repo_path": str(WORKSPACE_ROOT),
        "test_cmd": juliet_win32_test_cmd(source_file, symbol, route, oracle_profile),
    }


def juliet_win32_oracle(oracle_profile: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "profile_id": oracle_profile.get("profile_id"),
        "profile_supported": bool(oracle_profile.get("supported")),
        "semantic_failure_patterns": oracle_profile.get("confirm_patterns") or [],
        "accepted_evidence": [
            "MAGUS_ROUTE_EXECUTED proves the selected dynamic route was reached",
            "MAGUS_ROUTE_CONFIRMED is emitted only when the selected oracle profile matches route-bound semantic evidence",
            "MAGUS_ORACLE_UNSUPPORTED means D reached the route but lacks an oracle for the hypothesis semantics",
            *(oracle_profile.get("accepted_evidence") or []),
        ],
        "failure_patterns": ["MAGUS_ROUTE_CONFIRMED"],
        "required_patterns": ["MAGUS_ROUTE_EXECUTED"],
        "unsupported_patterns": ["MAGUS_ORACLE_UNSUPPORTED"],
        "failure_code_patterns": {
            "NOT_ROUTE_BOUND": ["MAGUS_NOT_ROUTE_BOUND"],
            "ENV_MISSING": ["MAGUS_BUILD_FAILED", "MAGUS_RUNNER_ERROR"],
            "NOT_EXPLOITABLE": ["MAGUS_NOT_CONFIRMED"],
        },
        "expect_nonzero_exit": False,
    }


def apply_juliet_win32_adapter(hypothesis: Dict[str, Any], case: Dict[str, Any]) -> bool:
    source_file = case.get("source_file") or hypothesis.get("file") or hypothesis.get("filepath")
    if source_file in (None, "", []):
        return False
    if not is_juliet_api_misuse_hypothesis(hypothesis, source_file):
        return False

    oracle_profile = case.get("oracle_profile") or {}
    symbol = str(case.get("entry_symbol") or "")
    case["name"] = "juliet_win32_source_api"
    case["execution_adapter_id"] = "juliet_win32_linux_shim"
    case["execution"] = juliet_win32_execution_context(source_file, symbol, hypothesis.get("route"), oracle_profile)
    case["oracle"] = juliet_win32_oracle(oracle_profile)
    return True


def apply_execution_adapters(hypothesis: Dict[str, Any], case: Dict[str, Any]) -> str | None:
    if apply_juliet_win32_adapter(hypothesis, case):
        return "juliet_win32_linux_shim"
    return None
