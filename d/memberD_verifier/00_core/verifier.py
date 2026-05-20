#!/usr/bin/env python3
"""
MAGUS Stage D source/API verifier.

In this project, "API" means a C/C++ programming interface or function-call
sequence. Stage D does not generate or execute HTTP requests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


FAILURE_CODES = {
    "NOT_EXPLOITABLE",
    "ENV_MISSING",
    "HYPOTHESIS_WRONG",
    "TIMEOUT",
    "NON_DETERMINISTIC",
}

MIN_EVIDENCE_FIELDS = ["project_id", "sample_id", "hypothesis_id", "route", "file", "line", "evidence_slice"]
UNRESOLVED_VALUES = ("AUTO_DETECT_FAILED", "TODO", "replace with", "真实", "待填写")
PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = PROJECT_ROOT.parent.parent


SOURCE_API_PAYLOAD_RUNNER = r'''#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_FAILURE_PATTERNS = [
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
    "Segmentation fault",
    "null pointer",
    "heap-use-after-free",
    "stack-buffer-overflow",
    "heap-buffer-overflow",
    "use-after-free",
    "double-free",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def as_list(value: Any) -> list[Any]:
    if value in (None, "", []):
        return []
    if isinstance(value, list):
        return value
    return [value]


def run_command(cmd: Any, cwd: Path, timeout: int) -> dict[str, Any]:
    started = time.perf_counter()
    if isinstance(cmd, str):
        cmd = cmd.replace("${PYTHON}", sys.executable)
    elif isinstance(cmd, list):
        cmd = [str(part).replace("${PYTHON}", sys.executable) for part in cmd]
    shell = isinstance(cmd, str)
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            shell=shell,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=os.environ.copy(),
        )
        return {
            "cmd": cmd,
            "cwd": str(cwd),
            "exit_code": proc.returncode,
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
            "stdout_tail": (proc.stdout or "")[-12000:],
            "stderr_tail": (proc.stderr or "")[-12000:],
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "cmd": cmd,
            "cwd": str(cwd),
            "exit_code": None,
            "elapsed_ms": int((time.perf_counter() - started) * 1000),
            "stdout_tail": (exc.stdout or "")[-12000:] if isinstance(exc.stdout, str) else "",
            "stderr_tail": (exc.stderr or "")[-12000:] if isinstance(exc.stderr, str) else "",
            "timed_out": True,
        }


def decide(run_results: list[dict[str, Any]], oracle: dict[str, Any]) -> tuple[str, str, list[str]]:
    patterns = oracle.get("failure_patterns") or DEFAULT_FAILURE_PATTERNS
    expect_nonzero = bool(oracle.get("expect_nonzero_exit", True))
    observations: list[str] = []
    for result in run_results:
        output = f"{result.get('stdout_tail') or ''}\n{result.get('stderr_tail') or ''}"
        if result.get("timed_out"):
            observations.append(f"timeout while running {result.get('cmd')}")
            return "failed", "TIMEOUT", observations
        matched = [str(pattern) for pattern in patterns if str(pattern) and str(pattern) in output]
        if matched:
            observations.append(f"oracle matched patterns: {', '.join(matched)}")
            return "confirmed", "ORACLE_MATCH", observations
        if expect_nonzero and result.get("exit_code") not in (0, None):
            observations.append(f"non-zero exit observed: {result.get('exit_code')}")
            return "confirmed", "NONZERO_EXIT", observations
        observations.append(f"exit={result.get('exit_code')} for {result.get('cmd')}")
    return "failed", "NOT_EXPLOITABLE", observations


def main() -> int:
    parser = argparse.ArgumentParser(description="Executable source/API misuse payload runner")
    parser.add_argument("--plan", default="__PLAN_NAME__")
    parser.add_argument("--result", default="")
    args = parser.parse_args()

    plan_path = Path(args.plan)
    if not plan_path.is_absolute():
        plan_path = Path(__file__).resolve().parent / plan_path
    result_path = Path(args.result) if args.result else Path(__file__).with_suffix(".payload-result.json")

    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    build = plan.get("build") or {}
    oracle = plan.get("oracle") or {}
    timeout = int(build.get("timeout_sec") or 60)
    repo_path = build.get("repo_path")

    if not repo_path:
        result = {
            "status": "failed",
            "failure_code": "ENV_MISSING",
            "failure_note": "repo_path is missing; cannot execute source/API payload",
            "observations": ["payload runner was generated but no source repository was configured"],
            "runtime_trace": [],
            "timestamps": {"finished_at": utc_now()},
        }
        result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return 2

    cwd = Path(str(repo_path)).expanduser().resolve()
    if not cwd.exists():
        result = {
            "status": "failed",
            "failure_code": "ENV_MISSING",
            "failure_note": f"repo_path does not exist: {cwd}",
            "observations": ["payload runner could not find the configured source repository"],
            "runtime_trace": [],
            "timestamps": {"finished_at": utc_now()},
        }
        result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return 2

    setup_cmds = as_list(build.get("config_cmd")) + as_list(build.get("build_cmd"))
    run_cmds = as_list(build.get("run_cmd")) or as_list(build.get("poc_cmd")) or as_list(build.get("test_cmd"))
    if not run_cmds:
        result = {
            "status": "failed",
            "failure_code": "ENV_MISSING",
            "failure_note": "run_cmd/poc_cmd/test_cmd is missing; cannot execute source/API payload",
            "observations": ["payload runner needs a concrete command that reaches the suspected API sequence"],
            "runtime_trace": [],
            "timestamps": {"finished_at": utc_now()},
        }
        result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return 2

    setup_results = [run_command(cmd, cwd, timeout) for cmd in setup_cmds]
    for item in setup_results:
        if item.get("timed_out") or item.get("exit_code") not in (0, None):
            result = {
                "status": "failed",
                "failure_code": "ENV_MISSING",
                "failure_note": "setup/build command failed before payload execution",
                "observations": [f"setup failed: {item.get('cmd')} exit={item.get('exit_code')}"],
                "runtime_trace": setup_results,
                "timestamps": {"finished_at": utc_now()},
            }
            result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            return 2

    run_results = [run_command(cmd, cwd, timeout) for cmd in run_cmds]
    status, reason, observations = decide(run_results, oracle)
    result = {
        "status": status,
        "reason": reason,
        "failure_code": reason if status == "failed" else None,
        "failure_note": "payload did not satisfy oracle" if status == "failed" else None,
        "observations": observations,
        "runtime_trace": setup_results + run_results,
        "timestamps": {"finished_at": utc_now()},
    }
    result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if status == "confirmed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
'''


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
            raise ValueError(f"Invalid JSON on {path}:{n}: {exc}") from exc
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


def write_jsonl(path: Path, rows: Iterable[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def load_targets(path: Path) -> Dict[str, Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "targets" in data:
        targets = data["targets"]
    elif isinstance(data, list):
        targets = data
    elif isinstance(data, dict) and "project_id" in data:
        targets = [data]
    else:
        raise ValueError("targets.json must be {project_id,...}, a list, or {targets:[...]}.")

    result: Dict[str, Dict[str, Any]] = {}
    for target in targets:
        project_id = target.get("project_id")
        if not project_id:
            raise ValueError("Every target must contain project_id.")
        result[str(project_id)] = target
    return result


def stable_verify_id(hypothesis_id: str) -> str:
    digest = hashlib.sha1(hypothesis_id.encode("utf-8")).hexdigest()[:8]
    return f"ver_{digest}"


def missing_fields(hyp: Dict[str, Any]) -> List[str]:
    return [field for field in MIN_EVIDENCE_FIELDS if hyp.get(field) in (None, "", [])]


def evidence_fields(hyp: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "route": hyp.get("route"),
        "file": hyp.get("file"),
        "line": hyp.get("line"),
        "evidence_slice": hyp.get("evidence_slice"),
    }


def get_case(target: Dict[str, Any], hyp: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    cases = target.get("cases") or {}
    hypothesis_id = hyp.get("hypothesis_id")
    route = hyp.get("route")
    if hypothesis_id in cases:
        return dict(cases[hypothesis_id])
    if route in cases:
        return dict(cases[route])
    return None


def failed_record(hyp: Dict[str, Any], code: str, note: str, suggested_action: str = "review hypothesis or target case") -> Dict[str, Any]:
    if code not in FAILURE_CODES:
        code = "HYPOTHESIS_WRONG"
    record = {
        "verify_id": stable_verify_id(str(hyp.get("hypothesis_id", "unknown"))),
        "project_id": hyp.get("project_id"),
        "sample_id": hyp.get("sample_id"),
        "hypothesis_id": hyp.get("hypothesis_id"),
        "status": "failed",
        "failure_code": code,
        "failure_note": note,
        "suggested_action": suggested_action,
        "timestamps": {"failed_at": utc_now()},
    }
    record.update(evidence_fields(hyp))
    return record


def has_unresolved_marker(value: Any) -> bool:
    if value in (None, "", []):
        return False
    text = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
    return any(marker.lower() in text.lower() for marker in UNRESOLVED_VALUES)


def resolve_repo_path(raw_path: str) -> str:
    repo = Path(raw_path).expanduser()
    if repo.is_absolute():
        return str(repo)

    candidates = [
        Path.cwd() / repo,
        PROJECT_ROOT / repo,
        PROJECT_ROOT.parent / repo,
        WORKSPACE_ROOT / repo,
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate.resolve())
    return str((Path.cwd() / repo).resolve())


def source_execution_config(target: Dict[str, Any], case: Dict[str, Any]) -> Dict[str, Any]:
    config: Dict[str, Any] = {}
    for source in (
        target.get("verification_context") or {},
        case.get("verification_context") or {},
        target.get("execution") or {},
        case.get("execution") or {},
        target,
        case,
    ):
        if not isinstance(source, dict):
            continue
        for key in ("repo_path", "config_cmd", "build_cmd", "run_cmd", "poc_cmd", "test_cmd", "docker_image", "timeout_sec"):
            value = source.get(key)
            if value not in (None, "", []) and not has_unresolved_marker(value):
                config[key] = value
    return config


def source_execution_missing(config: Dict[str, Any]) -> List[str]:
    missing: List[str] = []
    if not config.get("repo_path"):
        missing.append("repo_path")
    if not (config.get("run_cmd") or config.get("poc_cmd") or config.get("test_cmd")):
        missing.append("run_cmd/poc_cmd/test_cmd")
    return missing


def write_source_api_plan(payload_path: Path, hyp: Dict[str, Any], case: Dict[str, Any], target: Dict[str, Any]) -> None:
    payload_path.parent.mkdir(parents=True, exist_ok=True)
    execution = source_execution_config(target, case)
    repo_path = execution.get("repo_path")
    if repo_path:
        execution["repo_path"] = resolve_repo_path(str(repo_path))
    plan = {
        "kind": "source_api_misuse_plan",
        "project_id": hyp.get("project_id"),
        "sample_id": hyp.get("sample_id"),
        "hypothesis_id": hyp.get("hypothesis_id"),
        "claim": hyp.get("claim"),
        "cwe_candidates": hyp.get("cwe_candidates") or hyp.get("CWE_candidates") or hyp.get("cwe_list"),
        "source_file": case.get("source_file") or hyp.get("file"),
        "entry_symbol": case.get("entry_symbol"),
        "api_sequence": case.get("api_sequence") or hyp.get("attack_path") or hyp.get("api_sequence"),
        "payload": case.get("payload"),
        "poc_plan": case.get("poc_plan"),
        "oracle": case.get("oracle"),
        "build": {
            "env_profile": target.get("env_profile"),
            "repo_path": execution.get("repo_path"),
            "config_cmd": execution.get("config_cmd"),
            "build_cmd": execution.get("build_cmd"),
            "run_cmd": execution.get("run_cmd"),
            "poc_cmd": execution.get("poc_cmd"),
            "test_cmd": execution.get("test_cmd"),
            "docker_image": execution.get("docker_image"),
            "timeout_sec": execution.get("timeout_sec"),
        },
        "evidence": evidence_fields(hyp),
        "timestamps": {"generated_at": utc_now()},
    }
    payload_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_source_payload_runner(runner_path: Path, plan_name: str) -> None:
    runner_path.parent.mkdir(parents=True, exist_ok=True)
    script = SOURCE_API_PAYLOAD_RUNNER.replace("__PLAN_NAME__", plan_name)
    runner_path.write_text(script + "\n", encoding="utf-8")


def execute_source_payload(runner_path: Path, timeout: float) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    runner_path = runner_path.resolve()
    result_path = runner_path.with_suffix(".payload-result.json")
    cmd = [sys.executable, str(runner_path), "--result", str(result_path)]
    try:
        subprocess.run(
            cmd,
            cwd=str(runner_path.parent),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return None, f"payload runner timed out: {exc}"

    if not result_path.exists():
        return None, "payload runner did not produce result json"
    try:
        return json.loads(result_path.read_text(encoding="utf-8")), None
    except json.JSONDecodeError as exc:
        return None, f"invalid payload runner result: {exc}"


def is_source_api_case(target: Dict[str, Any], case: Optional[Dict[str, Any]]) -> bool:
    return (
        (target.get("target_type") in {"source_api", "native"})
        or bool(case and case.get("target_type") in {"source_api", "native"})
        or bool(case and case.get("payload_kind") in {"api_misuse_plan", "native_plan"})
    )


def run_one(hyp: Dict[str, Any], target: Dict[str, Any], out_dir: Path, timeout: float, dry_run: bool) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    missing = missing_fields(hyp)
    if missing:
        return None, failed_record(hyp, "HYPOTHESIS_WRONG", f"missing required fields: {', '.join(missing)}")

    if hyp.get("agent_verdict") and str(hyp.get("agent_verdict")).lower() not in {"accept", "accepted"}:
        return None, failed_record(hyp, "HYPOTHESIS_WRONG", f"agent_verdict is {hyp.get('agent_verdict')!r}", "send only accepted C hypotheses")

    case = get_case(target, hyp)
    if case is None:
        return None, failed_record(
            hyp,
            "HYPOTHESIS_WRONG",
            f"no source/API case for hypothesis_id={hyp.get('hypothesis_id')}",
            "regenerate targets.json from the same Stage C hypotheses input",
        )
    if not is_source_api_case(target, case):
        return None, failed_record(
            hyp,
            "HYPOTHESIS_WRONG",
            f"unsupported target_type={target.get('target_type')!r}; Stage D only verifies source/API cases",
            "remove HTTP/Web targets and provide source_api targets",
        )

    plan_rel = Path("payloads") / f"{hyp['hypothesis_id']}.api-plan.json"
    runner_rel = Path("payloads") / f"{hyp['hypothesis_id']}.payload.py"
    plan_abs = out_dir / plan_rel
    runner_abs = out_dir / runner_rel
    write_source_api_plan(plan_abs, hyp, case, target)
    write_source_payload_runner(runner_abs, plan_rel.name)

    execution = source_execution_config(target, case)
    missing_execution = source_execution_missing(execution)
    if missing_execution:
        record = failed_record(
            hyp,
            "ENV_MISSING",
            "executable source/API payload generated but execution config is incomplete: "
            + ", ".join(missing_execution),
            "provide repo_path plus run_cmd/poc_cmd/test_cmd; optional config_cmd/build_cmd can prepare the project",
        )
        record["payload_ref"] = runner_rel.as_posix()
        record["plan_ref"] = plan_rel.as_posix()
        record["target_type"] = "source_api"
        record["attack_type"] = case.get("attack_type")
        record["runtime_trace"] = [
            {
                "name": case.get("name") or "source_api_payload",
                "status": "payload_generated",
                "payload_ref": runner_rel.as_posix(),
                "plan_ref": plan_rel.as_posix(),
                "missing": missing_execution,
                "ts": utc_now(),
            }
        ]
        return None, record

    if dry_run:
        record = failed_record(
            hyp,
            "HYPOTHESIS_WRONG",
            "dry-run mode: source/API payload generated but not executed",
            f"inspect {plan_rel.as_posix()} and rerun without --dry-run",
        )
        record["payload_ref"] = runner_rel.as_posix()
        record["plan_ref"] = plan_rel.as_posix()
        record["target_type"] = "source_api"
        record["attack_type"] = case.get("attack_type")
        return None, record

    result, runner_error = execute_source_payload(runner_abs, timeout)
    if runner_error:
        record = failed_record(
            hyp,
            "ENV_MISSING",
            runner_error,
            "check that local Python can execute the generated payload runner",
        )
        record["payload_ref"] = runner_rel.as_posix()
        record["plan_ref"] = plan_rel.as_posix()
        record["target_type"] = "source_api"
        record["attack_type"] = case.get("attack_type")
        return None, record
    assert result is not None

    if result.get("status") == "confirmed":
        record = {
            "verify_id": stable_verify_id(str(hyp["hypothesis_id"])),
            "project_id": hyp["project_id"],
            "sample_id": hyp["sample_id"],
            "hypothesis_id": hyp["hypothesis_id"],
            "status": "confirmed",
            "severity": "P0",
            "target_type": "source_api",
            "attack_type": case.get("attack_type"),
            "payload_ref": runner_rel.as_posix(),
            "plan_ref": plan_rel.as_posix(),
            "repro_steps": [
                f"run generated payload runner {runner_rel.as_posix()}",
                "execute configured config/build commands if present",
                "execute configured run_cmd/poc_cmd/test_cmd against the source project",
                "mark confirmed only when the oracle matches runtime evidence",
            ],
            "observations": result.get("observations") or [],
            "runtime_trace": result.get("runtime_trace") or [],
            "timestamps": {"verified_at": utc_now()},
        }
        record.update(evidence_fields(hyp))
        if hyp.get("claim"):
            record["claim"] = hyp.get("claim")
        cwe = hyp.get("cwe_candidates") or hyp.get("CWE_candidates") or hyp.get("cwe_list")
        if cwe:
            record["cwe_candidates"] = cwe
        if hyp.get("confidence") is not None:
            record["confidence"] = hyp.get("confidence")
        return record, None

    record = failed_record(
        hyp,
        result.get("failure_code") or "NOT_EXPLOITABLE",
        result.get("failure_note") or "source/API payload executed but oracle did not confirm exploitability",
        "inspect payload result, adjust run_cmd/poc_cmd/test_cmd, or refine oracle patterns",
    )
    record["payload_ref"] = runner_rel.as_posix()
    record["plan_ref"] = plan_rel.as_posix()
    record["target_type"] = "source_api"
    record["attack_type"] = case.get("attack_type")
    record["observations"] = result.get("observations") or []
    record["runtime_trace"] = result.get("runtime_trace") or []
    return None, record


def write_summary(out_dir: Path, success_rows: List[Dict[str, Any]], failed_rows: List[Dict[str, Any]]) -> None:
    lines = [
        "# Member D Verification Summary",
        "",
        f"- generated_at: {utc_now()}",
        f"- target_type: source_api",
        f"- confirmed: {len(success_rows)}",
        f"- failed: {len(failed_rows)}",
        "",
    ]
    if success_rows:
        lines.extend(["## Confirmed P0", ""])
        for row in success_rows:
            lines.append(
                f"- {row.get('hypothesis_id')} | {row.get('project_id')} | {row.get('route')} | "
                f"payload: {row.get('payload_ref')}"
            )
    if failed_rows:
        lines.extend(["", "## Failed / 回流", ""])
        for row in failed_rows:
            lines.append(
                f"- {row.get('hypothesis_id')} | {row.get('failure_code')} | "
                f"{row.get('failure_note')} | action: {row.get('suggested_action')}"
            )
    (out_dir / "verification.summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Source/API hypothesis verifier")
    parser.add_argument("--hypotheses", required=True, type=Path, help="Path to C output directory or hypotheses JSONL file")
    parser.add_argument("--targets", required=True, type=Path, help="Path to source/API targets.json")
    parser.add_argument("--out-dir", required=True, type=Path, help="Output directory")
    parser.add_argument("--timeout", default=10.0, type=float, help="Payload runner timeout seconds")
    parser.add_argument("--dry-run", action="store_true", help="Generate payloads and plans without executing run_cmd")
    args = parser.parse_args(argv)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    targets = load_targets(args.targets)
    hypotheses = read_hypotheses(args.hypotheses)

    success_rows: List[Dict[str, Any]] = []
    failed_rows: List[Dict[str, Any]] = []

    for hyp in hypotheses:
        target = targets.get(str(hyp.get("project_id")))
        if not target:
            failed_rows.append(
                failed_record(
                    hyp,
                    "ENV_MISSING",
                    f"no source/API target for project_id={hyp.get('project_id')}",
                    "regenerate targets.json from the same Stage C hypotheses input",
                )
            )
            continue
        success, failed = run_one(hyp, target, args.out_dir, args.timeout, args.dry_run)
        if success:
            success_rows.append(success)
        if failed:
            failed_rows.append(failed)

    write_jsonl(args.out_dir / "verification.jsonl", success_rows)
    write_jsonl(args.out_dir / "verification.failed.jsonl", failed_rows)
    write_summary(args.out_dir, success_rows, failed_rows)

    print(f"confirmed: {len(success_rows)}")
    print(f"failed:    {len(failed_rows)}")
    print(f"output:    {args.out_dir}")
    return 0 if success_rows or failed_rows else 1


if __name__ == "__main__":
    sys.exit(main())
