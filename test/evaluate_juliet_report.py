#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import math
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = REPO_ROOT / "report" / "verification.report.jsonl"
DEFAULT_JULIET_ROOT = REPO_ROOT / "srcs" / "juliet-api-misuse"
DEFAULT_OUT_DIR = REPO_ROOT / "test" / "out" / "juliet_eval"
DEFAULT_D_OUTPUT_DIR = REPO_ROOT / "d" / "memberD_verifier" / "02_run_with_C" / "output"
SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx"}
POSITIVE_LABELS = {"1", "true", "yes", "y", "bad", "bug", "vulnerable", "vuln", "positive"}
NEGATIVE_LABELS = {"0", "false", "no", "n", "good", "clean", "safe", "non_vulnerable", "negative"}


@dataclass
class TruthItem:
    key: str
    is_vulnerable: bool
    cwe: str = ""
    files: set[str] = field(default_factory=set)
    basis: set[str] = field(default_factory=set)


@dataclass
class ReportFinding:
    row_index: int
    report_id: str
    project_id: str
    sample_id: str
    hypothesis_id: str
    file_path: str
    juliet_file: str
    route: str
    route_symbol: str
    case_key: str
    cwe: str
    route_label: str
    classification: str
    classification_reason: str
    duplicate_of_key: str = ""


@dataclass
class TimingInfo:
    stage_a_start: str = ""
    report_generated_at: str = ""
    elapsed_seconds: float | None = None
    stage_a_start_source: str = ""
    report_generated_source: str = ""
    elapsed_source: str = ""
    warnings: list[str] = field(default_factory=list)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig", errors="replace")


def read_json_or_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"required input is missing: {path}")
    text = read_text(path).strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
        if isinstance(payload, list):
            return ensure_object_rows(payload, path)
        if isinstance(payload, dict):
            return [payload]
    except json.JSONDecodeError:
        pass

    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{line_no}: expected a JSON object")
        rows.append(row)
    return rows


def ensure_object_rows(rows: Iterable[Any], path: Path) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for idx, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{idx}: expected a JSON object")
        result.append(row)
    return result


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def scalar_list(value: Any) -> list[Any]:
    if value in (None, "", []):
        return []
    if isinstance(value, list):
        return value
    return [value]


def first_text(*values: Any) -> str:
    for value in values:
        if value in (None, "", []):
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def normalize_cwe(value: Any) -> str:
    for item in scalar_list(value):
        text = str(item).strip()
        if not text:
            continue
        match = re.search(r"CWE[-_]?(\d+)", text, flags=re.IGNORECASE)
        if match:
            return f"CWE-{match.group(1)}"
        return text
    return ""


def cwe_from_relpath(rel: str) -> str:
    for part in PurePosixPath(rel).parts:
        match = re.match(r"(CWE\d+)", part, flags=re.IGNORECASE)
        if match:
            return f"CWE-{match.group(1)[3:]}"
    return ""


def path_marker_relative(text: str) -> str | None:
    normalized = text.replace("\\", "/")
    marker = "juliet-api-misuse/"
    if marker in normalized:
        return normalized.split(marker, 1)[1].lstrip("/")
    if normalized.startswith("testcases/"):
        return normalized
    if normalized.startswith("./testcases/"):
        return normalized[2:]
    return None


def normalize_juliet_relpath(raw: Any, juliet_root: Path, workspace_root: Path) -> str | None:
    text = str(raw or "").strip()
    if not text:
        return None

    marker_rel = path_marker_relative(text)
    if marker_rel:
        return marker_rel

    candidate = Path(text)
    roots = [juliet_root, workspace_root]
    candidates: list[Path] = []
    if candidate.is_absolute():
        candidates.append(candidate)
    else:
        candidates.extend(root / candidate for root in roots)

    juliet_resolved = juliet_root.resolve()
    for path in candidates:
        try:
            rel = path.resolve().relative_to(juliet_resolved)
        except ValueError:
            continue
        return rel.as_posix()
    return None


def route_symbol(route: Any) -> str:
    text = str(route or "").strip()
    if "::" in text:
        return text.rsplit("::", 1)[1].strip()
    return text


def canonical_stem(stem: str) -> str:
    result = stem
    for suffix in ("_goodB2G", "_goodG2B", "_good", "_bad"):
        if result.endswith(suffix):
            result = result[: -len(suffix)]
            break
    match = re.match(r"^(.*?_\d{2,3})([a-z])$", result)
    if match:
        result = match.group(1)
    return result


def canonical_case_key(rel: str) -> str:
    path = PurePosixPath(rel)
    cwe = cwe_from_relpath(rel)
    stem = canonical_stem(path.stem)
    return f"{cwe}/{stem}" if cwe else stem


def file_name_label(rel: str) -> str:
    stem = PurePosixPath(rel).stem.lower()
    if stem.endswith("_good") or "_goodb2g" in stem or "_goodg2b" in stem:
        return "non_vulnerable"
    if stem.endswith("_bad") or "_bad_" in stem:
        return "vulnerable"
    return "unknown"


def route_label(rel: str, route: str) -> str:
    symbol = route_symbol(route).lower()
    file_label = file_name_label(rel)
    if "good" in symbol or file_label == "non_vulnerable":
        return "non_vulnerable"
    if "bad" in symbol or file_label == "vulnerable":
        return "vulnerable"
    return "unknown"


def is_source_file(path: Path) -> bool:
    return path.suffix.lower() in SOURCE_EXTENSIONS


def is_juliet_testcase_source(rel: str) -> bool:
    path = PurePosixPath(rel)
    if "testcasesupport" in path.parts:
        return False
    if "testcases" not in path.parts:
        return False
    if path.name == "main.cpp":
        return False
    return path.suffix.lower() in SOURCE_EXTENSIONS


def source_has_bad_path(text: str, rel: str) -> bool:
    stem = PurePosixPath(rel).stem
    if file_name_label(rel) == "vulnerable":
        return True
    if "OMITBAD" in text:
        return True
    if re.search(r"\b[A-Za-z_]\w*_bad\s*\(", text):
        return True
    if re.search(r"\b[A-Za-z_]\w*_bad::", text):
        return True
    if re.search(r"\bvoid\s+bad\s*\(", text):
        return True
    return stem.endswith("_bad")


def source_has_good_path(text: str, rel: str) -> bool:
    if file_name_label(rel) == "non_vulnerable":
        return True
    if "OMITGOOD" in text:
        return True
    if re.search(r"\b[A-Za-z_]\w*_good\w*\s*\(", text):
        return True
    if re.search(r"\bgood(?:G2B|B2G)?\s*\(", text):
        return True
    return False


def iter_scoped_source_paths(juliet_root: Path, scoped_files: set[str] | None) -> list[str]:
    if scoped_files is not None:
        return sorted(rel for rel in scoped_files if is_juliet_testcase_source(rel))
    result: list[str] = []
    for path in juliet_root.rglob("*"):
        if not path.is_file() or not is_source_file(path):
            continue
        rel = path.relative_to(juliet_root).as_posix()
        if is_juliet_testcase_source(rel):
            result.append(rel)
    return sorted(result)


def infer_truth_from_source(juliet_root: Path, scoped_files: set[str] | None) -> dict[str, TruthItem]:
    truth: dict[str, TruthItem] = {}
    for rel in iter_scoped_source_paths(juliet_root, scoped_files):
        path = juliet_root / rel
        text = read_text(path)
        key = canonical_case_key(rel)
        item = truth.setdefault(
            key,
            TruthItem(
                key=key,
                is_vulnerable=False,
                cwe=cwe_from_relpath(rel),
            ),
        )
        item.files.add(rel)
        if source_has_good_path(text, rel):
            item.basis.add("source_has_good_path")
        if source_has_bad_path(text, rel):
            item.is_vulnerable = True
            item.basis.add("source_has_bad_path")
    return truth


def parse_truth_label(row: dict[str, Any], path: Path, row_index: int) -> bool:
    raw = first_text(
        row.get("is_vulnerable"),
        row.get("vulnerable"),
        row.get("expected"),
        row.get("label"),
        row.get("verdict"),
        row.get("answer"),
    )
    lowered = raw.strip().lower()
    if lowered in POSITIVE_LABELS:
        return True
    if lowered in NEGATIVE_LABELS:
        return False
    raise ValueError(f"{path}:{row_index}: cannot infer vulnerability label from {raw!r}")


def load_answer_file(path: Path, juliet_root: Path, workspace_root: Path) -> dict[str, TruthItem]:
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
    else:
        rows = read_json_or_jsonl(path)

    truth: dict[str, TruthItem] = {}
    for idx, row in enumerate(rows, 1):
        is_vulnerable = parse_truth_label(row, path, idx)
        key = first_text(row.get("key"), row.get("case_key"))
        rel = ""
        if not key:
            rel = normalize_juliet_relpath(
                first_text(row.get("file"), row.get("file_path"), row.get("path")),
                juliet_root,
                workspace_root,
            ) or ""
            if not rel:
                raise ValueError(f"{path}:{idx}: answer row must contain key/case_key or Juliet file path")
            key = canonical_case_key(rel)
        item = truth.setdefault(
            key,
            TruthItem(key=key, is_vulnerable=is_vulnerable, cwe=cwe_from_relpath(rel)),
        )
        item.is_vulnerable = item.is_vulnerable or is_vulnerable
        if rel:
            item.files.add(rel)
        item.basis.add(f"answer_file:{path.name}")
    return truth


def load_scope_compile_commands(path: Path, juliet_root: Path, workspace_root: Path) -> set[str]:
    payload = json.loads(read_text(path))
    if not isinstance(payload, list):
        raise ValueError(f"{path}: expected compile_commands.json list")
    result: set[str] = set()
    for idx, entry in enumerate(payload, 1):
        if not isinstance(entry, dict):
            raise ValueError(f"{path}:{idx}: expected a compile command object")
        rel = normalize_juliet_relpath(entry.get("file"), juliet_root, workspace_root)
        if rel and is_juliet_testcase_source(rel):
            result.add(rel)
    return result


def load_scope_file_list(path: Path, juliet_root: Path, workspace_root: Path) -> set[str]:
    result: set[str] = set()
    for line_no, line in enumerate(read_text(path).splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rel = normalize_juliet_relpath(line, juliet_root, workspace_root)
        if not rel:
            raise ValueError(f"{path}:{line_no}: path is not under Juliet root: {line}")
        if is_juliet_testcase_source(rel):
            result.add(rel)
    return result


def extract_report_file_and_route(row: dict[str, Any]) -> tuple[str, str]:
    location = row.get("location") if isinstance(row.get("location"), dict) else {}
    file_path = first_text(
        location.get("file_path"),
        row.get("file"),
        row.get("file_path"),
        row.get("source_file"),
    )
    route = first_text(location.get("route"), row.get("route"), row.get("entry_symbol"), row.get("symbol"))
    if not file_path and "::" in route:
        file_path = route.rsplit("::", 1)[0]
    return file_path, route


def cwe_from_report(row: dict[str, Any], rel: str) -> str:
    cwe = normalize_cwe(row.get("cwe_candidates") or row.get("CWE_candidates") or row.get("cwe_list"))
    return cwe or cwe_from_relpath(rel)


def build_finding(
    row: dict[str, Any],
    row_index: int,
    truth: dict[str, TruthItem],
    juliet_root: Path,
    workspace_root: Path,
) -> ReportFinding:
    file_path, route = extract_report_file_and_route(row)
    rel = normalize_juliet_relpath(file_path, juliet_root, workspace_root) or ""
    key = canonical_case_key(rel) if rel else ""
    label = route_label(rel, route) if rel else "unknown"

    classification = "FP"
    reason = "report path is outside the Juliet benchmark"
    if rel and key in truth:
        if label == "non_vulnerable":
            classification = "FP"
            reason = "reported route is a Juliet good path"
        elif truth[key].is_vulnerable:
            classification = "TP"
            reason = "reported case matches a Juliet bad testcase"
        else:
            classification = "FP"
            reason = "reported case is not marked vulnerable in the Juliet answers"
    elif rel:
        classification = "FP"
        reason = "reported Juliet case is outside the selected answer scope"

    return ReportFinding(
        row_index=row_index,
        report_id=first_text(row.get("report_id")),
        project_id=first_text(row.get("project_id")),
        sample_id=first_text(row.get("sample_id")),
        hypothesis_id=first_text(row.get("hypothesis_id")),
        file_path=file_path,
        juliet_file=rel,
        route=route,
        route_symbol=route_symbol(route),
        case_key=key,
        cwe=cwe_from_report(row, rel),
        route_label=label,
        classification=classification,
        classification_reason=reason,
    )


def classify_findings(
    rows: list[dict[str, Any]],
    truth: dict[str, TruthItem],
    juliet_root: Path,
    workspace_root: Path,
) -> list[ReportFinding]:
    findings = [build_finding(row, idx, truth, juliet_root, workspace_root) for idx, row in enumerate(rows, 1)]
    covered: set[str] = set()
    for finding in findings:
        if finding.classification != "TP":
            continue
        if finding.case_key in covered:
            finding.classification = "DUPLICATE_TP"
            finding.classification_reason = "additional report for an already covered Juliet bad testcase"
            finding.duplicate_of_key = finding.case_key
        else:
            covered.add(finding.case_key)
    return findings


def finding_to_row(finding: ReportFinding) -> dict[str, Any]:
    return {
        "row_index": finding.row_index,
        "classification": finding.classification,
        "reason": finding.classification_reason,
        "case_key": finding.case_key,
        "cwe": finding.cwe,
        "route_label": finding.route_label,
        "juliet_file": finding.juliet_file,
        "route": finding.route,
        "route_symbol": finding.route_symbol,
        "report_id": finding.report_id,
        "project_id": finding.project_id,
        "sample_id": finding.sample_id,
        "hypothesis_id": finding.hypothesis_id,
    }


def truth_to_row(item: TruthItem) -> dict[str, Any]:
    return {
        "case_key": item.key,
        "is_vulnerable": item.is_vulnerable,
        "cwe": item.cwe,
        "files": sorted(item.files),
        "basis": sorted(item.basis),
    }


def stringify_csv_value(value: Any) -> str:
    if isinstance(value, (list, dict, set, tuple)):
        if isinstance(value, set):
            value = sorted(value)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if value is None:
        return ""
    return str(value)


def write_csv_rows(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: stringify_csv_value(row.get(field)) for field in fieldnames})


def safe_div(num: float, den: float) -> float | None:
    if den == 0:
        return None
    return num / den


def round_metric(value: float | None) -> float | None:
    if value is None:
        return None
    return round(value, 6)


def metric_percent(value: float | None) -> str:
    if value is None:
        return "N/A"
    return f"{value * 100:.2f}%"


def parse_datetime_value(value: str) -> datetime:
    text = value.strip()
    if not text:
        raise ValueError("empty datetime")
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        return datetime.fromtimestamp(float(text), timezone.utc)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    text = text.replace(" ", "T", 1) if " " in text and "T" not in text else text
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def isoformat_z(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_timing_json(path: Path) -> dict[str, Any]:
    rows = read_json_or_jsonl(path)
    if not rows:
        return {}
    if len(rows) == 1:
        return rows[0]
    merged: dict[str, Any] = {}
    for row in rows:
        merged.update(row)
    return merged


def find_time_value(payload: dict[str, Any], keys: Iterable[str]) -> str:
    for key in keys:
        value = payload.get(key)
        if value not in (None, "", []):
            return str(value)
    return ""


def report_md_generated_at(path: Path) -> str:
    if not path.exists():
        return ""
    for line in read_text(path).splitlines():
        lowered = line.strip().lower()
        if lowered.startswith("- generated_at:"):
            return line.split(":", 1)[1].strip()
    return ""


def resolve_timing(args: argparse.Namespace, report_path: Path) -> TimingInfo:
    info = TimingInfo()
    timing_payload: dict[str, Any] = {}
    if args.timing_json:
        timing_payload = read_timing_json(args.timing_json)

    start_raw = first_text(args.stage_a_start)
    if start_raw:
        info.stage_a_start_source = "--stage-a-start"
    if not start_raw and args.stage_a_manifest:
        manifest = json.loads(read_text(args.stage_a_manifest))
        start_raw = first_text(manifest.get("started_at"))
        if start_raw:
            info.stage_a_start_source = str(args.stage_a_manifest)
    if not start_raw and timing_payload:
        start_raw = find_time_value(
            timing_payload,
            ("stage_a_start", "a_started_at", "started_at", "start_time", "pipeline_start"),
        )
        if start_raw:
            info.stage_a_start_source = str(args.timing_json)

    end_raw = first_text(args.report_generated_at)
    if end_raw:
        info.report_generated_source = "--report-generated-at"
    if not end_raw and timing_payload:
        end_raw = find_time_value(
            timing_payload,
            ("report_generated_at", "final_report_generated_at", "report_finished_at", "finished_at", "end_time"),
        )
        if end_raw:
            info.report_generated_source = str(args.timing_json)
    if not end_raw:
        report_md = args.report_md or report_path.with_name("verification.report.md")
        end_raw = report_md_generated_at(report_md)
        if end_raw:
            info.report_generated_source = str(report_md)
    if not end_raw and report_path.exists():
        end_dt = datetime.fromtimestamp(report_path.stat().st_mtime, timezone.utc)
        end_raw = isoformat_z(end_dt)
        info.report_generated_source = f"{report_path} mtime"
        info.warnings.append("report_generated_at was inferred from report file mtime")

    elapsed_raw = find_time_value(timing_payload, ("elapsed_seconds", "duration_seconds", "runtime_seconds"))
    start_dt: datetime | None = None
    end_dt: datetime | None = None

    if start_raw:
        start_dt = parse_datetime_value(start_raw)
        info.stage_a_start = isoformat_z(start_dt)
    if end_raw:
        end_dt = parse_datetime_value(end_raw)
        info.report_generated_at = isoformat_z(end_dt)

    if start_dt and end_dt:
        info.elapsed_seconds = max(0.0, (end_dt - start_dt).total_seconds())
        info.elapsed_source = "stage_a_start_to_report_generated_at"
    elif elapsed_raw:
        info.elapsed_seconds = float(elapsed_raw)
        info.elapsed_source = str(args.timing_json)
    else:
        info.warnings.append(
            "elapsed time is unavailable; pass --stage-a-start or --timing-json to measure A start to report generation"
        )

    if args.require_timing and info.elapsed_seconds is None:
        raise ValueError("timing is required but could not be resolved")
    return info


def hms(seconds: float | None) -> str:
    if seconds is None:
        return "N/A"
    total = int(round(seconds))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def annotate_missing_cases(
    missing_keys: set[str],
    args: argparse.Namespace,
    juliet_root: Path,
    workspace_root: Path,
) -> dict[str, dict[str, Any]]:
    annotations: dict[str, dict[str, Any]] = {key: {} for key in missing_keys}
    failed_paths: list[Path] = []
    if args.d_failed:
        failed_paths.append(args.d_failed)
    else:
        default_failed = args.d_output_dir / "verification.failed.jsonl"
        if default_failed.exists():
            failed_paths.append(default_failed)
    for path in failed_paths:
        for row in read_json_or_jsonl(path):
            file_path, route = extract_report_file_and_route(row)
            rel = normalize_juliet_relpath(file_path, juliet_root, workspace_root) or ""
            key = canonical_case_key(rel) if rel else ""
            if key in annotations:
                codes = annotations[key].setdefault("d_failure_codes", set())
                code = first_text(row.get("failure_code"))
                if code:
                    codes.add(code)
                routes = annotations[key].setdefault("d_failed_routes", set())
                if route:
                    routes.add(route)

    for path in args.audit_jsonl or []:
        for row in read_json_or_jsonl(path):
            file_path, route = extract_report_file_and_route(row)
            rel = normalize_juliet_relpath(file_path, juliet_root, workspace_root) or ""
            key = canonical_case_key(rel) if rel else ""
            if key in annotations:
                reasons = annotations[key].setdefault("audit_reasons", set())
                reason = first_text(row.get("suspicion_reason"), row.get("routing_decision"), row.get("agent_verdict"))
                if reason:
                    reasons.add(reason)
                routes = annotations[key].setdefault("audit_routes", set())
                if route:
                    routes.add(route)

    return annotations


def build_summary(
    findings: list[ReportFinding],
    truth: dict[str, TruthItem],
    timing: TimingInfo,
    args: argparse.Namespace,
) -> dict[str, Any]:
    positive_truth = {key for key, item in truth.items() if item.is_vulnerable}
    negative_truth = {key for key, item in truth.items() if not item.is_vulnerable}
    tp_rows = [item for item in findings if item.classification in {"TP", "DUPLICATE_TP"}]
    first_tp_rows = [item for item in findings if item.classification == "TP"]
    duplicate_tp_rows = [item for item in findings if item.classification == "DUPLICATE_TP"]
    fp_rows = [item for item in findings if item.classification == "FP"]
    covered_positive = {item.case_key for item in first_tp_rows}
    missed_positive = positive_truth - covered_positive
    unique_fp_units = {
        item.case_key if item.case_key else f"row:{item.row_index}"
        for item in fp_rows
    }
    truth_source_files = {
        file_name
        for item in truth.values()
        for file_name in item.files
    }

    precision = safe_div(len(tp_rows), len(tp_rows) + len(fp_rows))
    unique_precision = safe_div(len(covered_positive), len(covered_positive) + len(unique_fp_units))
    recall = safe_div(len(covered_positive), len(positive_truth))
    f1 = None
    if precision is not None and recall is not None and precision + recall > 0:
        f1 = 2 * precision * recall / (precision + recall)
    false_discovery_rate = safe_div(len(fp_rows), len(tp_rows) + len(fp_rows))
    false_negative_rate = safe_div(len(missed_positive), len(positive_truth))
    false_positive_rate = safe_div(len({row.case_key for row in fp_rows if row.case_key in negative_truth}), len(negative_truth))

    return {
        "inputs": {
            "report": str(args.report),
            "juliet_root": str(args.juliet_root),
            "answer_file": str(args.answer_file) if args.answer_file else "",
            "scope_compile_commands": str(args.scope_compile_commands) if args.scope_compile_commands else "",
            "scope_file_list": str(args.scope_file_list) if args.scope_file_list else "",
        },
        "timing": {
            "stage_a_start": timing.stage_a_start,
            "stage_a_start_source": timing.stage_a_start_source,
            "report_generated_at": timing.report_generated_at,
            "report_generated_source": timing.report_generated_source,
            "elapsed_seconds": timing.elapsed_seconds,
            "elapsed_hms": hms(timing.elapsed_seconds),
            "elapsed_source": timing.elapsed_source,
            "warnings": timing.warnings,
        },
        "counts": {
            "report_rows": len(findings),
            "truth_cases": len(truth),
            "truth_source_files": len(truth_source_files),
            "truth_positive_cases": len(positive_truth),
            "truth_negative_cases": len(negative_truth),
            "tp_report_rows": len(tp_rows),
            "tp_unique_cases": len(covered_positive),
            "duplicate_tp_report_rows": len(duplicate_tp_rows),
            "fp_report_rows": len(fp_rows),
            "fp_unique_units": len(unique_fp_units),
            "fn_cases": len(missed_positive),
        },
        "metrics": {
            "precision_report_rows": round_metric(precision),
            "precision_unique_cases": round_metric(unique_precision),
            "recall_unique_cases": round_metric(recall),
            "f1": round_metric(f1),
            "false_discovery_rate": round_metric(false_discovery_rate),
            "false_negative_rate": round_metric(false_negative_rate),
            "false_positive_rate_unique_negative_cases": round_metric(false_positive_rate),
        },
    }


def markdown_table(rows: list[tuple[str, Any]]) -> list[str]:
    lines = ["| Metric | Value |", "| --- | --- |"]
    for key, value in rows:
        if isinstance(value, float):
            rendered = f"{value:.6f}" if not math.isnan(value) else "N/A"
        elif value is None:
            rendered = "N/A"
        else:
            rendered = str(value)
        lines.append(f"| {key} | {rendered} |")
    return lines


def write_markdown(
    path: Path,
    summary: dict[str, Any],
    false_positive_rows: list[dict[str, Any]],
    false_negative_rows: list[dict[str, Any]],
) -> None:
    counts = summary["counts"]
    metrics = summary["metrics"]
    timing = summary["timing"]
    lines: list[str] = ["# MAGUS Juliet Evaluation", ""]
    lines.extend(
        markdown_table(
            [
                ("Report rows", counts["report_rows"]),
                ("Truth source files", counts["truth_source_files"]),
                ("Truth positive cases", counts["truth_positive_cases"]),
                ("TP report rows", counts["tp_report_rows"]),
                ("TP unique cases", counts["tp_unique_cases"]),
                ("Duplicate TP report rows", counts["duplicate_tp_report_rows"]),
                ("FP report rows", counts["fp_report_rows"]),
                ("FP unique units", counts["fp_unique_units"]),
                ("FN cases", counts["fn_cases"]),
                ("Report-row precision", metric_percent(metrics["precision_report_rows"])),
                ("Unique-case precision", metric_percent(metrics["precision_unique_cases"])),
                ("Recall", metric_percent(metrics["recall_unique_cases"])),
                ("F1", metrics["f1"]),
                ("False discovery rate", metric_percent(metrics["false_discovery_rate"])),
                ("False negative rate", metric_percent(metrics["false_negative_rate"])),
                ("False positive rate", metric_percent(metrics["false_positive_rate_unique_negative_cases"])),
            ]
        )
    )
    lines.extend(["", "## Timing", ""])
    lines.extend(
        markdown_table(
            [
                ("Stage A start", timing["stage_a_start"] or "N/A"),
                ("Stage A start source", timing["stage_a_start_source"] or "N/A"),
                ("Report generated at", timing["report_generated_at"] or "N/A"),
                ("Report generated source", timing["report_generated_source"] or "N/A"),
                ("Elapsed seconds", timing["elapsed_seconds"]),
                ("Elapsed hms", timing["elapsed_hms"]),
            ]
        )
    )
    if timing["warnings"]:
        lines.extend(["", "## Timing Warnings", ""])
        lines.extend(f"- {warning}" for warning in timing["warnings"])

    lines.extend(["", "## False Positives Preview", ""])
    if false_positive_rows:
        lines.extend(["| Row | Case | Reason | Route |", "| --- | --- | --- | --- |"])
        for row in false_positive_rows[:20]:
            lines.append(
                f"| {row['row_index']} | {row['case_key']} | {row['reason']} | {row['route_symbol'] or row['route']} |"
            )
    else:
        lines.append("No false positives.")

    lines.extend(["", "## False Negatives Preview", ""])
    if false_negative_rows:
        lines.extend(["| Case | CWE | Files | D failures | Audit reasons |", "| --- | --- | --- | --- | --- |"])
        for row in false_negative_rows[:20]:
            files = "; ".join(row.get("files", [])[:3])
            d_codes = "; ".join(row.get("d_failure_codes", []))
            audit = "; ".join(row.get("audit_reasons", []))
            lines.append(f"| {row['case_key']} | {row.get('cwe', '')} | {files} | {d_codes} | {audit} |")
    else:
        lines.append("No false negatives.")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_outputs(
    out_dir: Path,
    summary: dict[str, Any],
    findings: list[ReportFinding],
    truth: dict[str, TruthItem],
    false_negative_rows: list[dict[str, Any]],
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    finding_rows = [finding_to_row(item) for item in findings]
    fp_rows = [row for row in finding_rows if row["classification"] == "FP"]
    tp_rows = [row for row in finding_rows if row["classification"] in {"TP", "DUPLICATE_TP"}]
    duplicate_rows = [row for row in finding_rows if row["classification"] == "DUPLICATE_TP"]
    truth_rows = [truth_to_row(item) for item in sorted(truth.values(), key=lambda row: row.key)]

    write_json(out_dir / "summary.json", summary)
    write_csv_rows(
        out_dir / "all_findings.csv",
        finding_rows,
        [
            "row_index",
            "classification",
            "reason",
            "case_key",
            "cwe",
            "route_label",
            "juliet_file",
            "route",
            "route_symbol",
            "report_id",
            "project_id",
            "sample_id",
            "hypothesis_id",
        ],
    )
    write_csv_rows(
        out_dir / "false_positives.csv",
        fp_rows,
        ["row_index", "reason", "case_key", "cwe", "route_label", "juliet_file", "route", "hypothesis_id"],
    )
    write_csv_rows(
        out_dir / "true_positives.csv",
        tp_rows,
        ["row_index", "classification", "case_key", "cwe", "juliet_file", "route", "hypothesis_id"],
    )
    write_csv_rows(
        out_dir / "duplicate_true_positives.csv",
        duplicate_rows,
        ["row_index", "case_key", "cwe", "juliet_file", "route", "hypothesis_id"],
    )
    write_csv_rows(
        out_dir / "false_negatives.csv",
        false_negative_rows,
        ["case_key", "cwe", "files", "basis", "d_failure_codes", "d_failed_routes", "audit_reasons", "audit_routes"],
    )
    write_csv_rows(out_dir / "truth_cases.csv", truth_rows, ["case_key", "is_vulnerable", "cwe", "files", "basis"])
    write_markdown(out_dir / "summary.md", summary, fp_rows, false_negative_rows)


def build_false_negative_rows(
    truth: dict[str, TruthItem],
    findings: list[ReportFinding],
    args: argparse.Namespace,
    juliet_root: Path,
    workspace_root: Path,
) -> list[dict[str, Any]]:
    covered = {finding.case_key for finding in findings if finding.classification == "TP"}
    missing = {key for key, item in truth.items() if item.is_vulnerable and key not in covered}
    annotations = annotate_missing_cases(missing, args, juliet_root, workspace_root)
    rows: list[dict[str, Any]] = []
    for key in sorted(missing):
        item = truth[key]
        annotation = annotations.get(key, {})
        rows.append(
            {
                "case_key": key,
                "cwe": item.cwe,
                "files": sorted(item.files),
                "basis": sorted(item.basis),
                "d_failure_codes": sorted(annotation.get("d_failure_codes", [])),
                "d_failed_routes": sorted(annotation.get("d_failed_routes", [])),
                "audit_reasons": sorted(annotation.get("audit_reasons", [])),
                "audit_routes": sorted(annotation.get("audit_routes", [])),
            }
        )
    return rows


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare the MAGUS final report against Juliet ground truth and emit paper-ready "
            "false-positive, false-negative, and timing artifacts."
        )
    )
    parser.add_argument("--report", default=DEFAULT_REPORT, type=Path, help="MAGUS final report JSONL")
    parser.add_argument("--juliet-root", default=DEFAULT_JULIET_ROOT, type=Path, help="Juliet API misuse root")
    parser.add_argument("--workspace-root", default=REPO_ROOT, type=Path, help="MAGUS workspace root")
    parser.add_argument("--answer-file", type=Path, help="Optional explicit Juliet answer file in JSONL/JSON/CSV")
    parser.add_argument(
        "--scope-compile-commands",
        type=Path,
        help="Restrict truth cases to files listed in this compile_commands.json",
    )
    parser.add_argument("--scope-file-list", type=Path, help="Restrict truth cases to newline-delimited Juliet files")
    parser.add_argument("--out-dir", default=DEFAULT_OUT_DIR, type=Path, help="Directory for evaluation artifacts")
    parser.add_argument("--d-output-dir", default=DEFAULT_D_OUTPUT_DIR, type=Path, help="Stage D output directory")
    parser.add_argument("--d-failed", type=Path, help="Optional Stage D verification.failed.jsonl for FN annotation")
    parser.add_argument(
        "--audit-jsonl",
        action="append",
        type=Path,
        default=[],
        help="Optional Stage C audit JSONL for FN annotation; repeatable",
    )
    parser.add_argument("--stage-a-start", help="UTC/ISO/epoch time when Stage A started")
    parser.add_argument("--stage-a-manifest", type=Path, help="Stage A run_manifest.json if it was preserved")
    parser.add_argument("--report-generated-at", help="UTC/ISO/epoch time when final report generation finished")
    parser.add_argument("--report-md", type=Path, help="Final report Markdown containing generated_at")
    parser.add_argument("--timing-json", type=Path, help="Optional JSON/JSONL timing file with start/end fields")
    parser.add_argument(
        "--run-command",
        help=(
            "Optional pipeline command to run before evaluation. The timer starts immediately before this command; "
            "use it for commands whose first step is Stage A, such as 'python3 pipeline.py abcd'."
        ),
    )
    parser.add_argument("--require-timing", action="store_true", help="Fail when elapsed time cannot be resolved")
    parser.add_argument("--fail-on-mismatch", action="store_true", help="Return non-zero if any FP or FN is found")
    return parser.parse_args(argv)


def load_scope(args: argparse.Namespace) -> set[str] | None:
    scoped: set[str] | None = None
    if args.scope_compile_commands:
        scoped = load_scope_compile_commands(args.scope_compile_commands, args.juliet_root, args.workspace_root)
    if args.scope_file_list:
        listed = load_scope_file_list(args.scope_file_list, args.juliet_root, args.workspace_root)
        scoped = listed if scoped is None else scoped & listed
    return scoped


def maybe_run_pipeline_command(args: argparse.Namespace) -> None:
    if not args.run_command:
        return
    command = shlex.split(args.run_command)
    if not command:
        raise ValueError("--run-command must not be empty")
    stage_a_start = datetime.now(timezone.utc)
    print(f"running timed command: {args.run_command}", flush=True)
    completed = subprocess.run(command, cwd=args.workspace_root)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)
    if not args.stage_a_start:
        args.stage_a_start = isoformat_z(stage_a_start)
    if not args.report_generated_at:
        report_md = args.report_md or args.report.with_name("verification.report.md")
        if not report_md.exists():
            args.report_generated_at = isoformat_z(datetime.now(timezone.utc))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    args.report = args.report.resolve()
    args.juliet_root = args.juliet_root.resolve()
    args.workspace_root = args.workspace_root.resolve()
    args.out_dir = args.out_dir.resolve()
    args.d_output_dir = args.d_output_dir.resolve()

    try:
        maybe_run_pipeline_command(args)
        report_rows = read_json_or_jsonl(args.report)
        scoped_files = load_scope(args)
        if args.answer_file:
            truth = load_answer_file(args.answer_file, args.juliet_root, args.workspace_root)
        else:
            truth = infer_truth_from_source(args.juliet_root, scoped_files)
        if not truth:
            raise ValueError("Juliet answer scope is empty")

        findings = classify_findings(report_rows, truth, args.juliet_root, args.workspace_root)
        timing = resolve_timing(args, args.report)
        false_negative_rows = build_false_negative_rows(truth, findings, args, args.juliet_root, args.workspace_root)
        summary = build_summary(findings, truth, timing, args)
        write_outputs(args.out_dir, summary, findings, truth, false_negative_rows)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    counts = summary["counts"]
    metrics = summary["metrics"]
    print("MAGUS Juliet evaluation")
    print(f"report_rows: {counts['report_rows']}")
    print(f"truth_positive_cases: {counts['truth_positive_cases']}")
    print(f"tp_unique_cases: {counts['tp_unique_cases']}")
    print(f"fp_report_rows: {counts['fp_report_rows']}")
    print(f"fn_cases: {counts['fn_cases']}")
    print(f"report_row_precision: {metric_percent(metrics['precision_report_rows'])}")
    print(f"unique_case_precision: {metric_percent(metrics['precision_unique_cases'])}")
    print(f"recall: {metric_percent(metrics['recall_unique_cases'])}")
    print(f"elapsed: {summary['timing']['elapsed_hms']} ({summary['timing']['elapsed_seconds']} seconds)")
    print(f"output: {args.out_dir}")

    if args.fail_on_mismatch and (counts["fp_report_rows"] or counts["fn_cases"]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
