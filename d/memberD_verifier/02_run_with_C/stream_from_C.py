#!/usr/bin/env python3
from __future__ import annotations

import argparse
import atexit
import copy
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, TextIO, Tuple


FLOW_DIR = Path(__file__).resolve().parent
ROOT_DIR = FLOW_DIR.parent
CORE_DIR = ROOT_DIR / "00_core"
TOOLS_DIR = ROOT_DIR / "03_tools"
LOCK_DIR = FLOW_DIR / ".stage_d_output.lock"

for import_dir in (CORE_DIR, FLOW_DIR, TOOLS_DIR):
    sys.path.insert(0, str(import_dir))

import bind_verification_contexts as context_binder  # noqa: E402
import gen_targets_from_hypotheses as target_gen  # noqa: E402
import validate_outputs  # noqa: E402
import verifier  # noqa: E402


TargetBundle = Dict[str, List[Dict[str, Any]]]
ContextIndex = Dict[str, Dict[Any, Dict[str, Any]]]
MatchedContexts = Dict[str, set[Any]]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stream Stage C JSONL hypotheses into Stage D verification")
    parser.add_argument("--hypotheses", required=True, type=Path, help="Single Stage C JSONL file to follow")
    parser.add_argument("--done-file", required=True, type=Path, help="File created by the producer when C is finished")
    parser.add_argument("--out-dir", default=Path("output"), type=Path, help="Stage D output directory")
    parser.add_argument("--contexts", default=FLOW_DIR / "verification_contexts.jsonl", type=Path)
    parser.add_argument("--targets-out", default=FLOW_DIR / "targets.auto.json", type=Path)
    parser.add_argument("--bound-targets-out", default=FLOW_DIR / "targets.executable.json", type=Path)
    parser.add_argument("--poll-interval", default=0.2, type=float, help="Seconds between JSONL polls")
    parser.add_argument("--dry-run", action="store_true", help="Generate payloads and plans without executing run_cmd")
    return parser.parse_args()


def acquire_lock(out_dir: Path) -> None:
    try:
        LOCK_DIR.mkdir()
    except FileExistsError as exc:
        pid_path = LOCK_DIR / "pid"
        pid = pid_path.read_text(encoding="utf-8").strip() if pid_path.exists() else "unknown"
        raise RuntimeError(
            f"another Stage D process is using {out_dir}; lock={LOCK_DIR} pid={pid}"
        ) from exc
    (LOCK_DIR / "pid").write_text(str(os.getpid()) + "\n", encoding="utf-8")

    def cleanup_lock() -> None:
        pid_path = LOCK_DIR / "pid"
        if pid_path.exists():
            pid_path.unlink()
        if LOCK_DIR.exists():
            try:
                LOCK_DIR.rmdir()
            except OSError:
                pass

    atexit.register(cleanup_lock)


def dump_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def prepare_outputs(out_dir: Path, targets_out: Path, bound_targets_out: Path, has_contexts: bool) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "payloads").mkdir(parents=True, exist_ok=True)
    (out_dir / "verification.jsonl").write_text("", encoding="utf-8")
    (out_dir / "verification.failed.jsonl").write_text("", encoding="utf-8")
    verifier.write_summary(out_dir, [], [])
    dump_json(targets_out, {"targets": []})
    if has_contexts:
        dump_json(bound_targets_out, {"targets": []})


def append_jsonl(file_obj: TextIO, row: Dict[str, Any]) -> None:
    file_obj.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
    file_obj.flush()


def stream_jsonl(path: Path, done_file: Path, poll_interval: float) -> Iterable[Dict[str, Any]]:
    if path.is_dir():
        raise ValueError(f"{path}: streaming input must be a single JSONL file, not a directory")

    offset = 0
    partial = ""
    while True:
        if path.exists():
            with path.open("r", encoding="utf-8-sig") as f:
                f.seek(offset)
                chunk = f.read()
                offset = f.tell()
        else:
            chunk = ""

        if chunk:
            partial += chunk
            while True:
                newline_index = partial.find("\n")
                if newline_index < 0:
                    break
                line = partial[:newline_index].rstrip("\r")
                partial = partial[newline_index + 1 :]
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}: invalid JSONL record: {exc}") from exc
                if not isinstance(record, dict):
                    raise ValueError(f"{path}: each streamed JSONL record must be an object")
                yield record
            continue

        if done_file.exists():
            if partial.strip():
                raise ValueError(f"{path}: producer ended with an incomplete JSONL record")
            return

        time.sleep(poll_interval)


def merge_targets(destination: TargetBundle, source: TargetBundle) -> None:
    by_project = {str(target.get("project_id")): target for target in destination["targets"]}
    for source_target in source["targets"]:
        project_id = str(source_target.get("project_id"))
        existing = by_project.get(project_id)
        if existing is None:
            copied = copy.deepcopy(source_target)
            destination["targets"].append(copied)
            by_project[project_id] = copied
            continue
        existing_cases = existing.setdefault("cases", {})
        existing_cases.update(copy.deepcopy(source_target.get("cases") or {}))


def apply_contexts(
    targets: TargetBundle,
    hypotheses: List[Dict[str, Any]],
    context_index: ContextIndex,
    matched: MatchedContexts,
) -> int:
    hyp_index = context_binder.hypotheses_by_id(hypotheses)
    bound = 0

    for target in targets["targets"]:
        project_id = str(target.get("project_id", "")).strip()
        cases = target.get("cases") or {}
        if not project_id or not isinstance(cases, dict):
            continue
        for hypothesis_id, case in cases.items():
            if not isinstance(case, dict):
                continue
            hypothesis = hyp_index.get((project_id, str(hypothesis_id)), {})
            route = str(hypothesis.get("route", "")).strip()
            project_context = context_index["project"].get(project_id)
            route_context = context_index["route"].get((project_id, route))
            hypothesis_context = context_index["hypothesis"].get((project_id, str(hypothesis_id)))
            if project_context:
                matched["project"].add(project_id)
            if route_context:
                matched["route"].add((project_id, route))
            if hypothesis_context:
                matched["hypothesis"].add((project_id, str(hypothesis_id)))

            context = context_binder.merged_context(project_id, hypothesis, case, context_index)
            if context["execution"]:
                case.setdefault("execution", {}).update(context["execution"])
            if context["oracle"]:
                case.setdefault("oracle", {}).update(context["oracle"])
            if context["payload"]:
                case.setdefault("payload", {}).update(context["payload"])
            if context["execution"] or context["oracle"] or context["payload"]:
                bound += 1
    return bound


def assert_all_contexts_matched(context_index: Optional[ContextIndex], matched: MatchedContexts) -> None:
    if context_index is None:
        return
    unused_project = sorted(set(context_index["project"]) - matched["project"])
    unused_route = sorted(set(context_index["route"]) - matched["route"])
    unused_hypothesis = sorted(set(context_index["hypothesis"]) - matched["hypothesis"])
    if not unused_project and not unused_route and not unused_hypothesis:
        return

    issues = []
    if unused_project:
        issues.append(f"unmatched project_id contexts: {unused_project}")
    if unused_route:
        issues.append(f"unmatched route contexts: {unused_route}")
    if unused_hypothesis:
        issues.append(f"unmatched hypothesis_id contexts: {unused_hypothesis}")
    raise ValueError("; ".join(issues))


def validate_output_files(out_dir: Path) -> None:
    confirmed = validate_outputs.read_jsonl(out_dir / "verification.jsonl")
    failed = validate_outputs.read_jsonl(out_dir / "verification.failed.jsonl")

    problems: List[str] = []
    for idx, row in enumerate(confirmed, 1):
        for err in validate_outputs.validate_confirmed(row):
            problems.append(f"verification.jsonl:{idx}: {err}")
    for idx, row in enumerate(failed, 1):
        for err in validate_outputs.validate_failed(row):
            problems.append(f"verification.failed.jsonl:{idx}: {err}")
    if problems:
        raise ValueError("Stage D output validation failed:\n- " + "\n- ".join(problems))


def process_hypothesis(
    hyp: Dict[str, Any],
    context_index: Optional[ContextIndex],
    matched_contexts: MatchedContexts,
    raw_targets: TargetBundle,
    executable_targets: TargetBundle,
    args: argparse.Namespace,
) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    raw_one = target_gen.build_targets([hyp], auto_fill=True)
    executable_one = copy.deepcopy(raw_one)

    if context_index is not None:
        apply_contexts(executable_one, [hyp], context_index, matched_contexts)

    merge_targets(raw_targets, raw_one)
    merge_targets(executable_targets, executable_one)
    dump_json(args.targets_out, raw_targets)
    if context_index is not None:
        dump_json(args.bound_targets_out, executable_targets)

    target = executable_one["targets"][0]
    return verifier.run_one(hyp, target, args.out_dir, args.dry_run)


def run(args: argparse.Namespace) -> int:
    acquire_lock(args.out_dir)

    context_index: Optional[ContextIndex] = None
    if args.contexts.exists():
        context_index = context_binder.load_context_index(args.contexts)

    prepare_outputs(args.out_dir, args.targets_out, args.bound_targets_out, context_index is not None)

    raw_targets: TargetBundle = {"targets": []}
    executable_targets: TargetBundle = {"targets": []}
    matched_contexts: MatchedContexts = {"project": set(), "route": set(), "hypothesis": set()}
    seen: Dict[Tuple[str, str], str] = {}
    success_rows: List[Dict[str, Any]] = []
    failed_rows: List[Dict[str, Any]] = []
    processed = 0

    with (
        (args.out_dir / "verification.jsonl").open("a", encoding="utf-8", buffering=1) as success_file,
        (args.out_dir / "verification.failed.jsonl").open("a", encoding="utf-8", buffering=1) as failed_file,
    ):
        for hyp in stream_jsonl(args.hypotheses, args.done_file, args.poll_interval):
            processed += 1
            project_id = str(hyp.get("project_id", "")).strip()
            hypothesis_id = str(hyp.get("hypothesis_id", "")).strip()
            if project_id and hypothesis_id:
                key = (project_id, hypothesis_id)
                previous = seen.get(key)
                if previous:
                    raise ValueError(
                        f"duplicate hypothesis project_id={project_id!r} hypothesis_id={hypothesis_id!r}: "
                        f"{previous} and stream record {processed}"
                    )
                seen[key] = f"stream record {processed}"

            print(f"[D-stream] verifying {project_id or '?'} {hypothesis_id or '?'}", flush=True)
            success, failed = process_hypothesis(
                hyp, context_index, matched_contexts, raw_targets, executable_targets, args
            )
            if success:
                success_rows.append(success)
                append_jsonl(success_file, success)
                if success.get("status") == "stage_c_preserved":
                    print(f"[D-stream] preserved {hypothesis_id} code=UNSUPPORTED_ORACLE", flush=True)
                else:
                    print(f"[D-stream] confirmed {hypothesis_id}", flush=True)
            if failed:
                failed_rows.append(failed)
                append_jsonl(failed_file, failed)
                print(
                    f"[D-stream] failed {hypothesis_id} code={failed.get('failure_code')}",
                    flush=True,
                )
            if not success and not failed:
                raise RuntimeError(f"{project_id}/{hypothesis_id}: verifier produced no result")

    if processed == 0:
        raise ValueError(f"{args.hypotheses}: no Stage C hypothesis records found")

    assert_all_contexts_matched(context_index, matched_contexts)
    verifier.write_summary(args.out_dir, success_rows, failed_rows)
    validate_output_files(args.out_dir)

    print(f"[D-stream] processed: {processed}", flush=True)
    confirmed_count = sum(1 for row in success_rows if row.get("status") == "confirmed")
    preserved_count = sum(1 for row in success_rows if row.get("status") == "stage_c_preserved")
    print(f"[D-stream] reportable: {len(success_rows)}", flush=True)
    print(f"[D-stream] confirmed:  {confirmed_count}", flush=True)
    print(f"[D-stream] preserved:  {preserved_count}", flush=True)
    print(f"[D-stream] failed:    {len(failed_rows)}", flush=True)
    print(f"[D-stream] output:    {args.out_dir}", flush=True)
    return 0


def main() -> int:
    try:
        return run(parse_args())
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
