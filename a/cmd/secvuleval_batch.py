#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


# 1. CLI 与基础 IO
def parse_args() -> argparse.Namespace:
    """解析 SecVulEval batch runner 参数。"""
    parser = argparse.ArgumentParser(description="Run Stage A over SecVulEval projects with per-project outputs")
    parser.add_argument(
        "--input",
        default="out/secvuleval/stagea.projects.in.jsonl",
        help="SecVulEval Stage A project input JSONL",
    )
    parser.add_argument(
        "--output-root",
        default="out",
        help="root directory that receives one output folder per project_id",
    )
    parser.add_argument(
        "--miner",
        default="cmd/miner.py",
        help="Stage A miner entrypoint",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="optional cap on projects processed from the input JSONL",
    )
    return parser.parse_args()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """读取 JSONL 文件。"""
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def write_json(path: Path, payload: Any) -> None:
    """写入格式化 JSON 文件。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    """写入 JSONL 文件。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False))
            handle.write("\n")


def count_jsonl_records(path: Path) -> int:
    """统计非空 JSONL 行数。"""
    if not path.exists():
        return 0
    count = 0
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                count += 1
    return count


def derived_stats_path(raw_output_path: Path) -> Path:
    name = raw_output_path.name
    if not name.endswith(".raw.jsonl"):
        raise ValueError("Stage A output path must end with .raw.jsonl")
    return raw_output_path.with_name(f"{name[:-10]}.stats.jsonl")


# 2. 单项目转换与执行
def project_record_for_miner(project: dict[str, Any], input_base_dir: Path) -> dict[str, Any]:
    """将 batch 记录转成可直接喂给 Stage A miner 的单项目输入。"""
    record = dict(project)
    repo_path = record.get("repo_path")
    if isinstance(repo_path, str) and repo_path.strip() and not Path(repo_path).is_absolute():
        record["repo_path"] = str((input_base_dir / repo_path).resolve())
    return record


def run_project(
    miner: Path,
    project: dict[str, Any],
    input_base_dir: Path,
    output_root: Path,
) -> dict[str, Any]:
    """执行一个 SecVulEval 项目，并写出该项目的 batch.result.json。"""
    project_id = str(project.get("project_id", "")).strip()
    if not project_id:
        raise ValueError("project record is missing project_id")

    project_out = output_root / project_id
    if project_out.exists():
        shutil.rmtree(project_out)
    project_out.mkdir(parents=True, exist_ok=True)

    project_input = project_out / "project.in.jsonl"
    output_path = project_out / "samples.raw.jsonl"
    stats_path = derived_stats_path(output_path)
    write_jsonl(project_input, [project_record_for_miner(project, input_base_dir)])

    command = [
        sys.executable,
        str(miner),
        "--input",
        str(project_input),
        "--output",
        str(output_path),
    ]
    result = subprocess.run(
        command,
        cwd=str(Path.cwd()),
        capture_output=True,
        text=True,
    )

    sample_count = count_jsonl_records(output_path)
    failure_manifest = project_out / "a.artifacts" / project_id / "failures.json"
    effective_returncode = result.returncode
    failure_reasons: list[str] = []
    if result.returncode != 0:
        failure_reasons.append("miner_returncode")
    if failure_manifest.exists():
        failure_reasons.append("failure_manifest")
    if sample_count == 0:
        failure_reasons.append("no_samples")
    if failure_reasons:
        effective_returncode = result.returncode or 1

    project_result = {
        "project_id": project_id,
        "output_dir": str(project_out),
        "input": str(project_input),
        "samples_raw": str(output_path),
        "samples_stats": str(stats_path) if stats_path.exists() else "",
        "returncode": effective_returncode,
        "miner_returncode": result.returncode,
        "sample_count": sample_count,
        "failure_manifest": str(failure_manifest) if failure_manifest.exists() else "",
        "failure_reasons": failure_reasons,
        "stdout_tail": result.stdout[-4000:],
        "stderr_tail": result.stderr[-4000:],
    }
    write_json(project_out / "batch.result.json", project_result)
    return project_result


# 3. 主流程
def main() -> None:
    """SecVulEval batch CLI 入口。"""
    args = parse_args()
    input_path = Path(args.input).resolve()
    output_root = Path(args.output_root).resolve()
    miner = Path(args.miner).resolve()

    if not input_path.exists():
        print(f"input file not found: {input_path}", file=sys.stderr)
        raise SystemExit(1)
    if not miner.exists():
        print(f"miner not found: {miner}", file=sys.stderr)
        raise SystemExit(1)

    projects = read_jsonl(input_path)
    if args.limit > 0:
        projects = projects[: args.limit]

    results = []
    for project in projects:
        try:
            result = run_project(miner, project, input_path.parent, output_root)
        except Exception as exc:
            project_id = str(project.get("project_id", "")).strip()
            result = {
                "project_id": project_id,
                "returncode": 1,
                "error": str(exc),
            }
        results.append(result)

        if result.get("returncode") == 0:
            print(f"secvuleval project ok: {result.get('project_id')}", file=sys.stderr)
        else:
            print(f"secvuleval project failed: {result.get('project_id')}", file=sys.stderr)

    failed = sum(1 for result in results if result.get("returncode") != 0)
    print(
        f"secvuleval batch finished: {len(results) - failed}/{len(results)} succeeded",
        file=sys.stderr,
    )

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
