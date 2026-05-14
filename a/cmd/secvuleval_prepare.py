#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse


CPP_SUFFIXES = {".cc", ".cpp", ".cxx", ".c++", ".hpp", ".hh", ".hxx", ".ipp", ".inl", ".tpp"}


@dataclass
class TargetRecord:
    idx: int
    project: str
    project_url: str
    filepath: str
    commit_id: str
    func_name: str
    is_vulnerable: bool
    cve_list: list[str]
    cwe_list: list[str]
    fixed_func_idx: int | None
    changed_lines: Any
    changed_statements: Any
    project_id: str
    checkout_path: str
    inferred_language: str


@dataclass
class ProjectGroup:
    project_id: str
    project: str
    project_url: str
    commit_id: str
    checkout_path: str
    target_count: int = 0
    vulnerable_target_count: int = 0
    non_vulnerable_target_count: int = 0
    inferred_language: str = "c"
    source_files: set[str] = field(default_factory=set)
    entry_functions: set[str] = field(default_factory=set)
    target_indexes: list[int] = field(default_factory=list)

    def add_target(self, target: TargetRecord) -> None:
        self.target_count += 1
        if target.is_vulnerable:
            self.vulnerable_target_count += 1
        else:
            self.non_vulnerable_target_count += 1
        self.source_files.add(target.filepath)
        self.entry_functions.add(target.func_name)
        self.target_indexes.append(target.idx)
        if target.inferred_language == "cpp":
            self.inferred_language = "cpp"


@dataclass
class RecipeAggregate:
    project: str
    project_url: str
    inferred_language: str = "c"
    target_count: int = 0
    vulnerable_target_count: int = 0
    non_vulnerable_target_count: int = 0
    commit_ids: set[str] = field(default_factory=set)
    project_ids: set[str] = field(default_factory=set)
    source_files: set[str] = field(default_factory=set)
    entry_functions: set[str] = field(default_factory=set)

    def add_group(self, group: ProjectGroup) -> None:
        self.target_count += group.target_count
        self.vulnerable_target_count += group.vulnerable_target_count
        self.non_vulnerable_target_count += group.non_vulnerable_target_count
        self.commit_ids.add(group.commit_id)
        self.project_ids.add(group.project_id)
        self.source_files.update(group.source_files)
        self.entry_functions.update(group.entry_functions)
        if group.inferred_language == "cpp":
            self.inferred_language = "cpp"


@dataclass
class BuildRecipe:
    project_url: str
    language: str | None = None
    framework: str = "generic"
    default_branch: str = "detached"
    build_cwd: str = ""
    config_cmd: str = ""
    build_cmd: str = ""
    bitcode_globs: list[str] = field(default_factory=list)
    build_env: dict[str, str] = field(default_factory=dict)
    analysis_timeout: int = 1800
    analyzer_jobs: int = 2

    def is_complete(self) -> bool:
        return bool(self.build_cmd.strip() and self.bitcode_globs)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prepare SecVulEval planning files for Stage A")
    parser.add_argument(
        "--dataset",
        default="input/SecVulEval/data/train-00000-of-00001.parquet",
        help="path to the SecVulEval parquet shard",
    )
    parser.add_argument(
        "--out-dir",
        default="out/secvuleval",
        help="directory for generated planning files",
    )
    parser.add_argument(
        "--recipes",
        default="",
        help="optional JSON file containing build recipes keyed by project_url",
    )
    parser.add_argument(
        "--checkout-root",
        default="input/secvuleval/src",
        help="planned checkout root recorded into repo_path fields; no clone is performed",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="optional cap on the number of dataset rows to read",
    )
    return parser.parse_args()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False))
            handle.write("\n")


def normalize_url(project_url: str) -> str:
    normalized = project_url.strip()
    if normalized.endswith(".git"):
        normalized = normalized[:-4]
    return normalized.rstrip("/")


def repo_slug(project_url: str) -> str:
    normalized = normalize_url(project_url)
    parsed = urlparse(normalized)
    path = parsed.path.strip("/")
    if not path:
        path = normalized.replace("://", "/")
    slug = re.sub(r"[^A-Za-z0-9._/-]+", "-", path).strip("./-")
    return slug.replace("/", "--") or "unknown-repo"


def project_id_for(project_url: str, commit_id: str) -> str:
    slug = repo_slug(project_url)
    digest = hashlib.sha1(f"{normalize_url(project_url)}|{commit_id}".encode("utf-8")).hexdigest()[:10]
    short_commit = re.sub(r"[^A-Za-z0-9]+", "", commit_id)[:12] or "unknown"
    return f"secvul-{slug}-{short_commit}-{digest}"


def infer_language(filepath: str) -> str:
    suffix = Path(filepath).suffix.lower()
    if suffix in CPP_SUFFIXES:
        return "cpp"
    return "c"


def as_clean_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def as_optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return None
        if numeric.is_integer():
            return int(numeric)
    return None


def load_parquet_rows(dataset_path: Path, limit: int = 0) -> list[dict[str, Any]]:
    try:
        import pyarrow.parquet as pq  # type: ignore
    except ModuleNotFoundError:
        try:
            import pandas as pd  # type: ignore
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "reading SecVulEval parquet requires pyarrow or pandas; no parquet reader is installed"
            ) from exc
        dataframe = pd.read_parquet(dataset_path)
        if limit > 0:
            dataframe = dataframe.head(limit)
        return json.loads(dataframe.to_json(orient="records"))

    table = pq.read_table(dataset_path)
    rows = table.to_pylist()
    if limit > 0:
        return rows[:limit]
    return rows


def load_build_recipes(path: Path | None) -> dict[str, BuildRecipe]:
    if path is None or not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and isinstance(payload.get("recipes"), list):
        entries = payload["recipes"]
    elif isinstance(payload, list):
        entries = payload
    else:
        raise ValueError("recipe file must be a list or an object with a recipes list")

    recipes: dict[str, BuildRecipe] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        project_url = normalize_url(str(entry.get("project_url", "")).strip())
        if not project_url:
            match = entry.get("match")
            if isinstance(match, dict):
                project_url = normalize_url(str(match.get("project_url", "")).strip())
        if not project_url:
            continue
        recipes[project_url] = BuildRecipe(
            project_url=project_url,
            language=str(entry.get("language", "")).strip() or None,
            framework=str(entry.get("framework", "generic")).strip() or "generic",
            default_branch=str(entry.get("default_branch", "detached")).strip() or "detached",
            build_cwd=str(entry.get("build_cwd", "")).strip(),
            config_cmd=str(entry.get("config_cmd", "")).strip(),
            build_cmd=str(entry.get("build_cmd", "")).strip(),
            bitcode_globs=[
                str(item).strip()
                for item in (entry.get("bitcode_globs") or [])
                if str(item).strip()
            ],
            build_env={
                str(key): str(value)
                for key, value in (entry.get("build_env") or {}).items()
            },
            analysis_timeout=int(entry.get("analysis_timeout") or 1800),
            analyzer_jobs=int(entry.get("analyzer_jobs") or 2),
        )
    return recipes


def target_record_from_row(row: dict[str, Any], checkout_root: Path) -> TargetRecord:
    project = str(row.get("project", "")).strip()
    project_url = normalize_url(str(row.get("project_url", "")).strip())
    filepath = str(row.get("filepath", "")).strip().lstrip("./")
    commit_id = str(row.get("commit_id", "")).strip()
    func_name = str(row.get("func_name", "")).strip()
    if not project_url or not filepath or not commit_id or not func_name:
        raise ValueError("dataset row is missing one of project_url/filepath/commit_id/func_name")

    project_id = project_id_for(project_url, commit_id)
    checkout_path = checkout_root / project_id
    return TargetRecord(
        idx=int(row.get("idx")),
        project=project,
        project_url=project_url,
        filepath=filepath,
        commit_id=commit_id,
        func_name=func_name,
        is_vulnerable=bool(row.get("is_vulnerable")),
        cve_list=as_clean_list(row.get("cve_list")),
        cwe_list=as_clean_list(row.get("cwe_list")),
        fixed_func_idx=as_optional_int(row.get("fixed_func_idx", row.get("fixed_func_id"))),
        changed_lines=row.get("changed_lines"),
        changed_statements=row.get("changed_statements"),
        project_id=project_id,
        checkout_path=str(checkout_path),
        inferred_language=infer_language(filepath),
    )


def stage_a_record_for_group(group: ProjectGroup, recipe: BuildRecipe) -> dict[str, Any]:
    extensions: dict[str, Any] = {
        "build_cmd": recipe.build_cmd,
        "bitcode_globs": recipe.bitcode_globs,
        "source_globs": sorted(group.source_files),
        "entry_functions": sorted(group.entry_functions),
        "analysis_timeout": recipe.analysis_timeout,
        "analyzer_jobs": recipe.analyzer_jobs,
    }
    if recipe.build_cwd:
        extensions["build_cwd"] = recipe.build_cwd
    if recipe.config_cmd:
        extensions["config_cmd"] = recipe.config_cmd
    if recipe.build_env:
        extensions["build_env"] = recipe.build_env

    return {
        "project_id": group.project_id,
        "repo_path": group.checkout_path,
        "language": recipe.language or group.inferred_language,
        "framework": recipe.framework,
        "default_branch": recipe.default_branch,
        "extensions": extensions,
    }


def recipe_template_for_group(group: ProjectGroup) -> dict[str, Any]:
    return {
        "project": group.project,
        "project_url": group.project_url,
        "language": group.inferred_language,
        "framework": "generic",
        "default_branch": "detached",
        "build_cwd": "",
        "config_cmd": "",
        "build_cmd": "",
        "bitcode_globs": [],
        "build_env": {},
        "analysis_timeout": 1800,
        "analyzer_jobs": 2,
        "notes": "fill build_cmd and bitcode_globs before using this project in Stage A",
    }


def recipe_template_for_aggregate(aggregate: RecipeAggregate) -> dict[str, Any]:
    return {
        "project": aggregate.project,
        "project_url": aggregate.project_url,
        "language": aggregate.inferred_language,
        "framework": "generic",
        "default_branch": "detached",
        "build_cwd": "",
        "config_cmd": "",
        "build_cmd": "",
        "bitcode_globs": [],
        "build_env": {},
        "analysis_timeout": 1800,
        "analyzer_jobs": 2,
        "notes": "fill build_cmd and bitcode_globs before using this project in Stage A",
        "coverage": {
            "commit_count": len(aggregate.commit_ids),
            "target_count": aggregate.target_count,
            "vulnerable_target_count": aggregate.vulnerable_target_count,
            "non_vulnerable_target_count": aggregate.non_vulnerable_target_count,
            "project_ids": sorted(aggregate.project_ids),
            "sample_source_files": sorted(aggregate.source_files)[:20],
            "sample_entry_functions": sorted(aggregate.entry_functions)[:20],
        },
    }


def main() -> None:
    args = parse_args()
    dataset_path = Path(args.dataset).resolve()
    out_dir = Path(args.out_dir).resolve()
    checkout_root = Path(args.checkout_root).resolve()
    recipes_path = Path(args.recipes).resolve() if args.recipes else None

    if not dataset_path.exists():
        print(f"dataset file not found: {dataset_path}", file=sys.stderr)
        raise SystemExit(1)

    try:
        rows = load_parquet_rows(dataset_path, limit=args.limit)
    except Exception as exc:
        print(f"failed to read parquet dataset: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    groups: dict[tuple[str, str], ProjectGroup] = {}
    targets: list[TargetRecord] = []
    skipped_rows: list[dict[str, Any]] = []

    for row in rows:
        try:
            target = target_record_from_row(row, checkout_root)
        except Exception as exc:
            skipped_rows.append(
                {
                    "idx": row.get("idx"),
                    "reason": str(exc),
                }
            )
            continue
        targets.append(target)
        key = (target.project_url, target.commit_id)
        group = groups.get(key)
        if group is None:
            group = ProjectGroup(
                project_id=target.project_id,
                project=target.project,
                project_url=target.project_url,
                commit_id=target.commit_id,
                checkout_path=target.checkout_path,
                inferred_language=target.inferred_language,
            )
            groups[key] = group
        group.add_target(target)

    recipes = load_build_recipes(recipes_path)
    runnable_records: list[dict[str, Any]] = []
    plan_records: list[dict[str, Any]] = []
    missing_recipe_templates: list[dict[str, Any]] = []
    missing_recipe_aggregates: dict[str, RecipeAggregate] = {}

    for group in sorted(groups.values(), key=lambda item: item.project_id):
        recipe = recipes.get(group.project_url)
        recipe_status = "missing"
        missing_fields: list[str] = []
        if recipe is not None:
            recipe_status = "ready" if recipe.is_complete() else "incomplete"
            if not recipe.build_cmd.strip():
                missing_fields.append("build_cmd")
            if not recipe.bitcode_globs:
                missing_fields.append("bitcode_globs")
        else:
            missing_fields = ["build_cmd", "bitcode_globs"]

        if recipe is None or not recipe.is_complete():
            aggregate = missing_recipe_aggregates.get(group.project_url)
            if aggregate is None:
                aggregate = RecipeAggregate(
                    project=group.project,
                    project_url=group.project_url,
                    inferred_language=group.inferred_language,
                )
                missing_recipe_aggregates[group.project_url] = aggregate
            aggregate.add_group(group)

        if recipe is not None and recipe.is_complete():
            runnable_records.append(stage_a_record_for_group(group, recipe))

        plan_records.append(
            {
                "project_id": group.project_id,
                "project": group.project,
                "project_url": group.project_url,
                "commit_id": group.commit_id,
                "checkout_path": group.checkout_path,
                "inferred_language": group.inferred_language,
                "target_count": group.target_count,
                "vulnerable_target_count": group.vulnerable_target_count,
                "non_vulnerable_target_count": group.non_vulnerable_target_count,
                "source_globs": sorted(group.source_files),
                "entry_functions": sorted(group.entry_functions),
                "target_indexes": group.target_indexes,
                "recipe_status": recipe_status,
                "missing_fields": missing_fields,
            }
        )

    missing_recipe_templates = [
        recipe_template_for_aggregate(aggregate)
        for aggregate in sorted(
            missing_recipe_aggregates.values(),
            key=lambda item: (-item.target_count, item.project_url),
        )
    ]

    targets_path = out_dir / "targets.jsonl"
    plan_path = out_dir / "projects.plan.jsonl"
    runnable_path = out_dir / "stagea.projects.in.jsonl"
    template_path = out_dir / "build_recipes.template.json"
    summary_path = out_dir / "prepare.summary.json"

    write_jsonl(
        targets_path,
        [
            {
                "idx": target.idx,
                "project": target.project,
                "project_url": target.project_url,
                "project_id": target.project_id,
                "commit_id": target.commit_id,
                "checkout_path": target.checkout_path,
                "filepath": target.filepath,
                "func_name": target.func_name,
                "is_vulnerable": target.is_vulnerable,
                "cve_list": target.cve_list,
                "cwe_list": target.cwe_list,
                "fixed_func_idx": target.fixed_func_idx,
                "changed_lines": target.changed_lines,
                "changed_statements": target.changed_statements,
                "inferred_language": target.inferred_language,
            }
            for target in targets
        ],
    )
    write_jsonl(plan_path, plan_records)
    write_jsonl(runnable_path, runnable_records)
    write_json(template_path, {"generated_at": utc_now(), "recipes": missing_recipe_templates})
    write_json(
        summary_path,
        {
            "generated_at": utc_now(),
            "dataset": str(dataset_path),
            "recipes": str(recipes_path) if recipes_path else "",
            "checkout_root": str(checkout_root),
            "target_count": len(targets),
            "skipped_row_count": len(skipped_rows),
            "project_group_count": len(groups),
            "runnable_project_count": len(runnable_records),
            "missing_or_incomplete_project_count": len(plan_records) - len(runnable_records),
            "outputs": {
                "targets": str(targets_path),
                "project_plan": str(plan_path),
                "stagea_projects": str(runnable_path),
                "build_recipe_template": str(template_path),
            },
            "skipped_rows": skipped_rows[:100],
        },
    )

    print(
        f"prepared {len(targets)} targets across {len(groups)} repo@commit groups; "
        f"{len(runnable_records)} groups are runnable with current recipes",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
