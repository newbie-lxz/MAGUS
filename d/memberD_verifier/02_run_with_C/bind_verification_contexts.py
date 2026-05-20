#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


EXECUTION_ALIASES = {
    "repo_path": "repo_path",
    "repository_path": "repo_path",
    "source_root": "repo_path",
    "project_root": "repo_path",
    "config_cmd": "config_cmd",
    "configure_cmd": "config_cmd",
    "build_cmd": "build_cmd",
    "compile_cmd": "build_cmd",
    "run_cmd": "run_cmd",
    "harness_cmd": "run_cmd",
    "trigger_cmd": "run_cmd",
    "poc_cmd": "poc_cmd",
    "test_cmd": "test_cmd",
    "docker_image": "docker_image",
    "timeout_sec": "timeout_sec",
    "timeout": "timeout_sec",
}

PAYLOAD_KEYS = {"input_source", "seed_inputs"}


def read_json_or_jsonl(path: Path) -> Any:
    text = path.read_text(encoding="utf-8-sig").strip()
    if not text:
        return []
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        rows = []
        for line_no, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
        return rows


def read_rows(path: Path) -> List[Dict[str, Any]]:
    data = read_json_or_jsonl(path)
    if isinstance(data, dict):
        if "targets" in data:
            raise ValueError(f"{path}: expected context/hypothesis rows, got targets.json")
        return [data]
    if isinstance(data, list) and all(isinstance(item, dict) for item in data):
        return data
    raise ValueError(f"{path}: expected a JSON object, JSON array of objects, or JSONL objects")


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
        for row_no, row in enumerate(read_rows(file_path), 1):
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


def load_targets(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("targets"), list):
        raise ValueError(f"{path}: expected {{\"targets\": [...]}}")
    return data


def hypotheses_by_id(rows: Iterable[Dict[str, Any]]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    result = {}
    for row in rows:
        project_id = str(row.get("project_id", "")).strip()
        hypothesis_id = str(row.get("hypothesis_id", "")).strip()
        if project_id and hypothesis_id:
            result[(project_id, hypothesis_id)] = row
    return result


def canonical_context(row: Dict[str, Any], label: str) -> Dict[str, Any]:
    execution = {}
    oracle = None
    payload = {}

    sources = [row]
    for key in ("verification_context", "execution"):
        nested = row.get(key)
        if nested is not None:
            if not isinstance(nested, dict):
                raise ValueError(f"{label}: {key} must be an object")
            sources.append(nested)

    for source in sources:
        for key, value in source.items():
            if value in (None, "", []):
                continue
            execution_key = EXECUTION_ALIASES.get(key)
            if execution_key:
                execution[execution_key] = value
            elif key == "oracle":
                if not isinstance(value, dict):
                    raise ValueError(f"{label}: oracle must be an object")
                oracle = value
            elif key in PAYLOAD_KEYS:
                if key == "seed_inputs" and not isinstance(value, list):
                    raise ValueError(f"{label}: seed_inputs must be a list")
                payload[key] = value

    if not execution and oracle is None and not payload:
        raise ValueError(f"{label}: missing execution/oracle/payload context fields")
    return {"execution": execution, "oracle": oracle, "payload": payload}


def load_context_index(path: Path) -> Dict[str, Dict[Any, Dict[str, Any]]]:
    index: Dict[str, Dict[Any, Dict[str, Any]]] = {"project": {}, "route": {}, "hypothesis": {}}
    for row_no, row in enumerate(read_rows(path), 1):
        label = f"{path}:{row_no}"
        project_id = str(row.get("project_id", "")).strip()
        if not project_id:
            raise ValueError(f"{label}: missing project_id")
        hypothesis_id = str(row.get("hypothesis_id", "")).strip()
        route = str(row.get("route", "")).strip()
        context = canonical_context(row, label)

        if hypothesis_id:
            scope = "hypothesis"
            key: Any = (project_id, hypothesis_id)
        elif route:
            scope = "route"
            key = (project_id, route)
        else:
            scope = "project"
            key = project_id

        if key in index[scope]:
            raise ValueError(f"{label}: duplicate {scope} context for {key}")
        index[scope][key] = context
    if not index["project"] and not index["route"] and not index["hypothesis"]:
        raise ValueError(f"{path}: verification_contexts is empty")
    return index


def render_value(value: Any, values: Dict[str, str]) -> Any:
    if isinstance(value, str):
        rendered = value
        for key, replacement in values.items():
            rendered = rendered.replace("${" + key + "}", replacement)
        return rendered
    if isinstance(value, list):
        return [render_value(item, values) for item in value]
    if isinstance(value, dict):
        return {key: render_value(item, values) for key, item in value.items()}
    return value


def template_values(hypothesis: Dict[str, Any], case: Dict[str, Any]) -> Dict[str, str]:
    values = {}
    for key in (
        "project_id",
        "sample_id",
        "hypothesis_id",
        "claim",
        "route",
        "file",
        "line",
        "evidence_slice",
        "agent_verdict",
    ):
        values[key] = str(hypothesis.get(key, ""))
    values["source_file"] = str(case.get("source_file") or hypothesis.get("file", ""))
    values["entry_symbol"] = str(case.get("entry_symbol") or "")
    values["attack_type"] = str(case.get("attack_type") or "")
    return values


def merged_context(
    project_id: str,
    hypothesis: Dict[str, Any],
    case: Dict[str, Any],
    index: Dict[str, Dict[Any, Dict[str, Any]]],
) -> Dict[str, Any]:
    route = str(hypothesis.get("route", "")).strip()
    hypothesis_id = str(hypothesis.get("hypothesis_id", "")).strip()
    layers = [
        index["project"].get(project_id),
        index["route"].get((project_id, route)),
        index["hypothesis"].get((project_id, hypothesis_id)),
    ]

    merged = {"execution": {}, "oracle": {}, "payload": {}}
    for layer in layers:
        if not layer:
            continue
        merged["execution"].update(layer.get("execution") or {})
        if layer.get("oracle"):
            merged["oracle"].update(layer["oracle"])
        merged["payload"].update(layer.get("payload") or {})

    values = template_values(hypothesis, case)
    return {
        "execution": render_value(merged["execution"], values),
        "oracle": render_value(merged["oracle"], values),
        "payload": render_value(merged["payload"], values),
    }


def bind_contexts(targets: Dict[str, Any], hypotheses: List[Dict[str, Any]], contexts_path: Path) -> int:
    hyp_index = hypotheses_by_id(hypotheses)
    context_index = load_context_index(contexts_path)
    bound = 0
    matched = {"project": set(), "route": set(), "hypothesis": set()}

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

            context = merged_context(project_id, hypothesis, case, context_index)
            if context["execution"]:
                case.setdefault("execution", {}).update(context["execution"])
            if context["oracle"]:
                case.setdefault("oracle", {}).update(context["oracle"])
            if context["payload"]:
                case.setdefault("payload", {}).update(context["payload"])
            if context["execution"] or context["oracle"] or context["payload"]:
                bound += 1

    unused_project = sorted(set(context_index["project"]) - matched["project"])
    unused_route = sorted(set(context_index["route"]) - matched["route"])
    unused_hypothesis = sorted(set(context_index["hypothesis"]) - matched["hypothesis"])
    if unused_project or unused_route or unused_hypothesis:
        issues = []
        if unused_project:
            issues.append(f"unmatched project_id contexts: {unused_project}")
        if unused_route:
            issues.append(f"unmatched route contexts: {unused_route}")
        if unused_hypothesis:
            issues.append(f"unmatched hypothesis_id contexts: {unused_hypothesis}")
        raise ValueError("; ".join(issues))

    return bound


def main() -> int:
    parser = argparse.ArgumentParser(description="Bind source/API execution contexts into generated D targets")
    parser.add_argument("--hypotheses", required=True, type=Path, help="C output directory or hypotheses JSONL file")
    parser.add_argument("--targets", required=True, type=Path, help="D generated targets.auto.json")
    parser.add_argument("--contexts", required=True, type=Path, help="verification_contexts JSON/JSONL")
    parser.add_argument("--out", required=True, type=Path, help="bound targets output")
    args = parser.parse_args()

    hypotheses = read_hypotheses(args.hypotheses)
    targets = load_targets(args.targets)
    bound = bind_contexts(targets, hypotheses, args.contexts)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(targets, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"bound contexts: {bound}")
    print(f"output: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
