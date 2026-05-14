#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SOURCE_CACHE: dict[Path, list[str]] = {}
FUNCTION_BLOCK_CACHE: dict[Path, list["FunctionBlock"]] = {}
SYMBOL_DEMANGLE_CACHE: dict[str, str] = {}
CPPFILT_PATH: str | None = None
CPPFILT_LOOKED_UP = False


@dataclass(frozen=True)
class FunctionBlock:
    name: str
    simple_name: str
    line_start: int
    body_start: int
    line_end: int
    signature: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export optional Stage A LLM evidence records")
    parser.add_argument("--input", required=True, help="path to samples.raw.jsonl")
    parser.add_argument("--projects", required=True, help="project input JSONL used to produce the samples")
    parser.add_argument("--output", default="", help="path to samples.llm.jsonl; defaults beside --input")
    return parser.parse_args()


def derived_llm_output_path(raw_samples_path: Path) -> Path:
    name = raw_samples_path.name
    if not name.endswith(".raw.jsonl"):
        raise ValueError("Stage A sample path must end with .raw.jsonl")
    return raw_samples_path.with_name(f"{name[:-10]}.llm.jsonl")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False))
            handle.write("\n")


def read_project_roots(path: Path) -> dict[str, Path]:
    roots: dict[str, Path] = {}
    base_dir = path.parent.resolve()
    for record in read_jsonl(path):
        project_id = str(record.get("project_id", "")).strip()
        repo_path = str(record.get("repo_path", "")).strip()
        if not project_id or not repo_path:
            continue
        root = Path(repo_path)
        roots[project_id] = root if root.is_absolute() else (base_dir / root).resolve()
    return roots


def resolve_source_path(repo_path: Path, file_path: str) -> Path | None:
    if not file_path:
        return None
    path = Path(file_path)
    source_path = path if path.is_absolute() else (repo_path / path)
    source_path = source_path.resolve()
    if not source_path.exists() or not source_path.is_file():
        return None
    return source_path


def read_source_lines(repo_path: Path, file_path: str) -> list[str]:
    source_path = resolve_source_path(repo_path, file_path)
    if source_path is None:
        return []
    if source_path not in SOURCE_CACHE:
        SOURCE_CACHE[source_path] = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
    return SOURCE_CACHE[source_path]


def read_source_window(
    repo_path: Path,
    file_path: str,
    line_no: int,
    context_before: int = 2,
    context_after: int = 2,
) -> dict[str, Any] | None:
    if line_no <= 0:
        return None
    lines = read_source_lines(repo_path, file_path)
    if not lines:
        return None
    start_line = max(1, line_no - context_before)
    end_line = min(len(lines), line_no + context_after)
    snippet = "\n".join(lines[start_line - 1 : end_line]).strip()
    if not snippet:
        return None
    return {
        "file": file_path,
        "line_start": start_line,
        "line_end": end_line,
        "anchor_line": line_no,
        "text": snippet,
    }


CONTROL_KEYWORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
    "case",
    "do",
    "else",
}
FUNCTION_SIGNATURE_RE = re.compile(
    r"([A-Za-z_~][A-Za-z0-9_:~]*)\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:[A-Za-z_][A-Za-z0-9_:<>]*\s*)*\{$"
)
CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_:]*)\s*\(")


def strip_line_comment(line: str) -> str:
    return line.split("//", 1)[0]


def brace_delta(line: str) -> int:
    code = strip_line_comment(line)
    return code.count("{") - code.count("}")


def compact_signature(lines: list[str]) -> str:
    return " ".join(line.strip() for line in lines if line.strip())


def function_name_from_signature(signature: str) -> str:
    matches = list(FUNCTION_SIGNATURE_RE.finditer(signature.strip()))
    if not matches:
        return ""
    name = matches[-1].group(1)
    simple_name = name.rsplit("::", 1)[-1]
    if simple_name in CONTROL_KEYWORDS:
        return ""
    return simple_name


def parse_function_blocks(repo_path: Path, file_path: str) -> list[FunctionBlock]:
    source_path = resolve_source_path(repo_path, file_path)
    if source_path is None:
        return []
    if source_path in FUNCTION_BLOCK_CACHE:
        return FUNCTION_BLOCK_CACHE[source_path]

    lines = read_source_lines(repo_path, file_path)
    blocks: list[FunctionBlock] = []
    signature_lines: list[str] = []
    signature_start = 0
    active: dict[str, Any] | None = None
    depth = 0
    in_block_comment = False

    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if active is not None:
            depth += brace_delta(line)
            if depth <= 0:
                blocks.append(
                    FunctionBlock(
                        name=active["name"],
                        simple_name=active["simple_name"],
                        line_start=active["line_start"],
                        body_start=active["body_start"],
                        line_end=index,
                        signature=active["signature"],
                    )
                )
                active = None
                depth = 0
            continue

        if in_block_comment:
            if "*/" in stripped:
                in_block_comment = False
            continue
        if stripped.startswith("/*"):
            if "*/" not in stripped:
                in_block_comment = True
            continue
        if stripped.startswith("*"):
            continue
        if not stripped or stripped.startswith("#"):
            signature_lines = []
            signature_start = 0
            continue
        if not signature_lines:
            signature_start = index
        signature_lines.append(stripped)
        signature = compact_signature(signature_lines)

        if "{" not in stripped:
            if stripped.endswith(";"):
                signature_lines = []
                signature_start = 0
            continue
        if stripped.endswith(";"):
            signature_lines = []
            signature_start = 0
            continue

        simple_name = function_name_from_signature(signature)
        if simple_name:
            active = {
                "name": simple_name,
                "simple_name": simple_name,
                "line_start": signature_start,
                "body_start": index,
                "signature": signature[:-1].strip(),
            }
            depth = brace_delta(line)
            if depth <= 0:
                blocks.append(
                    FunctionBlock(
                        name=simple_name,
                        simple_name=simple_name,
                        line_start=signature_start,
                        body_start=index,
                        line_end=index,
                        signature=signature[:-1].strip(),
                    )
                )
                active = None
                depth = 0
        signature_lines = []
        signature_start = 0

    FUNCTION_BLOCK_CACHE[source_path] = blocks
    return blocks


def find_enclosing_function(repo_path: Path, file_path: str, line_no: int) -> FunctionBlock | None:
    if line_no <= 0:
        return None
    candidates = [
        block
        for block in parse_function_blocks(repo_path, file_path)
        if block.line_start <= line_no <= block.line_end
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda block: block.line_end - block.line_start)


def find_function_block_by_name(repo_path: Path, file_path: str, function_name: str) -> FunctionBlock | None:
    simple_name = sanitize_callee_name(function_name)
    if not simple_name:
        return None
    for block in parse_function_blocks(repo_path, file_path):
        if sanitize_callee_name(block.simple_name) == simple_name:
            return block
    return None


def cxxfilt_path() -> str | None:
    global CPPFILT_LOOKED_UP, CPPFILT_PATH
    if not CPPFILT_LOOKED_UP:
        CPPFILT_PATH = shutil.which("c++filt")
        CPPFILT_LOOKED_UP = True
    return CPPFILT_PATH


def strip_llvm_symbol_suffix(symbol: str) -> str:
    if not symbol.startswith(("_Z", "__Z")):
        return symbol
    for marker in (".llvm.", ".cold", ".part.", ".isra.", ".constprop."):
        index = symbol.find(marker)
        if index > 0:
            return symbol[:index]
    return symbol


def parse_itanium_symbol_components(symbol: str) -> list[str]:
    text = strip_llvm_symbol_suffix(symbol)
    if text.startswith("__Z"):
        text = text[1:]
    if not text.startswith("_Z"):
        return []

    components: list[str] = []
    index = 2
    if index < len(text) and text[index] == "N":
        index += 1
        while index < len(text) and text[index] in "KVO":
            index += 1

    while index < len(text) and text[index].isdigit():
        length_start = index
        while index < len(text) and text[index].isdigit():
            index += 1
        try:
            length = int(text[length_start:index])
        except ValueError:
            break
        if length <= 0 or index + length > len(text):
            break
        components.append(text[index : index + length])
        index += length
        if index < len(text) and text[index] == "E":
            break

    return components


def demangle_cpp_symbol(symbol: str) -> str:
    text = strip_llvm_symbol_suffix(symbol.strip())
    if text in SYMBOL_DEMANGLE_CACHE:
        return SYMBOL_DEMANGLE_CACHE[text]
    demangled = text
    if text.startswith(("_Z", "__Z")):
        filt = cxxfilt_path()
        if filt is not None:
            try:
                result = subprocess.run(
                    [filt, "-n", text],
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                candidate = result.stdout.strip()
                if result.returncode == 0 and candidate and candidate != text:
                    demangled = candidate
            except (OSError, subprocess.TimeoutExpired):
                pass
        if demangled == text:
            components = parse_itanium_symbol_components(text)
            if components:
                demangled = components[-1]
    SYMBOL_DEMANGLE_CACHE[text] = demangled
    return demangled


def strip_trailing_parameter_list(name: str) -> str:
    text = name.strip()
    while True:
        original = text
        for qualifier in (" const", " volatile", " noexcept", " &", " &&"):
            if text.endswith(qualifier):
                text = text[: -len(qualifier)].rstrip()
        if text == original:
            break
    if not text.endswith(")"):
        return text

    depth = 0
    angle_depth = 0
    for index in range(len(text) - 1, -1, -1):
        char = text[index]
        if char == ">":
            angle_depth += 1
            continue
        if char == "<" and angle_depth > 0:
            angle_depth -= 1
            continue
        if angle_depth:
            continue
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                return text[:index].strip()
    return text


def sanitize_callee_name(name: str) -> str:
    text = str(name).strip().strip("\"'")
    if not text:
        return ""
    text = text.lstrip("&*")
    if text.startswith("@"):
        text = text[1:]
    text = demangle_cpp_symbol(text)
    text = strip_trailing_parameter_list(text)
    text = text.rsplit("::", 1)[-1]
    if " " in text and not text.startswith("operator "):
        text = text.split()[-1]
    return text.lstrip("&*")


def collect_calls_in_lines(lines: list[str], function_name: str = "", max_calls: int = 12) -> list[str]:
    calls: list[str] = []
    seen: set[str] = set()
    self_name = function_name.rsplit("::", 1)[-1]
    for line in lines:
        code = strip_line_comment(line)
        for match in CALL_RE.finditer(code):
            name = match.group(1).rsplit("::", 1)[-1]
            if name in CONTROL_KEYWORDS or name == self_name or name in seen:
                continue
            seen.add(name)
            calls.append(name)
            if len(calls) >= max_calls:
                return calls
    return calls


def collect_check_lines(lines: list[str], line_offset: int, max_checks: int = 6) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    for index, line in enumerate(lines, start=line_offset):
        stripped = line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        if (
            lowered.startswith("if ")
            or lowered.startswith("if(")
            or lowered.startswith("switch ")
            or lowered.startswith("switch(")
            or lowered.startswith("return ")
            or "assert(" in lowered
        ):
            checks.append({"line": index, "text": stripped})
            if len(checks) >= max_checks:
                break
    return checks


def function_body_excerpt(
    repo_path: Path,
    file_path: str,
    block: FunctionBlock,
    anchor_line: int,
    max_lines: int = 40,
) -> dict[str, Any] | None:
    lines = read_source_lines(repo_path, file_path)
    if not lines:
        return None
    clamped_anchor = min(max(anchor_line, block.line_start), block.line_end)
    function_line_count = block.line_end - block.line_start + 1
    start_line = block.line_start
    end_line = min(block.line_end, start_line + max_lines - 1)
    if clamped_anchor > end_line and function_line_count > max_lines:
        half_window = max_lines // 2
        start_line = max(block.line_start, clamped_anchor - half_window)
        end_line = min(block.line_end, start_line + max_lines - 1)
    text = "\n".join(lines[start_line - 1 : end_line]).strip()
    if not text:
        return None
    return {
        "line_start": start_line,
        "line_end": end_line,
        "anchor_line": clamped_anchor,
        "truncated": block.line_end > end_line,
        "text": text,
    }


def unique_text(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        text = item.strip()
        if not text or text in seen:
            continue
        seen.add(text)
        ordered.append(text)
    return ordered


def sample_node_index(sample: dict[str, Any]) -> dict[str, dict[str, Any]]:
    nodes = sample.get("graph", {}).get("nodes") or []
    return {
        str(node.get("id", "")).strip(): node
        for node in nodes
        if str(node.get("id", "")).strip()
    }


def sample_seed_id(sample: dict[str, Any]) -> str:
    seed = sample.get("seed") or {}
    return str(seed.get("id") or seed.get("address") or "").strip()


def sample_direct_edges(sample: dict[str, Any]) -> list[dict[str, Any]]:
    graph = sample.get("graph", {}) or {}
    direct_edges = graph.get("direct_edges")
    if isinstance(direct_edges, list):
        return direct_edges
    return []


def sample_node_sort_key(node: dict[str, Any]) -> tuple[Any, ...]:
    return (
        str(node.get("file", "")),
        int(node.get("line", 0) or 0),
        str(node.get("id", "")),
    )


def sample_evidence_slice(node_ids: list[str], node_index: dict[str, dict[str, Any]]) -> str:
    return "\n".join(
        unique_text(
            [
                str(node_index[node_id].get("source_slice", "")).strip()
                for node_id in node_ids
                if node_id in node_index and str(node_index[node_id].get("source_slice", "")).strip()
            ]
        )
    )


def representative_traces_for_sample(
    sample: dict[str, Any],
    node_index: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    traces: list[dict[str, Any]] = []
    for flow in (sample.get("source_sink_flows") or [])[:3]:
        node_ids = [
            str(node_id).strip()
            for node_id in (flow.get("trace_node_ids") or [])
            if str(node_id).strip() in node_index
        ]
        if not node_ids:
            continue
        traces.append(
            {
                "status": str(flow.get("status", "")).strip(),
                "flow_kind": str(flow.get("flow_kind", "")).strip(),
                "source_id": str(flow.get("source_id", "")).strip(),
                "sink_id": str(flow.get("sink_id", "")).strip(),
                "node_ids": node_ids,
                "tokens": [
                    str(node_index[node_id].get("token", "")).strip()
                    for node_id in node_ids
                    if str(node_index[node_id].get("token", "")).strip()
                ],
                "evidence_slice": sample_evidence_slice(node_ids, node_index),
            }
        )
    return traces


def graph_excerpt_for_sample(
    sample: dict[str, Any],
    node_index: dict[str, dict[str, Any]],
    traces: list[dict[str, Any]],
    max_nodes: int = 12,
    max_edges: int = 20,
) -> dict[str, Any]:
    ordered_node_ids: list[str] = []
    seen_node_ids: set[str] = set()

    def append_node_id(node_id: str) -> None:
        if node_id in node_index and node_id not in seen_node_ids and len(ordered_node_ids) < max_nodes:
            seen_node_ids.add(node_id)
            ordered_node_ids.append(node_id)

    seed_id = sample_seed_id(sample)
    if seed_id:
        append_node_id(seed_id)

    focus = sample.get("focus") or {}
    focus_file = str(focus.get("file", "")).strip()
    focus_line = int(focus.get("line", 0) or 0)
    for node_id, node in sorted(node_index.items(), key=lambda item: sample_node_sort_key(item[1])):
        if str(node.get("file", "")).strip() == focus_file and int(node.get("line", 0) or 0) == focus_line:
            append_node_id(node_id)

    for trace in traces:
        for node_id in trace.get("node_ids") or []:
            append_node_id(str(node_id).strip())

    edges = sample_direct_edges(sample)
    incident: dict[str, list[str]] = {}
    for edge in edges:
        source_id = str(edge.get("from", "")).strip()
        target_id = str(edge.get("to", "")).strip()
        if not source_id or not target_id:
            continue
        incident.setdefault(source_id, []).append(target_id)
        incident.setdefault(target_id, []).append(source_id)

    for node_id in list(ordered_node_ids):
        for neighbor_id in sorted(
            incident.get(node_id, []),
            key=lambda candidate: sample_node_sort_key(node_index.get(candidate, {})),
        ):
            append_node_id(neighbor_id)
            if len(ordered_node_ids) >= max_nodes:
                break
        if len(ordered_node_ids) >= max_nodes:
            break

    excerpt_node_ids = set(ordered_node_ids)
    excerpt_edges: list[dict[str, Any]] = []
    for edge in edges:
        source_id = str(edge.get("from", "")).strip()
        target_id = str(edge.get("to", "")).strip()
        if source_id in excerpt_node_ids and target_id in excerpt_node_ids:
            excerpt_edges.append(
                {
                    "from": source_id,
                    "to": target_id,
                    "from_token": str(edge.get("from_token", "")).strip(),
                    "to_token": str(edge.get("to_token", "")).strip(),
                }
            )
        if len(excerpt_edges) >= max_edges:
            break

    return {
        "nodes": [
            {
                "id": node_id,
                "name": str(node_index[node_id].get("name", "")).strip(),
                "token": str(node_index[node_id].get("token", "")).strip(),
                "file": str(node_index[node_id].get("file", "")).strip(),
                "line": int(node_index[node_id].get("line", 0) or 0),
                "is_seed": bool(node_index[node_id].get("is_seed")),
                "is_check": bool(node_index[node_id].get("is_check")),
            }
            for node_id in ordered_node_ids
        ],
        "edges": excerpt_edges,
    }


def code_slices_for_sample(
    sample: dict[str, Any],
    node_index: dict[str, dict[str, Any]],
    traces: list[dict[str, Any]],
    repo_root: Path,
    max_slices: int = 8,
) -> list[dict[str, Any]]:
    ordered_specs: list[tuple[str | None, str, int]] = []
    roles_by_spec: dict[tuple[str | None, str, int], list[str]] = {}

    def add_spec(role: str, node_id: str | None, file_name: str, line_no: int) -> None:
        if not file_name or line_no <= 0:
            return
        key = (node_id, file_name, line_no)
        if key not in roles_by_spec:
            roles_by_spec[key] = []
            ordered_specs.append(key)
        if role not in roles_by_spec[key]:
            roles_by_spec[key].append(role)

    seed_id = sample_seed_id(sample)
    if seed_id in node_index:
        seed_node = node_index[seed_id]
        add_spec("seed", seed_id, str(seed_node.get("file", "")).strip(), int(seed_node.get("line", 0) or 0))

    focus = sample.get("focus") or {}
    focus_file = str(focus.get("file", "")).strip()
    focus_line = int(focus.get("line", 0) or 0)
    focus_node_ids = [
        node_id
        for node_id, node in sorted(node_index.items(), key=lambda item: sample_node_sort_key(item[1]))
        if str(node.get("file", "")).strip() == focus_file and int(node.get("line", 0) or 0) == focus_line
    ]
    if focus_node_ids:
        for node_id in focus_node_ids[:2]:
            add_spec("focus", node_id, focus_file, focus_line)
    else:
        add_spec("focus", None, focus_file, focus_line)

    for trace in traces:
        source_id = str(trace.get("source_id", "")).strip()
        sink_id = str(trace.get("sink_id", "")).strip()
        if source_id in node_index:
            source_node = node_index[source_id]
            add_spec("source", source_id, str(source_node.get("file", "")).strip(), int(source_node.get("line", 0) or 0))
        if sink_id in node_index:
            sink_node = node_index[sink_id]
            add_spec("sink", sink_id, str(sink_node.get("file", "")).strip(), int(sink_node.get("line", 0) or 0))
        for node_id in trace.get("node_ids") or []:
            node = node_index.get(str(node_id).strip())
            if not node:
                continue
            if str(node.get("name", "")).strip() == "CHECK" or str(node.get("check_kind", "")).strip():
                add_spec("guard", str(node_id).strip(), str(node.get("file", "")).strip(), int(node.get("line", 0) or 0))

    slices: list[dict[str, Any]] = []
    for node_id, file_name, line_no in ordered_specs:
        window = read_source_window(repo_root, file_name, line_no)
        if window is None:
            continue
        entry = {
            "roles": roles_by_spec[(node_id, file_name, line_no)],
            "file": file_name,
            "line_start": window["line_start"],
            "line_end": window["line_end"],
            "anchor_line": window["anchor_line"],
            "text": window["text"],
        }
        if node_id is not None and node_id in node_index:
            node = node_index[node_id]
            entry["node_id"] = node_id
            entry["token"] = str(node.get("token", "")).strip()
            entry["name"] = str(node.get("name", "")).strip()
        slices.append(entry)
        if len(slices) >= max_slices:
            break
    return slices


def internal_function_summaries_for_sample(
    sample: dict[str, Any],
    node_index: dict[str, dict[str, Any]],
    repo_root: Path,
    max_functions: int = 4,
) -> list[dict[str, Any]]:
    entrypoint = sample.get("entrypoint") or {}
    entry_file = str(entrypoint.get("file", "")).strip()
    entry_function = str(entrypoint.get("function", "")).strip()
    entry_function_name = sanitize_callee_name(entry_function)

    summaries: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    ordered_nodes = sorted(node_index.values(), key=sample_node_sort_key)
    for node in ordered_nodes:
        file_name = str(node.get("file", "")).strip()
        line_no = int(node.get("line", 0) or 0)
        if not file_name or line_no <= 0:
            continue
        candidate_blocks: list[tuple[FunctionBlock, int]] = []

        for callee_name in (node.get("resolved_callees") or []):
            block = find_function_block_by_name(repo_root, file_name, str(callee_name))
            if block is not None:
                candidate_blocks.append((block, block.line_start))

        enclosing = find_enclosing_function(repo_root, file_name, line_no)
        if enclosing is not None:
            candidate_blocks.append((enclosing, line_no))

        for function_block, anchor_line in candidate_blocks:
            function_name = sanitize_callee_name(function_block.simple_name)
            if file_name == entry_file and function_name == entry_function_name:
                continue
            key = (file_name, function_block.simple_name, function_block.line_start)
            if key in seen:
                continue

            excerpt = function_body_excerpt(repo_root, file_name, function_block, anchor_line)
            if excerpt is None:
                continue
            block_lines = read_source_lines(repo_root, file_name)[function_block.line_start - 1 : function_block.line_end]
            summaries.append(
                {
                    "function": function_block.simple_name,
                    "file": file_name,
                    "line_start": function_block.line_start,
                    "line_end": function_block.line_end,
                    "signature": function_block.signature,
                    "evidence_node": str(node.get("id", "")).strip(),
                    "evidence_token": str(node.get("token", "")).strip(),
                    "calls": collect_calls_in_lines(block_lines, function_block.simple_name),
                    "checks": collect_check_lines(block_lines, function_block.line_start),
                    "excerpt": excerpt,
                }
            )
            seen.add(key)
            if len(summaries) >= max_functions:
                break
        if len(summaries) >= max_functions:
            break

    return summaries


def llm_record_for_sample(sample: dict[str, Any], project_roots: dict[str, Path]) -> dict[str, Any]:
    project_id = str(sample.get("project_id", "")).strip()
    repo_root = project_roots.get(project_id)
    node_index = sample_node_index(sample)
    traces = representative_traces_for_sample(sample, node_index)
    graph_excerpt = graph_excerpt_for_sample(sample, node_index, traces)
    code_slices = code_slices_for_sample(sample, node_index, traces, repo_root) if repo_root is not None else []
    internal_function_summaries = (
        internal_function_summaries_for_sample(sample, node_index, repo_root)
        if repo_root is not None
        else []
    )
    flow_payload: list[dict[str, Any]] = []
    for flow in (sample.get("source_sink_flows") or [])[:3]:
        source_id = str(flow.get("source_id", "")).strip()
        sink_id = str(flow.get("sink_id", "")).strip()
        flow_payload.append(
            {
                "source_id": source_id,
                "source_token": str(node_index.get(source_id, {}).get("token", "")).strip(),
                "sink_id": sink_id,
                "sink_token": str(node_index.get(sink_id, {}).get("token", "")).strip(),
                "status": str(flow.get("status", "")).strip(),
                "flow_kind": str(flow.get("flow_kind", "")).strip(),
                "trace_node_ids": [
                    str(node_id).strip()
                    for node_id in (flow.get("trace_node_ids") or [])
                    if str(node_id).strip()
                ],
            }
        )

    evidence_slice = sample.get("evidence_slice", "")
    if traces:
        evidence_slice = traces[0].get("evidence_slice", "") or evidence_slice
    elif code_slices:
        evidence_slice = code_slices[0].get("text", "") or evidence_slice

    return {
        "project_id": project_id,
        "sample_id": sample.get("sample_id", ""),
        "entrypoint": sample.get("entrypoint", {}),
        "seed": {
            "id": sample_seed_id(sample),
            "api": str(sample.get("seed", {}).get("api", "")).strip(),
            "token": str(sample.get("seed", {}).get("token", "")).strip(),
            "file": str(sample.get("seed", {}).get("file", "")).strip(),
            "line": int(sample.get("seed", {}).get("line", 0) or 0),
        },
        "focus": sample.get("focus", {}),
        "evidence_slice": evidence_slice,
        "analysis_warnings": sample.get("analysis_warnings", []),
        "source_sink_flows": flow_payload,
        "representative_traces": traces,
        "graph_excerpt": graph_excerpt,
        "code_slices": code_slices,
        "internal_function_summaries": internal_function_summaries,
    }


def main() -> None:
    args = parse_args()
    samples_path = Path(args.input)
    if not samples_path.name.endswith(".raw.jsonl"):
        raise SystemExit("Stage A sample path must end with .raw.jsonl")
    projects_path = Path(args.projects)
    output_path = Path(args.output) if args.output else derived_llm_output_path(samples_path)

    project_roots = read_project_roots(projects_path)
    samples = read_jsonl(samples_path)
    missing_project_ids = sorted(
        {
            str(sample.get("project_id", "")).strip()
            for sample in samples
            if str(sample.get("project_id", "")).strip()
            and str(sample.get("project_id", "")).strip() not in project_roots
        }
    )
    if missing_project_ids:
        raise SystemExit(f"missing repo_path for project_id(s): {', '.join(missing_project_ids)}")

    records = [llm_record_for_sample(sample, project_roots) for sample in samples]
    write_jsonl(output_path, records)
    print(f"wrote {len(records)} LLM evidence records to {output_path}")


if __name__ == "__main__":
    main()
