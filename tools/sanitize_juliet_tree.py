#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path
from typing import Any


SCHEMA = "magus.juliet.sanitization.v1"
DEFAULT_INPUT = "srcs"
DEFAULT_OUTPUT = "srcs_sanitized"
DEFAULT_MAP_NAME = "juliet_sanitization_map.json"

TEXT_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".inc",
    ".txt",
    ".md",
    ".xml",
}
SKIPPED_DIRS = {"bc", ".git", "__pycache__"}

LABEL_REPLACEMENTS = (
    ("G2B", "V1"),
    ("B2G", "V2"),
    ("g2b", "v1"),
    ("b2g", "v2"),
    ("BAD", "CASE0"),
    ("Bad", "Case0"),
    ("bad", "case0"),
    ("GOOD", "CASE1"),
    ("Good", "Case1"),
    ("good", "case1"),
)
COMMENT_LABEL_REPLACEMENTS = (
    ("POTENTIAL FLAW", "NOTE"),
    ("Potential Flaw", "Note"),
    ("potential flaw", "note"),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a label-neutralized copy of the Juliet sample tree and a reverse mapping."
    )
    parser.add_argument("--input", default=DEFAULT_INPUT, help="original source root, usually srcs")
    parser.add_argument("--output", default=DEFAULT_OUTPUT, help="sanitized source root")
    parser.add_argument("--map-name", default=DEFAULT_MAP_NAME, help="mapping file name written under --output")
    parser.add_argument("--force", action="store_true", help="replace an existing sanitized output directory")
    return parser.parse_args()


def resolve_path(raw: str) -> Path:
    return Path(raw).expanduser().resolve()


def neutralize_text(text: str) -> str:
    result = text
    for old, new in COMMENT_LABEL_REPLACEMENTS:
        result = result.replace(old, new)
    result = re.sub(r"\bFLAW\b", "NOTE", result)
    result = re.sub(r"\bFlaw\b", "Note", result)
    result = re.sub(r"\bflaw\b", "note", result)
    result = re.sub(r"\bFIX\b", "ALT", result)
    result = re.sub(r"\bFix\b", "Alt", result)
    result = re.sub(r"\bfix\b", "alt", result)
    for old, new in LABEL_REPLACEMENTS:
        result = result.replace(old, new)
    return result


def should_skip(path: Path, source_root: Path) -> bool:
    rel = path.relative_to(source_root)
    if any(part in SKIPPED_DIRS for part in rel.parts):
        return True
    if path.is_file() and path.name.startswith("compile_commands") and path.suffix == ".json":
        return True
    return False


def is_text_file(path: Path) -> bool:
    return path.suffix.lower() in TEXT_SUFFIXES


def sanitized_relative_path(rel: Path) -> Path:
    return Path(*[neutralize_text(part) for part in rel.parts])


def copy_file(source: Path, destination: Path) -> bool:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if is_text_file(source):
        text = source.read_text(encoding="utf-8", errors="surrogateescape")
        destination.write_text(neutralize_text(text), encoding="utf-8", errors="surrogateescape")
        return True
    shutil.copy2(source, destination)
    return False


def build_mapping(
    source_root: Path,
    output_root: Path,
    path_map: dict[str, str],
    text_files_sanitized: int,
) -> dict[str, Any]:
    reverse_path_map = {sanitized: original for original, sanitized in path_map.items()}
    return {
        "schema": SCHEMA,
        "original_root": str(source_root),
        "sanitized_root": str(output_root),
        "map_file": str(output_root / DEFAULT_MAP_NAME),
        "path_map": path_map,
        "reverse_path_map": reverse_path_map,
        "token_map": {
            "bad": "case0",
            "Bad": "Case0",
            "BAD": "CASE0",
            "good": "case1",
            "Good": "Case1",
            "GOOD": "CASE1",
            "G2B": "V1",
            "B2G": "V2",
            "OMITBAD": "OMITCASE0",
            "OMITGOOD": "OMITCASE1",
        },
        "reverse_token_map": {
            "case0": "bad",
            "Case0": "Bad",
            "CASE0": "BAD",
            "case1": "good",
            "Case1": "Good",
            "CASE1": "GOOD",
            "V1": "G2B",
            "V2": "B2G",
            "v1": "g2b",
            "v2": "b2g",
            "OMITCASE0": "OMITBAD",
            "OMITCASE1": "OMITGOOD",
        },
        "stats": {
            "files_total": len(path_map),
            "text_files_sanitized": text_files_sanitized,
            "paths_changed": sum(1 for original, sanitized in path_map.items() if original != sanitized),
        },
    }


def sanitize_tree(source_root: Path, output_root: Path, map_name: str, force: bool) -> dict[str, Any]:
    if not source_root.exists() or not source_root.is_dir():
        raise ValueError(f"input source root does not exist or is not a directory: {source_root}")
    if output_root.exists():
        if not force:
            raise ValueError(f"output already exists: {output_root}; pass --force to replace it")
        shutil.rmtree(output_root)

    path_map: dict[str, str] = {}
    reverse_seen: dict[str, str] = {}
    text_files_sanitized = 0

    for source_path in sorted(source_root.rglob("*")):
        if should_skip(source_path, source_root):
            continue
        if source_path.is_dir():
            continue
        original_rel = source_path.relative_to(source_root)
        sanitized_rel = sanitized_relative_path(original_rel)
        original_key = original_rel.as_posix()
        sanitized_key = sanitized_rel.as_posix()
        previous = reverse_seen.get(sanitized_key)
        if previous and previous != original_key:
            raise ValueError(f"sanitized path collision: {previous} and {original_key} -> {sanitized_key}")
        reverse_seen[sanitized_key] = original_key
        path_map[original_key] = sanitized_key
        if copy_file(source_path, output_root / sanitized_rel):
            text_files_sanitized += 1

    mapping = build_mapping(source_root, output_root, path_map, text_files_sanitized)
    mapping_path = output_root / map_name
    mapping["map_file"] = str(mapping_path)
    mapping_path.write_text(json.dumps(mapping, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return mapping


def main() -> int:
    args = parse_args()
    source_root = resolve_path(args.input)
    output_root = resolve_path(args.output)
    mapping = sanitize_tree(source_root, output_root, args.map_name, args.force)
    stats = mapping["stats"]
    print(f"sanitized Juliet tree: {source_root} -> {output_root}")
    print(f"files: {stats['files_total']} total, {stats['paths_changed']} renamed paths")
    print(f"map: {mapping['map_file']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"juliet sanitization failed: {exc}")
        raise SystemExit(1) from exc
