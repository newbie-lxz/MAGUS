#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SUPPORTED_SUFFIXES = {".c", ".cc", ".cpp", ".cxx"}
DEFAULT_INCLUDE_DIRS = ("juliet-small/testcasesupport",)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate compile_commands.json for the checked-in srcs Juliet sample tree."
    )
    parser.add_argument("--repo-path", default="srcs", help="source tree root")
    parser.add_argument("--output", default="", help="output path; defaults to <repo-path>/compile_commands.json")
    parser.add_argument("--cc", default="clang", help="compiler token recorded for C sources")
    parser.add_argument("--cxx", default="clang++", help="compiler token recorded for C++ sources")
    parser.add_argument(
        "--source-glob",
        action="append",
        default=[],
        help="source glob under repo-path; repeatable; defaults to Juliet testcases C/C++ files",
    )
    parser.add_argument(
        "--include-dir",
        action="append",
        default=[],
        help="include directory under repo-path or absolute path; repeatable",
    )
    parser.add_argument("--force", action="store_true", help="overwrite an existing output file")
    return parser.parse_args()


def resolve_path(raw: str) -> Path:
    return Path(raw).expanduser().resolve()


def resolve_under_repo(repo_path: Path, raw_path: str) -> Path:
    path = Path(raw_path).expanduser()
    return path.resolve() if path.is_absolute() else (repo_path / path).resolve()


def validate_under_repo(repo_path: Path, path: Path, label: str) -> None:
    try:
        path.relative_to(repo_path)
    except ValueError as exc:
        raise ValueError(f"{label} is outside repo_path: {path}") from exc


def source_globs(args: argparse.Namespace) -> list[str]:
    explicit = [item.strip() for item in args.source_glob if item.strip()]
    if explicit:
        return explicit
    return [
        "juliet-small/testcases/**/*.c",
        "juliet-small/testcases/**/*.cc",
        "juliet-small/testcases/**/*.cpp",
        "juliet-small/testcases/**/*.cxx",
    ]


def include_dirs(args: argparse.Namespace, repo_path: Path) -> list[Path]:
    raw_dirs = args.include_dir or list(DEFAULT_INCLUDE_DIRS)
    paths: list[Path] = []
    seen: set[Path] = set()
    for raw_dir in raw_dirs:
        path = resolve_under_repo(repo_path, raw_dir)
        if path in seen:
            continue
        if not path.exists() or not path.is_dir():
            raise ValueError(f"include directory does not exist: {path}")
        seen.add(path)
        paths.append(path)
    return paths


def discover_sources(repo_path: Path, globs: list[str]) -> list[Path]:
    sources: dict[str, Path] = {}
    for pattern in globs:
        for candidate in repo_path.glob(pattern):
            if not candidate.is_file():
                continue
            if candidate.suffix.lower() not in SUPPORTED_SUFFIXES:
                continue
            source_path = candidate.resolve()
            validate_under_repo(repo_path, source_path, "source file")
            sources[source_path.relative_to(repo_path).as_posix()] = source_path
    if not sources:
        raise ValueError(f"no supported C/C++ sources found under {repo_path}")
    return [sources[key] for key in sorted(sources)]


def compiler_for(source_path: Path, cc: str, cxx: str) -> str:
    return cc if source_path.suffix.lower() == ".c" else cxx


def compile_record(repo_path: Path, source_path: Path, include_paths: list[Path], cc: str, cxx: str) -> dict[str, Any]:
    arguments = [compiler_for(source_path, cc, cxx)]
    for include_path in include_paths:
        arguments.extend(["-I", str(include_path)])
    arguments.extend(["-c", str(source_path), "-o", "/tmp/magus-unused.o"])
    return {
        "directory": str(repo_path),
        "file": str(source_path),
        "arguments": arguments,
    }


def write_output(path: Path, records: list[dict[str, Any]], force: bool) -> None:
    if path.exists() and not force:
        raise ValueError(f"output already exists: {path}; pass --force to overwrite")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    repo_path = resolve_path(args.repo_path)
    if not repo_path.exists() or not repo_path.is_dir():
        raise ValueError(f"repo_path must be an existing directory: {repo_path}")

    output_path = resolve_path(args.output) if args.output else repo_path / "compile_commands.json"
    includes = include_dirs(args, repo_path)
    sources = discover_sources(repo_path, source_globs(args))
    records = [
        compile_record(repo_path, source_path, includes, args.cc, args.cxx)
        for source_path in sources
    ]
    write_output(output_path, records, args.force)
    print(f"wrote {len(records)} compile commands to {output_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"compile commands generation failed: {exc}")
        raise SystemExit(1) from exc
