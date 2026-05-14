#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path


SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".c++", ".C"}
SOURCE_GLOBS_ENV = "STAGE_A_SOURCE_GLOBS_JSON"
DROP_STANDALONE_FLAGS = {
    "-c",
    "-MMD",
    "-MD",
    "-MP",
    "-MM",
    "-E",
    "-S",
}
DROP_WITH_VALUE_FLAGS = {
    "-o",
    "-MF",
    "-MT",
    "-MQ",
    "-MJ",
    "-include",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Replay compile_commands entries into LLVM bitcode files")
    parser.add_argument("--compile-commands", required=True, help="path to compile_commands.json")
    parser.add_argument("--repo-root", required=True, help="repository root used for relative output paths")
    parser.add_argument("--output-dir", required=True, help="output directory for generated .bc files")
    parser.add_argument(
        "--source-glob",
        action="append",
        default=[],
        help="optional glob filter relative to repo root; can be passed multiple times",
    )
    parser.add_argument(
        "--stop-on-error",
        action="store_true",
        help="stop after the first failed compilation instead of collecting all failures",
    )
    return parser.parse_args()


def load_commands(path: Path) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("compile_commands.json must contain a list")
    return payload


def command_arguments(entry: dict) -> list[str]:
    arguments = entry.get("arguments")
    if isinstance(arguments, list) and arguments:
        return [str(item) for item in arguments]
    command = entry.get("command")
    if isinstance(command, str) and command.strip():
        return shlex.split(command)
    raise ValueError("compile_commands entry is missing arguments/command")


def should_keep_source(relative_path: Path, source_globs: list[str]) -> bool:
    if not source_globs:
        return True
    return any(relative_path.match(pattern) for pattern in source_globs)


def sanitize_compile_args(arguments: list[str], source_arg: str, output_arg: str) -> list[str]:
    sanitized: list[str] = []
    index = 0
    while index < len(arguments):
        item = arguments[index]
        if item in DROP_STANDALONE_FLAGS:
            index += 1
            continue
        if item in DROP_WITH_VALUE_FLAGS:
            index += 2
            continue
        if item == source_arg:
            index += 1
            continue
        if any(item.startswith(prefix) for prefix in ("-MF", "-MT", "-MQ", "-MJ")) and item not in DROP_WITH_VALUE_FLAGS:
            index += 1
            continue
        if item.startswith("-o") and item != "-o":
            index += 1
            continue
        if item.endswith(".o") or item == output_arg:
            index += 1
            continue
        sanitized.append(item)
        index += 1
    return sanitized


def main() -> None:
    args = parse_args()
    compile_commands_path = Path(args.compile_commands).resolve()
    repo_root = Path(args.repo_root).resolve()
    output_dir = Path(args.output_dir).resolve()
    source_globs = [pattern.strip() for pattern in args.source_glob if pattern.strip()]
    if not source_globs:
        env_value = os.environ.get(SOURCE_GLOBS_ENV, "").strip()
        if env_value:
            try:
                payload = json.loads(env_value)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{SOURCE_GLOBS_ENV} must be a JSON string list") from exc
            if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
                raise ValueError(f"{SOURCE_GLOBS_ENV} must be a JSON string list")
            source_globs = [pattern.strip() for pattern in payload if pattern.strip()]

    if not compile_commands_path.exists():
        print(f"compile_commands not found: {compile_commands_path}", file=sys.stderr)
        raise SystemExit(1)
    if not repo_root.exists():
        print(f"repo root not found: {repo_root}", file=sys.stderr)
        raise SystemExit(1)

    output_dir.mkdir(parents=True, exist_ok=True)
    commands = load_commands(compile_commands_path)

    built = 0
    skipped = 0
    failures: list[dict[str, str | int]] = []
    seen_outputs: set[Path] = set()

    for entry in commands:
        source_text = str(entry.get("file", "")).strip()
        directory_text = str(entry.get("directory", "")).strip()
        if not source_text or not directory_text:
            skipped += 1
            continue

        directory = Path(directory_text).resolve()
        source_path = Path(source_text)
        if not source_path.is_absolute():
            source_path = (directory / source_path).resolve()
        else:
            source_path = source_path.resolve()
        if source_path.suffix not in SOURCE_SUFFIXES:
            skipped += 1
            continue
        try:
            relative_source = source_path.relative_to(repo_root)
        except ValueError:
            skipped += 1
            continue
        if not should_keep_source(relative_source, source_globs):
            skipped += 1
            continue

        output_path = (output_dir / relative_source).with_suffix(".bc")
        if output_path in seen_outputs:
            continue
        seen_outputs.add(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        raw_arguments = command_arguments(entry)
        compile_args = sanitize_compile_args(
            raw_arguments,
            source_arg=entry.get("file", ""),
            output_arg=str(output_path),
        )
        compile_args.extend(["-emit-llvm", "-c", str(source_path), "-o", str(output_path)])

        result = subprocess.run(
            compile_args,
            cwd=str(directory),
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            failure = {
                "source": relative_source.as_posix(),
                "returncode": result.returncode,
                "stderr_tail": "\n".join(result.stderr.splitlines()[-20:]),
                "stdout_tail": "\n".join(result.stdout.splitlines()[-20:]),
            }
            failures.append(failure)
            if args.stop_on_error:
                break
            continue
        built += 1

    if failures:
        print(
            json.dumps(
                {
                    "built": built,
                    "skipped": skipped,
                    "failure_count": len(failures),
                    "failures": failures[:20],
                },
                ensure_ascii=False,
                indent=2,
            ),
            file=sys.stderr,
        )
        raise SystemExit(1)

    print(
        json.dumps(
            {
                "built": built,
                "skipped": skipped,
                "output_dir": str(output_dir),
            },
            ensure_ascii=False,
        ),
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
