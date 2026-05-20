#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SHIM_DIR = REPO_ROOT / "tools" / "juliet_win_shim"
SRC_ROOT = REPO_ROOT / "srcs" / "juliet-api-misuse"
SUPPORT_DIR = SRC_ROOT / "testcasesupport"
SUPPORT_IO = SUPPORT_DIR / "io.c"
STUBS = SHIM_DIR / "winapi_runtime_stubs.c"
CONFIRM_MARKER = "MAGUS_CWE15_CONFIRMED"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build and run one Juliet CWE15 w32 testcase with Linux stubs")
    parser.add_argument("--source-file", required=True, help="C/C++ source file from the Stage C hypothesis")
    parser.add_argument("--entry-symbol", default="", help="Entry symbol from D target generation; kept for traceability")
    parser.add_argument("--payload", default="magus-cwe15-controlled-host", help="Payload returned by the recv stub")
    parser.add_argument("--cc", default=os.environ.get("MAGUS_CC", "/usr/bin/clang-20"))
    parser.add_argument("--cxx", default=os.environ.get("MAGUS_CXX", "/usr/bin/clang++-20"))
    return parser.parse_args()


def resolve_source(source_file: str) -> Path:
    raw = Path(source_file)
    candidates = []
    if raw.is_absolute():
        candidates.append(raw)
    else:
        candidates.extend(
            [
                REPO_ROOT / raw,
                SRC_ROOT / raw,
                REPO_ROOT / "srcs" / raw,
            ]
        )

    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    raise SystemExit(f"source file not found: {source_file}")


def compiler_for(path: Path, args: argparse.Namespace) -> str:
    if path.suffix.lower() in {".cpp", ".cc", ".cxx"}:
        return args.cxx
    return args.cc


def companion_sources(source: Path) -> list[Path]:
    match = re.match(r"(.+__w32_\d+)[a-z]\.(c|cpp|cc|cxx)$", source.name)
    if not match:
        return [source]

    prefix = match.group(1)
    suffix = match.group(2)
    companions = sorted(source.parent.glob(f"{prefix}*.{suffix}"))
    return companions or [source]


def run_checked(cmd: list[str], cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def main() -> int:
    args = parse_args()
    source = resolve_source(args.source_file)
    compiler = compiler_for(source, args)

    if not Path(compiler).exists():
        raise SystemExit(f"compiler not found: {compiler}")

    with tempfile.TemporaryDirectory(prefix="magus-cwe15-") as tmp:
        tmp_path = Path(tmp)
        binary = Path(tmp) / "case_under_test"

        objects: list[Path] = []
        for index, unit in enumerate(companion_sources(source)):
            unit_compiler = compiler_for(unit, args)
            obj = tmp_path / f"case_{index}.o"
            command = [
                unit_compiler,
                "-c",
                "-DINCLUDEMAIN" if unit == source else "-DMAGUS_COMPANION_UNIT",
                "-DOMITGOOD",
                "-I",
                str(SHIM_DIR),
                "-I",
                str(SUPPORT_DIR),
                str(unit),
                "-o",
                str(obj),
            ]
            build = run_checked(command, REPO_ROOT)
            if build.returncode != 0:
                print("MAGUS_CWE15_BUILD_FAILED")
                print(build.stdout, end="")
                print(build.stderr, end="", file=sys.stderr)
                return build.returncode
            objects.append(obj)

        support_obj = tmp_path / "io.o"
        stub_obj = tmp_path / "winapi_runtime_stubs.o"
        for obj, unit in ((support_obj, SUPPORT_IO), (stub_obj, STUBS)):
            command = [
                compiler,
                "-c",
                "-DglobalReturnsTrueOrFalse=magus_unused_globalReturnsTrueOrFalse" if unit == SUPPORT_IO else "-DMAGUS_WINAPI_RUNTIME_STUBS",
                "-I",
                str(SHIM_DIR),
                "-I",
                str(SUPPORT_DIR),
                str(unit),
                "-o",
                str(obj),
            ]
            build = run_checked(command, REPO_ROOT)
            if build.returncode != 0:
                print("MAGUS_CWE15_BUILD_FAILED")
                print(build.stdout, end="")
                print(build.stderr, end="", file=sys.stderr)
                return build.returncode
            objects.append(obj)

        command = [compiler, *[str(obj) for obj in objects], "-o", str(binary)]
        build = run_checked(command, REPO_ROOT)
        if build.returncode != 0:
            print("MAGUS_CWE15_BUILD_FAILED")
            print(build.stdout, end="")
            print(build.stderr, end="", file=sys.stderr)
            return build.returncode

        env = os.environ.copy()
        env["MAGUS_CWE15_PAYLOAD"] = args.payload
        run = run_checked([str(binary)], REPO_ROOT, env=env)
        print(run.stdout, end="")
        print(run.stderr, end="", file=sys.stderr)
        if CONFIRM_MARKER in run.stdout:
            return 0
        print("MAGUS_CWE15_NOT_CONFIRMED")
        print(f"entry_symbol={args.entry_symbol}")
        print(f"source_file={source}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
