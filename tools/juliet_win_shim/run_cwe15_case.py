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
PAYLOAD_REACHED_MARKER = "MAGUS_CWE15_PAYLOAD_REACHED_SET_COMPUTER_NAME"
ROUTE_EXECUTED_MARKER = "MAGUS_CWE15_ROUTE_EXECUTED"
ROUTE_CONFIRMED_MARKER = "MAGUS_CWE15_ROUTE_CONFIRMED"
NOT_ROUTE_BOUND_MARKER = "MAGUS_CWE15_NOT_ROUTE_BOUND"
NOT_CONFIRMED_MARKER = "MAGUS_CWE15_NOT_CONFIRMED"
SOURCE_SUFFIXES = (".c", ".cpp", ".cc", ".cxx")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build and run one Juliet CWE15 w32 testcase with Linux stubs")
    parser.add_argument("--source-file", required=True, help="C/C++ source file from the Stage C hypothesis")
    parser.add_argument("--entry-symbol", default="", help="Entry symbol from D target generation; kept for traceability")
    parser.add_argument("--route", default="", help="Full Stage C route; used to bind the dynamic run to bad/good scenario")
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


def testcase_prefix(source: Path) -> str | None:
    match = re.match(r"(.+__w32_\d+)(?:[a-z]|_(?:bad|goodG2B))?\.(c|cpp|cc|cxx|h)$", source.name)
    if not match:
        return None
    return match.group(1)


def testcase_suffix(source: Path, prefix: str) -> str:
    suffix = source.suffix.lower()
    if suffix in SOURCE_SUFFIXES:
        return suffix
    for candidate_suffix in (".c", ".cpp", ".cc", ".cxx"):
        if (source.parent / f"{prefix}a{candidate_suffix}").exists() or (source.parent / f"{prefix}{candidate_suffix}").exists():
            return candidate_suffix
    return ".c"


def companion_sources(source: Path) -> list[Path]:
    prefix = testcase_prefix(source)
    if not prefix:
        return [source]

    suffix = testcase_suffix(source, prefix)
    companions = sorted(source.parent.glob(f"{prefix}*{suffix}"))
    return companions or [source]


def main_source(companions: list[Path], source: Path) -> Path:
    prefix = testcase_prefix(source)
    if prefix:
        suffix = testcase_suffix(source, prefix)
        for name in (f"{prefix}a{suffix}", f"{prefix}{suffix}"):
            candidate = source.parent / name
            if candidate in companions:
                return candidate

    for candidate in companions:
        try:
            if "INCLUDEMAIN" in candidate.read_text(encoding="utf-8", errors="ignore"):
                return candidate
        except OSError:
            continue
    return source if source in companions else companions[0]


def scenario_for(args: argparse.Namespace, source: Path) -> str:
    text = f"{args.route} {args.entry_symbol} {source.name}".lower()
    if "good" in text:
        return "good"
    if "bad" in text:
        return "bad"
    return "bad"


def sanitized_stdout(stdout: str) -> str:
    return stdout.replace(
        f"{CONFIRM_MARKER} external payload reached SetComputerNameA",
        f"{PAYLOAD_REACHED_MARKER} external payload reached SetComputerNameA",
    )


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
    companions = companion_sources(source)
    entry_unit = main_source(companions, source)
    scenario = scenario_for(args, source)
    omit_macro = "-DOMITBAD" if scenario == "good" else "-DOMITGOOD"
    compiler = compiler_for(entry_unit, args)

    if not Path(compiler).exists():
        raise SystemExit(f"compiler not found: {compiler}")

    with tempfile.TemporaryDirectory(prefix="magus-cwe15-") as tmp:
        tmp_path = Path(tmp)
        binary = Path(tmp) / "case_under_test"

        objects: list[Path] = []
        for index, unit in enumerate(companions):
            unit_compiler = compiler_for(unit, args)
            obj = tmp_path / f"case_{index}.o"
            command = [
                unit_compiler,
                "-c",
                "-DINCLUDEMAIN" if unit == entry_unit else "-DMAGUS_COMPANION_UNIT",
                omit_macro,
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
        raw_stdout = run.stdout or ""
        raw_stderr = run.stderr or ""
        print(sanitized_stdout(raw_stdout), end="")
        print(raw_stderr, end="", file=sys.stderr)

        expected_call = f"Calling {scenario}()..."
        expected_finish = f"Finished {scenario}()"
        unexpected_call = "Calling good()..." if scenario == "bad" else "Calling bad()..."
        route_executed = expected_call in raw_stdout and expected_finish in raw_stdout and unexpected_call not in raw_stdout
        payload_reached_sink = CONFIRM_MARKER in raw_stdout

        if route_executed:
            print(
                f"{ROUTE_EXECUTED_MARKER} scenario={scenario} "
                f"entry_symbol={args.entry_symbol or '<unknown>'} source_file={source}"
            )
        else:
            print(
                f"{NOT_ROUTE_BOUND_MARKER} expected_scenario={scenario} "
                f"entry_symbol={args.entry_symbol or '<unknown>'} source_file={source} main_source={entry_unit}"
            )

        if route_executed and payload_reached_sink:
            print(
                f"{ROUTE_CONFIRMED_MARKER} scenario={scenario} "
                f"entry_symbol={args.entry_symbol or '<unknown>'} source_file={source}"
            )
            print(f"{CONFIRM_MARKER} route-bound external payload reached SetComputerNameA")
            return 0

        print(NOT_CONFIRMED_MARKER)
        print(f"entry_symbol={args.entry_symbol}")
        print(f"route={args.route}")
        print(f"source_file={source}")
        print(f"main_source={entry_unit}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
