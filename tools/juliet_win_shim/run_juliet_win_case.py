#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SHIM_DIR = REPO_ROOT / "tools" / "juliet_win_shim"
ORIGINAL_SOURCE_ROOT = REPO_ROOT / "srcs"
SANITIZED_SOURCE_ROOT = REPO_ROOT / "srcs_sanitized"
ORIGINAL_SRC_ROOT = ORIGINAL_SOURCE_ROOT / "juliet-api-misuse"
SANITIZED_SRC_ROOT = SANITIZED_SOURCE_ROOT / "juliet-api-misuse"
SANITIZATION_MAP = SANITIZED_SOURCE_ROOT / "juliet_sanitization_map.json"
STUBS = SHIM_DIR / "winapi_runtime_stubs.c"

ROUTE_EXECUTED_MARKER = "MAGUS_JULIET_ROUTE_EXECUTED"
ROUTE_CONFIRMED_MARKER = "MAGUS_JULIET_ROUTE_CONFIRMED"
NOT_ROUTE_BOUND_MARKER = "MAGUS_JULIET_NOT_ROUTE_BOUND"
NOT_CONFIRMED_MARKER = "MAGUS_JULIET_NOT_CONFIRMED"
BUILD_FAILED_MARKER = "MAGUS_JULIET_BUILD_FAILED"
RUNNER_ERROR_MARKER = "MAGUS_JULIET_RUNNER_ERROR"
SOURCE_SUFFIXES = (".c", ".cpp", ".cc", ".cxx")
SCENARIO_LABELS = {"bad": "case0", "good": "case1"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build and run one Juliet Win32 testcase with Linux API shims")
    parser.add_argument("--source-file", required=True, help="C/C++ source file from the Stage C hypothesis")
    parser.add_argument("--entry-symbol", default="", help="Entry symbol from D target generation; kept for traceability")
    parser.add_argument("--route", default="", help="Full Stage C route; used to bind the dynamic run to bad/good scenario")
    parser.add_argument("--payload", default="magus-juliet-controlled-input", help="Payload returned by shimmed external sources")
    parser.add_argument("--cc", default=os.environ.get("MAGUS_CC", "/usr/bin/clang-20"))
    parser.add_argument("--cxx", default=os.environ.get("MAGUS_CXX", "/usr/bin/clang++-20"))
    return parser.parse_args()


def load_sanitization_map() -> dict[str, object]:
    if not SANITIZATION_MAP.exists():
        return {}
    try:
        payload = json.loads(SANITIZATION_MAP.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def path_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def is_sanitized_source(source: Path) -> bool:
    return path_under(source, SANITIZED_SOURCE_ROOT)


def support_dir_for(source: Path) -> Path:
    return (SANITIZED_SRC_ROOT if is_sanitized_source(source) else ORIGINAL_SRC_ROOT) / "testcasesupport"


def require_sanitization_map_for(source: Path) -> None:
    if is_sanitized_source(source) and not SANITIZATION_MAP.exists():
        raise SystemExit(f"{RUNNER_ERROR_MARKER} sanitized Juliet source requires mapping: {SANITIZATION_MAP}")


def desanitize_text(text: str) -> str:
    mapping = load_sanitization_map()
    reverse = mapping.get("reverse_token_map") if isinstance(mapping.get("reverse_token_map"), dict) else {}
    replacements = reverse or {
        "OMITCASE0": "OMITBAD",
        "OMITCASE1": "OMITGOOD",
        "CASE0": "BAD",
        "Case0": "Bad",
        "case0": "bad",
        "CASE1": "GOOD",
        "Case1": "Good",
        "case1": "good",
    }
    result = text
    for sanitized, original in sorted(replacements.items(), key=lambda item: len(str(item[0])), reverse=True):
        result = result.replace(str(sanitized), str(original))
    return result


def resolve_source(source_file: str) -> Path:
    raw = Path(source_file)
    candidates = []
    if raw.is_absolute():
        candidates.append(raw)
    else:
        candidates.extend(
            [
                REPO_ROOT / raw,
                SANITIZED_SOURCE_ROOT / raw,
                SANITIZED_SRC_ROOT / raw,
                ORIGINAL_SOURCE_ROOT / raw,
                ORIGINAL_SRC_ROOT / raw,
                REPO_ROOT / "srcs" / raw,
            ]
        )

    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    raise SystemExit(f"{RUNNER_ERROR_MARKER} source file not found: {source_file}")


def compiler_for(path: Path, args: argparse.Namespace) -> str:
    if path.suffix.lower() in {".cpp", ".cc", ".cxx"}:
        return args.cxx
    return args.cc


def testcase_stem(source: Path) -> str | None:
    suffix = source.suffix.lower()
    if suffix not in SOURCE_SUFFIXES:
        return None
    stem = source.stem
    match = re.match(
        r"(.+_\d+)(?:[a-z]|_(?:bad|goodG2B|goodB2G|goodG2B1|goodG2B2|goodB2G1|goodB2G2|"
        r"case0|case1G2B|case1B2G|case1G2B1|case1G2B2|case1B2G1|case1B2G2|"
        r"case1V1|case1V2|case1V11|case1V12|case1V21|case1V22))?$",
        stem,
    )
    if match:
        return match.group(1)
    return stem


def companion_sources(source: Path) -> list[Path]:
    stem = testcase_stem(source)
    if not stem:
        return [source]
    companions: list[Path] = []
    for suffix in SOURCE_SUFFIXES:
        companions.extend(source.parent.glob(f"{stem}*{suffix}"))
    companions = sorted(path for path in companions if path.suffix.lower() in SOURCE_SUFFIXES)
    return companions or [source]


def main_source(companions: list[Path], source: Path) -> Path:
    stem = testcase_stem(source)
    if stem:
        for suffix in SOURCE_SUFFIXES:
            for name in (f"{stem}a{suffix}", f"{stem}{suffix}"):
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
    text = desanitize_text(f"{args.route} {args.entry_symbol}").lower()
    if "good" in text:
        return "good"
    if "bad" in text:
        return "bad"
    text = desanitize_text(source.name).lower()
    if "good" in text:
        return "good"
    if "bad" in text:
        return "bad"
    return "bad"


def omit_macro_for(source: Path, scenario: str) -> str:
    if is_sanitized_source(source):
        return "-DOMITCASE0" if scenario == "good" else "-DOMITCASE1"
    return "-DOMITBAD" if scenario == "good" else "-DOMITGOOD"


def scenario_label(source: Path, scenario: str) -> str:
    if is_sanitized_source(source):
        return SCENARIO_LABELS[scenario]
    return scenario


def link_compiler(companions: list[Path], args: argparse.Namespace) -> str:
    if any(path.suffix.lower() in {".cpp", ".cc", ".cxx"} for path in companions):
        return args.cxx
    return args.cc


def run_checked(
    cmd: list[str],
    cwd: Path,
    env: dict[str, str] | None = None,
    stdin_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        input=stdin_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def write_runtime_files(cwd: Path, payload: str) -> None:
    repeated = (payload + "\n") * 128
    binary_payload = (payload.encode("utf-8", errors="ignore") + b"\n") * 128
    for name in (
        "BadSource_fopen.txt",
        "GoodSource_fopen.txt",
        "Case0Source_fopen.txt",
        "Case1Source_fopen.txt",
        "BadSink_fopen.txt",
        "GoodSink_fopen.txt",
        "Case0Sink_fopen.txt",
        "Case1Sink_fopen.txt",
        "file.txt",
        "log.txt",
    ):
        (cwd / name).write_text(repeated, encoding="utf-8")
    (cwd / "password.txt").write_text(("41 " * 256) + "\n", encoding="utf-8")
    (cwd / "encrypted.txt").write_bytes(binary_payload[:256].ljust(128, b"X"))


def configure_failure_environment(env: dict[str, str], source: Path) -> None:
    source_text = str(source)
    source_name = source.name
    if "CWE252_Unchecked_Return_Value" in source_text or "CWE253_Incorrect_Check_of_Function_Return_Value" in source_text:
        if "CreateMutex" in source_name:
            env["MAGUS_JULIET_FAIL_CREATE_MUTEX"] = "1"
        if "CreateNamedPipe" in source_name:
            env["MAGUS_JULIET_FAIL_CREATE_NAMED_PIPE"] = "1"
    if "CWE273_Improper_Check_for_Dropped_Privileges" in source_text:
        env["MAGUS_JULIET_FAIL_IMPERSONATE_NAMED_PIPE_CLIENT"] = "1"
    if "CWE338_Weak_PRNG" in source_text:
        env["MAGUS_JULIET_MARK_RAND_FLAW"] = "1"
    if "CWE690_NULL_Deref_From_Return" in source_text and "w32_wfopen" in source_name:
        env["MAGUS_JULIET_FAIL_WFOPEN"] = "1"
    if (
        "CWE773_Missing_Reference_to_Active_File_Descriptor_or_Handle" in source_text
        or "CWE775_Missing_Release_of_File_Descriptor_or_Handle" in source_text
    ):
        env["MAGUS_JULIET_REPORT_HANDLE_LEAKS"] = "1"


def compile_unit(command: list[str], tmp_path: Path) -> bool:
    build = run_checked(command, REPO_ROOT)
    if build.returncode == 0:
        return True
    print(BUILD_FAILED_MARKER)
    print("command=" + " ".join(command))
    print(build.stdout, end="")
    print(build.stderr, end="", file=sys.stderr)
    return False


def compile_case(args: argparse.Namespace, source: Path, tmp_path: Path) -> tuple[Path | None, Path | None]:
    companions = companion_sources(source)
    entry_unit = main_source(companions, source)
    scenario = scenario_for(args, source)
    omit_macro = omit_macro_for(source, scenario)
    support_dir = support_dir_for(source)
    support_io = support_dir / "io.c"
    support_thread = support_dir / "std_thread.c"

    objects: list[Path] = []
    for index, unit in enumerate(companions):
        unit_compiler = compiler_for(unit, args)
        obj = tmp_path / f"case_{index}.o"
        command = [
            unit_compiler,
            "-c",
            "-D_WIN32",
            "-DINCLUDEMAIN" if unit == entry_unit else "-DMAGUS_COMPANION_UNIT",
            omit_macro,
            "-I",
            str(SHIM_DIR),
            "-I",
            str(support_dir),
            str(unit),
            "-o",
            str(obj),
        ]
        if not compile_unit(command, tmp_path):
            return None, entry_unit
        objects.append(obj)

    support_units = [
        (tmp_path / "io.o", support_io, args.cc, ["-DglobalReturnsTrueOrFalse=magus_unused_globalReturnsTrueOrFalse"]),
        (tmp_path / "std_thread.o", support_thread, args.cc, []),
        (tmp_path / "winapi_runtime_stubs.o", STUBS, args.cc, ["-DMAGUS_WINAPI_RUNTIME_STUBS"]),
    ]
    for obj, unit, compiler, extra_macros in support_units:
        command = [
            compiler,
            "-c",
            "-D_WIN32",
            *extra_macros,
            "-I",
            str(SHIM_DIR),
            "-I",
            str(support_dir),
            str(unit),
            "-o",
            str(obj),
        ]
        if not compile_unit(command, tmp_path):
            return None, entry_unit
        objects.append(obj)

    binary = tmp_path / "case_under_test"
    command = [link_compiler(companions, args), *[str(obj) for obj in objects], "-o", str(binary)]
    if not compile_unit(command, tmp_path):
        return None, entry_unit
    return binary, entry_unit


def route_was_executed(stdout: str, source: Path, scenario: str) -> bool:
    label = scenario_label(source, scenario)
    other_label = scenario_label(source, "good" if scenario == "bad" else "bad")
    expected_call = f"Calling {label}()..."
    expected_finish = f"Finished {label}()"
    unexpected_call = f"Calling {other_label}()..."
    return expected_call in stdout and expected_finish in stdout and unexpected_call not in stdout


def oracle_confirmed(stdout: str, scenario: str) -> bool:
    for line in stdout.splitlines():
        if line.startswith("MAGUS_JULIET_SINK ") and "tainted=1" in line:
            return True
        if scenario == "bad" and line.startswith("MAGUS_JULIET_FLAW "):
            return True
    return False


def main() -> int:
    args = parse_args()
    source = resolve_source(args.source_file)
    require_sanitization_map_for(source)
    scenario = scenario_for(args, source)

    for compiler in {args.cc, args.cxx}:
        if not Path(compiler).exists():
            print(f"{RUNNER_ERROR_MARKER} compiler not found: {compiler}")
            return 2

    with tempfile.TemporaryDirectory(prefix="magus-juliet-win-") as tmp:
        tmp_path = Path(tmp)
        binary, entry_unit = compile_case(args, source, tmp_path)
        if binary is None:
            return 2

        write_runtime_files(tmp_path, args.payload)
        env = os.environ.copy()
        env["MAGUS_JULIET_PAYLOAD"] = args.payload
        env["MAGUS_CWE15_PAYLOAD"] = args.payload
        env.setdefault("ADD", args.payload)
        env.setdefault("WINDIR", r"C:\Windows")
        configure_failure_environment(env, source)

        run = run_checked([str(binary)], tmp_path, env=env, stdin_text=args.payload + "\n")
        raw_stdout = run.stdout or ""
        raw_stderr = run.stderr or ""
        print(raw_stdout, end="")
        print(raw_stderr, end="", file=sys.stderr)

        route_executed = route_was_executed(raw_stdout, source, scenario)
        confirmed = oracle_confirmed(raw_stdout, scenario)

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

        if route_executed and confirmed:
            print(
                f"{ROUTE_CONFIRMED_MARKER} scenario={scenario} "
                f"entry_symbol={args.entry_symbol or '<unknown>'} source_file={source}"
            )
            return 0

        print(NOT_CONFIRMED_MARKER)
        print(f"entry_symbol={args.entry_symbol}")
        print(f"route={args.route}")
        print(f"source_file={source}")
        print(f"main_source={entry_unit}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
