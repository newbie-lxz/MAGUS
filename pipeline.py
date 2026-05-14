#!/usr/bin/env python3

import argparse
import shlex
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
STAGE_A_DIR = REPO_ROOT / "a"
STAGE_B_DIR = REPO_ROOT / "b"
DEFAULT_STAGE_A_INPUT = STAGE_A_DIR / "input/zlib.in.jsonl"
DEFAULT_STAGE_A_OUTPUT = STAGE_A_DIR / "out/samples.raw.jsonl"
DEFAULT_STAGE_B_OUTPUT_DIR = STAGE_B_DIR / "b_output"


def resolve_path(raw: str) -> Path:
    return Path(raw).expanduser().resolve()


def derived_stats_path(raw_output_path: Path) -> Path:
    name = raw_output_path.name
    if not name.endswith(".raw.jsonl"):
        raise ValueError("Stage A output path must end with .raw.jsonl")
    return raw_output_path.with_name(f"{name[:-10]}.stats.jsonl")


def derived_llm_path(raw_output_path: Path) -> Path:
    name = raw_output_path.name
    if not name.endswith(".raw.jsonl"):
        raise ValueError("Stage A output path must end with .raw.jsonl")
    return raw_output_path.with_name(f"{name[:-10]}.llm.jsonl")


def run_command(command: list[str], cwd: Path) -> None:
    print(f"[pipeline] cwd={cwd}", flush=True)
    print(f"[pipeline] cmd={shlex.join(command)}", flush=True)
    completed = subprocess.run(command, cwd=cwd)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def build_analyzer() -> None:
    run_command(["make", "build-analyzer"], STAGE_A_DIR)


def run_stage_a(input_path: Path, output_path: Path) -> None:
    run_command(
        [
            sys.executable,
            "cmd/miner.py",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
        STAGE_A_DIR,
    )


def run_llm_export(input_path: Path, projects_path: Path, output_path: Path) -> None:
    run_command(
        [
            sys.executable,
            "cmd/llm_export.py",
            "--input",
            str(input_path),
            "--projects",
            str(projects_path),
            "--output",
            str(output_path),
        ],
        STAGE_A_DIR,
    )


def run_stage_b(input_path: Path, output_dir: Path, min_support: int) -> None:
    run_command(
        [
            sys.executable,
            "b_miner.py",
            "--input",
            str(input_path),
            "--output-dir",
            str(output_dir),
            "--min-support",
            str(min_support),
        ],
        STAGE_B_DIR,
    )


def require_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label} not found: {path}")


def add_stage_a_args(parser: argparse.ArgumentParser, input_flag: str, output_flag: str) -> None:
    parser.add_argument(input_flag, default=str(DEFAULT_STAGE_A_INPUT), help="Stage A 输入 projects.in.jsonl")
    parser.add_argument(output_flag, default=str(DEFAULT_STAGE_A_OUTPUT), help="Stage A 输出 samples.raw.jsonl")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Stage A/B pipeline runner. Supports separate A, LLM export, B, or chained A->LLM->B execution."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("build-analyzer", help="构建 Stage A LLVM analyzer")

    parser_stats = subparsers.add_parser("stats-path", help="根据 Stage A raw 输出推导 samples.stats.jsonl 路径")
    parser_stats.add_argument("--raw-output", default=str(DEFAULT_STAGE_A_OUTPUT), help="Stage A raw 输出路径")

    parser_a = subparsers.add_parser("a", help="只运行 Stage A")
    add_stage_a_args(parser_a, "--input", "--output")

    parser_llm = subparsers.add_parser("llm", help="从 Stage A raw 输出显式导出 LLM evidence 视图")
    parser_llm.add_argument("--input", default=str(DEFAULT_STAGE_A_OUTPUT), help="Stage A raw 样本路径")
    parser_llm.add_argument("--projects", default=str(DEFAULT_STAGE_A_INPUT), help="产生 raw 样本的 Stage A 输入 JSONL")
    parser_llm.add_argument(
        "--output",
        default="",
        help="LLM evidence 输出路径；默认由 --input 推导 samples.llm.jsonl",
    )

    parser_b = subparsers.add_parser("b", help="只运行 Stage B")
    parser_b.add_argument(
        "--input",
        default=str(derived_stats_path(DEFAULT_STAGE_A_OUTPUT)),
        help="Stage B 输入 samples.stats.jsonl",
    )
    parser_b.add_argument(
        "--output-dir",
        default=str(DEFAULT_STAGE_B_OUTPUT_DIR),
        help="Stage B 输出目录",
    )
    parser_b.add_argument(
        "--min-support",
        type=int,
        default=3,
        help="Stage B 频繁模式最低支持度",
    )

    parser_ab = subparsers.add_parser("ab", help="串联运行 Stage A、LLM evidence 导出和 Stage B")
    add_stage_a_args(parser_ab, "--a-input", "--a-output")
    parser_ab.add_argument(
        "--llm-output",
        default="",
        help="LLM evidence 输出路径；默认由 --a-output 推导 samples.llm.jsonl",
    )
    parser_ab.add_argument(
        "--b-output-dir",
        default=str(DEFAULT_STAGE_B_OUTPUT_DIR),
        help="Stage B 输出目录",
    )
    parser_ab.add_argument(
        "--min-support",
        type=int,
        default=3,
        help="Stage B 频繁模式最低支持度",
    )

    args = parser.parse_args()

    if args.command == "build-analyzer":
        build_analyzer()
        return

    if args.command == "stats-path":
        print(derived_stats_path(resolve_path(args.raw_output)))
        return

    if args.command == "a":
        run_stage_a(resolve_path(args.input), resolve_path(args.output))
        return

    if args.command == "llm":
        input_path = resolve_path(args.input)
        projects_path = resolve_path(args.projects)
        output_path = resolve_path(args.output) if args.output else derived_llm_path(input_path)
        require_file(input_path, "Stage A raw input")
        require_file(projects_path, "Stage A projects input")
        run_llm_export(input_path, projects_path, output_path)
        return

    if args.command == "b":
        input_path = resolve_path(args.input)
        require_file(input_path, "Stage B input")
        run_stage_b(input_path, resolve_path(args.output_dir), args.min_support)
        return

    if args.command == "ab":
        a_input = resolve_path(args.a_input)
        a_output = resolve_path(args.a_output)
        run_stage_a(a_input, a_output)
        require_file(a_output, "Stage A raw output")

        llm_output = resolve_path(args.llm_output) if args.llm_output else derived_llm_path(a_output)
        print(f"[pipeline] derived LLM evidence output={llm_output}", flush=True)
        run_llm_export(a_output, a_input, llm_output)

        b_input = derived_stats_path(a_output)
        require_file(b_input, "Derived Stage B input")
        print(f"[pipeline] derived Stage B input={b_input}", flush=True)
        run_stage_b(b_input, resolve_path(args.b_output_dir), args.min_support)
        return

    raise ValueError(f"unsupported command: {args.command}")


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
