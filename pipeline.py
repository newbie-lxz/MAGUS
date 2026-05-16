#!/usr/bin/env python3

import argparse
import shlex
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
STAGE_A2_DIR = REPO_ROOT / "a2"
STAGE_B_DIR = REPO_ROOT / "b"
DEFAULT_STAGE_A2_INPUT = STAGE_A2_DIR / "input/zlib.in.jsonl"
DEFAULT_STAGE_A2_OUTPUT = STAGE_A2_DIR / "out/samples.raw.jsonl"
DEFAULT_STAGE_B_OUTPUT_DIR = STAGE_B_DIR / "b_output"


def resolve_path(raw: str) -> Path:
    return Path(raw).expanduser().resolve()


def derived_stats_path(raw_output_path: Path) -> Path:
    return raw_output_path.with_suffix("").with_suffix(".stats.jsonl")


def run_command(command: list[str], cwd: Path) -> None:
    print(f"[pipeline] cwd={cwd}", flush=True)
    print(f"[pipeline] cmd={shlex.join(command)}", flush=True)
    completed = subprocess.run(command, cwd=cwd)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def build_analyzer() -> None:
    run_command(["make", "build-analyzer"], STAGE_A2_DIR)


def run_stage_a2(input_path: Path, output_path: Path) -> None:
    run_command(
        [
            sys.executable,
            "cmd/miner.py",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
        ],
        STAGE_A2_DIR,
    )


def run_stage_b(input_path: Path, output_dir: Path, min_support: int, workers: int | None) -> None:
    command = [
        sys.executable,
        "b_miner.py",
        "--input",
        str(input_path),
        "--output-dir",
        str(output_dir),
        "--min-support",
        str(min_support),
    ]
    if workers is not None:
        command.extend(["--workers", str(workers)])
    run_command(
        command,
        STAGE_B_DIR,
    )


def add_stage_a2_args(parser: argparse.ArgumentParser, input_flag: str, output_flag: str) -> None:
    parser.add_argument(input_flag, default=str(DEFAULT_STAGE_A2_INPUT), help="Stage A2 输入 projects.in.jsonl")
    parser.add_argument(output_flag, default=str(DEFAULT_STAGE_A2_OUTPUT), help="Stage A2 输出 samples.raw.jsonl")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Stage A2/B pipeline runner. Supports separate A2, B, or chained A2->B execution."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("build-analyzer", help="构建 Stage A2 LLVM analyzer")

    parser_stats = subparsers.add_parser("stats-path", help="根据 Stage A2 raw 输出推导 samples.stats.jsonl 路径")
    parser_stats.add_argument("--raw-output", default=str(DEFAULT_STAGE_A2_OUTPUT), help="Stage A2 raw 输出路径")

    parser_a = subparsers.add_parser("a2", help="只运行 Stage A2")
    add_stage_a2_args(parser_a, "--input", "--output")

    parser_b = subparsers.add_parser("b", help="只运行 Stage B")
    parser_b.add_argument(
        "--input",
        default=str(derived_stats_path(DEFAULT_STAGE_A2_OUTPUT)),
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
    parser_b.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Stage B 进程池 worker 数；默认 CPU/4，设为 1 可关闭多进程",
    )

    parser_ab = subparsers.add_parser("ab", help="串联运行 Stage A2 和 Stage B")
    add_stage_a2_args(parser_ab, "--a2-input", "--a2-output")
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
    parser_ab.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Stage B 进程池 worker 数；默认 CPU/4，设为 1 可关闭多进程",
    )

    args = parser.parse_args()

    if args.command == "build-analyzer":
        build_analyzer()
        return

    if args.command == "stats-path":
        print(derived_stats_path(resolve_path(args.raw_output)))
        return

    if args.command == "a2":
        run_stage_a2(resolve_path(args.input), resolve_path(args.output))
        return

    if args.command == "b":
        input_path = resolve_path(args.input)
        run_stage_b(input_path, resolve_path(args.output_dir), args.min_support, args.workers)
        return

    if args.command == "ab":
        a2_input = resolve_path(args.a2_input)
        a2_output = resolve_path(args.a2_output)
        run_stage_a2(a2_input, a2_output)

        b_input = derived_stats_path(a2_output)
        print(f"[pipeline] derived Stage B input={b_input}", flush=True)
        run_stage_b(b_input, resolve_path(args.b_output_dir), args.min_support, args.workers)
        return


if __name__ == "__main__":
    main()
