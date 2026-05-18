#!/usr/bin/env python3

import argparse
import shlex
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
STAGE_A_DIR = REPO_ROOT / "a"
STAGE_B_DIR = REPO_ROOT / "b"
STAGE_C_DIR = REPO_ROOT / "c"
DEFAULT_STAGE_A_INPUT = STAGE_A_DIR / "input/zlib.in.jsonl"
DEFAULT_STAGE_A_OUTPUT = STAGE_A_DIR / "out/samples.raw.jsonl"
DEFAULT_STAGE_A_GENERATED_INPUT = STAGE_A_DIR / "input/srcs.in.jsonl"
DEFAULT_SOURCE_ROOT = REPO_ROOT / "srcs"
DEFAULT_STAGE_B_OUTPUT_DIR = STAGE_B_DIR / "b_output"
DEFAULT_STAGE_C_OUTPUT = STAGE_C_DIR / "out/hypotheses.jsonl"


def resolve_path(raw: str) -> Path:
    return Path(raw).expanduser().resolve()


def derived_stats_path(raw_output_path: Path) -> Path:
    return raw_output_path.with_suffix("").with_suffix(".stats.jsonl")


def derived_llm_path(raw_output_path: Path) -> Path:
    return raw_output_path.with_suffix("").with_suffix(".llm.jsonl")


def b_candidates_path(output_dir: Path) -> Path:
    return output_dir / "candidates.scored.jsonl"


def run_command(command: list[str], cwd: Path) -> None:
    print(f"[pipeline] cwd={cwd}", flush=True)
    print(f"[pipeline] cmd={shlex.join(command)}", flush=True)
    completed = subprocess.run(command, cwd=cwd)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def build_analyzer() -> None:
    run_command(["make", "build-analyzer"], STAGE_A_DIR)


def run_stage_a_gen_input(
    repo_path: Path,
    compile_commands: Path | None,
    output_path: Path,
    project_id: str,
    language: str,
    framework: str,
    analyzer_jobs: int,
    analysis_timeout: int,
    clang: str,
    clangxx: str,
    bc_dir: str,
    source_globs: list[str],
    force: bool,
) -> None:
    command = [
        sys.executable,
        "cmd/gen_input.py",
        "--repo-path",
        str(repo_path),
        "--output",
        str(output_path),
        "--project-id",
        project_id,
        "--language",
        language,
        "--framework",
        framework,
        "--analyzer-jobs",
        str(analyzer_jobs),
        "--analysis-timeout",
        str(analysis_timeout),
        "--clang",
        clang,
        "--clangxx",
        clangxx,
        "--bc-dir",
        bc_dir,
    ]
    if compile_commands is not None:
        command.extend(["--compile-commands", str(compile_commands)])
    for source_glob in source_globs:
        command.extend(["--source-glob", source_glob])
    if force:
        command.append("--force")
    run_command(command, STAGE_A_DIR)


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


def run_stage_a_llm(raw_input_path: Path, projects_path: Path, output_path: Path) -> None:
    run_command(
        [
            sys.executable,
            "cmd/llm_export.py",
            "--input",
            str(raw_input_path),
            "--projects",
            str(projects_path),
            "--output",
            str(output_path),
        ],
        STAGE_A_DIR,
    )


def run_stage_b(input_path: Path, output_dir: Path, min_support: int) -> None:
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
    run_command(
        command,
        STAGE_B_DIR,
    )


def run_stage_c(llm_input_path: Path, b_candidates_path: Path, output_path: Path, max_samples: int | None) -> None:
    command = [
        sys.executable,
        "agent1.py",
        "--llm-input",
        str(llm_input_path),
        "--b-candidates",
        str(b_candidates_path),
        "--output",
        str(output_path),
    ]
    if max_samples is not None:
        command.extend(["--max-samples", str(max_samples)])
    run_command(command, STAGE_C_DIR)


def add_stage_a_args(parser: argparse.ArgumentParser, input_flag: str, output_flag: str) -> None:
    parser.add_argument(input_flag, default=str(DEFAULT_STAGE_A_INPUT), help="Stage A 输入 projects.in.jsonl")
    parser.add_argument(output_flag, default=str(DEFAULT_STAGE_A_OUTPUT), help="Stage A 输出 samples.raw.jsonl")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MAGUS pipeline runner. Supports separate Stage A, B, C, or chained A->B execution."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("build-analyzer", help="构建 Stage A LLVM analyzer")

    parser_gen_input = subparsers.add_parser(
        "gen-input",
        help="从 compile_commands.json 生成 Stage A projects.in.jsonl",
    )
    parser_gen_input.add_argument("--repo-path", default=str(DEFAULT_SOURCE_ROOT), help="源码项目根目录")
    parser_gen_input.add_argument(
        "--compile-commands",
        default="",
        help="compile_commands.json 路径；为空时使用 <repo-path>/compile_commands.json",
    )
    parser_gen_input.add_argument("--output", default=str(DEFAULT_STAGE_A_GENERATED_INPUT), help="输出 projects.in.jsonl")
    parser_gen_input.add_argument("--project-id", default="srcs", help="Stage A project_id")
    parser_gen_input.add_argument("--language", default="c", help="Stage A language")
    parser_gen_input.add_argument("--framework", default="generic", help="Stage A framework")
    parser_gen_input.add_argument("--analyzer-jobs", type=int, default=2, help="Stage A analyzer_jobs")
    parser_gen_input.add_argument("--analysis-timeout", type=int, default=900, help="Stage A analysis_timeout")
    parser_gen_input.add_argument("--clang", default="clang", help="C bitcode compiler")
    parser_gen_input.add_argument("--clangxx", default="clang++", help="C++ bitcode compiler")
    parser_gen_input.add_argument("--bc-dir", default="bc", help="repo_path 下的 bitcode 输出目录")
    parser_gen_input.add_argument(
        "--source-glob",
        action="append",
        default=[],
        help="Stage A source_globs 条目，可重复",
    )
    parser_gen_input.add_argument("--force", action="store_true", help="允许覆盖已存在输出")

    parser_stats = subparsers.add_parser("stats-path", help="根据 Stage A raw 输出推导 samples.stats.jsonl 路径")
    parser_stats.add_argument("--raw-output", default=str(DEFAULT_STAGE_A_OUTPUT), help="Stage A raw 输出路径")

    parser_llm = subparsers.add_parser("llm-path", help="根据 Stage A raw 输出推导 samples.llm.jsonl 路径")
    parser_llm.add_argument("--raw-output", default=str(DEFAULT_STAGE_A_OUTPUT), help="Stage A raw 输出路径")

    parser_llm_export = subparsers.add_parser("llm", help="从 Stage A raw 输出导出 samples.llm.jsonl")
    parser_llm_export.add_argument("--input", default=str(DEFAULT_STAGE_A_OUTPUT), help="Stage A samples.raw.jsonl 路径")
    parser_llm_export.add_argument("--projects", default=str(DEFAULT_STAGE_A_INPUT), help="Stage A projects.in.jsonl 路径")
    parser_llm_export.add_argument("--output", default="", help="Stage A samples.llm.jsonl 输出路径")

    parser_a = subparsers.add_parser("a", help="只运行 Stage A")
    add_stage_a_args(parser_a, "--input", "--output")

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
    parser_c = subparsers.add_parser("c", help="只运行 Stage C")
    parser_c.add_argument(
        "--llm-input",
        default=str(derived_llm_path(DEFAULT_STAGE_A_OUTPUT)),
        help="Stage C 输入 Stage A samples.llm.jsonl",
    )
    parser_c.add_argument(
        "--b-candidates",
        default=str(b_candidates_path(DEFAULT_STAGE_B_OUTPUT_DIR)),
        help="Stage C 输入 Stage B candidates.scored.jsonl",
    )
    parser_c.add_argument(
        "--output",
        default=str(DEFAULT_STAGE_C_OUTPUT),
        help="Stage C 输出 hypotheses.jsonl",
    )
    parser_c.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Stage C 可选候选数量上限",
    )
    parser_ab = subparsers.add_parser("ab", help="串联运行 Stage A 和 Stage B")
    add_stage_a_args(parser_ab, "--a-input", "--a-output")
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
    parser_abc = subparsers.add_parser("abc", help="串联运行 Stage A、Stage B 和 Stage C")
    add_stage_a_args(parser_abc, "--a-input", "--a-output")
    parser_abc.add_argument(
        "--b-output-dir",
        default=str(DEFAULT_STAGE_B_OUTPUT_DIR),
        help="Stage B 输出目录",
    )
    parser_abc.add_argument(
        "--c-output",
        default=str(DEFAULT_STAGE_C_OUTPUT),
        help="Stage C 输出 hypotheses.jsonl",
    )
    parser_abc.add_argument(
        "--min-support",
        type=int,
        default=3,
        help="Stage B 频繁模式最低支持度",
    )
    parser_abc.add_argument(
        "--c-max-samples",
        type=int,
        default=None,
        help="Stage C 可选候选数量上限",
    )
    args = parser.parse_args()

    if args.command == "build-analyzer":
        build_analyzer()
        return

    if args.command == "gen-input":
        compile_commands = resolve_path(args.compile_commands) if args.compile_commands else None
        run_stage_a_gen_input(
            resolve_path(args.repo_path),
            compile_commands,
            resolve_path(args.output),
            args.project_id,
            args.language,
            args.framework,
            args.analyzer_jobs,
            args.analysis_timeout,
            args.clang,
            args.clangxx,
            args.bc_dir,
            args.source_glob,
            args.force,
        )
        return

    if args.command == "stats-path":
        print(derived_stats_path(resolve_path(args.raw_output)))
        return

    if args.command == "llm-path":
        print(derived_llm_path(resolve_path(args.raw_output)))
        return

    if args.command == "llm":
        raw_input = resolve_path(args.input)
        output = resolve_path(args.output) if args.output else derived_llm_path(raw_input)
        run_stage_a_llm(raw_input, resolve_path(args.projects), output)
        return

    if args.command == "a":
        run_stage_a(resolve_path(args.input), resolve_path(args.output))
        return

    if args.command == "b":
        input_path = resolve_path(args.input)
        run_stage_b(input_path, resolve_path(args.output_dir), args.min_support)
        return

    if args.command == "c":
        run_stage_c(
            resolve_path(args.llm_input),
            resolve_path(args.b_candidates),
            resolve_path(args.output),
            args.max_samples,
        )
        return

    if args.command == "ab":
        a_input = resolve_path(args.a_input)
        a_output = resolve_path(args.a_output)
        run_stage_a(a_input, a_output)

        b_input = derived_stats_path(a_output)
        print(f"[pipeline] derived Stage B input={b_input}", flush=True)
        run_stage_b(b_input, resolve_path(args.b_output_dir), args.min_support)
        return

    if args.command == "abc":
        a_input = resolve_path(args.a_input)
        a_output = resolve_path(args.a_output)
        b_output_dir = resolve_path(args.b_output_dir)
        c_output = resolve_path(args.c_output)

        run_stage_a(a_input, a_output)

        llm_output = derived_llm_path(a_output)
        print(f"[pipeline] derived Stage C LLM input={llm_output}", flush=True)
        run_stage_a_llm(a_output, a_input, llm_output)

        b_input = derived_stats_path(a_output)
        print(f"[pipeline] derived Stage B input={b_input}", flush=True)
        run_stage_b(b_input, b_output_dir, args.min_support)

        candidates_path = b_candidates_path(b_output_dir)
        print(f"[pipeline] derived Stage C candidates input={candidates_path}", flush=True)
        run_stage_c(llm_output, candidates_path, c_output, args.c_max_samples)
        return


if __name__ == "__main__":
    main()
