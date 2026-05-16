import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LLVM_BITCODE_MAGIC = b"BC\xc0\xde"
LLVM_BITCODE_WRAPPER_MAGIC = b"\xde\xc0\x17\x0b"
ELF_MAGIC = b"\x7fELF"
CANONICAL_ANALYSIS_BACKEND = "llvm_api_dfa"
COMPILE_COMMANDS_SOURCE_GLOBS_ENV = "STAGE_A_SOURCE_GLOBS_JSON"

SOURCE_CACHE: dict[Path, list[str]] = {}
SOURCE_KIND_EXACT: dict[str, str] = {
    "read": "filesystem",
    "pread": "filesystem",
    "pread64": "filesystem",
    "fread": "filesystem",
    "fgetc": "stdin",
    "getc": "stdin",
    "getchar": "stdin",
    "getline": "stdin",
    "getdelim": "stdin",
    "fgets": "stdin",
    "gets": "stdin",
    "scanf": "stdin",
    "fscanf": "stdin",
    "sscanf": "stdin",
    "recv": "network",
    "recvfrom": "network",
    "recvmsg": "network",
    "recvmmsg": "network",
    "accept": "network",
    "accept4": "network",
    "getenv": "environment",
    "secure_getenv": "environment",
    "getopt": "argv",
    "getopt_long": "argv",
    "getopt_long_only": "argv",
    "readlink": "filesystem",
    "readlinkat": "filesystem",
}
SOURCE_KIND_PREFIX: tuple[tuple[str, str], ...] = (
    ("recv", "network"),
    ("scanf", "stdin"),
    ("fget", "stdin"),
    ("getenv", "environment"),
    ("getopt", "argv"),
)


# 1. 输入模型与运行状态
@dataclass
class ProjectInput:
    """Stage A 单个项目输入记录。"""
    project_id: str
    repo_path: str
    language: str
    framework: str
    default_branch: str = ""
    extensions: dict = field(default_factory=dict)

    def normalize(self, base_dir: Path) -> None:
        self.framework = self.framework.strip().lower()
        self.language = self.language.strip().lower()
        if self.repo_path and not Path(self.repo_path).is_absolute():
            self.repo_path = str((base_dir / self.repo_path).resolve())

    def validate(self) -> None:
        if not self.project_id:
            raise ValueError("missing project_id")
        if not self.repo_path:
            raise ValueError("missing repo_path")
        if not self.framework:
            raise ValueError("missing framework")
        if not self.language:
            raise ValueError("missing language")
        if normalize_language(self.language) is None:
            raise ValueError("language must be c/cpp for the current miner")
        if self.build_command() is None:
            raise ValueError("missing extensions.build_cmd for build-based analysis")
        self.backend_mode()
        self.analyzer_jobs()

    def backend_mode(self) -> str:
        raw_mode = self.extensions.get("analysis_backend")
        if raw_mode is None:
            return CANONICAL_ANALYSIS_BACKEND
        if not isinstance(raw_mode, str):
            raise ValueError("extensions.analysis_backend must be a string")
        mode = raw_mode.strip().lower() or CANONICAL_ANALYSIS_BACKEND
        if mode != CANONICAL_ANALYSIS_BACKEND:
            raise ValueError(f"stage A only supports the {CANONICAL_ANALYSIS_BACKEND} backend")
        return mode

    def build_command(self):
        return normalize_command(self.extensions.get("build_cmd"), "extensions.build_cmd")

    def config_command(self):
        return normalize_command(self.extensions.get("config_cmd"), "extensions.config_cmd")

    def build_env(self) -> dict[str, str]:
        raw_env = self.extensions.get("build_env") or {}
        if not isinstance(raw_env, dict):
            raise ValueError("extensions.build_env must be an object")
        return {str(key): str(value) for key, value in raw_env.items()}

    def build_cwd(self) -> Path:
        raw = self.extensions.get("build_cwd")
        repo_path = Path(self.repo_path)
        if raw is None:
            return repo_path
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError("extensions.build_cwd must be a non-empty string")
        path = Path(raw)
        return path if path.is_absolute() else (repo_path / path).resolve()

    def analysis_timeout(self) -> int:
        raw = self.extensions.get("analysis_timeout", 900)
        if isinstance(raw, bool):
            raise ValueError("extensions.analysis_timeout must be an integer")
        try:
            timeout = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError("extensions.analysis_timeout must be an integer") from exc
        if timeout <= 0:
            raise ValueError("extensions.analysis_timeout must be positive")
        return timeout

    def analyzer_jobs(self) -> int:
        if "analyzer_jobs" not in self.extensions:
            raise ValueError("missing extensions.analyzer_jobs for chunked analyzer execution")
        raw = self.extensions.get("analyzer_jobs")
        if isinstance(raw, bool):
            raise ValueError("extensions.analyzer_jobs must be an integer")
        try:
            jobs = int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError("extensions.analyzer_jobs must be an integer") from exc
        if jobs <= 1:
            raise ValueError("extensions.analyzer_jobs must be greater than 1")
        return jobs

    def target_subdirs(self) -> list[str]:
        raw = self.extensions.get("target_subdirs")
        if raw is None:
            return []
        if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
            raise ValueError("extensions.target_subdirs must be a list of strings")
        return [normalize_prefix(item) for item in raw if normalize_prefix(item)]

    def entry_functions(self) -> list[str]:
        raw = self.extensions.get("entry_functions")
        if raw is None:
            return []
        if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
            raise ValueError("extensions.entry_functions must be a list of strings")
        return [item.strip() for item in raw if item.strip()]

    def source_globs(self) -> list[str]:
        raw = self.extensions.get("source_globs")
        if raw is None:
            return []
        if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
            raise ValueError("extensions.source_globs must be a list of strings")
        return [item for item in raw if item.strip()]

    def bitcode_globs(self) -> list[str]:
        raw = self.extensions.get("bitcode_globs")
        if raw is None:
            return ["**/*.bc"]
        if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
            raise ValueError("extensions.bitcode_globs must be a list of strings")
        globs = [item for item in raw if item.strip()]
        if not globs:
            raise ValueError("extensions.bitcode_globs must not be empty")
        return globs


@dataclass
class CommandResult:
    """外部命令执行结果，用于 run manifest 和失败摘要。"""
    stage: str
    command: list[str] | str
    cwd: str
    returncode: int
    stdout: str
    stderr: str

    def as_manifest(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "command": self.command,
            "cwd": self.cwd,
            "returncode": self.returncode,
            "stdout_tail": tail_text(self.stdout),
            "stderr_tail": tail_text(self.stderr),
        }


@dataclass
class AnalyzerBinary:
    """可执行 analyzer 的发现结果。"""
    path: str
    source: str


@dataclass(frozen=True)
class AnalyzerChunk:
    """并行 analyzer 子任务的切片计划。"""
    chunk_index: int
    bc_list_path: Path
    output_root: Path
    module_indices: tuple[int, ...]


@dataclass
class DfaGraphNode:
    """归一化后的 DFA 图节点。"""
    node_id: str
    name: str
    file: str
    line: int
    sink_kind: str
    params: list[int]
    order: int
    source_slice: str
    call_kind: str = ""
    unresolved_indirect: bool = False
    resolved_callees: list[str] = field(default_factory=list)
    check_kind: str = ""
    condition_text: str = ""
    branch_count: int = 0


class ProjectFailure(RuntimeError):
    """带阶段信息的 Stage A 失败包装。"""
    def __init__(self, stage: str, reason: str, details: dict[str, Any] | None = None):
        super().__init__(f"{stage}: {reason}")
        self.stage = stage
        self.reason = reason
        self.details = details or {}


# 2. CLI 与通用输入输出
def parse_args():
    """解析 Stage A CLI 参数。"""
    parser = argparse.ArgumentParser(description="Stage A LLVM API DFA miner")
    parser.add_argument("--input", required=True, help="path to projects.in.jsonl")
    parser.add_argument("--output", required=True, help="path to samples.raw.jsonl")
    return parser.parse_args()


def normalize_language(language: str) -> str | None:
    """将语言字段归一化到 Stage A 支持的枚举。"""
    lowered = language.strip().lower()
    if lowered in {"c"}:
        return "c"
    if lowered in {"c++", "cpp", "cc", "cxx"}:
        return "cpp"
    return None


def normalize_prefix(value: str) -> str:
    """归一化目录前缀，统一成 posix 风格。"""
    normalized = value.strip().strip("/")
    if not normalized:
        return ""
    return Path(normalized).as_posix()


def expand_recursive_glob(pattern: str) -> list[str]:
    patterns = {pattern}
    collapsed = pattern
    while "**/" in collapsed:
        collapsed = collapsed.replace("**/", "", 1)
        patterns.add(collapsed)
    return sorted(patterns)


def normalize_command(value, field_name: str):
    """校验并归一化 shell 命令字段。"""
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        return text or None
    raise ValueError(f"{field_name} must be a shell string")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_projects(path: Path) -> list[ProjectInput]:
    """读取 `projects.in.jsonl` 并转成 ProjectInput 列表。"""
    projects: list[ProjectInput] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            payload = json.loads(line)
            projects.append(
                ProjectInput(
                    project_id=payload.get("project_id", ""),
                    repo_path=payload.get("repo_path", ""),
                    language=payload.get("language", ""),
                    framework=payload.get("framework", ""),
                    default_branch=payload.get("default_branch", ""),
                    extensions=payload.get("extensions") or {},
                )
            )
    return projects


def write_samples(path: Path, samples: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for sample in samples:
            handle.write(json.dumps(sample, ensure_ascii=False))
            handle.write("\n")


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False))
            handle.write("\n")


def derived_stats_output_path(raw_output_path: Path) -> Path:
    """基于 `samples.raw.jsonl` 推导 Stage B 使用的 stats 输出路径。"""
    name = raw_output_path.name
    if not name.endswith(".raw.jsonl"):
        raise ValueError("Stage A output path must end with .raw.jsonl")
    return raw_output_path.with_name(f"{name[:-10]}.stats.jsonl")


def tail_text(text: str, max_lines: int = 40, max_chars: int = 4000) -> str:
    if not text:
        return ""
    lines = text.splitlines()
    if len(lines) > max_lines:
        lines = lines[-max_lines:]
    trimmed = "\n".join(lines)
    if len(trimmed) > max_chars:
        trimmed = trimmed[-max_chars:]
    return trimmed


def ensure_clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def artifact_root_for(output_path: Path, project: ProjectInput) -> Path:
    return output_path.parent / "a.artifacts" / project.project_id


# 3. 环境发现与命令执行
def stage_a_root() -> Path:
    """定位 Stage A 根目录并校验关键配置文件存在。"""
    root = Path(__file__).resolve().parents[1]
    if (root / "config" / "sink_taxonomy.json").is_file():
        return root
    raise ProjectFailure(
        "analysis_setup",
        "stage_a_root_not_found",
        {"expected": str(root / "config" / "sink_taxonomy.json")},
    )


def sink_taxonomy_path() -> Path:
    """返回 analyzer 使用的 sink taxonomy 绝对路径。"""
    path = stage_a_root() / "config" / "sink_taxonomy.json"
    if not path.is_file():
        raise ProjectFailure(
            "analysis_setup",
            "sink_taxonomy_missing",
            {"expected": str(path)},
        )
    return path


def detect_bitcode_format(path: Path) -> str:
    """识别 bitcode/IR/ELF 文件格式，辅助失败诊断。"""
    with path.open("rb") as handle:
        header = handle.read(64)
    if header.startswith(LLVM_BITCODE_MAGIC):
        return "llvm_bitcode"
    if header.startswith(LLVM_BITCODE_WRAPPER_MAGIC):
        return "llvm_bitcode_wrapper"
    if header.startswith(ELF_MAGIC):
        return "elf_object"
    text = header.decode("utf-8", errors="ignore").lstrip()
    if text.startswith("; ModuleID") or text.startswith("source_filename"):
        return "llvm_ir_text"
    return "unknown"


def run_command(stage: str, command, cwd: Path, env: dict[str, str], timeout: int) -> CommandResult:
    """执行一个 Stage A 子阶段命令并保留完整 stdout/stderr。"""
    shell = isinstance(command, str)
    result = subprocess.run(
        command,
        cwd=str(cwd),
        env=env,
        timeout=timeout,
        capture_output=True,
        text=True,
        shell=shell,
        executable="/bin/bash" if shell else None,
    )
    return CommandResult(
        stage=stage,
        command=command,
        cwd=str(cwd),
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def filter_source_file(project: ProjectInput, relative_path: str) -> bool:
    target_subdirs = project.target_subdirs()
    if target_subdirs:
        return any(
            relative_path == prefix or relative_path.startswith(f"{prefix}/")
            for prefix in target_subdirs
        )
    source_globs = project.source_globs()
    if source_globs:
        path = Path(relative_path)
        return any(
            path.match(candidate_pattern)
            for pattern in source_globs
            for candidate_pattern in expand_recursive_glob(pattern)
        )
    return True


def sample_id(
    project_id: str,
    entrypoint_id: str,
    seed_api: str,
    seed_address: str,
    context_signature_tokens: list[str],
) -> str:
    payload = f"{project_id}|{entrypoint_id}|{seed_api}|{seed_address}|{'|'.join(context_signature_tokens)}"
    digest = hashlib.sha1(payload.encode("utf-8")).hexdigest()
    return f"path_{digest[:12]}"


def parse_parameter_list(values: list[Any]) -> list[int]:
    parsed: list[int] = []
    for value in values:
        try:
            parsed.append(int(value))
        except (TypeError, ValueError):
            continue
    return sorted(set(parsed))


def node_order_from_id(node_id: str, fallback: int) -> int:
    try:
        return int(node_id.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return fallback


def sort_node_ids(node_ids: list[str], nodes: dict[str, DfaGraphNode]) -> list[str]:
    return sorted(
        node_ids,
        key=lambda node_id: (
            nodes.get(node_id).order if node_id in nodes else 1_000_000_000,
            node_id,
        ),
    )


def node_token(node: DfaGraphNode) -> str:
    if node.name == "CHECK":
        return "check:CHECK"
    if node.sink_kind:
        return f"{node.sink_kind}:{node.name}"
    return f"call:{node.name}"


def sequence_tokens_for(entry_name: str, path_ids: list[str], nodes: dict[str, DfaGraphNode]) -> list[str]:
    tokens = [f"entry:{entry_name}"]
    tokens.extend(node_token(nodes[node_id]) for node_id in path_ids if node_id in nodes)
    return tokens


def ordered_context_node_ids(
    root_id: str,
    nodes: dict[str, DfaGraphNode],
) -> list[str]:
    if not nodes:
        return []
    ordered = sort_node_ids(list(nodes), nodes)
    if not ordered and root_id in nodes:
        return [root_id]
    return ordered


def context_signature_tokens_for(
    entry_name: str,
    children_map: dict[str, list[str]],
    nodes: dict[str, DfaGraphNode],
    context_node_ids: list[str],
) -> list[str]:
    tokens = graph_edge_tokens(entry_name, children_map, nodes)
    if tokens:
        return tokens
    return sequence_tokens_for(entry_name, context_node_ids, nodes)


def unique_locations(items: list[tuple[str, int]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, int]] = set()
    locations: list[dict[str, Any]] = []
    for file_name, line_no in items:
        if not file_name or line_no <= 0:
            continue
        key = (file_name, line_no)
        if key in seen:
            continue
        seen.add(key)
        locations.append({"file": file_name, "line": line_no})
    return locations


def write_failure_manifest(artifact_root: Path, failure: ProjectFailure) -> None:
    write_json(
        artifact_root / "failures.json",
        [
            {
                "stage": failure.stage,
                "reason": failure.reason,
                "details": failure.details,
                "ts": utc_now(),
            }
        ],
    )


def command_failure(stage_name: str, command, cwd: Path, timeout: int, exc: Exception) -> ProjectFailure:
    if isinstance(exc, FileNotFoundError):
        return ProjectFailure(
            stage_name,
            "command_not_found",
            {
                "command": command,
                "cwd": str(cwd),
                "error": str(exc),
            },
        )
    if isinstance(exc, subprocess.TimeoutExpired):
        return ProjectFailure(
            stage_name,
            "command_timed_out",
            {
                "command": command,
                "cwd": str(cwd),
                "timeout": timeout,
            },
        )
    return ProjectFailure(
        stage_name,
        "command_failed_to_start",
        {
            "command": command,
            "cwd": str(cwd),
            "error": str(exc),
        },
    )


def execute_optional_stage(
    stage_name: str,
    command,
    cwd: Path,
    env: dict[str, str],
    timeout: int,
    run_manifest: dict[str, Any],
) -> None:
    if command is None:
        return
    try:
        result = run_command(stage_name, command, cwd, env, timeout)
    except Exception as exc:
        raise command_failure(stage_name, command, cwd, timeout, exc) from exc
    run_manifest.setdefault("commands", []).append(result.as_manifest())
    if result.returncode != 0:
        raise ProjectFailure(
            stage_name,
            "command_failed",
            {
                "command": command,
                "cwd": str(cwd),
                "returncode": result.returncode,
                "stderr_tail": tail_text(result.stderr),
                "stdout_tail": tail_text(result.stdout),
            },
        )


def collect_bitcode(project: ProjectInput, artifact_root: Path) -> tuple[Path, Path, dict[str, Any]]:
    repo_path = Path(project.repo_path)
    bcfs_root = artifact_root / "bcfs" / project.project_id
    ensure_clean_dir(bcfs_root)

    matches: dict[str, Path] = {}
    for pattern in project.bitcode_globs():
        for candidate in repo_path.glob(pattern):
            if candidate.is_file() and candidate.suffix == ".bc":
                try:
                    relative = candidate.relative_to(repo_path).as_posix()
                except ValueError:
                    continue
                matches[relative] = candidate

    if not matches:
        raise ProjectFailure(
            "bitcode_collect",
            "no_bitcode_found",
            {"patterns": project.bitcode_globs()},
        )

    copied_files = []
    invalid_files = []
    for relative, source_path in sorted(matches.items()):
        destination = bcfs_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination)
        detected_format = detect_bitcode_format(destination)
        copied_files.append(
            {
                "source": relative,
                "copied": destination.relative_to(artifact_root).as_posix(),
                "detected_format": detected_format,
            }
        )
        if detected_format not in {"llvm_bitcode", "llvm_bitcode_wrapper"}:
            invalid_files.append(
                {
                    "source": relative,
                    "copied": destination.relative_to(artifact_root).as_posix(),
                    "detected_format": detected_format,
                }
            )

    bc_list_path = artifact_root / "bc.list"
    with bc_list_path.open("w", encoding="utf-8") as handle:
        for relative in sorted(matches):
            handle.write(str((bcfs_root / relative).resolve()))
            handle.write("\n")

    manifest = {
        "status": "ok",
        "reason": "",
        "patterns": project.bitcode_globs(),
        "bcfs_root": bcfs_root.relative_to(artifact_root).as_posix(),
        "bc_list": bc_list_path.relative_to(artifact_root).as_posix(),
        "file_count": len(copied_files),
        "files": copied_files,
    }
    if invalid_files:
        manifest["status"] = "invalid"
        manifest["reason"] = "non_llvm_bitcode_detected"
    write_json(artifact_root / "bitcode_manifest.json", manifest)
    if invalid_files:
        raise ProjectFailure(
            "bitcode_collect",
            "invalid_bitcode_format",
            {"files": invalid_files},
        )
    return bcfs_root, bc_list_path, manifest


def write_dfa_summary(
    artifact_root: Path,
    dfa_root: Path,
    backend: str,
    toolchain: dict[str, Any] | None = None,
) -> None:
    record_files = [path for path in dfa_root.rglob("*") if path.is_file()]
    timeout_log = dfa_root.parent / "timeout"
    if not record_files:
        details = {"expected": str(dfa_root)}
        if timeout_log.exists():
            details["timeout_log"] = str(timeout_log)
        raise ProjectFailure(
            "dfa_analyzer",
            "dfa_output_empty",
            details,
        )
    payload = {
        "backend": backend,
        "dfa_root": str(dfa_root.relative_to(artifact_root)),
        "record_files": [path.relative_to(dfa_root).as_posix() for path in sorted(record_files)],
        "ts": utc_now(),
    }
    if timeout_log.exists():
        timeout_lines = [
            line.strip()
            for line in timeout_log.read_text(encoding="utf-8", errors="replace").splitlines()
            if line.strip()
        ]
        payload["timeout_log"] = str(timeout_log.relative_to(artifact_root))
        payload["timeout_events"] = len(timeout_lines)
    if toolchain:
        payload["toolchain"] = toolchain
    write_json(artifact_root / "dfa_summary.json", payload)


def read_bitcode_list_file(path: Path) -> list[str]:
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.strip()
    ]


def write_bitcode_list_file(path: Path, bitcode_paths: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for bitcode_path in bitcode_paths:
            handle.write(bitcode_path)
            handle.write("\n")


def plan_analyzer_chunks(
    bitcode_paths: list[str],
    requested_jobs: int,
    workdir: Path,
    dfa_root: Path,
) -> list[AnalyzerChunk]:
    if not bitcode_paths:
        return []
    chunk_count = min(requested_jobs, len(bitcode_paths))
    base_size, extra = divmod(len(bitcode_paths), chunk_count)
    chunk_lists_root = workdir / "analyzer_inputs"
    chunk_lists_root.mkdir(parents=True, exist_ok=True)

    chunks: list[AnalyzerChunk] = []
    start = 0
    for chunk_index in range(chunk_count):
        size = base_size + (1 if chunk_index < extra else 0)
        module_indices = tuple(range(start, start + size))
        bitcode_chunk = [bitcode_paths[module_index] for module_index in module_indices]
        bc_list_path = chunk_lists_root / f"chunk-{chunk_index:03d}.bc.list"
        write_bitcode_list_file(bc_list_path, bitcode_chunk)
        chunks.append(
            AnalyzerChunk(
                chunk_index=chunk_index,
                bc_list_path=bc_list_path,
                output_root=dfa_root.parent / "dfa_chunks" / f"chunk-{chunk_index:03d}",
                module_indices=module_indices,
            )
        )
        start += size
    return chunks


def run_dfa_analyzer_chunk(
    analyzer: AnalyzerBinary,
    project: ProjectInput,
    chunk: AnalyzerChunk,
    sink_config: Path,
    workdir: Path,
    env: dict[str, str],
    timeout: int,
) -> CommandResult:
    command = [
        analyzer.path,
        "--project-id",
        project.project_id,
        "--repo-path",
        project.repo_path,
        "--output-root",
        str(chunk.output_root.resolve()),
        "--bc-list",
        str(chunk.bc_list_path.resolve()),
        "--sink-config",
        str(sink_config),
    ]
    try:
        return run_command(
            f"dfa_analyzer_chunk_{chunk.chunk_index:03d}",
            command,
            workdir,
            env,
            timeout,
        )
    except Exception as exc:
        failure = command_failure("dfa_analyzer", command, workdir, timeout, exc)
        failure.details.update(
            {
                "chunk_index": chunk.chunk_index,
                "chunk_bc_list": str(chunk.bc_list_path),
                "chunk_output_root": str(chunk.output_root),
                "module_indices": list(chunk.module_indices),
            }
        )
        raise failure from exc


def relocate_chunk_outputs(chunk: AnalyzerChunk, dfa_root: Path) -> None:
    local_to_global = {local_index: module_index for local_index, module_index in enumerate(chunk.module_indices)}
    if not chunk.output_root.exists():
        return

    for path in sorted(chunk.output_root.rglob("*")):
        if not path.is_file():
            continue
        try:
            local_index = int(path.name)
        except ValueError as exc:
            raise ProjectFailure(
                "dfa_analyzer",
                "unexpected_chunk_output",
                {
                    "chunk_index": chunk.chunk_index,
                    "path": str(path),
                },
            ) from exc
        if local_index not in local_to_global:
            raise ProjectFailure(
                "dfa_analyzer",
                "unexpected_chunk_output",
                {
                    "chunk_index": chunk.chunk_index,
                    "path": str(path),
                    "local_index": local_index,
                },
            )
        relative_parent = path.parent.relative_to(chunk.output_root)
        destination_dir = dfa_root / relative_parent
        destination_dir.mkdir(parents=True, exist_ok=True)
        destination_path = destination_dir / str(local_to_global[local_index])
        if destination_path.exists():
            raise ProjectFailure(
                "dfa_analyzer",
                "duplicate_chunk_output",
                {
                    "chunk_index": chunk.chunk_index,
                    "path": str(path),
                    "destination": str(destination_path),
                },
            )
        shutil.move(str(path), str(destination_path))

    shutil.rmtree(chunk.output_root, ignore_errors=True)


def merge_chunk_timeout_logs(chunks: list[AnalyzerChunk], dfa_root: Path) -> None:
    timeout_sources = sorted({chunk.output_root.parent / "timeout" for chunk in chunks})
    final_timeout = dfa_root.parent / "timeout"

    for source in timeout_sources:
        if not source.exists() or not source.is_file():
            continue
        final_timeout.parent.mkdir(parents=True, exist_ok=True)
        with source.open("r", encoding="utf-8", errors="replace") as reader:
            with final_timeout.open("a", encoding="utf-8") as writer:
                for line in reader:
                    writer.write(line)
                    if line and not line.endswith("\n"):
                        writer.write("\n")
        source.unlink()

    for source in timeout_sources:
        try:
            source.parent.rmdir()
        except OSError:
            pass


def cleanup_analyzer_chunk_temps(chunks: list[AnalyzerChunk]) -> None:
    temp_dirs: set[Path] = set()
    for chunk in chunks:
        if chunk.bc_list_path.exists():
            chunk.bc_list_path.unlink()
        temp_dirs.add(chunk.bc_list_path.parent)
        temp_dirs.add(chunk.output_root.parent)

    for temp_dir in sorted(temp_dirs, key=lambda path: len(path.parts), reverse=True):
        try:
            temp_dir.rmdir()
        except OSError:
            pass


def bundled_analyzer_binary() -> AnalyzerBinary | None:
    candidate = stage_a_root() / "analyzer" / "llvm-api-analyzer"
    if candidate.exists() and os.access(candidate, os.X_OK):
        return AnalyzerBinary(path=str(candidate), source="workspace")
    return None


def ensure_llvm_api_analyzer(
    run_manifest: dict[str, Any],
    timeout: int,
    env: dict[str, str],
) -> AnalyzerBinary:
    existing = bundled_analyzer_binary()
    if existing is not None:
        return existing

    analyzer_dir = stage_a_root() / "analyzer"
    command = ["make"]
    try:
        result = run_command("analyzer_build", command, analyzer_dir, env, timeout)
    except Exception as exc:
        raise command_failure("analyzer_build", command, analyzer_dir, timeout, exc) from exc
    run_manifest.setdefault("commands", []).append(result.as_manifest())
    if result.returncode != 0:
        raise ProjectFailure(
            "analyzer_build",
            "llvm_api_analyzer_build_failed",
            {
                "command": command,
                "cwd": str(analyzer_dir),
                "returncode": result.returncode,
                "stderr_tail": tail_text(result.stderr),
                "stdout_tail": tail_text(result.stdout),
            },
        )

    built = analyzer_dir / "llvm-api-analyzer"
    if not built.exists() or not os.access(built, os.X_OK):
        raise ProjectFailure(
            "analyzer_build",
            "llvm_api_analyzer_missing_after_build",
            {"expected": str(built)},
        )
    return AnalyzerBinary(path=str(built), source="built_workspace")


def run_dfa_analyzer(
    project: ProjectInput,
    artifact_root: Path,
    bcfs_root: Path,
    bc_list_path: Path,
    timeout: int,
    run_manifest: dict[str, Any],
    env: dict[str, str],
) -> Path:
    workdir = artifact_root / "analysis_workdir"
    ensure_clean_dir(workdir)
    dfa_root = workdir / "tmp" / project.project_id / "dfa"
    ensure_clean_dir(dfa_root)
    dfa_root_abs = dfa_root.resolve()
    bc_list_abs = bc_list_path.resolve()
    requested_jobs = project.analyzer_jobs()
    bitcode_paths = read_bitcode_list_file(bc_list_abs)

    analyzer = ensure_llvm_api_analyzer(run_manifest, timeout, env)
    sink_config = sink_taxonomy_path()
    chunks = plan_analyzer_chunks(bitcode_paths, requested_jobs, workdir, dfa_root)
    if not chunks:
        raise ProjectFailure("dfa_analyzer", "no_bitcode_paths", {"bc_list": str(bc_list_abs)})
    run_manifest["analyzer"] = {
        "kind": "binary",
        "backend": "llvm_api_analyzer",
        "binary": analyzer.path,
        "binary_source": analyzer.source,
        "sink_config": str(sink_config),
        "bc_list": str(bc_list_abs),
        "bcfs_root": str(bcfs_root.resolve()),
        "output_root": str(dfa_root_abs),
        "jobs_requested": requested_jobs,
        "jobs_used": len(chunks),
        "chunks": [
            {
                "chunk_index": chunk.chunk_index,
                "bc_list": str(chunk.bc_list_path.relative_to(artifact_root)),
                "output_root": str(chunk.output_root.relative_to(artifact_root)),
                "module_start": chunk.module_indices[0],
                "module_end": chunk.module_indices[-1],
                "module_count": len(chunk.module_indices),
            }
            for chunk in chunks
        ],
    }

    chunk_results: dict[int, CommandResult] = {}
    chunk_failures: list[ProjectFailure] = []
    with ThreadPoolExecutor(max_workers=len(chunks)) as executor:
        futures = {
            executor.submit(
                run_dfa_analyzer_chunk,
                analyzer,
                project,
                chunk,
                sink_config,
                workdir,
                env,
                timeout,
            ): chunk
            for chunk in chunks
        }
        for future in as_completed(futures):
            chunk = futures[future]
            try:
                chunk_results[chunk.chunk_index] = future.result()
            except ProjectFailure as failure:
                chunk_failures.append(failure)

    for chunk in chunks:
        result = chunk_results.get(chunk.chunk_index)
        if result is not None:
            run_manifest.setdefault("commands", []).append(result.as_manifest())

    if chunk_failures:
        primary_failure = chunk_failures[0]
        if len(chunk_failures) > 1:
            primary_failure.details = dict(primary_failure.details)
            primary_failure.details["chunk_failures"] = [
                {
                    "stage": failure.stage,
                    "reason": failure.reason,
                    "details": failure.details,
                }
                for failure in chunk_failures
            ]
        raise primary_failure

    for chunk in chunks:
        result = chunk_results[chunk.chunk_index]
        if result.returncode != 0:
            raise ProjectFailure(
                "dfa_analyzer",
                "command_failed",
                {
                    "command": result.command,
                    "cwd": result.cwd,
                    "returncode": result.returncode,
                    "stderr_tail": tail_text(result.stderr),
                    "stdout_tail": tail_text(result.stdout),
                    "chunk_index": chunk.chunk_index,
                    "chunk_bc_list": str(chunk.bc_list_path),
                    "chunk_output_root": str(chunk.output_root),
                    "module_indices": list(chunk.module_indices),
                },
            )

    for chunk in chunks:
        relocate_chunk_outputs(chunk, dfa_root)
    merge_chunk_timeout_logs(chunks, dfa_root)
    cleanup_analyzer_chunk_temps(chunks)

    write_dfa_summary(
        artifact_root,
        dfa_root,
        backend="llvm_api_analyzer",
        toolchain={
            "binary": analyzer.path,
            "binary_source": analyzer.source,
        },
    )
    return dfa_root


# 4. DFA 记录回放与源码恢复
def iter_dfa_records(dfa_root: Path):
    """遍历 analyzer 输出目录中的 DFA 记录。"""
    for path in sorted(dfa_root.rglob("*")):
        if not path.is_file():
            continue
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                payload = json.loads(line)
                payload["_record_file"] = path.relative_to(dfa_root).as_posix()
                yield payload


def positive_parameter_arity(parameters: list[Any]) -> int:
    count = 0
    for value in parameters:
        try:
            if int(value) > 0:
                count += 1
        except (TypeError, ValueError):
            continue
    return count


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


def read_source_line(repo_path: Path, file_path: str, line_no: int) -> str:
    if line_no <= 0:
        return ""
    lines = read_source_lines(repo_path, file_path)
    if not lines:
        return ""
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip()
    return ""


def build_record_node_index(record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    nodes: dict[str, dict[str, Any]] = {}
    for item in record.get("path") or []:
        address = str(item.get("address", "")).strip()
        api_name = str(item.get("AP", "")).strip()
        if address and api_name and address not in nodes:
            nodes[address] = item
        for next_item in item.get("direct_next") or []:
            next_address = str(next_item.get("address", "")).strip()
            next_name = str(next_item.get("AP", "")).strip()
            if next_address and next_name and next_address not in nodes:
                nodes[next_address] = next_item
    return nodes


def build_record_graph(
    record: dict[str, Any],
    repo_path: Path,
    source_file: str,
) -> tuple[dict[str, DfaGraphNode], dict[str, set[str]], str]:
    node_index = build_record_node_index(record)
    direct_graph: dict[str, set[str]] = {}
    nodes: dict[str, DfaGraphNode] = {}

    for fallback_order, (node_id, payload) in enumerate(node_index.items()):
        name = str(payload.get("AP", "")).strip()
        if not name:
            continue
        node_file = str(payload.get("file", "")).strip() or source_file
        node_line = int(payload.get("line") or 0)
        source_slice = read_source_line(repo_path, node_file, node_line) or name
        sink_kind = str(payload.get("sink_kind", "")).strip().lower()
        nodes[node_id] = DfaGraphNode(
            node_id=node_id,
            name=name,
            file=node_file,
            line=node_line,
            sink_kind=sink_kind,
            params=parse_parameter_list(payload.get("parameter") or []),
            order=node_order_from_id(node_id, fallback_order),
            source_slice=source_slice,
            call_kind=str(payload.get("call_kind", "")).strip().lower(),
            unresolved_indirect=bool(payload.get("unresolved_indirect")),
            resolved_callees=[
                str(item).strip()
                for item in (payload.get("resolved_callees") or [])
                if str(item).strip()
            ],
            check_kind=str(payload.get("check_kind", "")).strip().lower(),
            condition_text=str(payload.get("condition_text", "")).strip(),
            branch_count=int(payload.get("branch_count") or 0),
        )
        direct_graph.setdefault(node_id, set())

    for item in record.get("path") or []:
        source_id = str(item.get("address", "")).strip()
        if source_id not in nodes:
            continue
        for next_item in item.get("direct_next") or []:
            target_id = str(next_item.get("address", "")).strip()
            if target_id in nodes and target_id != source_id:
                direct_graph.setdefault(source_id, set()).add(target_id)
                direct_graph.setdefault(target_id, set())

    root_id = str(record.get("address", "")).strip()
    return nodes, direct_graph, root_id


def reduce_record_graph(
    graph: dict[str, set[str]],
    nodes: dict[str, DfaGraphNode],
) -> dict[str, list[str]]:
    return {
        node: sort_node_ids(list(children), nodes)
        for node, children in graph.items()
    }


def graph_sources(children_map: dict[str, list[str]]) -> list[str]:
    indegree: dict[str, int] = {node: 0 for node in children_map}
    for children in children_map.values():
        for child in children:
            indegree[child] = indegree.get(child, 0) + 1
    return sorted(node for node, degree in indegree.items() if degree == 0)


def graph_leaves(children_map: dict[str, list[str]]) -> list[str]:
    return sorted(node for node, children in children_map.items() if not children)


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


def normalized_warning_list(*groups: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for group in groups:
        for item in group:
            warning = str(item).strip()
            if not warning or warning in seen:
                continue
            seen.add(warning)
            ordered.append(warning)
    return ordered


def path_evidence_slice(path_ids: list[str], nodes: dict[str, DfaGraphNode]) -> str:
    snippets = unique_text(
        [nodes[node_id].source_slice for node_id in path_ids if node_id in nodes and nodes[node_id].source_slice]
    )
    return "\n".join(snippets)


def classify_source_name(name: str) -> str | None:
    lowered = name.strip().lower()
    if not lowered:
        return None
    if lowered in SOURCE_KIND_EXACT:
        return SOURCE_KIND_EXACT[lowered]
    for prefix, kind in SOURCE_KIND_PREFIX:
        if lowered.startswith(prefix):
            return kind
    return None


def build_source_candidates(nodes: dict[str, DfaGraphNode]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for node_id in sort_node_ids(list(nodes), nodes):
        node = nodes[node_id]
        source_kind = classify_source_name(node.name)
        if source_kind is None:
            continue
        candidates.append(
            {
                "id": node.node_id,
                "kind": source_kind,
                "call": node.name,
                "file": node.file,
                "line": node.line,
                "token": node_token(node),
            }
        )
    return candidates


def shortest_path_between(
    children_map: dict[str, list[str]],
    start_id: str,
    goal_id: str,
    nodes: dict[str, DfaGraphNode],
) -> list[str]:
    if start_id == goal_id:
        return [start_id]

    queue: list[str] = [start_id]
    parents: dict[str, str | None] = {start_id: None}
    cursor = 0
    while cursor < len(queue):
        current = queue[cursor]
        cursor += 1
        for child_id in sort_node_ids(children_map.get(current) or [], nodes):
            if child_id in parents:
                continue
            parents[child_id] = current
            if child_id == goal_id:
                path: list[str] = [goal_id]
                walker: str | None = current
                while walker is not None:
                    path.append(walker)
                    walker = parents[walker]
                path.reverse()
                return path
            queue.append(child_id)
    return []


def build_source_sink_flows(
    source_candidates: list[dict[str, Any]],
    sink_candidates: list[dict[str, Any]],
    children_map: dict[str, list[str]],
    nodes: dict[str, DfaGraphNode],
) -> list[dict[str, Any]]:
    flows: list[dict[str, Any]] = []
    for source in source_candidates:
        source_id = str(source.get("id", "")).strip()
        if source_id not in nodes:
            continue
        for sink in sink_candidates:
            sink_id = str(sink.get("address", "")).strip()
            if sink_id not in nodes:
                continue
            if sink_id == source_id:
                continue
            trace_node_ids = shortest_path_between(children_map, source_id, sink_id, nodes)
            if not trace_node_ids:
                continue
            flows.append(
                {
                    "source_id": source_id,
                    "sink_id": sink_id,
                    "status": "candidate",
                    "flow_kind": "related",
                    "trace_node_ids": trace_node_ids,
                }
            )
    flows.sort(
        key=lambda item: (
            len(item.get("trace_node_ids") or []),
            str(item.get("source_id", "")),
            str(item.get("sink_id", "")),
        )
    )
    return flows[:3]


def build_sink_candidates(nodes: dict[str, DfaGraphNode]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for node_id in sort_node_ids(list(nodes), nodes):
        node = nodes[node_id]
        if not node.sink_kind:
            continue
        candidates.append(
            {
                "type": node.sink_kind,
                "call": node.name,
                "file": node.file,
                "line": node.line,
                "address": node.node_id,
                "parameter": node.params,
                "token": node_token(node),
                "source_slice": node.source_slice,
            }
        )
    return candidates


def build_graph_payload(
    nodes: dict[str, DfaGraphNode],
    direct_children_map: dict[str, list[str]],
    root_id: str,
) -> dict[str, Any]:
    ordered_node_ids = sort_node_ids(list(nodes), nodes)
    direct_edges: list[dict[str, Any]] = []
    for node_id in ordered_node_ids:
        for child_id in sort_node_ids(direct_children_map.get(node_id) or [], nodes):
            if child_id not in nodes:
                continue
            source = nodes[node_id]
            target = nodes[child_id]
            direct_edges.append(
                {
                    "from": source.node_id,
                    "to": target.node_id,
                    "from_name": source.name,
                    "to_name": target.name,
                    "from_token": node_token(source),
                    "to_token": node_token(target),
                }
            )

    return {
        "nodes": [
            {
                "id": node.node_id,
                "name": node.name,
                "token": node_token(node),
                "file": node.file,
                "line": node.line,
                "parameter": node.params,
                "sink_kind": node.sink_kind,
                "source_slice": node.source_slice,
                "call_kind": node.call_kind,
                "unresolved_indirect": node.unresolved_indirect,
                "resolved_callees": node.resolved_callees,
                "check_kind": node.check_kind,
                "condition_text": node.condition_text,
                "branch_count": node.branch_count,
                "is_seed": node.node_id == root_id,
                "is_check": node.name == "CHECK",
            }
            for node_id in ordered_node_ids
            for node in [nodes[node_id]]
        ],
        "direct_edges": direct_edges,
        "roots": sort_node_ids(graph_sources(direct_children_map), nodes),
        "leaves": sort_node_ids(graph_leaves(direct_children_map), nodes),
        "checks": [
            node_id
            for node_id in ordered_node_ids
            if nodes[node_id].name == "CHECK"
        ],
    }


def graph_edge_tokens(
    entry_name: str,
    children_map: dict[str, list[str]],
    nodes: dict[str, DfaGraphNode],
) -> list[str]:
    entry_token = f"entry:{entry_name}"
    ordered_edges: list[str] = []
    seen: set[str] = set()

    for source_id in sort_node_ids(graph_sources(children_map), nodes):
        if source_id not in nodes:
            continue
        edge = f"{entry_token}->{node_token(nodes[source_id])}"
        if edge not in seen:
            seen.add(edge)
            ordered_edges.append(edge)

    for node_id in sort_node_ids(list(children_map), nodes):
        if node_id not in nodes:
            continue
        for child_id in sort_node_ids(children_map.get(node_id) or [], nodes):
            if child_id not in nodes:
                continue
            edge = f"{node_token(nodes[node_id])}->{node_token(nodes[child_id])}"
            if edge not in seen:
                seen.add(edge)
                ordered_edges.append(edge)

    return ordered_edges


def source_locations_for_sample(
    source_file: str,
    source_line: int,
    nodes: dict[str, DfaGraphNode],
) -> list[dict[str, Any]]:
    locations = [(source_file, source_line)]
    for node_id in sort_node_ids(list(nodes), nodes):
        node = nodes[node_id]
        locations.append((node.file, node.line))
    return unique_locations(locations)


def sample_seed_id(sample: dict[str, Any]) -> str:
    seed = sample.get("seed") or {}
    return str(seed.get("id") or seed.get("address") or "").strip()


def sample_direct_edges(sample: dict[str, Any]) -> list[dict[str, Any]]:
    graph = sample.get("graph", {}) or {}
    direct_edges = graph.get("direct_edges")
    if isinstance(direct_edges, list):
        return direct_edges
    return []


def sample_direct_edge_tokens(sample: dict[str, Any]) -> list[str]:
    tokens: list[str] = []
    for edge in sample_direct_edges(sample):
        source_token = str(edge.get("from_token", "")).strip()
        target_token = str(edge.get("to_token", "")).strip()
        if source_token and target_token:
            tokens.append(f"{source_token}->{target_token}")
    return unique_text(tokens)


# 5. 派生视图构建
def stats_records_for_samples(samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """从 canonical raw samples 派生 `samples.stats.jsonl` 记录。"""
    location_keys = sorted(
        {
            json.dumps(
                {
                    "file": str(sample.get("entrypoint", {}).get("file", "")).strip(),
                    "function": str(sample.get("entrypoint", {}).get("function", "")).strip(),
                },
                sort_keys=True,
            )
            for sample in samples
        }
    )
    edge_tokens = sorted(
        {
            token
            for sample in samples
            for token in sample_direct_edge_tokens(sample)
        }
    )
    location_ids = {key: index for index, key in enumerate(location_keys)}
    edge_ids = {token: index for index, token in enumerate(edge_tokens)}

    records: list[dict[str, Any]] = []
    for sample in samples:
        entrypoint = sample.get("entrypoint") or {}
        location = {
            "file": str(entrypoint.get("file", "")).strip(),
            "function": str(entrypoint.get("function", "")).strip(),
        }
        location_key = json.dumps(location, sort_keys=True)
        tokens = sample_direct_edge_tokens(sample)
        records.append(
            {
                "project_id": sample.get("project_id", ""),
                "sample_id": sample.get("sample_id", ""),
                "location_id": location_ids[location_key],
                "location": location,
                "seed_id": sample_seed_id(sample),
                "seed_token": str(sample.get("seed", {}).get("token", "")).strip(),
                "edge_ids": [edge_ids[token] for token in tokens],
                "edge_tokens": tokens,
                "source_kinds": unique_text(
                    [str(item.get("kind", "")).strip() for item in (sample.get("source_candidates") or [])]
                ),
                "sink_types": unique_text(
                    [str(item.get("type", "")).strip() for item in (sample.get("sink_candidates") or [])]
                ),
                "focus": sample.get("focus", {}),
            }
        )
    return records


def write_stats_output(raw_output_path: Path, samples: list[dict[str, Any]]) -> None:
    """写出 Stage B 使用的 stats 派生视图。"""
    stats_path = derived_stats_output_path(raw_output_path)
    write_jsonl(stats_path, stats_records_for_samples(samples))


def best_focus_location(
    sink_candidates: list[dict[str, Any]],
    seed_node: DfaGraphNode,
) -> tuple[str, int]:
    if sink_candidates:
        best = sorted(
            sink_candidates,
            key=lambda item: (
                item.get("line", 0),
                item.get("call", ""),
            ),
        )[0]
        return str(best.get("file", "")), int(best.get("line", 0) or 0)
    return seed_node.file, seed_node.line


# 6. 样本恢复与主流程
def record_to_sample(
    project: ProjectInput,
    repo_path: Path,
    record: dict[str, Any],
    bitcode_status: dict[str, Any],
) -> dict[str, Any] | None:
    """将单条 analyzer 记录恢复成 canonical sample。"""
    source_file = str(record.get("file", "")).strip()
    function_name = str(record.get("function", "")).strip()
    root_api = str(record.get("API", "")).strip()
    root_id = str(record.get("address", "")).strip()
    if not source_file or not function_name or not root_api or not root_id:
        return None
    if not filter_source_file(project, source_file):
        return None
    if project.entry_functions() and function_name not in set(project.entry_functions()):
        return None

    nodes, direct_graph, root_id = build_record_graph(record, repo_path, source_file)
    if not nodes or not direct_graph or root_id not in nodes:
        return None

    direct_children_map = reduce_record_graph(direct_graph, nodes)
    context_node_ids = ordered_context_node_ids(root_id, nodes)

    entrypoint_id = f"{source_file}::{function_name}"
    source_line = int(record.get("function_line") or 0)
    context_signature_tokens = context_signature_tokens_for(function_name, direct_children_map, nodes, context_node_ids)
    source_candidates = build_source_candidates(nodes)
    sink_candidates = build_sink_candidates(nodes)
    source_sink_flows = build_source_sink_flows(source_candidates, sink_candidates, direct_children_map, nodes)
    sink_locs = [
        {
            "type": candidate["type"],
            "call": candidate["call"],
            "file": candidate["file"],
            "line": candidate["line"],
        }
        for candidate in sink_candidates
    ]
    seed_node = nodes[root_id]
    focus_file, focus_line = best_focus_location(sink_candidates, seed_node)
    record_warnings = [
        str(item).strip()
        for item in (record.get("analysis_warnings") or [])
        if str(item).strip()
    ]
    analyzer_stats = record.get("analysis_stats") or {}
    indirect_call_stats = record.get("indirect_call_stats") or {}
    analysis_warnings = normalized_warning_list(record_warnings)
    evidence_slice = path_evidence_slice(context_node_ids, nodes) or seed_node.source_slice or seed_node.name
    graph_payload = build_graph_payload(nodes, direct_children_map, root_id)
    seed_params = parse_parameter_list(record.get("parameter") or [])
    sample = {
        "project_id": project.project_id,
        "sample_id": sample_id(project.project_id, entrypoint_id, root_api, root_id, context_signature_tokens),
        "language": normalize_language(project.language),
        "framework": project.framework,
        "entrypoint": {
            "id": entrypoint_id,
            "file": source_file,
            "function": function_name,
            "line": source_line,
        },
        "source_locs": source_locations_for_sample(source_file, source_line, nodes),
        "sink_locs": sink_locs,
        "evidence_slice": evidence_slice,
        "source_candidates": source_candidates,
        "sink_candidates": sink_candidates,
        "source_sink_flows": source_sink_flows,
        "analysis_backend": CANONICAL_ANALYSIS_BACKEND,
        "context_mode": "seed_full_context",
        "api_group": f"seed:{root_api}",
        "context_signature_tokens": context_signature_tokens,
        "bitcode": {
            "status": bitcode_status.get("status", ""),
            "reason": bitcode_status.get("reason", ""),
        },
        "dfa": {
            "api": root_api,
            "parameter_arity": positive_parameter_arity(seed_params),
            "record_file": record.get("_record_file", ""),
        },
        "seed": {
            "id": root_id,
            "api": root_api,
            "address": root_id,
            "parameter": seed_params,
            "file": seed_node.file,
            "line": seed_node.line,
            "token": node_token(seed_node),
            "evidence_slice": seed_node.source_slice,
        },
        "graph": graph_payload,
        "analysis_warnings": analysis_warnings,
        "analyzer_stats": analyzer_stats,
        "indirect_call_stats": indirect_call_stats,
        "focus": {
            "file": focus_file,
            "line": focus_line,
        },
        "graph_stats": {
            "node_count": len(graph_payload["nodes"]),
            "edge_count": len(graph_payload["direct_edges"]),
        },
        "timestamps": {"mined_at": utc_now()},
    }
    return sample


def normalize_dfa(project: ProjectInput, artifact_root: Path, dfa_root: Path) -> list[dict]:
    """归一化 DFA 目录并恢复去重后的 canonical samples。"""
    repo_path = Path(project.repo_path)
    bitcode_status = {
        "status": "ok",
        "reason": "",
        "compiler": "external_build",
        "files": [],
    }
    seen_records = 0
    deduped: dict[str, dict[str, Any]] = {}
    for record in iter_dfa_records(dfa_root):
        seen_records += 1
        sample = record_to_sample(project, repo_path, record, bitcode_status)
        if sample is not None:
            deduped.setdefault(sample["sample_id"], sample)

    if seen_records == 0:
        raise ProjectFailure("normalize_dfa", "no_dfa_records")
    if not deduped:
        raise ProjectFailure("normalize_dfa", "no_seed_samples_recovered")

    normalized_samples = sorted(deduped.values(), key=lambda sample: sample["sample_id"])
    return normalized_samples


def formal_mine(project: ProjectInput, artifact_root: Path) -> list[dict]:
    """执行 Stage A 单项目正式流程。"""
    run_manifest: dict[str, Any] = {
        "project_id": project.project_id,
        "analysis_backend": project.backend_mode(),
        "started_at": utc_now(),
        "commands": [],
    }

    repo_path = Path(project.repo_path)
    if not repo_path.exists():
        raise FileNotFoundError(project.repo_path)
    if not repo_path.is_dir():
        raise ValueError("repo_path is not a directory")

    build_cwd = project.build_cwd()
    if not build_cwd.exists():
        raise ProjectFailure("build_setup", "build_cwd_missing", {"build_cwd": str(build_cwd)})
    if not build_cwd.is_dir():
        raise ProjectFailure("build_setup", "build_cwd_not_directory", {"build_cwd": str(build_cwd)})

    env = os.environ.copy()
    env.update(project.build_env())
    source_globs = project.source_globs()
    if source_globs and COMPILE_COMMANDS_SOURCE_GLOBS_ENV not in env:
        env[COMPILE_COMMANDS_SOURCE_GLOBS_ENV] = json.dumps(source_globs, ensure_ascii=False)
    timeout = project.analysis_timeout()
    try:
        execute_optional_stage(
            "config",
            project.config_command(),
            build_cwd,
            env,
            timeout,
            run_manifest,
        )
        execute_optional_stage(
            "build",
            project.build_command(),
            build_cwd,
            env,
            timeout,
            run_manifest,
        )

        bcfs_root, bc_list_path, bitcode_manifest = collect_bitcode(project, artifact_root)
        run_manifest["bitcode_manifest"] = bitcode_manifest
        dfa_root = run_dfa_analyzer(
            project,
            artifact_root,
            bcfs_root,
            bc_list_path,
            timeout,
            run_manifest,
            env,
        )
        samples = normalize_dfa(project, artifact_root, dfa_root)
        run_manifest["sample_count"] = len(samples)
        return samples
    except ProjectFailure as failure:
        run_manifest["failure"] = {
            "stage": failure.stage,
            "reason": failure.reason,
            "details": failure.details,
        }
        raise
    finally:
        run_manifest["finished_at"] = utc_now()
        write_json(artifact_root / "run_manifest.json", run_manifest)


def mine(project: ProjectInput, output_path: Path) -> list[dict]:
    """包装正式流程，并在失败时落盘 failure manifest。"""
    artifact_root = artifact_root_for(output_path, project)
    ensure_clean_dir(artifact_root)

    try:
        return formal_mine(project, artifact_root)
    except ProjectFailure as failure:
        write_failure_manifest(artifact_root, failure)
        raise


def prepare_project(project: ProjectInput, base_dir: Path) -> bool:
    try:
        project.normalize(base_dir)
        project.validate()
    except Exception as exc:
        print(f'skip invalid project "{project.project_id}": {exc}', file=sys.stderr)
        return False
    return True


def run_project(project: ProjectInput, output_path: Path) -> list[dict] | None:
    try:
        return mine(project, output_path)
    except ProjectFailure as exc:
        print(
            f'mine failed for "{project.project_id}" during {exc.stage}: {exc.reason}',
            file=sys.stderr,
        )
    except Exception as exc:
        print(f'mine failed for "{project.project_id}": {exc}', file=sys.stderr)
    return None


def write_outputs(output_path: Path, samples: list[dict[str, Any]]) -> None:
    write_samples(output_path, samples)
    write_stats_output(output_path, samples)


def main() -> None:
    """Stage A CLI 入口。"""
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)
    base_dir = input_path.parent.resolve()

    try:
        projects = read_projects(input_path)
    except Exception as exc:
        print(f"read input failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    all_samples: list[dict] = []
    for project in projects:
        if not prepare_project(project, base_dir):
            continue

        samples = run_project(project, output_path)
        if samples is None:
            continue
        all_samples.extend(samples)

    all_samples.sort(key=lambda sample: (sample.get("project_id", ""), sample.get("sample_id", "")))

    try:
        write_outputs(output_path, all_samples)
    except Exception as exc:
        print(f"write output failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    print(f"wrote {len(all_samples)} samples to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
