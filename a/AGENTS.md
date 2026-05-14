# Stage A Agent Guide

## Scope

- This repository contains only Stage `A` from APIagents.
- Stage `A` is a build-based static-analysis pipeline that mines seed-centric API context samples from LLVM bitcode.
- Do not describe this repository as a web project or a framework-specific endpoint analyzer.
- The orchestration layer is implemented in Python.
- The bundled analyzer is implemented in C++ with LLVM.

## Repo Map

- `cmd/miner.py`: Stage `A` entrypoint and normalization pipeline.
- `cmd/llm_export.py`: optional LLM evidence exporter for existing raw samples.
- `cmd/secvuleval_batch.py`: SecVulEval batch runner that writes one `out/<project_id>/` folder per Stage `A` project.
- `analyzer/llvm_api_analyzer.cpp`: bundled LLVM API-level analyzer.
- `analyzer/Makefile`: local build entry for the analyzer binary.
- `config/sink_taxonomy.json`: analyzer sink classification taxonomy.
- `input/zlib.in.jsonl`: default local zlib input.
- `input/zlib/`: repository-local zlib checkout used by the bundled input.
- `input/secvuleval/src/`: local SecVulEval source checkouts used by generated project records.
- `contracts/README.md`: Stage `A` input/output contract.
- `docs/architecture.md`: implementation notes and limits.
- `docs/runbook.md`: run and troubleshooting instructions.

## Current Behavior

- Stage `A` has one formal execution path: build, collect `.bc`, run DFA, normalize JSON.
- `extensions.build_cmd` is required.
- `extensions.build_cmd` and optional `extensions.config_cmd` are shell strings.
- `extensions.analyzer_jobs` is required and must be greater than `1`.
- Stage `A` splits `bc.list` into contiguous chunks so analyzer subprocesses run in parallel before Stage `A` reassembles stable module-indexed DFA output and removes successful-run chunk temp files.
- The analyzer owns sink classification through `config/sink_taxonomy.json`; normalization consumes emitted `sink_kind`.
- Project artifacts are written under `out/a.artifacts/<project_id>/`.
- SecVulEval batch outputs are written under `out/<project_id>/`.
- SecVulEval source checkouts live under `input/secvuleval/src/`, not under `out/`.
- Project failures are written to `failures.json`.
- Normalized output is `samples.raw.jsonl`.
- Stage `A` output paths must end with `.raw.jsonl`.
- Default derived output is `samples.stats.jsonl`.
- `samples.llm.jsonl` is optional and generated only by the explicit LLM export command.
- Relative `repo_path` values are resolved against the directory containing the input file.
- The bundled `input/zlib.in.jsonl` resolves `repo_path: "zlib"` to the repository-local checkout at `input/zlib`.
- Normalized samples expose `graph.direct_edges` as the downstream graph.
- Normalized samples include best-effort `source_candidates`, `sink_candidates`, and `source_sink_flows`.
- `samples.llm.jsonl` includes budgeted best-effort `internal_function_summaries` for project-local functions referenced by sample graph nodes; this is LLM evidence only and does not replace `graph.direct_edges`.

## Commands

- `make build-analyzer`
- `make run-a`
- `make run-llm`
- `python3 cmd/miner.py --input input/zlib.in.jsonl --output out/samples.raw.jsonl`
- `python3 cmd/llm_export.py --input out/samples.raw.jsonl --projects input/zlib.in.jsonl`

## Sync Rules

- Keep the Stage `A` sample contract in `contracts/README.md` stable unless behavior intentionally changes.
- Keep `samples.raw.jsonl`, `samples.stats.jsonl`, and optional `samples.llm.jsonl` field names, nesting, and core semantics backward-compatible by default; do not change output shape casually.
- If Stage `A` behavior changes, update `README.md`, `contracts/README.md`, `docs/architecture.md`, and `docs/runbook.md` in the same change.
- Do not claim local verification unless the command was actually run in the current environment.
