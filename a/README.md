# Stage A

This repository is the standalone Stage `A` extraction from `APIagents`.

Stage `A` builds target projects to LLVM bitcode, runs the bundled LLVM API-level analyzer, and normalizes the analyzer records into seed-centric `samples.raw.jsonl` output.

## Layout

- `cmd/miner.py`: Python entrypoint
- `cmd/llm_export.py`: optional LLM evidence exporter for existing raw samples
- `cmd/secvuleval_batch.py`: SecVulEval batch runner that writes one output folder per project under `out/`
- `analyzer/`: LLVM analyzer source and build rules
- `config/sink_taxonomy.json`: analyzer sink taxonomy
- `input/zlib.in.jsonl`: bundled local zlib input
- `input/zlib/`: repository-local zlib checkout used by the bundled input
- `input/secvuleval/src/`: local SecVulEval source checkouts used by generated project records
- `contracts/README.md`: input/output contract
- `docs/`: architecture and runbook

## Commands

- Build analyzer: `make build-analyzer`
- Run Stage `A`: `make run-a`
- Direct run: `python3 cmd/miner.py --input input/zlib.in.jsonl --output out/samples.raw.jsonl`
- Optional LLM evidence export: `make run-llm`
- SecVulEval batch run: `python3 cmd/secvuleval_batch.py --input out/secvuleval/stagea.projects.in.jsonl --output-root out`

## Current Behavior

- accepts only the build-based LLVM DFA backend
- requires `extensions.build_cmd`
- accepts `extensions.build_cmd` and optional `extensions.config_cmd` as shell strings
- requires `extensions.analyzer_jobs` greater than `1`
- builds and validates LLVM bitcode before analysis
- forwards `extensions.source_globs` into compile-commands bitcode replay when that helper is used, so large repositories can restrict `.bc` generation to Stage `A` target files
- splits `bc.list` across analyzer subprocesses, then reassembles stable module-indexed DFA output before normalization
- runs the bundled analyzer from `analyzer/`
- uses the bundled `input/zlib.in.jsonl` to target the repository-local checkout at `input/zlib`
- uses `input/secvuleval/src/` for SecVulEval source checkouts; `out/` is reserved for planning files and analysis outputs
- preserves the original input-file base for relative `repo_path` values when running SecVulEval projects through the per-project batch runner
- retains non-intrinsic call operations in raw samples instead of pre-filtering ordinary helpers like allocation, free, logging, or string utilities
- writes project artifacts under `out/a.artifacts/<project_id>/`
- SecVulEval batch output is written under `out/<project_id>/`, including `samples.raw.jsonl`, `samples.stats.jsonl`, `batch.result.json`, and that project's artifacts; a miner failure manifest or zero raw samples marks that project failed
- emits one normalized source-sink-aware sample per analyzer seed record into `samples.raw.jsonl`
- requires the Stage `A` output path to end with `.raw.jsonl` so derived output names are unambiguous
- derives `samples.stats.jsonl` for frequency mining
- exports `samples.llm.jsonl` only through the explicit `cmd/llm_export.py` command for LLM-facing evidence payloads, including budgeted internal function summaries
- relies on analyzer timeouts instead of node-count or retained-path count caps
- exposes `graph.direct_edges` as the structural graph exported to downstream consumers
- exports best-effort `source_candidates`, `sink_candidates`, and `source_sink_flows` for downstream ranking and LLM handoff; these are candidate relations, not confirmed vulnerabilities
- reports `cross_function_budget_hit` in analyzer stats and warnings when the same-module callee expansion depth budget stops traversal
- uses the bundled analyzer and taxonomy from this Stage `A` tree only

See [`contracts/README.md`](./contracts/README.md) for field semantics and [`docs/runbook.md`](./docs/runbook.md) for operating steps.
