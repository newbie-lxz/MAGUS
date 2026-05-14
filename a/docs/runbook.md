# Runbook

## Prerequisites

- Python 3
- `clang` or another LLVM-capable frontend for target bitcode builds
- `llvm-config`
- C++ compiler capable of building the analyzer

## Common Commands

- Build analyzer: `make build-analyzer`
- Run Stage `A`: `make run-a`
- Export optional LLM evidence: `make run-llm`
- Direct run:

```bash
python3 cmd/miner.py --input input/zlib.in.jsonl --output out/samples.raw.jsonl
```

The Stage `A` output path must end with `.raw.jsonl`; the miner derives the sibling `.stats.jsonl` output from that name.

Optional LLM evidence export:

```bash
python3 cmd/llm_export.py --input out/samples.raw.jsonl --projects input/zlib.in.jsonl
```

SecVulEval planning helpers:

```bash
python3 cmd/secvuleval_prepare.py --dataset input/SecVulEval/data/train-00000-of-00001.parquet
python3 cmd/secvuleval_batch.py --input out/secvuleval/stagea.projects.in.jsonl --output-root out
```

These helpers keep generated planning files under `out/secvuleval/`, use source checkouts under `input/secvuleval/src/`, and write Stage `A` batch outputs under `out/<project_id>/`. The batch runner resolves relative `repo_path` values against the original batch input file before writing per-project inputs.

The bundled input file targets a repository-local zlib checkout at `input/zlib` through the relative `repo_path` value in `input/zlib.in.jsonl`. If you move the checkout elsewhere, update `input/zlib.in.jsonl`.

Analyzer process parallelism is required:

- set `extensions.analyzer_jobs` to an integer greater than `1`; Stage `A` splits `bc.list` across that many analyzer subprocesses, capped by the number of bitcode files
- use moderate values first; each analyzer subprocess parses LLVM bitcode independently, so memory pressure rises with the job count
- after a successful parallel run, temporary chunk input lists and chunk output directories are removed after DFA records and timeout logs are reassembled

Analyzer timeout thresholds are fixed:

- instruction/root scope: `60` seconds
- function scope: `3600` seconds
- file scope: `36000` seconds

## Outputs

- normalized samples: `out/samples.raw.jsonl`
- stats samples: `out/samples.stats.jsonl` for frequency mining over `edge_tokens`, `seed_token`, `sink_types`, and `location`
- per-project artifacts: `out/a.artifacts/<project_id>/`
- SecVulEval batch project outputs: `out/<project_id>/samples.raw.jsonl`, `out/<project_id>/samples.stats.jsonl`, `out/<project_id>/batch.result.json`, and `out/<project_id>/a.artifacts/<project_id>/`
- SecVulEval planning files: `out/secvuleval/`
- SecVulEval source checkouts: `input/secvuleval/src/`

Optional output:

- llm samples from `cmd/llm_export.py`: `out/samples.llm.jsonl`

Important artifact files:

- `run_manifest.json`
- `bitcode_manifest.json`
- `dfa_summary.json`
- `failures.json` when a project fails

## Troubleshooting

Zero samples:

- inspect `out/<project_id>/batch.result.json` for SecVulEval batch runs; a miner non-zero exit, failure manifest, or zero raw sample count marks the project failed
- inspect `out/a.artifacts/<project_id>/failures.json` for direct runs or `out/<project_id>/a.artifacts/<project_id>/failures.json` for batch runs
- inspect `out/a.artifacts/<project_id>/run_manifest.json` for direct runs or `out/<project_id>/a.artifacts/<project_id>/run_manifest.json` for batch runs
- confirm `extensions.build_cmd` really emits LLVM `.bc`
- confirm `extensions.bitcode_globs` match real files
- inspect `run_manifest.json` to see which analyzer chunk failed and which module range it owned; successful runs clean up chunk temp files
- if the build recipe uses `cmd/compile_commands_to_bc.py`, confirm `extensions.source_globs` is narrow enough for large repositories; otherwise the helper may lower far more translation units than Stage `A` needs

Analyzer build fails:

- verify `llvm-config` is on `PATH`
- verify `clang++` or `g++` is available
- run `make -C analyzer` directly

Unexpected graph output:

- inspect `graph.nodes`, `graph.direct_edges`, `graph.roots`, and `graph.leaves`
- inspect `source_candidates`, `sink_candidates`, and `source_sink_flows`
- inspect `analyzer_stats.cross_function_budget_hit` when expected same-module callees are absent
- inspect `out/samples.stats.jsonl` if frequency mining behavior looks wrong
- run `cmd/llm_export.py` and inspect `out/samples.llm.jsonl` if explanation payloads, internal function summaries, or code evidence look wrong
- inspect `analysis_warnings` and `graph_stats`
- remember that `source_sink_flows` is best-effort candidate evidence, not a confirmed proof
- remember that raw Stage `A` samples intentionally retain ordinary non-LLVM helper calls like `free`, logging, and string utilities when they are seed-related; task-specific denoising belongs downstream

Large-project normalization pressure:

- if DFA itself is the bottleneck and the host has spare CPU and memory, increase `extensions.analyzer_jobs` before increasing timeout values
- if a repository still pushes the host too hard, first reduce `extensions.source_globs` and re-run before increasing timeouts
