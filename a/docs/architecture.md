# Architecture

## Pipeline

Stage `A` performs four steps:

1. Read `projects.in.jsonl`.
2. Run the configured build command and collect LLVM bitcode.
3. Execute the bundled LLVM API-level analyzer over the collected `.bc` files.
4. Normalize analyzer records into seed-centric `samples.raw.jsonl`.

## Components

- `cmd/miner.py` orchestrates project execution, bitcode validation, analyzer execution, and normalization.
- `cmd/llm_export.py` is an optional exporter that builds LLM evidence records from existing raw samples and the matching project input file.
- `cmd/secvuleval_batch.py` runs Stage `A` over SecVulEval project JSONL records, resolves relative `repo_path` values against the original batch input file, writes each project's outputs under `out/<project_id>/`, and treats miner failure manifests or zero raw samples as per-project failures.
- when build recipes replay `compile_commands.json` through `cmd/compile_commands_to_bc.py`, `cmd/miner.py` forwards `extensions.source_globs` so bitcode generation can stay scoped to Stage `A` target files
- `cmd/miner.py` requires `extensions.analyzer_jobs` greater than `1`, splits `bc.list` into contiguous chunks, launches analyzer subprocesses in parallel, reassembles stable module-indexed DFA bucket files before normalization, and removes successful-run chunk temp files
- `analyzer/llvm_api_analyzer.cpp` reconstructs related-operation graphs around API seeds using FRV/BRV propagation plus CFG-recursive `APIPath` construction.
- `config/sink_taxonomy.json` is the analyzer's sink classification source; Python normalization consumes the analyzer-emitted `sink_kind`.
- `input/zlib.in.jsonl` is the default local CLI input for the bundled zlib target and resolves to the repository-local checkout at `input/zlib`.
- SecVulEval project records use source checkouts under `input/secvuleval/src/`; `out/secvuleval/` is reserved for generated planning metadata and `out/<project_id>/` for per-project analysis outputs.
- the default derived export from canonical samples is `samples.stats.jsonl` for pattern mining
- `samples.llm.jsonl` is an optional evidence-oriented export produced only by `cmd/llm_export.py`

## Graph Semantics

- same-module direct callees are expanded structurally
- bounded static indirect-call recovery is best-effort
- minimal callee summaries can propagate return and pointer-write tags back to the caller
- caller flow remains connected after callee expansion when analysis returns to the caller body
- ordinary non-LLVM call sites are preserved in raw samples even when they look like housekeeping, because they may participate in resource lifetime, error handling, double-fetch, or ordering patterns
- same-module callee expansion records `cross_function_budget_hit` when the configured depth budget prevents deeper traversal
- analysis termination is governed by fixed instruction/function/file timeout thresholds rather than node-count or retained-path caps
- analyzer records serialize each node with direct structural edges in `direct_next`
- normalized samples expose `graph.direct_edges` as the downstream graph
- normalized samples also export best-effort `source_candidates`, `sink_candidates`, and representative `source_sink_flows`
- derived stats samples flatten `graph.direct_edges` into normalized `edge_ids`/`edge_tokens` while retaining `sample_id` as the join key
- optional LLM samples keep graph excerpts, representative traces, local code windows, and budgeted internal function summaries instead of forwarding the full normalized graph
- optional LLM internal function summaries normalize C++/Itanium symbols before matching analyzer callees to source function blocks

## Limits

- only the LLVM DFA path is supported
- the standalone miner resolves its analyzer and sink taxonomy from this repository only
- the target project must already be buildable to LLVM bitcode
- interprocedural expansion remains conservative and same-module only
- LLVM intrinsics and common toolchain-injected runtime helpers are skipped; downstream consumers must apply any stricter task-specific filtering themselves
- unresolved indirect calls remain diagnostic-only
- line/evidence enrichment depends on debug metadata and source lookup
- `samples.stats.jsonl` edge IDs are normalized per run and are not intended as stable cross-run identifiers
- optional `samples.llm.jsonl` source/sink/guard code slices and internal function summaries are best-effort local windows and should not be mistaken for a full slicing engine
