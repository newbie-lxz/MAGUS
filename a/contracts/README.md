# Stage A Contract

## Input

`cmd/miner.py` reads a JSONL file. Each line must contain:

```json
{
  "project_id": "zlib",
  "repo_path": "zlib",
  "language": "c",
  "framework": "generic",
  "default_branch": "master",
  "extensions": {
    "config_cmd": "./configure --static",
    "build_cmd": "set -euo pipefail; for f in adler32.c compress.c crc32.c deflate.c gzclose.c gzlib.c gzread.c gzwrite.c infback.c inffast.c inflate.c inftrees.c trees.c uncompr.c zutil.c test/example.c test/minigzip.c; do out=\"build/apiagents-bitcode/${f%.c}.bc\"; mkdir -p \"$(dirname \"$out\")\"; /usr/lib/llvm-20/bin/clang -I. -emit-llvm -c -g -O0 -o \"$out\" \"$f\"; done",
    "bitcode_globs": ["build/apiagents-bitcode/**/*.bc"],
    "source_globs": ["*.c", "test/*.c"],
    "analysis_timeout": 1800,
    "analyzer_jobs": 2
  }
}
```

Required behavior:

- `language` must be `c` or `cpp`
- `extensions.build_cmd` is required
- `extensions.build_cmd` and optional `extensions.config_cmd` are shell strings
- `extensions.analyzer_jobs` is required and must be an integer greater than `1`
- when `extensions.source_globs` is present and the build recipe replays `compile_commands.json` through `cmd/compile_commands_to_bc.py`, those globs are forwarded to the helper so only matching sources are lowered to `.bc`
- Stage `A` splits `bc.list` into contiguous chunks, runs analyzer subprocesses in parallel, and reassembles stable module-indexed DFA files before normalization
- relative `repo_path` values are resolved against the input file directory
- `cmd/secvuleval_batch.py` preserves that same base by resolving relative `repo_path` values against the original batch input file before writing per-project inputs under `out/<project_id>/`
- this repository ships a ready-to-run local input at `input/zlib.in.jsonl`, which resolves `repo_path: "zlib"` to `input/zlib`
- analyzer timeouts are fixed at 60 seconds per root instruction, 3600 seconds per function, and 36000 seconds per file
- raw samples retain ordinary non-LLVM call operations, including allocation, free, logging, and string helpers when they are data/control related to the seed; only LLVM/toolchain-internal intrinsics and injected runtime helpers are skipped by default

## Output

Stage `A` emits one canonical downstream file plus one default derived view:

- `samples.raw.jsonl`: canonical normalized sample contract for general downstream consumers
- `samples.stats.jsonl`: derived flat edge-token view for frequency/pattern mining

The CLI output path must end with `.raw.jsonl`; Stage `A` derives the sibling `.stats.jsonl` path from that name. The optional `cmd/llm_export.py` command can export a sibling `samples.llm.jsonl` evidence view from an existing raw output and the matching project input file.

Each sample contains:

- `project_id`, `sample_id`
- `entrypoint`, `seed`
- `source_candidates`, `sink_candidates`, `source_sink_flows`
- `source_locs`, `sink_locs`
- `focus`, `evidence_slice`
- `analysis_backend`, `context_mode`, `api_group`
- `context_signature_tokens`, `bitcode`, `dfa`
- `graph`
- `analysis_warnings`, `analyzer_stats`, `indirect_call_stats`, `graph_stats`

Graph and flow semantics:

- `graph.nodes` plus `graph.direct_edges` is the canonical structural view for downstream consumers.
- `source_candidates` and `sink_candidates` are plausible endpoints, not proof of a vulnerability by themselves.
- `source_sink_flows` records candidate or confirmed source-to-sink relations. `trace_node_ids` is a representative explanation trace, not an exhaustive path listing.
- `source_sink_flows[].status` distinguishes at least `candidate` and `confirmed`.
- `analyzer_stats.cross_function_budget_hit` is true when same-module callee expansion hit the analyzer depth budget; the sample also carries a matching `cross_function_budget_hit` warning.
- `graph_stats` currently records structural counts for the normalized graph, including `node_count` and `edge_count`.

Artifacts written per project:

- `out/a.artifacts/<project_id>/run_manifest.json`
- `out/a.artifacts/<project_id>/bitcode_manifest.json`
- `out/a.artifacts/<project_id>/dfa_summary.json`
- `out/a.artifacts/<project_id>/failures.json` on failure
- SecVulEval batch runs additionally write `out/<project_id>/batch.result.json`; any miner non-zero exit, failure manifest, or zero-line `samples.raw.jsonl` marks that project and the batch as failed

## Derived Views

`samples.stats.jsonl` is derived from `samples.raw.jsonl` and is meant for frequency analysis rather than code review or LLM prompting. Each record keeps:

- `project_id`, `sample_id`
- `location_id`, `location`
- `seed_id`, `seed_token`
- `edge_ids`, `edge_tokens`
- `source_kinds`, `sink_types`
- `focus`

Important semantics:

- `sample_id` is the join key back to `samples.raw.jsonl` and, when exported, `samples.llm.jsonl`
- `edge_tokens` are taken from `graph.direct_edges`
- `edge_ids` are run-local normalized integers for compact pattern mining and should not be treated as globally stable IDs

Example JSONL record:

```json
{"project_id":"zlib","sample_id":"path_002e1ba97b97","location_id":104,"location":{"file":"test/example.c","function":"test_compress"},"seed_id":"test/example.c::test_compress:37","seed_token":"compression:fprintf","edge_ids":[183,166],"edge_tokens":["check:CHECK->compression:fprintf","check:CHECK->check:CHECK"],"source_kinds":[],"sink_types":["compression"],"focus":{"file":"test/example.c","line":72}}
```

`samples.llm.jsonl` is an optional view derived by `cmd/llm_export.py` from `samples.raw.jsonl` and the matching projects input. It is meant for explanation-oriented consumers. Each record keeps:

- `project_id`, `sample_id`
- `entrypoint`, `seed`, `focus`
- `evidence_slice`
- `analysis_warnings`
- `source_sink_flows`
- `representative_traces`
- `graph_excerpt`
- `code_slices`
- `internal_function_summaries`

Important semantics:

- `graph_excerpt` is a small neighborhood around seed/focus/representative traces, not the full graph
- `representative_traces` are explanatory examples, not exhaustive path listings
- `code_slices` are local source windows around seed, focus, source, sink, or guard nodes so LLM consumers do not need the full normalized graph to reason about context
- `internal_function_summaries` are budgeted best-effort summaries for project-local functions referenced by the sample graph; they include short excerpts plus internal call/check hints and are not a replacement for the canonical `graph.direct_edges`
