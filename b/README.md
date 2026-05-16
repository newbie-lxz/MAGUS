# Stage B

Stage `B` mines frequent patterns and scores candidates from Stage `A` `samples.stats.jsonl` records.

It does not analyze raw LLVM output directly and it does not consume Stage `A` `samples.raw.jsonl`.

## Inputs

Required input contract:

- one JSON object per line
- the record shape must match Stage `A` `samples.stats.jsonl`
- required fields: `project_id`, `sample_id`, `location_id`, `location`, `seed_id`, `seed_token`, `edge_ids`, `edge_tokens`, `source_kinds`, `sink_types`, `focus`

If the input does not match the Stage `A` stats view, Stage `B` exits with a contract error before mining starts.

## Commands

Direct run:

```bash
python3 b/b_miner.py --input a/out/samples.stats.jsonl --output-dir b/b_output
python3 b/b_miner.py --input a/out/samples.stats.jsonl --output-dir b/b_output --workers 2
```

Root orchestration:

```bash
make run-b
make run-b B_WORKERS=2
```

Chained execution through the root pipeline, which also writes the matching Stage `A` `samples.llm.jsonl` evidence view before Stage `B` starts:

```bash
make run-ab
make run-ab B_WORKERS=2
```

You can also validate Stage `B` independently against any per-project Stage `A` stats file, for example:

```bash
python3 pipeline.py b --input a/out/<project_id>/samples.stats.jsonl --output-dir /tmp/stageb-check
```

Use `--workers` or `B_WORKERS` to tune the mining process pool. The default is `CPU/4` workers; `--workers 1` disables multiprocessing for the frequent-pattern expansion stage.

## Outputs

Stage `B` writes:

- `patterns.json`: mined frequent sequence patterns
- `candidates.scored.jsonl`: scored candidates sorted by descending `risk_score`
- `b_miner_stats.json`: aggregate counts and score distribution summary

The default root-level destination is `b/b_output/`.

## Notes

- The mining and scoring logic live entirely in `b_miner.py`.
- The root `pipeline.py` connects Stage `A` stats output to Stage `B` input and separately exports the Stage `A` LLM evidence view; it does not rewrite Stage `B` internals.
- Stage `B` keeps global mining semantics: multiprocessing is used only to parallelize large prefix-group expansion, not to split the input into independent per-API mining jobs.
- `risk_score >= 0.50` is the current threshold gate used in the output summary.
