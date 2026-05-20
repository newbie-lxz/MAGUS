# Stage B Miner

Stage `B` consumes Stage `A` `samples.stats.jsonl` records, mines high-support feature relations within each `api_group`, and scores samples that miss those expected features.

## Input Contract

Input records must use:

```text
schema_version = stagea.stats.features.v1
```

Required fields:

- `project_id`
- `sample_id`
- `api_group`
- `location_id`
- `location`
- `seed_id`
- `seed_token`
- `feature_tokens`
- `feature_details`
- `source_kinds`
- `sink_types`
- `focus`
- `feature_stats`

The miner validates these fields in `b_miner.py` before mining. It does not accept the old `edge_tokens` stats schema.

## Run

From the repository root:

```bash
make run-b
```

The root Stage `A` command emits both `samples.stats.jsonl` and `samples.llm.jsonl`; Stage `B` still consumes only the stats file. Use `make run-abcd` for the full `A -> B -> C -> D` chain.

Or directly from `b/`:

```bash
python3 b_miner.py \
  --input ../a/out/samples.stats.jsonl \
  --output-dir b_output \
  --min-support 3
```

Direct runs may also set:

- `--min-support-ratio`: minimum within-`api_group` support ratio, default `0.90`
- `--risk-threshold`: `risk_score` threshold for `threshold_pass`, default `0.60`

## Outputs

Stage `B` writes:

- `patterns.json`: high-support feature patterns
- `candidates.scored.jsonl`: scored samples with missing expected features
- `b_miner_stats.json`: aggregate run statistics

Candidate records include `schema_version = stageb.feature_candidates.v1`.
