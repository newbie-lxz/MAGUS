# A + B Pipeline

This workspace contains a two-stage pipeline plus a small root-level orchestrator:

- `a/`: Stage `A` static-analysis pipeline that emits `samples.raw.jsonl` plus the derived `samples.stats.jsonl` view
- `b/`: Stage `B` miner that consumes Stage `A` `samples.stats.jsonl` records, mines frequent patterns, and scores candidates
- `pipeline.py`: root entrypoint for running Stage `A`, Stage `B`, or the chained `A -> B` flow from one place


## Layout

- `pipeline.py`: root orchestration for `build-analyzer`, `a`, `b`, `ab`, and `stats-path`
- `Makefile`: convenience wrappers around `pipeline.py`
- `a/`: standalone Stage `A` project
- `b/`: standalone Stage `B` miner and outputs

## Common Commands

Build the Stage `A` analyzer once before the first Stage `A` or chained `A -> B` run if the binary is not present yet.

- Build the Stage `A` analyzer:

```bash
make build-analyzer
```

- Run only Stage `A`:

```bash
make run-a
```

- Run only Stage `B` against the derived stats view:

```bash
make run-b
```

- Run the full `A -> B` pipeline:

```bash
make run-ab
```

- Show the derived `samples.stats.jsonl` path for a given Stage `A` raw output:

```bash
python3 pipeline.py stats-path --raw-output a/out/samples.raw.jsonl
```

## Validation Boundaries

The root orchestrator intentionally preserves separate validation:

- Stage `A` can still be validated independently through `make run-a` or the original commands inside `a/`
- Stage `B` can still be validated independently by pointing it at any existing `samples.stats.jsonl`
- `make run-ab` chains Stage `A` and Stage `B` without changing either stage's internal logic

Important contract boundary:

- Stage `B` consumes `samples.stats.jsonl`

## Outputs

Default outputs:

- Stage `A` raw output: `a/out/samples.raw.jsonl`
- Stage `A` derived stats output: `a/out/samples.stats.jsonl`
- Stage `B` outputs: `b/b_output/patterns.json`, `b/b_output/candidates.scored.jsonl`, `b/b_output/b_miner_stats.json`

If you override `A_OUTPUT`, `pipeline.py` derives the matching stats path automatically during `run-ab`.

Stage `B` currently manages frequent-pattern mining parallelism internally. The root pipeline does not expose a worker-count flag because `b/b_miner.py` does not accept one in the current implementation.
