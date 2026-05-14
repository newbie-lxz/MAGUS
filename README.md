# A + B Pipeline

This workspace contains a two-stage pipeline plus a small root-level orchestrator:

- `a/`: Stage `A` static-analysis pipeline that emits `samples.raw.jsonl` plus the derived `samples.stats.jsonl` view
- `b/`: Stage `B` miner that consumes Stage `A` `samples.stats.jsonl` records, mines frequent patterns, and scores candidates
- `pipeline.py`: root entrypoint for running Stage `A`, LLM evidence export, Stage `B`, or the chained `A -> LLM export -> B` flow from one place

Stage `A` documentation remains under [`a/README.md`](./a/README.md), [`a/contracts/README.md`](./a/contracts/README.md), and [`a/docs/`](./a/docs/). Stage `B` usage is documented in [`b/README.md`](./b/README.md).

## Layout

- `pipeline.py`: root orchestration for `build-analyzer`, `a`, `llm`, `b`, `ab`, and `stats-path`
- `Makefile`: convenience wrappers around `pipeline.py`
- `a/`: standalone Stage `A` project and its docs
- `b/`: standalone Stage `B` miner and outputs

## Common Commands

Build the Stage `A` analyzer once before the first Stage `A` or chained `A -> LLM export -> B` run if the binary is not present yet.

- Build the Stage `A` analyzer:

```bash
make build-analyzer
```

- Run only Stage `A`:

```bash
make run-a
```

- Export LLM evidence independently from an existing Stage `A` raw output:

```bash
make run-llm
make run-llm LLM_OUTPUT=/tmp/samples.llm.jsonl
```

- Run only Stage `B` against the derived stats view:

```bash
make run-b
```

- Run the full `A -> LLM export -> B` pipeline:

```bash
make run-ab
make run-ab LLM_OUTPUT=/tmp/samples.llm.jsonl
```

- Show the derived `samples.stats.jsonl` path for a given Stage `A` raw output:

```bash
python3 pipeline.py stats-path --raw-output a/out/samples.raw.jsonl
```

## Validation Boundaries

The root orchestrator intentionally preserves separate validation:

- Stage `A` can still be validated independently through `make run-a` or the original commands inside `a/`
- LLM evidence can be exported independently through `make run-llm`, and `make run-ab` emits it after Stage `A`
- Stage `B` can still be validated independently by pointing it at any existing `samples.stats.jsonl`
- `make run-ab` chains Stage `A`, LLM evidence export, and Stage `B` without changing either stage's internal logic

Important contract boundary:

- Stage `B` consumes `samples.stats.jsonl`
- Stage `B` does not consume `samples.raw.jsonl`
- if you pass `samples.raw.jsonl` to Stage `B`, it exits with a contract error instead of silently reinterpreting the record shape

## Outputs

Default outputs:

- Stage `A` raw output: `a/out/samples.raw.jsonl`
- Stage `A` derived stats output: `a/out/samples.stats.jsonl`
- Stage `A` LLM evidence output from `make run-ab` or `make run-llm`: `a/out/samples.llm.jsonl`
- Stage `B` outputs: `b/b_output/patterns.json`, `b/b_output/candidates.scored.jsonl`, `b/b_output/b_miner_stats.json`

If you override `A_OUTPUT`, the path must end with `.raw.jsonl`; `pipeline.py` derives the matching `.llm.jsonl` and `.stats.jsonl` paths automatically during `run-ab`. Set `LLM_OUTPUT` to override only the LLM evidence path for `run-llm` or `run-ab`.
