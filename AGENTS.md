# Root Agent Guide

## Scope

- This root workspace now contains both Stage `A` and Stage `B`, plus the root orchestration layer that connects them.
- Stage `A` still owns code extraction and derived sample generation.
- Stage `B` owns pattern mining and candidate scoring over Stage `A` stats records.

## Repo Map

- `pipeline.py`: root orchestration entrypoint for `build-analyzer`, `a`, `b`, `ab`, and `stats-path`
- `Makefile`: convenience wrappers around `pipeline.py`
- `a/`: standalone Stage `A` project and transient/failure artifacts
- `b/b_miner.py`: Stage `B` entrypoint
- `b/README.md`: Stage `B` usage and contract notes
- `README.md`: root overview for the combined pipeline

## Current Behavior

- `pipeline.py a` runs Stage `A` only.
- `pipeline.py b` runs Stage `B` only.
- `make run-a`, `make run-b`, and `make run-ab` are thin wrappers over `pipeline.py`.
- Root `B_WORKERS` overrides the Stage `B` process-pool worker count for `make run-b` and `make run-ab`; otherwise Stage `B` defaults to `CPU/4`.
- Stage `A` default runs emit `samples.raw.jsonl` 、 `samples.llm.jsonl`and `samples.stats.jsonl`.
- Stage `B` expects Stage `A` `samples.stats.jsonl` records and validates that contract before mining.

## Commands

- `make build-analyzer`
- `make run-a`
- `make run-b`
- `make run-ab`
- `python3 pipeline.py stats-path --raw-output a/out/samples.raw.jsonl`

## Sync Rules

- If the root orchestration contract changes, update `README.md`, this file, and any Stage `B` user-facing docs in the same change.
- If Stage `B` input or output fields change, update `b/README.md` and keep the contract aligned with the loader validation in `b/b_miner.py`.
