# Root Agent Guide

## Scope

- This root workspace now contains both Stage `A` and Stage `B`, plus the root orchestration layer that connects them.
- Do not describe the root as Stage `A` only.
- Stage `A` still owns code extraction and derived sample generation.
- Stage `B` owns pattern mining and candidate scoring over Stage `A` stats records.

## Repo Map

- `pipeline.py`: root orchestration entrypoint for `build-analyzer`, `a`, `llm`, `b`, `ab`, and `stats-path`
- `Makefile`: convenience wrappers around `pipeline.py`
- `a/`: standalone Stage `A` project, docs, and artifacts
- `b/b_miner.py`: Stage `B` entrypoint
- `b/README.md`: Stage `B` usage and contract notes
- `README.md`: root overview for the combined pipeline

## Current Behavior

- `pipeline.py a` runs Stage `A` only.
- `pipeline.py llm` exports LLM evidence from an existing Stage `A` raw output plus the matching project input file.
- `pipeline.py b` runs Stage `B` only.
- `pipeline.py ab` runs Stage `A` first, exports the matching `samples.llm.jsonl`, derives the matching `samples.stats.jsonl` path from the Stage `A` raw output path, then runs Stage `B`.
- Stage `A` raw output paths used by root orchestration must end with `.raw.jsonl`.
- `make run-a`, `make run-llm`, `make run-b`, and `make run-ab` are thin wrappers over `pipeline.py`.
- Root `LLM_OUTPUT` overrides the LLM evidence path for `make run-llm` and `make run-ab`; otherwise the path is derived from the raw output name.
- Stage `A` default runs emit `samples.raw.jsonl` and `samples.stats.jsonl`; root `run-ab` also emits `samples.llm.jsonl` before Stage `B`.
- Stage `B` expects Stage `A` `samples.stats.jsonl` records and validates that contract before mining.
- Stage `B` must reject `samples.raw.jsonl` input rather than trying to reinterpret Stage `A` raw records.
- Stage `A` documentation under `a/` remains authoritative for Stage `A` internals and field semantics.

## Commands

- `make build-analyzer`
- `make run-a`
- `make run-llm`
- `make run-b`
- `make run-ab`
- `python3 pipeline.py stats-path --raw-output a/out/samples.raw.jsonl`

## Sync Rules

- If the root orchestration contract changes, update `README.md`, this file, and any Stage `B` user-facing docs in the same change.
- If Stage `B` input or output fields change, update `b/README.md` and keep the contract aligned with the loader validation in `b/b_miner.py`.
- If Stage `A` behavior changes, continue updating the existing `a/README.md`, `a/contracts/README.md`, and `a/docs/` files there rather than duplicating those details here.
