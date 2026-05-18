# Root Agent Guide

## Scope

- This root workspace is the MAGUS pipeline. It contains Stage `A`, Stage `B`, and Stage `C`, plus the root orchestration layer that connects them.
- Stage `A` still owns code extraction and derived sample generation.
- Stage `B` owns pattern mining and candidate scoring over Stage `A` stats records.
- Stage `C` owns adversarial audit over Stage `A` LLM evidence and Stage `B` candidates.

## Repo Map

- `pipeline.py`: root orchestration entrypoint for `build-analyzer`, `gen-input`, `a`, `llm`, `b`, `c`, `ab`, `abc`, `stats-path`, and `llm-path`
- `Makefile`: convenience wrappers around `pipeline.py`
- `tools/gen_srcs_compile_commands.py`: explicit helper that generates `srcs/compile_commands.json` for the checked-in Juliet sample tree
- `a/`: standalone Stage `A` project and transient/failure artifacts
- `a/cmd/gen_input.py`: Stage `A` input generator from `compile_commands.json`
- `b/b_miner.py`: Stage `B` entrypoint
- `b/README.md`: Stage `B` usage and contract notes
- `c/agent1.py`: Stage `C` adversarial audit entrypoint
- `README.md`: root overview for the combined pipeline

## Engineering Rules

- Do not use patch-style design. Fix the actual contract or data-flow boundary, and carry the change through code, docs, and verification.
- Do not use compatibility-style design unless the user explicitly asks for backward compatibility. When a contract changes, migrate callers and documentation in the same change instead of keeping old and new paths alive.
- Do not use fallback-style design. Required inputs must be validated and missing or malformed data must fail explicitly instead of being silently guessed or substituted.
- Every requested implementation must be completed end to end when feasible: code, orchestration, documentation, and verification commands.

## Current Behavior

- `pipeline.py a` runs Stage `A` only.
- `pipeline.py gen-input` generates a Stage `A` projects JSONL from `compile_commands.json`; it does not run Stage `A`.
- `pipeline.py llm` exports Stage `A` `samples.llm.jsonl` from an existing raw output.
- `pipeline.py b` runs Stage `B` only.
- `pipeline.py c` runs Stage `C` over Stage `A` LLM evidence and Stage `B` candidates.
- `pipeline.py ab` chains Stage `A` and Stage `B`.
- `pipeline.py abc` chains Stage `A`, Stage `A` LLM export, Stage `B`, and Stage `C`.
- `make gen-input`, `make run-a`, `make run-llm`, `make run-b`, `make run-c`, `make run-ab`, and `make run-abc` are thin wrappers over `pipeline.py`.
- `make gen-srcs-compile-commands` is an explicit helper for the checked-in `srcs` Juliet sample tree; it only writes `srcs/compile_commands.json` and does not run Stage `A`.
- Stage `A` default runs emit `samples.raw.jsonl` and `samples.stats.jsonl`.
- Stage `A` input generation is explicit and requires an existing `compile_commands.json`; it must not fall back to guessing compile flags from bare source scans.
- Stage `A` can produce optional `samples.llm.jsonl` evidence through `a/cmd/llm_export.py`; the default `make run-a` path does not emit it.
- Stage `B` expects Stage `A` `samples.stats.jsonl` records with schema `stagea.stats.features.v1` and validates that contract before mining.
- Stage `C` expects Stage `A` `samples.llm.jsonl` plus Stage `B` `candidates.scored.jsonl`; it must not read `samples.raw.jsonl` as its evidence input.
- Stage `C` uses the DeepSeek-compatible OpenAI Python SDK client configured in `c/agent1.py`; `make run-abc` reaches this networked LLM call.
- The root pipeline does not currently expose a Stage `B` worker-count flag.

## Commands

- `make build-analyzer`
- `make gen-srcs-compile-commands`
- `make gen-input GEN_CLANG=/usr/bin/clang-20 GEN_CLANGXX=/usr/bin/clang++-20 GEN_FORCE=1`
- `make gen-input`
- `make run-a`
- `make run-llm`
- `make run-b`
- `make run-c`
- `make run-ab`
- `make run-abc`
- `python3 pipeline.py stats-path --raw-output a/out/samples.raw.jsonl`
- `python3 pipeline.py llm-path --raw-output a/out/samples.raw.jsonl`
- `python3 pipeline.py gen-input --repo-path srcs --compile-commands srcs/compile_commands.json --output a/input/srcs.in.jsonl`

## Sync Rules

- If the root orchestration contract changes, update `README.md`, this file, and any Stage `B` user-facing docs in the same change.
- If Stage `B` input or output fields change, update `b/README.md` and keep the contract aligned with the loader validation in `b/b_miner.py`.
- If Stage `C` input or output fields change, keep this file and `README.md` aligned with `c/agent1.py` CLI validation.
