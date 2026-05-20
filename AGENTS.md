# Root Agent Guide

## Scope

- This root workspace is the MAGUS pipeline. It contains Stage `A`, Stage `B`, Stage `C`, and the downstream Stage `D` verifier. The root orchestration layer connects Stage `A` through Stage `D`.
- Stage `A` still owns code extraction, derived sample generation, and LLM evidence export.
- Stage `B` owns pattern mining and candidate scoring over Stage `A` stats records.
- Stage `C` owns adversarial audit over Stage `A` LLM evidence and Stage `B` candidates.
- Stage `D` owns dynamic source/API verification over Stage `C` hypotheses.

## Repo Map

- `pipeline.py`: root orchestration entrypoint for `build-analyzer`, `gen-input`, `a`, `b`, `c`, `d`, `abcd`, `stats-path`, and `llm-path`
- `Makefile`: convenience wrappers around `pipeline.py`
- `tools/gen_srcs_compile_commands.py`: explicit helper that generates `srcs/compile_commands.json` for the checked-in Juliet sample tree
- `a/`: standalone Stage `A` project and transient/failure artifacts
- `a/cmd/gen_input.py`: Stage `A` input generator from `compile_commands.json`
- `b/b_miner.py`: Stage `B` entrypoint
- `b/README.md`: Stage `B` usage and contract notes
- `c/agent1.py`: Stage `C` adversarial audit entrypoint
- `d/`: standalone Stage `D` source/API verifier and usage notes
- `d/使用说明.md`: Stage `D` high-level handoff and run contract
- `d/memberD_verifier/02_run_with_C/01_auto_attack_from_C_linux.sh`: Stage `D` automatic verifier entrypoint for all `c/out/*.jsonl`
- `README.md`: root overview for the combined pipeline

## Engineering Rules

- Do not use patch-style design. Fix the actual contract or data-flow boundary, and carry the change through code, docs, and verification.
- Do not use compatibility-style design unless the user explicitly asks for backward compatibility. When a contract changes, migrate callers and documentation in the same change instead of keeping old and new paths alive.
- Do not use fallback-style design. Required inputs must be validated and missing or malformed data must fail explicitly instead of being silently guessed or substituted.
- Every requested implementation must be completed end to end when feasible: code, orchestration, documentation, and verification commands.

## Current Behavior

- `pipeline.py a` runs Stage `A` only, including `samples.llm.jsonl` export beside the raw output.
- `pipeline.py gen-input` generates a Stage `A` projects JSONL from `compile_commands.json`; it does not run Stage `A`.
- `pipeline.py b` runs Stage `B` only.
- `pipeline.py c` runs Stage `C` over Stage `A` LLM evidence and Stage `B` candidates.
- `pipeline.py d` runs Stage `D` over Stage `C` `c/out/*.jsonl` by calling `d/memberD_verifier/02_run_with_C/01_auto_attack_from_C_linux.sh`.
- `pipeline.py abcd` chains Stage `A`, Stage `B`, Stage `C`, and Stage `D`.
- `make gen-input`, `make run-a`, `make run-b`, `make run-c`, `make run-d`, and `make run-abcd` are thin wrappers over `pipeline.py`.
- `make gen-srcs-compile-commands` is an explicit helper for the checked-in `srcs` Juliet sample tree; it only writes `srcs/compile_commands.json` and does not run Stage `A`.
- Stage `A` default root runs emit `samples.raw.jsonl`, `samples.stats.jsonl`, and `samples.llm.jsonl`.
- Stage `A` input generation is explicit and requires an existing `compile_commands.json`; it must not fall back to guessing compile flags from bare source scans.
- Stage `A` LLM evidence is produced through `a/cmd/llm_export.py` as part of the root `a` and `abcd` flows.
- Stage `B` expects Stage `A` `samples.stats.jsonl` records with schema `stagea.stats.features.v1` and validates that contract before mining.
- Stage `C` expects Stage `A` `samples.llm.jsonl` plus Stage `B` `candidates.scored.jsonl`; it must not read `samples.raw.jsonl` as its evidence input.
- Stage `C` uses the DeepSeek-compatible OpenAI Python SDK client configured in `c/agent1.py`; `make run-abcd` reaches this networked LLM call.
- Stage `D` expects Stage `C` hypotheses under `c/out/*.jsonl`; it reads those files in filename order, rejects duplicate `project_id + hypothesis_id` records, and must not read Stage `A` or Stage `B` outputs directly.
- Stage `D` verifies C/C++ source/API misuse hypotheses and does not generate HTTP requests, `base_url` payloads, or `*.http` files.
- The root pipeline does not currently expose a Stage `B` worker-count flag.

## Commands

- `make build-analyzer`
- `make gen-srcs-compile-commands`
- `make gen-input GEN_CLANG=/usr/bin/clang-20 GEN_CLANGXX=/usr/bin/clang++-20 GEN_FORCE=1`
- `make gen-input`
- `make run-a`
- `make run-b`
- `make run-c`
- `make run-d`
- `make run-abcd`
- `(cd d/memberD_verifier/01_demo_test && ./01_setup_linux.sh)`
- `(cd d/memberD_verifier/02_run_with_C && ./01_auto_attack_from_C_linux.sh)`
- `python3 pipeline.py stats-path --raw-output a/out/samples.raw.jsonl`
- `python3 pipeline.py llm-path --raw-output a/out/samples.raw.jsonl`
- `python3 pipeline.py gen-input --repo-path srcs --compile-commands srcs/compile_commands.json --output a/input/srcs.in.jsonl`

## Sync Rules

- If the root orchestration contract changes, update `README.md`, this file, and any Stage `B` user-facing docs in the same change.
- If Stage `B` input or output fields change, update `b/README.md` and keep the contract aligned with the loader validation in `b/b_miner.py`.
- If Stage `C` input or output fields change, keep this file and `README.md` aligned with `c/agent1.py` CLI validation.
- If Stage `D` input, sidecar, or output fields change, keep this file, `README.md`, `d/使用说明.md`, and `d/memberD_verifier/02_run_with_C/README_正式接C流程.md` aligned with `d/memberD_verifier/00_core/gen_targets_from_hypotheses.py`, `verifier.py`, and `bind_verification_contexts.py`.
