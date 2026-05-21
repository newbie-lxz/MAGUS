# Root Agent Guide

## Scope

- This root workspace is the MAGUS pipeline. It contains Stage `A`, Stage `B`, Stage `C`, the downstream Stage `D` verifier, and the final Report stage. The root orchestration layer connects Stage `A` through Report.
- Stage `A` still owns code extraction, derived sample generation, and LLM evidence export.
- Stage `B` owns pattern mining and candidate scoring over Stage `A` stats records, then prepares a route-aggregated C-ready audit queue from matching Stage `A` LLM evidence plus Stage `B` metadata.
- Stage `C` owns red-team audit and routing over Stage `B` C-ready candidates.
- Stage `D` owns dynamic source/API verification over the Stage `C` candidates placed under `c/out/*.jsonl`.
- Report owns final vulnerability report generation from Stage `D` confirmed/failed verification outputs.

## Repo Map

- `pipeline.py`: root orchestration entrypoint for `build-analyzer`, `gen-input`, `a`, `b`, `c`, `d`, `report`, `abcd`, `stats-path`, and `llm-path`
- `Makefile`: convenience wrappers around `pipeline.py`
- `tools/gen_srcs_compile_commands.py`: explicit helper that generates `srcs/compile_commands.json` for the checked-in Juliet sample tree
- `a/`: standalone Stage `A` project and transient/failure artifacts
- `a/cmd/gen_input.py`: Stage `A` input generator from `compile_commands.json`
- `b/b_miner.py`: Stage `B` entrypoint
- `b/README.md`: Stage `B` usage and B-to-C contract notes
- `c/agent1.py`: Stage `C` adversarial audit entrypoint
- `d/`: standalone Stage `D` source/API verifier and usage notes
- `d/使用说明.md`: Stage `D` high-level handoff and run contract
- `d/memberD_verifier/02_run_with_C/01_auto_attack_from_C_linux.sh`: Stage `D` automatic verifier entrypoint for all `c/out/*.jsonl`
- `d/memberD_verifier/02_run_with_C/stream_from_C.py`: Stage `D` streaming verifier entrypoint used by root `abcd`
- `report/code/generate_report.py`: final report generator over Stage `D` `verification.jsonl` and `verification.failed.jsonl`
- `report/code/validate_report.py`: final report validator
- `test/evaluate_juliet_report.py`: paper-evaluation helper that compares the final report with Juliet answers and writes FP/FN/metric/timing artifacts
- `test/README.md`: Juliet report evaluation usage notes
- `README.md`: root overview for the combined pipeline

## Engineering Rules

- Do not use patch-style design. Fix the actual contract or data-flow boundary, and carry the change through code, docs, and verification.
- Do not use compatibility-style design unless the user explicitly asks for backward compatibility. When a contract changes, migrate callers and documentation in the same change instead of keeping old and new paths alive.
- Do not use fallback-style design. Required inputs must be validated and missing or malformed data must fail explicitly instead of being silently guessed or substituted.
- Every requested implementation must be completed end to end when feasible: code, orchestration, documentation, and verification commands.

## Current Behavior

- `pipeline.py a` runs Stage `A` only, including `samples.llm.jsonl` export beside the raw output.
- `pipeline.py gen-input` generates a Stage `A` projects JSONL from `compile_commands.json`; it does not run Stage `A`.
- `pipeline.py b` runs Stage `B` only over Stage `A` stats and matching LLM evidence.
- `pipeline.py c` runs Stage `C` over Stage `B` `candidates.for_c.jsonl`, routing completed `P0` static confirmations and `P1`/`P2` dynamic candidates to Stage `D`, and routing `P3` audit-only records to audit output.
- `pipeline.py d` runs Stage `D` over Stage `C` `c/out/*.jsonl` by calling `d/memberD_verifier/02_run_with_C/01_auto_attack_from_C_linux.sh`; the script runs Report after D validation.
- `pipeline.py report` generates the final report from a Stage `D` output directory.
- `pipeline.py abcd` chains Stage `A` and Stage `B`, streams Stage `C` dynamic candidates into Stage `D` while Stage `C` is still running, then runs Report.
- `make gen-input`, `make run-a`, `make run-b`, `make run-c`, `make run-d`, `make run-report`, and `make run-abcd` are thin wrappers over `pipeline.py`.
- `make gen-srcs-compile-commands` is an explicit helper for the checked-in `srcs` Juliet sample tree; it only writes `srcs/compile_commands.json` and does not run Stage `A`.
- Stage `A` default root runs emit `samples.raw.jsonl`, `samples.stats.jsonl`, and `samples.llm.jsonl`.
- Stage `A` input generation is explicit and requires an existing `compile_commands.json`; it must not fall back to guessing compile flags from bare source scans.
- Stage `A` LLM evidence is produced through `a/cmd/llm_export.py` as part of the root `a` and `abcd` flows.
- Stage `B` expects Stage `A` `samples.stats.jsonl` records with schema `stagea.stats.features.v1` plus matching `samples.llm.jsonl` evidence keyed by `sample_id`, and validates those contracts before mining.
- Stage `B` writes complete seed-level scored candidates to `candidates.scored.jsonl` and writes the route-aggregated C-ready queue to `candidates.for_c.jsonl`; each C-ready record keeps only Stage `C` input fields, stores merged Stage `A` LLM evidence under `llm_evidence`, and carries route-level B metadata under `stage_b`, including risk score weights and `static_confirmation_support`.
- Stage `C` expects Stage `B` `candidates.for_c.jsonl`; it must not read Stage `A` outputs directly, and it uses `stage_b` threshold/missing-feature/seed-token/reference-sample/static-confirmation evidence as anti-hallucination constraints rather than vulnerability conclusions. Stage `C` validates `stage_b.static_confirmation_support` and does not allow P0 static confirmation when B marks static confirmation unsupported; such vulnerability findings stay in the dynamic-verification path.
- Stage `C` uses a process-based time budget when requested and does not expose a candidate-count limit; after the deadline plus grace, unfinished workers are terminated and their candidates are written as `P3` `stage_c_time_budget_exhausted` audit records.
- Stage `C` writes `P1`/`P2` dynamic-verification candidates to `c/out/*.jsonl`. Completed `P0` static confirmations are also written to `c/out/*.jsonl` so Stage `D` can route-bound verify them; Stage `C` time budgets only affect candidate submission and unfinished workers, not whether a completed P0 is handed to D. `P3` audit-only records go to `c/audit/audit.jsonl`; debated records enter `P3` only when every red-team round returns no vulnerability, while any round that reports a vulnerability keeps the record in the dynamic-verification path even if later rounds mark hard contradictions or incomplete evidence.
- Stage `C` outputs hypothesis and routing evidence only. It must not infer or emit D verifier configuration, `verification_context`, or oracle rules; Stage `D` owns verifier/oracle generation.
- Stage `C` uses the DeepSeek-compatible OpenAI Python SDK client configured in `c/agent1.py`; `make run-abcd` reaches this networked LLM call.
- Stage `D` batch mode expects Stage `C` dynamic-verification candidates under `c/out/*.jsonl`; it reads those files in filename order, trusts Stage `C` routing instead of re-checking `P1`/`P2` or `agent_verdict`, rejects duplicate `project_id + hypothesis_id` records, and must not read Stage `A` or Stage `B` outputs directly. Stage `D` applies a 10-second execution timeout only to `P0`; `P1`/`P2` records are not D-time-limited.
- Stage `D` streaming mode is used by root `abcd`; it follows the current Stage `C --output` JSONL file, processes only complete newline-terminated records, rejects duplicate `project_id + hypothesis_id` records, and exits after the root pipeline marks Stage `C` done.
- Stage `D` batch and streaming modes share an output lock under `d/memberD_verifier/02_run_with_C/.stage_d_output.lock`; do not run another D writer against the same output directory while one mode is active.
- Stage `D` verifies C/C++ source/API misuse hypotheses and does not generate HTTP requests, `base_url` payloads, or `*.http` files.
- Stage `D` auto-detects checked-in `srcs/juliet-api-misuse` hypotheses and generates an executable Linux Juliet Win32 shim runner plus route-bound oracle for batch and streaming modes; those records do not need `verification_contexts.jsonl` unless an explicit D-side override is required.
- Stage `D` confirmed output requires route-bound dynamic evidence. The executable harness can run the full source project/testcase, but its oracle must prove the candidate route or source/API sequence was reached; otherwise the record stays in failed output, using `NOT_ROUTE_BOUND` when route attribution cannot be proven.
- Report writes final report artifacts `report/<run-name>/verification.report.jsonl` and `report/<run-name>/verification.report.md` from Stage `D` `verification.jsonl` and `verification.failed.jsonl`. The root pipeline derives `<run-name>` from the unique CWE source folder in D output, or from the unique `project_id` when no single CWE folder is present; `REPORT_RUN_NAME` / `--run-name` overrides it. Each confirmed vulnerability report row must include location (`file_path`, `line`, `route`), vulnerability type, risk level, and trigger condition. The Report validator checks that the report has one row per confirmed record.
- `test/evaluate_juliet_report.py` compares `report/<run-name>/verification.report.jsonl` with Juliet answers for paper testing. By default it infers Juliet truth from bad/good testcase paths under `srcs/juliet-api-misuse`; it can also consume an explicit JSONL/JSON/CSV answer file. It writes evaluation artifacts under `test/out/juliet_eval/<run-name>/` unless `--out-dir` is supplied, and reports false positives, false negatives, duplicate true positives, precision/recall/F1, and elapsed time from Stage `A` start to final report generation when `--stage-a-start`, `--timing-json`, or `--run-command` is supplied.
- The root pipeline does not currently expose a Stage `B` worker-count flag.

## Commands

- `export LLVM_HOME=/usr/lib/llvm-20 && export PATH="$LLVM_HOME/bin:$PATH"`
- `make build-analyzer`
- `make gen-srcs-compile-commands`
- `make gen-input GEN_CLANG=/usr/bin/clang-20 GEN_CLANGXX=/usr/bin/clang++-20 GEN_FORCE=1`
- `make gen-input`
- `make run-a`
- `make run-b`
- `make run-c`
- `make run-d`
- `make run-report`
- `make run-abcd`
- `make run-c C_TIME_LIMIT_SECONDS=600`
- `make run-abcd C_TIME_LIMIT_SECONDS=600`
- `(cd d/memberD_verifier/01_demo_test && ./01_setup_linux.sh)`
- `(cd d/memberD_verifier/02_run_with_C && ./01_auto_attack_from_C_linux.sh)`
- `python3 pipeline.py report --d-output-dir d/memberD_verifier/02_run_with_C/output --report-root report`
- `python3 pipeline.py stats-path --raw-output a/out/samples.raw.jsonl`
- `python3 pipeline.py llm-path --raw-output a/out/samples.raw.jsonl`
- `python3 pipeline.py gen-input --repo-path srcs --compile-commands srcs/compile_commands.json --output a/input/srcs.in.jsonl`
- `python3 test/evaluate_juliet_report.py --report report/CWE15_External_Control_of_System_or_Configuration_Setting/verification.report.jsonl --scope-compile-commands srcs/compile_commands.cwe15.json --stage-a-start 2026-05-20T10:00:00Z`
- `python3 test/evaluate_juliet_report.py --run-command "python3 pipeline.py abcd" --scope-compile-commands srcs/compile_commands.cwe15.json`

## Sync Rules

- If the root orchestration contract changes, update `README.md`, this file, and any Stage `B` user-facing docs in the same change.
- If Stage `B` input or output fields change, update `b/README.md` and keep the contract aligned with the loader validation in `b/b_miner.py`.
- If Stage `C` input or output fields change, keep this file and `README.md` aligned with `c/agent1.py` CLI validation.
- If Stage `D` input, sidecar, or output fields change, keep this file, `README.md`, `d/使用说明.md`, and `d/memberD_verifier/02_run_with_C/README_正式接C流程.md` aligned with `d/memberD_verifier/00_core/gen_targets_from_hypotheses.py`, `verifier.py`, and `bind_verification_contexts.py`.
- If Report input or output fields change, keep this file, `README.md`, `d/使用说明.md`, and `d/memberD_verifier/02_run_with_C/README_正式接C流程.md` aligned with `report/code/generate_report.py` and `report/code/validate_report.py`.
