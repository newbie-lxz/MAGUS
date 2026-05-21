# MAGUS Pipeline

MAGUS is a multi-stage mining pipeline plus a small root-level orchestrator:

- `a/`: Stage `A` static-analysis pipeline that emits `samples.raw.jsonl`, the derived `samples.stats.jsonl` view, and `samples.llm.jsonl` evidence.
- `b/`: Stage `B` miner that consumes Stage `A` `samples.stats.jsonl` and `samples.llm.jsonl`, mines high-support feature patterns, scores candidates, and prepares the route-aggregated C audit queue.
- `c/`: Stage `C` red-team audit that consumes Stage `B` `candidates.for_c.jsonl`, then routes findings into static confirmations, D candidates, or audit-only records.
- `d/`: Stage `D` source/API verifier that consumes the Stage `C` dynamic-verification queue in `c/out/*.jsonl` and produces confirmed/failed dynamic-verification records.
- `report/code/`: final report generator and validator; it reads Stage `D` verification outputs and writes final report artifacts under `report/<run-name>/`.
- `test/`: paper-evaluation helpers, including Juliet final-report comparison and timing summaries.
- `pipeline.py`: root entrypoint for generating Stage `A` input, running Stage `A`, Stage `B`, Stage `C`, Stage `D`, Report, or the full `A -> B -> streamed C/D -> Report` flow from one place.
- `tools/sanitize_juliet_tree.py`: generates `srcs_sanitized/` plus `juliet_sanitization_map.json` from the original Juliet tree.
- `tools/gen_srcs_compile_commands.py`: explicit helper for generating `srcs_sanitized/compile_commands.json` for the sanitized Juliet sample tree.


## Layout

- `pipeline.py`: root orchestration for `build-analyzer`, `gen-input`, `a`, `b`, `c`, `d`, `report`, `abcd`, `stats-path`, and `llm-path`
- `Makefile`: convenience wrappers around `pipeline.py`
- `tools/`: repository-level helper scripts
- `a/`: standalone Stage `A` project
- `b/`: standalone Stage `B` miner, usage notes, and outputs
- `c/`: standalone Stage `C` audit agent and outputs
- `d/`: standalone Stage `D` source/API verifier, Linux scripts, and usage notes
- `report/code/`: standalone Report generator and validator
- `test/`: final-report evaluation scripts and generated evaluation artifacts

## Common Commands

Build the Stage `A` analyzer once before the first Stage `A` or full pipeline run if the binary is not present yet.

- Temporarily add the local Clang/LLVM toolchain to the current shell `PATH` when only the versioned LLVM install is available:

```bash
export LLVM_HOME=/usr/lib/llvm-20
export PATH="$LLVM_HOME/bin:$PATH"
clang --version
llvm-link --version
```

This is intentionally temporary: open a new shell to clear it, or run the same export again before generating Stage `A` input or launching `pipeline.py abcd`.

- Build the Stage `A` analyzer:

```bash
make build-analyzer
```

- Generate the sanitized Juliet copy and `srcs_sanitized/compile_commands.json`:

```bash
make gen-srcs-compile-commands
```

The Juliet compile database helper defaults to the Linux Win32 shim include path, the Juliet `testcasesupport` include path, `-D_WIN32`, and the shared `tools/juliet_win_shim/juliet_win_compat.h` forced include so Windows API samples compile to bitcode under Linux using the same shim declarations as Stage `D`.

If the environment only has versioned Clang binaries, generate the compile database normally, then pass the real compiler paths when converting it to Stage `A` input:

```bash
make gen-srcs-compile-commands SRC_CC_FORCE=1
make gen-input \
  GEN_CLANG=/usr/bin/clang-20 \
  GEN_CLANGXX=/usr/bin/clang++-20 \
  GEN_FORCE=1
```

- Generate a Stage `A` input JSONL from `compile_commands.json`:

```bash
make gen-input
```

Equivalent direct command:

```bash
python3 pipeline.py gen-input \
  --repo-path ./srcs_sanitized \
  --compile-commands ./srcs_sanitized/compile_commands.json \
  --output ./a/input/srcs.in.jsonl
```

This step is explicit. `make run-a` does not generate or overwrite Stage `A` input automatically.
By default, `gen-input` writes `extensions.analysis_timeout = 1800` seconds into the Stage `A` project record; override it with `GEN_ANALYSIS_TIMEOUT` or `--analysis-timeout`.
The Juliet helper above is also explicit; Stage `A` input generation still requires an existing `compile_commands.json` and does not infer compile flags from a bare source scan. The original `srcs/` tree remains the Juliet ground-truth source; default MAGUS runs use the sanitized `srcs_sanitized/` copy so comments, path names, macros, and symbols no longer expose bad/good labels to Stage `A`, Stage `B`, or Stage `C`.

- Run Stage `A` on the sanitized Juliet sample tree after generating its compile database and Stage `A` input:

```bash
make run-a A_INPUT=a/input/srcs.in.jsonl A_OUTPUT=a/out/srcs.raw.jsonl
```

- Run only Stage `A`. This also exports `samples.llm.jsonl` beside the raw output:

```bash
make run-a
```

- Run only Stage `B` against the derived stats view:

```bash
make run-b
```

- Run only Stage `C` against the Stage `B` C-ready candidate queue:

```bash
make run-c
```

- Run Stage `D` after Stage `C` has written one or more dynamic-verification candidate files under `c/out/`; this also generates the final report:

```bash
make run-d
```

- Regenerate only the final report from an existing Stage `D` output directory:

```bash
make run-report
```

- Run the full `A -> B -> streamed C/D -> Report` pipeline:

```bash
make run-abcd
```

This command runs Stage `A` and Stage `B`, then starts Stage `D` as a stream consumer for the current Stage `C` output file before launching Stage `C`. Stage `B` writes `candidates.for_c.jsonl` as route-aggregated Stage `A` LLM evidence records with `stage_b` scoring metadata attached and sorted by `c_priority_score` to front-load candidates that are more likely to become `P0`/`P1`/`P2` under a Stage `C` time budget. As Stage `C` flushes dynamic-verification JSONL records, including `P1`/`P2` and completed `P0` records, Stage `D` verifies those records without waiting for all Stage `C` candidates to finish. After Stage `D` finishes, Report reads the D output and writes the final vulnerability report under `report/<run-name>/`. The run name defaults to the unique CWE source folder in D output, such as `CWE15_External_Control_of_System_or_Configuration_Setting`; if D produced no records, the full-chain command uses the Stage `A` input `project_id`. Override it with `REPORT_RUN_NAME=<name>`. Set `C_TIME_LIMIT_SECONDS=<seconds>` to stop Stage `C` from submitting more candidates after a time budget. Stage `C` runs candidates in worker processes and uses positive-only Juliet template reuse: one candidate per unresolved template is audited first, and when it routes to `P0`/`P1`/`P2`, sibling template records are emitted with their own `route`/`file`/`line` and `stage_c_template_reuse` provenance for D to verify individually. After the deadline plus a short grace period, unfinished workers are terminated and their candidates are written as `P3` timeout audit records, while completed records remain complete newline-terminated JSONL. This command reaches Stage `C` and calls the DeepSeek API through the OpenAI-compatible Python SDK.

Stage `D` has two root modes. `make run-d` uses the formal batch script under `d/memberD_verifier/02_run_with_C`; it reads every `c/out/*.jsonl` file in filename order, trusts that Stage `C` has already selected the records that need dynamic verification, rejects duplicate `project_id + hypothesis_id` records, generates source/API targets, optionally binds `verification_contexts.jsonl`, runs the verifier, and validates the D output files. `make run-abcd` uses `d/memberD_verifier/02_run_with_C/stream_from_C.py` to follow only the current `--c-output` file while Stage `C` is still running. Both D modes use the same output lock so two D processes cannot write the same output directory concurrently. D may execute a complete project or full testcase, but `verification.jsonl` confirmations require route-bound oracle evidence that the candidate route or source/API sequence was reached; unbound runs stay in `verification.failed.jsonl` as `NOT_ROUTE_BOUND`. Stage `C` emits hypothesis/routing evidence only; Stage `D` owns verifier and oracle generation. For sanitized Juliet records under `srcs_sanitized/juliet-api-misuse`, D auto-fills a Linux Juliet Win32 runner plus route-bound oracle and uses `srcs_sanitized/juliet_sanitization_map.json` to choose the original bad/good execution scenario without exposing those labels to upstream stages. Other source/API projects provide D-owned execution context through `verification_contexts.jsonl` with `repo_path`, `run_cmd`/`poc_cmd`/`test_cmd`, and oracle fields. Report then writes `report/<run-name>/verification.report.jsonl` and `report/<run-name>/verification.report.md` from the D confirmed/failed records; each report entry includes file path, line, vulnerability type, risk level, and trigger condition. Prepare the local D Python environment once before running D:

```bash
(cd d/memberD_verifier/01_demo_test && ./01_setup_linux.sh)
```

Stage `D` currently uses only the Python standard library, so the setup script creates a no-pip virtual environment unless `00_core/requirements.txt` contains real dependencies.

- Compare the final report with Juliet answers for paper evaluation:

```bash
python3 test/evaluate_juliet_report.py \
  --report report/CWE15_External_Control_of_System_or_Configuration_Setting/verification.report.jsonl \
  --scope-compile-commands srcs_sanitized/compile_commands.cwe15.json \
  --stage-a-start 2026-05-20T10:00:00Z
```

To time a fresh full run from Stage `A` start through final report generation and then evaluate it:

```bash
python3 test/evaluate_juliet_report.py \
  --run-command "python3 pipeline.py abcd" \
  --scope-compile-commands srcs_sanitized/compile_commands.cwe15.json
```

The evaluator infers Juliet ground truth from the original `srcs/juliet-api-misuse` bad/good paths by default, or from an explicit `--answer-file`. Report paths from `srcs_sanitized/` are mapped back through `srcs_sanitized/juliet_sanitization_map.json` before classification. It writes paper-ready precision/recall/F1, false-positive, false-negative, duplicate-report, and elapsed-time artifacts under `test/out/juliet_eval/<run-name>/`; `<run-name>` follows the same derivation used for the final report. Override the evaluation output location with `--out-dir`.

- Show the derived `samples.stats.jsonl` path for a given Stage `A` raw output:

```bash
python3 pipeline.py stats-path --raw-output a/out/samples.raw.jsonl
```

- Show the derived `samples.llm.jsonl` path for a given Stage `A` raw output:

```bash
python3 pipeline.py llm-path --raw-output a/out/samples.raw.jsonl
```

## Validation Boundaries

The root orchestrator intentionally preserves separate validation:

- Stage `A` can still be validated independently through `make run-a` or the original commands inside `a/`; the root `make run-a` command also exports LLM evidence
- Stage `A` exits non-zero if any project record is invalid or mining fails, so root chained runs stop before Stage `B` consumes empty stats
- `srcs_sanitized/` and `srcs_sanitized/compile_commands.json` can be generated independently with `make gen-srcs-compile-commands`
- Stage `A` input can be generated independently with `make gen-input` from an existing `compile_commands.json`
- Stage `B` can still be validated independently by pointing it at matching `samples.stats.jsonl` and `samples.llm.jsonl`
- Stage `C` can still be validated independently by pointing it at an existing `candidates.for_c.jsonl`
- `make run-abcd` chains Stage `A` and Stage `B`, then streams Stage `C` dynamic candidates into Stage `D`
- Stage `D` can still be validated independently from `d/memberD_verifier` or through `make run-d`
- Report can be regenerated independently with `make run-report` from an existing Stage `D` output directory; it writes under `report/<run-name>/`
- Juliet report evaluation can be run independently from the final report; `--run-command` is only a convenience wrapper for timing a fresh pipeline run.

Important contract boundary:

- Stage `B` consumes Stage `A` stats records with schema `stagea.stats.features.v1` and matching Stage `A` LLM evidence keyed by `sample_id`
- Stage `B` validates the required stats fields before mining and rejects unsupported schemas
- Stage `B` writes a complete seed-level `candidates.scored.jsonl` plus a route-aggregated C-ready `candidates.for_c.jsonl`; C-ready records use schema `stageb.c_ready_candidates.v3`, keep only Stage `C` input fields, store merged Stage `A` LLM evidence under `llm_evidence`, and attach B scoring metadata under `stage_b`, including risk score weights, `static_confirmation_support`, `c_priority_score`, and `c_priority_components`
- Stage `C` consumes Stage `B` `candidates.for_c.jsonl`; it does not read Stage `A` outputs directly, and its prompt treats `stage_b` threshold gates, missing high-support features, seed tokens, reference samples, C queue priority metadata, and static-confirmation support as anti-hallucination constraints rather than vulnerability conclusions. Stage `C` validates `stage_b.static_confirmation_support` and routes otherwise-P0 findings to dynamic verification when B says static confirmation is unsupported.
- Stage `C` routes records by priority: `P1`/`P2` dynamic-verification candidates go to `c/out/*.jsonl`; completed `P0` static confirmations also go to `c/out/*.jsonl` so Stage `D` can route-bound verify them; `P3` audit-only records go to `c/audit/audit.jsonl`. Stage `C` time budgets only stop new submissions and turn unfinished in-flight work into `P3` timeout audit records. A debated candidate is written to `P3` only when every red-team round returns no vulnerability; if any round reports a vulnerability, hard contradictions or incomplete evidence keep it in the dynamic-verification queue instead of suppressing it. For sanitized Juliet templates, Stage `C` may reuse a positive `P0`/`P1`/`P2` audit result for sibling template routes, but it does not reuse `P3` no-vulnerability decisions; reused records keep candidate-specific location fields and include `stage_c_template_reuse` provenance. Stage `C` does not infer or emit D verifier/oracle configuration.
- Stage `D` batch mode consumes every record Stage `C` places under `c/out/*.jsonl`; root full-chain streaming mode consumes the current Stage `C --output` file as JSONL lines become complete. In both modes D does not re-check `P1`/`P2` or `agent_verdict`, does not read Stage `A` or Stage `B` outputs directly, and verifies C/C++ source/API misuse cases rather than HTTP endpoints. Stage `D` applies a 10-second execution timeout only to `P0`; `P1`/`P2` dynamic-verification records are not D-time-limited. Confirmed records require route-bound dynamic evidence; D returns failed records such as `NOT_EXPLOITABLE`, `NOT_ROUTE_BOUND`, `ENV_MISSING`, `HYPOTHESIS_WRONG`, `TIMEOUT`, or `NON_DETERMINISTIC` when execution or attribution is insufficient. Records whose `file`/`project_id` points at `srcs_sanitized/juliet-api-misuse` get an executable Juliet Win32 shim runner and oracle from target generation automatically; D-owned sidecar context is still available for non-Juliet projects or explicit overrides.
- Report consumes Stage `D` `verification.jsonl` and `verification.failed.jsonl`; it does not read Stage `A`, Stage `B`, or Stage `C` outputs directly. The root pipeline names the report directory from the unique CWE source folder in D output, or from the unique `project_id` when no single CWE folder is present. `validate_report.py` requires one report row per confirmed D record.
- `test/evaluate_juliet_report.py` consumes the final report plus Juliet answers only. It does not change pipeline outputs; it maps sanitized report paths back to original Juliet paths, classifies report rows against original Juliet bad/good cases, and measures elapsed time from Stage `A` start to final report generation when timing inputs are provided.

## Outputs

Default outputs:

- Stage `A` raw output: `a/out/samples.raw.jsonl`
- Stage `A` derived stats output: `a/out/samples.stats.jsonl`
- Stage `A` LLM evidence output: `a/out/samples.llm.jsonl`
- Generated Stage `A` project input: `a/input/srcs.in.jsonl`
- Sanitized Juliet copy and mapping: `srcs_sanitized/` and `srcs_sanitized/juliet_sanitization_map.json`
- Stage `B` outputs: `b/b_output/patterns.json`, `b/b_output/candidates.scored.jsonl`, `b/b_output/candidates.for_c.jsonl`, `b/b_output/b_miner_stats.json`
- Stage `C` dynamic-verification output: `c/out/hypotheses.jsonl` for `P1`/`P2` plus completed `P0` records, including optional `stage_c_template_reuse` provenance on positive template-reused Juliet records; Stage `C` audit-only output: `c/audit/audit.jsonl`; Stage `D` batch input: all `c/out/*.jsonl`; Stage `D` streaming input in `run-abcd`: the current `C_OUTPUT` file
- Stage `D` outputs: `d/memberD_verifier/02_run_with_C/output/verification.jsonl`, `verification.failed.jsonl`, `verification.summary.md`, and `payloads/*.api-plan.json` / `payloads/*.payload.py`
- Report outputs: `report/<run-name>/verification.report.jsonl` and `report/<run-name>/verification.report.md`
- Juliet evaluation outputs: `test/out/juliet_eval/<run-name>/summary.md`, `summary.json`, `false_positives.csv`, `false_negatives.csv`, `true_positives.csv`, `duplicate_true_positives.csv`, `all_findings.csv`, and `truth_cases.csv`

If you override `A_OUTPUT`, `pipeline.py` derives the matching stats and LLM paths automatically during full runs; `make run-b` derives the matching `samples.llm.jsonl` path for `B_LLM_INPUT`.

`samples.llm.jsonl` is Stage `A` evidence output produced by `a/cmd/llm_export.py`; it is emitted by the root `make run-a` and `make run-abcd` paths.

Stage `C` uses the DeepSeek-compatible OpenAI client configuration in `c/agent1.py`. It requires the Python `openai` package to be installed in the runtime environment.

Stage `B` does not currently expose a worker-count flag, and the root pipeline does not provide one. Stage `C` no longer exposes a candidate-count limit; use `C_TIME_LIMIT_SECONDS` or `pipeline.py c --time-limit-seconds` for time-bounded C runs. Time-bounded C runs write explicit `stage_c_time_budget_exhausted` P3 records for unfinished in-flight candidates after the grace period.
