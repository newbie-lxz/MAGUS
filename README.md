# MAGUS Pipeline

MAGUS is a multi-stage mining pipeline plus a small root-level orchestrator:

- `a/`: Stage `A` static-analysis pipeline that emits `samples.raw.jsonl`, the derived `samples.stats.jsonl` view, and `samples.llm.jsonl` evidence.
- `b/`: Stage `B` miner that consumes Stage `A` `samples.stats.jsonl` records, mines high-support feature patterns, and scores candidates.
- `c/`: Stage `C` adversarial audit that consumes Stage `A` `samples.llm.jsonl` evidence and Stage `B` `candidates.scored.jsonl`.
- `d/`: Stage `D` source/API verifier that consumes Stage `C` `c/out/*.jsonl` hypotheses and produces confirmed or failed dynamic-verification records.
- `pipeline.py`: root entrypoint for generating Stage `A` input, running Stage `A`, Stage `B`, Stage `C`, Stage `D`, or the full `A -> B -> C -> D` flow from one place.
- `tools/gen_srcs_compile_commands.py`: explicit helper for generating `srcs/compile_commands.json` for the checked-in Juliet sample tree.


## Layout

- `pipeline.py`: root orchestration for `build-analyzer`, `gen-input`, `a`, `b`, `c`, `d`, `abcd`, `stats-path`, and `llm-path`
- `Makefile`: convenience wrappers around `pipeline.py`
- `tools/`: repository-level helper scripts
- `a/`: standalone Stage `A` project
- `b/`: standalone Stage `B` miner, usage notes, and outputs
- `c/`: standalone Stage `C` audit agent and outputs
- `d/`: standalone Stage `D` source/API verifier, Linux scripts, and usage notes

## Common Commands

Build the Stage `A` analyzer once before the first Stage `A` or full pipeline run if the binary is not present yet.

- Build the Stage `A` analyzer:

```bash
make build-analyzer
```

- Generate `srcs/compile_commands.json` for the checked-in Juliet sample tree:

```bash
make gen-srcs-compile-commands
```

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
  --repo-path ./srcs \
  --compile-commands ./srcs/compile_commands.json \
  --output ./a/input/srcs.in.jsonl
```

This step is explicit. `make run-a` does not generate or overwrite Stage `A` input automatically.
The `srcs` helper above is also explicit; Stage `A` input generation still requires an existing `compile_commands.json` and does not infer compile flags from a bare source scan.

- Run Stage `A` on the checked-in `srcs` sample tree after generating its compile database and Stage `A` input:

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

- Run only Stage `C` against Stage `A` LLM evidence and Stage `B` candidates:

```bash
make run-c
```

- Run only Stage `D` after Stage `C` has written one or more `*.jsonl` files under `c/out/`:

```bash
make run-d
```

- Run the full `A -> B -> C -> D` pipeline:

```bash
make run-abcd
```

This command reaches Stage `C` and will call the DeepSeek API through the OpenAI-compatible Python SDK before entering Stage `D`.

Stage `D` still uses the formal script under `d/memberD_verifier/02_run_with_C`. The root `d` and `abcd` commands call that script, which reads every `c/out/*.jsonl` file in filename order, rejects duplicate `project_id + hypothesis_id` records, generates source/API targets, optionally binds `verification_contexts.jsonl`, runs the verifier, and validates the output files. Prepare the local D Python environment once before running D:

```bash
(cd d/memberD_verifier/01_demo_test && ./01_setup_linux.sh)
```

Stage `D` currently uses only the Python standard library, so the setup script creates a no-pip virtual environment unless `00_core/requirements.txt` contains real dependencies.

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
- `srcs/compile_commands.json` can be generated independently with `make gen-srcs-compile-commands`
- Stage `A` input can be generated independently with `make gen-input` from an existing `compile_commands.json`
- Stage `B` can still be validated independently by pointing it at any existing `samples.stats.jsonl`
- Stage `C` can still be validated independently by pointing it at an existing `samples.llm.jsonl` and `candidates.scored.jsonl`
- `make run-abcd` chains Stage `A`, Stage `B`, Stage `C`, and Stage `D`
- Stage `D` can still be validated independently from `d/memberD_verifier` or through `make run-d`

Important contract boundary:

- Stage `B` consumes Stage `A` stats records with schema `stagea.stats.features.v1`
- Stage `B` validates the required stats fields before mining and rejects unsupported schemas
- Stage `C` consumes Stage `A` `samples.llm.jsonl` and Stage `B` `candidates.scored.jsonl`; it does not read `samples.raw.jsonl`
- Stage `D` consumes Stage `C` `c/out/*.jsonl`; it does not read Stage `A` or Stage `B` outputs directly, and it verifies C/C++ source/API misuse cases rather than HTTP endpoints

## Outputs

Default outputs:

- Stage `A` raw output: `a/out/samples.raw.jsonl`
- Stage `A` derived stats output: `a/out/samples.stats.jsonl`
- Stage `A` LLM evidence output: `a/out/samples.llm.jsonl`
- Generated Stage `A` project input: `a/input/srcs.in.jsonl`
- Stage `B` outputs: `b/b_output/patterns.json`, `b/b_output/candidates.scored.jsonl`, `b/b_output/b_miner_stats.json`
- Stage `C` default output: `c/out/hypotheses.jsonl`; Stage `D` batch input: all `c/out/*.jsonl`
- Stage `D` outputs: `d/memberD_verifier/02_run_with_C/output/verification.jsonl`, `verification.failed.jsonl`, `verification.summary.md`, and `payloads/*.api-plan.json` / `payloads/*.payload.py`

If you override `A_OUTPUT`, `pipeline.py` derives the matching stats path automatically during full runs; `make run-a`, `make run-c`, and `make run-abcd` derive the matching `samples.llm.jsonl` path for `C_LLM_INPUT`.

`samples.llm.jsonl` is Stage `A` evidence output produced by `a/cmd/llm_export.py`; it is emitted by the root `make run-a` and `make run-abcd` paths.

Stage `C` uses the DeepSeek-compatible OpenAI client configuration in `c/agent1.py`. It requires the Python `openai` package to be installed in the runtime environment.

Stage `B` does not currently expose a worker-count flag, and the root pipeline does not provide one.
