# MAGUS Pipeline

MAGUS is a multi-stage mining pipeline plus a small root-level orchestrator:

- `a/`: Stage `A` static-analysis pipeline that emits `samples.raw.jsonl` plus the derived `samples.stats.jsonl` view.
- `b/`: Stage `B` miner that consumes Stage `A` `samples.stats.jsonl` records, mines high-support feature patterns, and scores candidates.
- `c/`: Stage `C` adversarial audit that consumes Stage `A` `samples.llm.jsonl` evidence and Stage `B` `candidates.scored.jsonl`.
- `pipeline.py`: root entrypoint for generating Stage `A` input, running Stage `A`, Stage `B`, Stage `C`, or chained `A -> B` / `A -> B -> C` flows from one place.
- `tools/gen_srcs_compile_commands.py`: explicit helper for generating `srcs/compile_commands.json` for the checked-in Juliet sample tree.


## Layout

- `pipeline.py`: root orchestration for `build-analyzer`, `gen-input`, `a`, `llm`, `b`, `c`, `ab`, `abc`, `stats-path`, and `llm-path`
- `Makefile`: convenience wrappers around `pipeline.py`
- `tools/`: repository-level helper scripts
- `a/`: standalone Stage `A` project
- `b/`: standalone Stage `B` miner, usage notes, and outputs
- `c/`: standalone Stage `C` audit agent and outputs

## Common Commands

Build the Stage `A` analyzer once before the first Stage `A` or chained `A -> B` run if the binary is not present yet.

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

- Run only Stage `A`:

```bash
make run-a
```

- Export Stage `A` LLM evidence from an existing raw output:

```bash
make run-llm
```

- Run only Stage `B` against the derived stats view:

```bash
make run-b
```

- Run only Stage `C` against Stage `A` LLM evidence and Stage `B` candidates:

```bash
make run-c
```

- Run the full `A -> B` pipeline:

```bash
make run-ab
```

- Run the full `A -> B -> C` pipeline:

```bash
make run-abc
```

This command reaches Stage `C` and will call the DeepSeek API through the OpenAI-compatible Python SDK.

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

- Stage `A` can still be validated independently through `make run-a` or the original commands inside `a/`
- `srcs/compile_commands.json` can be generated independently with `make gen-srcs-compile-commands`
- Stage `A` input can be generated independently with `make gen-input` from an existing `compile_commands.json`
- Stage `B` can still be validated independently by pointing it at any existing `samples.stats.jsonl`
- Stage `C` can still be validated independently by pointing it at an existing `samples.llm.jsonl` and `candidates.scored.jsonl`
- `make run-ab` chains Stage `A` and Stage `B` without changing either stage's internal logic
- `make run-abc` chains Stage `A`, Stage `A` LLM export, Stage `B`, and Stage `C`

Important contract boundary:

- Stage `B` consumes Stage `A` stats records with schema `stagea.stats.features.v1`
- Stage `B` validates the required stats fields before mining and rejects unsupported schemas
- Stage `C` consumes Stage `A` `samples.llm.jsonl` and Stage `B` `candidates.scored.jsonl`; it does not read `samples.raw.jsonl`

## Outputs

Default outputs:

- Stage `A` raw output: `a/out/samples.raw.jsonl`
- Stage `A` derived stats output: `a/out/samples.stats.jsonl`
- Stage `A` optional LLM evidence output: `a/out/samples.llm.jsonl`
- Generated Stage `A` project input: `a/input/srcs.in.jsonl`
- Stage `B` outputs: `b/b_output/patterns.json`, `b/b_output/candidates.scored.jsonl`, `b/b_output/b_miner_stats.json`
- Stage `C` output: `c/out/hypotheses.jsonl`

If you override `A_OUTPUT`, `pipeline.py` derives the matching stats path automatically during `run-ab`; `make run-llm`, `make run-c`, and `make run-abc` derive the matching `samples.llm.jsonl` path for `C_LLM_INPUT`.

`samples.llm.jsonl` is optional evidence output produced by `a/cmd/llm_export.py`; it is emitted by `make run-llm` and by the `make run-abc` chain, but not by the default `make run-a` path.

Stage `C` uses the DeepSeek-compatible OpenAI client configuration in `c/agent1.py`. It requires the Python `openai` package to be installed in the runtime environment.

Stage `B` does not currently expose a worker-count flag, and the root pipeline does not provide one.
