# Unfinished Work

## Linux Kernel Compile Commands Tooling

- Linux kernel input preparation is not implemented yet.
- `tools/gen_srcs_compile_commands.py` is intentionally limited to the checked-in `srcs/juliet-small` sample tree and must not be reused as a generic compile database generator.
- A future Linux-specific helper should generate or collect a real `compile_commands.json` from the kernel build system, preserving kernel configuration, architecture flags, generated headers, include paths, and per-translation-unit compiler arguments.
- The generic MAGUS boundary remains `pipeline.py gen-input --compile-commands <path>` after a valid kernel `compile_commands.json` exists.

## Stage C LLM Failure Handling

- `c/agent1.py` currently treats any `call_llm()` failure as a missing response and silently falls back to `NO_VULNERABILITY_FOUND` / `reject`.
- This masks real API, network, timeout, and JSON parsing failures as security decisions, so valid Stage B candidates can be dropped without an explicit pipeline failure.
- Future work should distinguish transport/API errors, empty responses, malformed JSON, and truncated JSON; failed LLM calls should either retry with bounded policy or fail the Stage C run with a clear diagnostic.
- Stage C output should only contain accept/reject verdicts derived from successfully parsed LLM responses, not infrastructure failure fallbacks.
