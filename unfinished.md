# Unfinished Work

## Linux Kernel Compile Commands Tooling

- Linux kernel input preparation is not implemented yet.
- `tools/gen_srcs_compile_commands.py` is intentionally limited to the checked-in `srcs/juliet-small` sample tree and must not be reused as a generic compile database generator.
- A future Linux-specific helper should generate or collect a real `compile_commands.json` from the kernel build system, preserving kernel configuration, architecture flags, generated headers, include paths, and per-translation-unit compiler arguments.
- The generic MAGUS boundary remains `pipeline.py gen-input --compile-commands <path>` after a valid kernel `compile_commands.json` exists.

## Stage C LLM Failure Handling

- `c/agent1.py` now routes failed LLM rounds to `P3` audit-only records instead of sending them to D as dynamic-verification candidates.
- Remaining risk: a transport/API/timeout/JSON parsing problem still does not fail the Stage C run by default, so a transient LLM outage can move candidates into `c/audit/audit.jsonl` rather than forcing operator intervention.
- Future work should distinguish transport/API errors, empty responses, malformed JSON, and truncated JSON; failed LLM calls should either retry with a bounded policy or fail the Stage C run with a clear diagnostic.
- Stage C `c/out/*.jsonl` should contain only dynamic-verification candidates selected for D: `P1`/`P2` plus completed `P0` records. Infrastructure failure fallbacks must not enter `c/out`.

## Stage C Interrupt Handling

- Stage C now writes each completed sample immediately, but one interrupt edge remains: because `ThreadPoolExecutor` is owned by a `with` block, a normal Ctrl-C may wait for already submitted queued tasks to continue for a while.
- To exactly match the desired behavior of "do not run the remaining samples; only keep results produced before interruption", a future change can add explicit `KeyboardInterrupt` handling that cancels futures which have not started, preserves already flushed output, and exits immediately.
