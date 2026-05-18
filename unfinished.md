# Unfinished Work

## Linux Kernel Compile Commands Tooling

- Linux kernel input preparation is not implemented yet.
- `tools/gen_srcs_compile_commands.py` is intentionally limited to the checked-in `srcs/juliet-small` sample tree and must not be reused as a generic compile database generator.
- A future Linux-specific helper should generate or collect a real `compile_commands.json` from the kernel build system, preserving kernel configuration, architecture flags, generated headers, include paths, and per-translation-unit compiler arguments.
- The generic MAGUS boundary remains `pipeline.py gen-input --compile-commands <path>` after a valid kernel `compile_commands.json` exists.
