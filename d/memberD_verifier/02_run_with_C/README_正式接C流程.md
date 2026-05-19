# 正式接 C 的流程

这个文件夹只放接 C 输出后真正运行的东西。D 只处理源码/API 误用假设，这里的 API 指 C/C++ 函数调用接口，不是 HTTP API。

## 1. C 输出位置

C 输出文件由 Stage C 写到：

```text
c/out/hypotheses.jsonl
```

D 的正式脚本直接读取这个文件。D 不直接接 A 的输出；A 的输出已经被 B/C 加工，D 只收 C 传来的 `hypotheses.jsonl`。

## 2. 自动验证

运行：

```text
01_auto_attack_from_C_windows.bat
```

输出：

```text
targets.auto.json
output/payloads/*.payload.py
output/payloads/*.api-plan.json
output/verification.jsonl
output/verification.failed.jsonl
output/verification.summary.md
```

## 3. 什么时候能执行

最小可执行字段是：

```text
verification_context.repo_path
verification_context.run_cmd 或 poc_cmd 或 test_cmd
verification_context.oracle
```

`config_cmd` 和 `build_cmd` 可选，用来准备源码项目。

## 4. 如果自动模式失败

失败不是坏事，它会输出失败回流。可以运行：

```text
02_generate_targets_from_C_windows.bat
```

生成 `targets.manual.json` 后补真实仓库路径、构建命令、运行命令、PoC harness 或 oracle，再运行：

```text
03_verify_manual_targets_windows.bat
```
