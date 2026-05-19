# 收到 C 的 hypotheses.jsonl 后怎么做

正式接 C 的所有东西都在：

```text
02_run_with_C
```

## 自动模式

1. 确认 C 已经输出：

```text
c/out/hypotheses.jsonl
```

2. 运行：

```text
02_run_with_C/01_auto_attack_from_C_windows.bat
```

Linux 环境可运行：

```text
02_run_with_C/01_auto_attack_from_C_linux.sh
```

它会自动生成：

```text
02_run_with_C/targets.auto.json
02_run_with_C/output/payloads/*.payload.py
02_run_with_C/output/payloads/*.api-plan.json
02_run_with_C/output/verification.jsonl
02_run_with_C/output/verification.failed.jsonl
02_run_with_C/output/verification.summary.md
```

## 能不能 confirmed

如果 C 提供了：

```text
verification_context.repo_path
verification_context.run_cmd 或 poc_cmd 或 test_cmd
verification_context.oracle
```

D 会执行生成的 runner，并按 oracle 判定 confirmed 或 failed。

如果缺少这些字段，D 仍会生成 payload 和 plan，但结果会进入 `verification.failed.jsonl`，用于回流缺失信息。

## 手动补强模式

如果自动模式没有确认漏洞，运行：

```text
02_run_with_C/02_generate_targets_from_C_windows.bat
```

然后编辑：

```text
02_run_with_C/targets.manual.json
```

补真实仓库路径、构建命令、运行命令、PoC harness 或 oracle 后，再运行：

```text
02_run_with_C/03_verify_manual_targets_windows.bat
```
