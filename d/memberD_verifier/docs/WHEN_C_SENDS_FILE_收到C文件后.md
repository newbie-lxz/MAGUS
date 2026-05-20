# 收到 C 的 c/out/*.jsonl 后怎么做

正式接 C 的所有东西都在：

```text
02_run_with_C
```

## 自动模式

1. 确认 C 已经输出一个或多个 JSONL 文件：

```text
c/out/*.jsonl
```

D 会按文件名排序读取这些文件；如果不同文件里有重复的 `project_id + hypothesis_id`，会直接报错。

2. 运行：

```text
02_run_with_C/01_auto_attack_from_C_linux.sh
```

它会自动生成：

```text
02_run_with_C/targets.auto.json
02_run_with_C/targets.executable.json  # 如果存在 verification_contexts.jsonl
02_run_with_C/output/payloads/*.payload.py
02_run_with_C/output/payloads/*.api-plan.json
02_run_with_C/output/verification.jsonl
02_run_with_C/output/verification.failed.jsonl
02_run_with_C/output/verification.summary.md
```

如果 C 的假设文件没有可执行上下文，可以在同目录补一个 sidecar：

```text
02_run_with_C/verification_contexts.jsonl
```

它不会修改 C 输出，也不改 D core。自动脚本会把 sidecar 绑定进 `targets.executable.json` 后交给原 verifier。
sidecar 必须能命中当前 targets；未匹配的 `project_id`、`route` 或 `hypothesis_id` 会直接报错。

## 能不能 confirmed

如果 C 提供了：

```text
verification_context.repo_path
verification_context.run_cmd 或 poc_cmd 或 test_cmd
verification_context.oracle
```

D 会执行生成的 runner，并按 oracle 判定 confirmed 或 failed。

这些字段也可以来自 `verification_contexts.jsonl`。sidecar 支持按 `project_id`、`route`、`hypothesis_id` 绑定，优先级是 `hypothesis_id > route > project_id`。

如果缺少这些字段，D 仍会生成 payload 和 plan，但结果会进入 `verification.failed.jsonl`，用于回流缺失信息。

## 手动补强模式

如果自动模式没有确认漏洞，运行：

```text
02_run_with_C/02_generate_targets_from_C_linux.sh
```

然后编辑：

```text
02_run_with_C/targets.manual.json
```

补真实仓库路径、构建命令、运行命令、PoC harness 或 oracle 后，再运行：

```text
02_run_with_C/03_verify_manual_targets_linux.sh
```
