# 最简单流程

```text
C 写 c/out/hypotheses.jsonl
        ↓
运行 gen_targets_from_hypotheses.py --auto-fill
        ↓
得到 source_api targets.auto.json
        ↓
运行 verifier.py
        ↓
生成 payloads/*.api-plan.json 和 payloads/*.payload.py
        ↓
如果有 repo_path + run_cmd/poc_cmd/test_cmd，则执行源码/API runner
        ↓
按 oracle 输出 verification.jsonl 或 verification.failed.jsonl
        ↓
运行 validate_outputs.py 校验门禁字段
        ↓
如果失败，补仓库路径、构建命令、运行命令、PoC harness 或 oracle
```

本流程只处理 C/C++ 函数调用接口和调用序列，不处理 HTTP API。
