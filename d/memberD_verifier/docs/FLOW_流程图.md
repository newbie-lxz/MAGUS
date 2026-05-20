# 最简单流程

```text
C 分流：P1/P2 写 c/out；P0 有时间预算写 c/out，deadline 后写 c/final；P3 写 c/audit
        ↓
D 读取 c/out/*.jsonl 动态验证队列
        ↓
D 按文件名排序读取并检查重复 project_id + hypothesis_id
        ↓
运行 gen_targets_from_hypotheses.py --auto-fill
        ↓
得到 source_api targets.auto.json
        ↓
如果存在 verification_contexts.jsonl，绑定 execution/oracle 到 targets.executable.json
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
