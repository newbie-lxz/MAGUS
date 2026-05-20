# 正式接 C 的流程

这个文件夹只放接 C 输出后真正运行的东西。D 只处理源码/API 误用假设，这里的 API 指 C/C++ 函数调用接口，不是 HTTP API。
本目录只保留 Ubuntu/Linux 脚本，不提供 Windows 路径。

## 1. C 输出位置

C 输出目录由 Stage C 写到：

```text
c/out/
```

D 的正式脚本直接读取这个目录下的所有 `*.jsonl` 文件，并按文件名排序合并。D 不直接接 A 的输出；A 的输出已经被 B/C 加工，D 只收 C 放入 `c/out/*.jsonl` 的动态验证候选。

根目录 `make run-abcd` 使用流式接入：`pipeline.py` 先启动本目录的 `stream_from_C.py`，让它监听当前 `C_OUTPUT` 文件；随后启动 C。C 每写入一条完整 JSONL 记录，D 就生成 target、绑定可选 sidecar、执行 verifier，并追加 confirmed/failed 输出。C 结束后 pipeline 写 done 文件，D 读完剩余完整行再退出。这个模式只消费本次 `C_OUTPUT` 文件；本目录的 `01_auto_attack_from_C_linux.sh` 仍是独立批处理入口，读取所有 `c/out/*.jsonl`。

C 的分流约定是：

```text
P0 -> c/final/static_confirmed.jsonl  # 静态强确认，不进入 D
P1/P2 -> c/out/*.jsonl                # D 动态验证队列
P3 -> c/audit/audit.jsonl             # 审计记录，不进入 D
```

如果多个文件里出现相同的 `project_id + hypothesis_id`，脚本会直接失败，要求先消除重复输入。

`gen_targets_from_hypotheses.py` 生成 targets 时要求每条假设至少有：

```text
project_id
hypothesis_id
route
```

`verifier.py` 写 confirmed/failed 记录时要求每条假设至少有：

```text
project_id
sample_id
hypothesis_id
route
file
line
evidence_slice
```

D 信任 `c/out` 的分流结果，不再根据 `agent_verdict` 或 `priority` 做准入判断；CWE 字段可以是 Stage C 当前的 `CWE_candidates`，也可以是 `cwe_candidates`。

## 2. 可选执行上下文

如果 C 输出没有 `verification_context`，不要改 C 核心逻辑。可以在本目录放一个 sidecar：

```text
verification_contexts.jsonl
```

格式支持 project、route、hypothesis 三级绑定，优先级为：

```text
hypothesis_id > route > project_id
```

示例：

```json
{"project_id":"juliet_small_c","repo_path":"srcs/juliet-small","test_cmd":"./repros/run_juliet_case.sh ${file} ${entry_symbol}","oracle":{"failure_patterns":["AddressSanitizer","Segmentation fault"],"expect_nonzero_exit":false}}
```

当前仓库的 `project_id=cwe15` 使用项目级 sidecar 绑定到
`tools/juliet_win_shim/run_cwe15_case.py`。该 runner 会在 Linux 下编译单个
Juliet CWE15 Win32 样本，链接本仓库的 WinSock/Windows API runtime stub，并用
`MAGUS_CWE15_CONFIRMED` 作为 oracle 标记确认外部输入到达 `SetComputerNameA`。

自动脚本会先生成 `targets.auto.json`，如果发现 `verification_contexts.jsonl`，再通过 `bind_verification_contexts.py` 输出 `targets.executable.json` 给原 verifier 执行。
sidecar 里的记录必须能命中当前 targets；如果出现未匹配的 `project_id`、`route` 或 `hypothesis_id`，脚本会直接失败。

## 3. 自动验证

运行：

```text
./01_auto_attack_from_C_linux.sh
```

仓库根目录也提供等价入口：

```text
make run-d
```

完整顺序链路：

```text
make run-abcd
```

`make run-abcd` 现在是 A、B 顺序执行，C 和 D 并行流式执行。D 只读 C 当前输出，不写回 `c/out`，并且只处理换行结束的完整 JSONL 记录。

D 的批处理和流式模式共用输出锁：

```text
.stage_d_output.lock
```

锁存在时，另一个写同一 `output` 目录的 D 进程会直接失败，避免 `verification*.jsonl` 和 `payloads/` 被并发写入。

D 当前只使用 Python 标准库；`../01_demo_test/01_setup_linux.sh` 在没有真实 requirements 依赖时会创建不带 pip 的 `.venv`。

输出：

```text
targets.auto.json
targets.executable.json  # only when verification_contexts.jsonl exists
output/payloads/*.payload.py
output/payloads/*.api-plan.json
output/verification.jsonl
output/verification.failed.jsonl
output/verification.summary.md
```

## 4. 什么时候能执行

最小可执行字段是：

```text
verification_context.repo_path
verification_context.run_cmd 或 poc_cmd 或 test_cmd
verification_context.oracle
```

`config_cmd` 和 `build_cmd` 可选，用来准备源码项目。

## 5. 如果自动模式失败

失败不是坏事，它会输出失败回流。可以运行：

```text
./02_generate_targets_from_C_linux.sh
```

生成 `targets.manual.json` 后补真实仓库路径、构建命令、运行命令、PoC harness 或 oracle，再运行：

```text
./03_verify_manual_targets_linux.sh
```
