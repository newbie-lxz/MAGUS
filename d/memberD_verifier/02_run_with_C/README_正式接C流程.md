# 正式接 C 的流程

这个文件夹只放接 C 输出后真正运行的东西。D 只处理源码/API 误用假设，这里的 API 指 C/C++ 函数调用接口，不是 HTTP API。
本目录只保留 Ubuntu/Linux 脚本，不提供 Windows 路径。

## 1. C 输出位置

C 输出目录由 Stage C 写到：

```text
c/out/
```

D 的正式脚本直接读取这个目录下的所有 `*.jsonl` 文件，并按文件名排序合并。D 不直接接 A 的输出；A 的输出已经被 B/C 加工，D 只收 C 放入 `c/out/*.jsonl` 的动态验证候选。

根目录 `make run-abcd` 使用流式接入：`pipeline.py` 先启动本目录的 `stream_from_C.py`，让它监听当前 `C_OUTPUT` 文件；随后启动 C。C 每写入一条完整 JSONL 记录，D 就生成 target、绑定可选 sidecar、执行 verifier，并追加 reportable/failed 输出。reportable 包括 D confirmed，以及 D 明确返回 `UNSUPPORTED_ORACLE` 时保留的 Stage C 判断。C 结束后 pipeline 写 done 文件，D 读完剩余完整行再退出，然后 Report 从 D 输出生成最终报告。这个模式只消费本次 `C_OUTPUT` 文件，并把 D 输出写到 `output/<run-name>/`；`<run-name>` 来自 `REPORT_RUN_NAME` / `--report-run-name`，未提供时使用 Stage A 输入的 `project_id`。本目录的 `01_auto_attack_from_C_linux.sh` 仍是独立批处理入口，读取所有 `c/out/*.jsonl`，写入固定 `output/`，并在 D 校验通过后运行 Report。

C 的分流约定是：

```text
P0 -> c/out/*.jsonl                                # D 动态验证队列
P1/P2 -> c/out/*.jsonl                              # D 动态验证队列
P3 -> c/audit/audit.jsonl                           # 审计记录，不进入 D
```

Stage C 的时间预算只控制是否继续提交候选，以及未完成 worker 是否转成
`P3` 超时审计记录。已完成的 P0 不因 C deadline 改写到非 D 输出；
D 只对 P0 施加每条 10 秒执行 timeout；P1/P2 不受 D timeout 限制。

如果多个文件里出现相同的 `project_id + hypothesis_id`，脚本会直接失败，要求先消除重复输入。

`gen_targets_from_hypotheses.py` 生成 targets 时要求每条假设至少有：

```text
project_id
hypothesis_id
route
```

`verifier.py` 写 reportable/failed 记录时要求每条假设至少有：

```text
project_id
sample_id
hypothesis_id
route
file
line
evidence_slice
```

D 信任 `c/out` 的分流结果，不再根据 `agent_verdict` 或 `priority` 做准入判断；CWE 字段可以是 Stage C 当前的 `CWE_candidates`，也可以是 `cwe_candidates`。Stage C 只输出漏洞假设、代码位置和 `route`，不输出 D verifier/oracle 配置；这些由 Stage D 生成或由本目录 sidecar 提供。

## 2. 可选执行上下文

需要为非 Juliet 项目提供执行上下文时，不要改 C 核心逻辑。在本目录放一个 D 侧 sidecar：

```text
verification_contexts.jsonl
```

格式支持 project、route、hypothesis 三级绑定，优先级为：

```text
hypothesis_id > route > project_id
```

示例：

```json
{"project_id":"custom_source_api","repo_path":"/datasets/custom-source-api","test_cmd":"./repros/run_case.sh ${file} ${entry_symbol}","oracle":{"failure_patterns":["AddressSanitizer","Segmentation fault"],"expect_nonzero_exit":false}}
```

当前仓库的 `srcs_sanitized/juliet-api-misuse` 不需要项目级 sidecar。`gen_targets_from_hypotheses.py`
会自动绑定到 `tools/juliet_win_shim/run_juliet_win_case.py`，在 Linux 下编译单个
Juliet Win32 testcase，并链接本仓库的 Win32 API shim。runner 会通过
`srcs_sanitized/juliet_sanitization_map.json` 把 `${route}` / `${entry_symbol}` 的
中性化 `case0` / `case1` / `V1` / `V2` 标签映射回原始 Juliet bad/good 场景；遇到 `*_case0.cpp`、
`*_case1V1.cpp`、`*b.c` 这类 helper 文件时，会回到同组主文件完整编译运行，不抽取
C 的 evidence slice。只有当前场景被执行且外部 payload 到达对应 source/API sink，
或坏路径触发了点缺陷 API 标记，才输出 `MAGUS_JULIET_ROUTE_CONFIRMED`；仅能证明同文件
其他路径触发时不会 confirmed。当前 route 已执行但 D 缺少对应漏洞语义 oracle 时，runner 输出
`MAGUS_JULIET_ORACLE_UNSUPPORTED`，D 会写 `stage_c_preserved` 以保留 Stage C 判断。

内置 shim 覆盖 WinSock、WinLDAP、WinCrypt、进程/命令执行、注册表/路径、管道/权限、
句柄生命周期、临时文件、弱 PRNG、VirtualLock 等 Juliet Win32 API misuse 场景。

sidecar 的 oracle 支持：

```text
failure_patterns         # confirmed 模式
required_patterns        # confirmed 前必须同时存在的 route-bound 模式
failure_code_patterns    # 把输出模式映射为 NOT_ROUTE_BOUND / NOT_EXPLOITABLE 等失败码
unsupported_patterns     # route 已执行但 D oracle 不支持当前漏洞语义时保留 C 判断
```

自动脚本会先生成 `targets.auto.json`；`srcs_sanitized/juliet-api-misuse` 记录在这一步已经带有可执行 runner/oracle。如果发现 `verification_contexts.jsonl`，再通过 `bind_verification_contexts.py` 输出 `targets.executable.json` 给原 verifier 执行。
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

锁存在时，另一个 D 写进程会直接失败，避免 `verification*.jsonl` 和 `payloads/` 被并发写入。

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

`run-abcd` 流式模式使用同样的文件名，但放在 `output/<run-name>/` 下。

`validate_outputs.py` 只校验 D 输出。自动脚本在 D 校验通过后调用根目录 `pipeline.py report`，再由它调用 `report/code/generate_report.py`。`run-abcd` 的最终漏洞报告写到 `report/<run-name>/`，并和 D 的 `output/<run-name>/` 使用同一个名字；需要手工指定目录名时设置 `REPORT_RUN_NAME=<name>`。独立批处理脚本的 Report 目录仍由根 `pipeline.py report` 从 D 输出中的唯一 Juliet CWE 源码目录或唯一 `project_id` 推导，也可用 `REPORT_RUN_NAME=<name>` 覆盖。

```text
report/<run-name>/verification.report.jsonl
report/<run-name>/verification.report.md
```

报告从 D `verification.jsonl` 的 reportable 记录生成。报告的每条漏洞必须包含：漏洞位置（文件路径、行号、route）、漏洞类型、风险等级、触发条件、运行证据和 payload/plan 引用。`report/code/validate_report.py` 会校验报告文件存在，并要求报告行数与 `verification.jsonl` reportable 行数一致；报告状态可以是 `confirmed` 或 `stage_c_preserved`。

`verification.failed.jsonl` 中的 `NOT_ROUTE_BOUND` 表示执行成功但不能把证据归因到当前候选 route。
`NOT_EXPLOITABLE` 只表示支持的 oracle 已运行且未确认漏洞；如果 D 没有能力验证当前漏洞语义，应使用 `UNSUPPORTED_ORACLE` 并保留 C 判断。

## 4. 什么时候能执行

非 Juliet 项目的 sidecar 最小可执行字段是：

```text
repo_path
run_cmd 或 poc_cmd 或 test_cmd
oracle
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
