# 演示测试流程

这个文件夹只保留源码/API 误用演示。这里的 API 指 C/C++ 函数调用接口，不是 HTTP API。

## 源码/API 计划演示

运行：

```text
07_source_api_demo_windows.bat
```

这个演示会生成：

```text
out_source_api/payloads/*.api-plan.json
out_source_api/payloads/*.payload.py
out_source_api/verification.failed.jsonl
```

该样例缺少真实仓库构建/运行命令，所以会进入 failed 回流。

## 可执行 payload 演示

运行：

```text
08_source_api_executable_demo_windows.bat
```

这个演示会进入 `mock_source_project` 执行 `poc.py`，命中 oracle 后写入：

```text
out_source_api_executable/verification.jsonl
```

## 文件说明

- `samples/`：演示用的 C 输出样例。
- `mock_source_project/`：源码/API 可执行 payload 演示项目。
- `out_source_api/`：源码/API 计划和失败回流输出。
- `out_source_api_executable/`：源码/API 可执行 confirmed 演示输出。
- `targets.source_api.auto.json`：根据源码/API 样例自动生成的 targets。
- `targets.source_api.executable.auto.json`：可执行源码/API 样例 targets。
