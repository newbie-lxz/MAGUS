# A 输出上下文说明

这些文件是从工作区根目录的 `out.zip` 里抽出来的，只保留 `out/secvuleval` 下和 relic 相关的关键信息。relic 只是样例项目，不代表正式输入一定是 C 语言库；Linux、OpenSSL、FFmpeg、Apache、zlib 这类论文项目也走同一个源码/API 误用理解方式。

## 这些文件能提供什么

- `relic.summary.json`：A 输出概览，例如数据集路径、target 数量、run 数量。
- `relic.targets.jsonl`：SecVulEval/relic 的标签目标，包括 `project_id`、`commit_id`、`filepath`、`func_name`、`is_vulnerable`、`cve_list`、`cwe_list`、`changed_lines`。
- `relic.run.plan.jsonl`：A 阶段为 relic 准备的构建/运行计划，包括 `repo_path`、`language`、`source_globs`、`entry_functions`、`config_cmd`、`build_cmd`。
- `relic.file.plan.jsonl`：按文件聚合的入口函数和 target 数量。

## 这些文件不能提供什么

这些文件只提供源码项目上下文，不提供可直接执行的 PoC harness。

relic 是 C 语言密码库数据。D 的动态验证方向是编译、测试和 PoC runner。

## D 应该怎么用

如果 C 的 `c/out/*.jsonl` 假设是基于这些 relic/A 输出生成的，D 可以把这里的文件当作验证上下文，用来定位：

- 哪个项目/commit
- 哪个 C 文件/函数
- 哪些 CWE/CVE 标签
- A 阶段怎么构建
- 哪些 changed lines 是证据

动态验证如果要做，需要基于 `relic.run.plan.jsonl` 的 `config_cmd/build_cmd` 或 C 最终给出的构建信息来运行测试/PoC。
