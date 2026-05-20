# A 输出参考

这个文件夹不是 D 的正式输入。

正式链路是：

```text
A -> B -> C -> D
```

D 只接 C 加工并分流到 `c/out/*.jsonl` 的 `P1`/`P2` 动态验证候选。

这里的文件只是我查看 `D:\lxz_whu\APP-Miner\out.zip` 时抽取出来的参考材料，用来确认 A 同学的包里有什么。

结论：

- A 的 `out.zip` 里是 SecVulEval/relic C 语言库相关数据。
- 它是源码/API 误用上下文，不是可直接执行的 PoC harness。
- 如果 C 最终传给 D 的假设仍然是源码/API 误用类漏洞，D 的动态验证方向应该是编译/测试/PoC。

注意：relic 只是 A 包里的一个样例项目，不代表正式任务一定是 C 语言库。论文里的 Linux、OpenSSL、FFmpeg、Apache、zlib 这类源码项目都应该归到同一个 `source_api` 分支。

文件含义：

- `relic.targets.jsonl`：A 阶段从数据集中取出的 relic 标注目标。
- `relic.run.plan.jsonl`：A 阶段的构建计划。
- `relic.file.plan.jsonl`：按文件聚合的入口函数计划。
- `relic.summary.json`：A 输出摘要。
