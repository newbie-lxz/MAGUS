正式 D 脚本不读取这个文件夹。C 输出文件应由 Stage C 写到仓库根目录下：

c/out/hypotheses.jsonl

文件可以是一行一个 JSON 对象的 JSONL，也可以是一个多行 JSON 对象或 JSON 数组。

旁边的 hypotheses.source_api.sample.json 是源码/API 误用验证上下文样例，不会被正式脚本自动读取。

然后回到 02_run_with_C 文件夹，运行：

01_auto_attack_from_C_windows.bat

输出会生成在：

02_run_with_C\output

D 只处理 C/C++ 函数调用接口和调用序列，不处理 HTTP API。脚本会生成 *.payload.py 和 *.api-plan.json。

如果 C 的文件里带 repo_path 和 run_cmd/poc_cmd/test_cmd，D 会执行 payload 并尝试 confirmed。
