# targets.json 是什么

`targets.json` 是 D 自己维护或自动生成的源码/API 验证配置。

C 给 D：哪里疑似存在 C/C++ 函数调用接口误用。  
D 的 `targets.json`：怎么在源码仓库里触达这条调用路径，以及用什么 oracle 判断。

D 不支持 HTTP API targets，因此没有 `base_url`、token、HTTP method、headers、query params 或 `*.http` payload。

## 最小例子

```json
{
  "targets": [
    {
      "project_id": "openssl",
      "target_type": "source_api",
      "env_profile": "source_repository",
      "cases": {
        "hyp_api_0001": {
          "target_type": "source_api",
          "payload_kind": "api_misuse_plan",
          "source_file": "crypto/x509/example.c",
          "entry_symbol": "parse_cert",
          "api_sequence": ["parse_cert -> ASN1_OCTET_STRING_new -> dereference"],
          "payload": {
            "seed_inputs": ["malformed serialized bytes"]
          },
          "execution": {
            "repo_path": "/datasets/openssl",
            "config_cmd": "./Configure enable-asan",
            "build_cmd": "make -j4",
            "run_cmd": "${PYTHON} poc_parse_cert.py"
          },
          "oracle": {
            "failure_patterns": ["AddressSanitizer", "Segmentation fault"],
            "expect_nonzero_exit": true
          }
        }
      }
    }
  ]
}
```

## 字段解释

- `project_id`：必须和 C 的 `c/out/*.jsonl` 假设记录里一致。
- `target_type`：固定为 `source_api`，历史 `native` 可视为同义。
- `cases`：每个假设一个 case，key 是 `hypothesis_id`。
- `payload_kind`：固定为 `api_misuse_plan` 或历史 `native_plan`。
- `source_file`：可疑源文件。
- `entry_symbol`：入口函数或可触达可疑路径的符号。
- `api_sequence`：C/C++ 函数调用链或 API 使用序列。
- `payload.seed_inputs`：用于构造 harness / PoC 的输入种子说明。
- `execution.repo_path`：源码仓库根目录。
- `execution.config_cmd` / `build_cmd`：可选准备命令。
- `execution.run_cmd` / `poc_cmd` / `test_cmd`：至少需要一个，用来实际触达 API 序列。
- `oracle.failure_patterns`：stdout/stderr 中可确认漏洞的模式。
- `oracle.expect_nonzero_exit`：是否把非零退出作为确认信号之一。

## 能否 confirmed

只有生成 payload 不会自动 confirmed。要 confirmed，必须能在 `repo_path` 中运行具体命令，并且运行结果命中 oracle。
