# MAGUS Final Vulnerability Report

- generated_at: 2026-05-22T13:46:32Z
- reportable_vulnerabilities: 54
- d_confirmed_vulnerabilities: 54
- stage_c_preserved_vulnerabilities: 0
- failed_verifications: 73
- source_confirmed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE328_Reversible_One_Way_Hash/verification.jsonl
- source_failed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE328_Reversible_One_Way_Hash/verification.failed.jsonl

## Confirmed Vulnerabilities

### 1. hyp_path_7d604ec53a96

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_08.c:55
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取或观察到生成的哈希值（calcHash）
- 触发路径: fgets(password, PASSWORD_INPUT_SIZE, stdin) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_08.c:42; if (!CryptCreateHash(hCryptProv, CALG_MD2, 0, 0, &hHash)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_08.c:44-45; CryptHashData(hHash, (BYTE*)password, strlen(password), 0) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_08.c:47; CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_08.c:51-53
- 结论: 程序使用可逆的MD2哈希算法对密码进行哈希处理，攻击者可以逆向哈希值获取原始密码，导致敏感信息泄露。
- D验证: confirmed / ver_48f56712
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 2. hyp_path_a03dfdd5bd4c

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_08.c:55
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取或观察到生成的哈希值（calcHash）
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) { CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv,... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_08.c:55; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_08.c::CWE328_Reversible_One_Way_Hash__w32_MD5_08_case0 @ route
- 结论: 程序使用可逆的MD2哈希算法对密码进行哈希处理，攻击者可以逆向哈希值获取原始密码，导致敏感信息泄露。
- D验证: confirmed / ver_68cb2aaa
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 3. hyp_path_aa71486d2357

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_08.c:55
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取或观察到生成的哈希值（calcHash）
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } } ... if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); ... if (!CryptCreateHash(h... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_08.c:55; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_08.c::CWE328_Reversible_One_Way_Hash__w32_SHA1_08_case0 @ route
- 结论: 程序使用可逆的MD2哈希算法对密码进行哈希处理，攻击者可以逆向哈希值获取原始密码，导致敏感信息泄露。
- D验证: confirmed / ver_0b329aa3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 4. hyp_path_02d67119f565

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_17.c:43
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够提供密码输入（通过stdin）并获取或利用生成的MD2哈希值
- 触发路径: if (fgets(password, PASSWORD_INPUT_SIZE, stdin) == NULL) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_17.c:43; if (!CryptCreateHash(hCryptProv, CALG_MD2, 0, 0, &hHash)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_17.c:86; if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_17.c:88-89; if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_17.c:92-93
- 结论: 使用可逆单向哈希算法MD2处理密码，违反了CWE328，可能导致密码被逆向恢复。
- D验证: confirmed / ver_d6455f06
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 5. hyp_path_007e9697a641

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_17.c:43
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够提供密码输入（通过stdin）并获取或利用生成的MD2哈希值
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) { CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (hCryptProv) { CryptReleaseContext(hCryptP... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_17.c:43; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_17.c::CWE328_Reversible_One_Way_Hash__w32_MD5_17_case0 @ route
- 结论: 使用可逆单向哈希算法MD2处理密码，违反了CWE328，可能导致密码被逆向恢复。
- D验证: confirmed / ver_153578c4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 6. hyp_path_a3bcbedbb518

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_17.c:43
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够提供密码输入（通过stdin）并获取或利用生成的MD2哈希值
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (!CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hHash)) { CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (hCryptProv) { CryptReleaseContext(hCrypt... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_17.c:43; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_17.c::CWE328_Reversible_One_Way_Hash__w32_SHA1_17_case0 @ route
- 结论: 使用可逆单向哈希算法MD2处理密码，违反了CWE328，可能导致密码被逆向恢复。
- D验证: confirmed / ver_c16a5123
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 7. hyp_path_9c246414b271

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_11.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够控制密码输入（通过stdin）或读取哈希结果; 程序使用MD2哈希算法
- 触发路径: fgets(password, PASSWORD_INPUT_SIZE, stdin); @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_11.c:29; CryptCreateHash(hCryptProv, CALG_MD2, 0, 0, &hHash); @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_11.c:85; CryptHashData(hHash, (BYTE*)password, strlen(password), 0); @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_11.c:41; CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0); @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_11.c:45
- 结论: 使用可逆的哈希算法MD2（CALG_MD2）对密码进行哈希，该算法已不再安全，攻击者可以轻松破解哈希值，恢复原始密码。
- D验证: confirmed / ver_0a6df658
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 8. hyp_path_df44c31e08ae

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_11.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够控制密码输入（通过stdin）或读取哈希结果; 程序使用MD2哈希算法
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); ... { CryptDestroyHash(hHash); CryptR... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_11.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_11.c::CWE328_Reversible_One_Way_Hash__w32_MD5_11_case0 @ route
- 结论: 使用可逆的哈希算法MD2（CALG_MD2）对密码进行哈希，该算法已不再安全，攻击者可以轻松破解哈希值，恢复原始密码。
- D验证: confirmed / ver_c6904b0a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 9. hyp_path_79b4d6e3b16b

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_11.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够控制密码输入（通过stdin）或读取哈希结果; 程序使用MD2哈希算法
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (!CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hHash)) { CryptReleaseContext(hCryptProv, 0); exit(1); } ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (!CryptGetHashParam(hHash, HP_HASHVAL, (B... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_11.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_11.c::CWE328_Reversible_One_Way_Hash__w32_SHA1_11_case0 @ route
- 结论: 使用可逆的哈希算法MD2（CALG_MD2）对密码进行哈希，该算法已不再安全，攻击者可以轻松破解哈希值，恢复原始密码。
- D验证: confirmed / ver_4c833f77
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 10. hyp_path_a8c6bc01a76b

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_12.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取calcHash哈希值（例如通过内存泄露或输出）
- 触发路径: pFile = fopen("password.txt", "r"); ... fgets(password, PASSWORD_INPUT_SIZE, stdin) @ 40-44; if (!CryptCreateHash(hCryptProv, CALG_MD2, 0, 0, &hHash)) ... if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) @ 94-98; if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0)) @ 101-105
- 结论: 使用可逆单向哈希算法MD2对密码进行哈希处理，攻击者可以逆向哈希值获取原始密码。
- D验证: confirmed / ver_f433022b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 11. hyp_path_473c0538d474

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_12.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取calcHash哈希值（例如通过内存泄露或输出）
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } } ... if (!CryptCreateHash(hCryptProv, CALG_SHA_512, 0, 0, &hHash)) { CryptReleaseContext(hCryptProv, 0); exit(1); } .... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_12.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_12.c::CWE328_Reversible_One_Way_Hash__w32_MD5_12_case0 @ route
- 结论: 使用可逆单向哈希算法MD2对密码进行哈希处理，攻击者可以逆向哈希值获取原始密码。
- D验证: confirmed / ver_71a2c874
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 12. hyp_path_281bfb47fe5c

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_12.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取calcHash哈希值（例如通过内存泄露或输出）
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } } ... if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) { CryptDestroyHash(hHash); Cr... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_12.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_12.c::CWE328_Reversible_One_Way_Hash__w32_SHA1_12_case0 @ route
- 结论: 使用可逆单向哈希算法MD2对密码进行哈希处理，攻击者可以逆向哈希值获取原始密码。
- D验证: confirmed / ver_729cd6eb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 13. hyp_path_4520a15136d1

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_01.c:40
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够读取哈希值存储位置（如password.txt）或通过网络拦截哈希摘要。
- 触发路径: pFile = fopen("password.txt", "r"); @ 38-42; if (fgets(password, PASSWORD_INPUT_SIZE, stdin) == NULL) @ 41; if (!CryptCreateHash(hCryptProv, CALG_MD2, 0, 0, &hHash)) @ 83-87; if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) @ 92-96; if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0)) @ 99-103
- 结论: 使用可逆的MD2哈希算法对密码进行哈希，可被攻击者逆向得到原始密码。
- D验证: confirmed / ver_01c03c83
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 14. hyp_path_edeae502a02c

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_01.c:40
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够读取哈希值存储位置（如password.txt）或通过网络拦截哈希摘要。
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); ... { CryptDestroyHash(hHash... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_01.c:40; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_01.c::CWE328_Reversible_One_Way_Hash__w32_MD5_01_case0 @ route
- 结论: 使用可逆的MD2哈希算法对密码进行哈希，可被攻击者逆向得到原始密码。
- D验证: confirmed / ver_7826f077
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 15. hyp_path_d2d228d5e197

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_01.c:40
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够读取哈希值存储位置（如password.txt）或通过网络拦截哈希摘要。
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } } ... if (!CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hHash)) { CryptReleaseContext(hCryptProv, 0... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_01.c:40; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_01.c::CWE328_Reversible_One_Way_Hash__w32_SHA1_01_case0 @ route
- 结论: 使用可逆的MD2哈希算法对密码进行哈希，可被攻击者逆向得到原始密码。
- D验证: confirmed / ver_a0d381db
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 16. hyp_path_c9f6d94b42ac

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_02.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够访问程序生成的哈希值（calcHash），例如通过读取内存、文件或网络通信。; 攻击者具备对MD2算法进行逆向或碰撞攻击的能力（使用现有工具或库）。
- 触发路径: if (fgets(password, PASSWORD_INPUT_SIZE, stdin) == NULL) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_02.c:36; if (!CryptCreateHash(hCryptProv, CALG_MD2, 0, 0, &hHash)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_02.c:85-89; if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_02.c:94-98; if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_02.c:102-106
- 结论: 代码使用了可逆的MD2哈希算法（CALG_MD2），该算法已被证明不安全，可被逆向或碰撞攻击，导致密码哈希值可被恢复，违反了CWE-328（使用可逆单向哈希）的安全要求。
- D验证: confirmed / ver_d2f0bd3a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 17. hyp_path_396f946e5961

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_02.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够访问程序生成的哈希值（calcHash），例如通过读取内存、文件或网络通信。; 攻击者具备对MD2算法进行逆向或碰撞攻击的能力（使用现有工具或库）。
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } } ... if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) { CryptDestroyHash(hHash); CryptReleaseContext(... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_02.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_02.c::CWE328_Reversible_One_Way_Hash__w32_MD5_02_case0 @ route
- 结论: 代码使用了可逆的MD2哈希算法（CALG_MD2），该算法已被证明不安全，可被逆向或碰撞攻击，导致密码哈希值可被恢复，违反了CWE-328（使用可逆单向哈希）的安全要求。
- D验证: confirmed / ver_5f090731
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 18. hyp_path_cdfb9f3badfa

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_02.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够访问程序生成的哈希值（calcHash），例如通过读取内存、文件或网络通信。; 攻击者具备对MD2算法进行逆向或碰撞攻击的能力（使用现有工具或库）。
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); ... if (!CryptGetHa... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_02.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_02.c::CWE328_Reversible_One_Way_Hash__w32_SHA1_02_case0 @ route
- 结论: 代码使用了可逆的MD2哈希算法（CALG_MD2），该算法已被证明不安全，可被逆向或碰撞攻击，导致密码哈希值可被恢复，违反了CWE-328（使用可逆单向哈希）的安全要求。
- D验证: confirmed / ver_03233008
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 19. hyp_path_9a5176c591c9

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_04.c:48
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取密码哈希值（通过文件读取如password.txt或嗅探哈希值）; 攻击者具备逆向MD2哈希的能力（如使用彩虹表或预计算）
- 触发路径: fgets(password, PASSWORD_INPUT_SIZE, stdin) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_04.c:46; CryptCreateHash(hCryptProv, CALG_MD2, 0, 0, &hHash) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_04.c:91-92; CryptHashData(hHash, (BYTE*)password, strlen(password), 0) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_04.c:100-101; CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_04.c:107-108
- 结论: 程序使用MD2哈希算法处理密码，MD2是一种可逆的弱哈希算法，攻击者可以逆向哈希值获取原始密码，导致密码泄露漏洞。
- D验证: confirmed / ver_880bbc3c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 20. hyp_path_4b532a6f7a4e

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_04.c:48
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取密码哈希值（通过文件读取如password.txt或嗅探哈希值）; 攻击者具备逆向MD2哈希的能力（如使用彩虹表或预计算）
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) { CryptReleaseContext(hCryptProv, 0); ... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_04.c:48; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_04.c::CWE328_Reversible_One_Way_Hash__w32_MD5_04_case0 @ route
- 结论: 程序使用MD2哈希算法处理密码，MD2是一种可逆的弱哈希算法，攻击者可以逆向哈希值获取原始密码，导致密码泄露漏洞。
- D验证: confirmed / ver_52a34c1c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 21. hyp_path_47f9f2a78245

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_04.c:48
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取密码哈希值（通过文件读取如password.txt或嗅探哈希值）; 攻击者具备逆向MD2哈希的能力（如使用彩虹表或预计算）
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (!CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hHash)) { CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &ha... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_04.c:48; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_04.c::CWE328_Reversible_One_Way_Hash__w32_SHA1_04_case0 @ route
- 结论: 程序使用MD2哈希算法处理密码，MD2是一种可逆的弱哈希算法，攻击者可以逆向哈希值获取原始密码，导致密码泄露漏洞。
- D验证: confirmed / ver_76dda742
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 22. hyp_path_a419e9e1cb17

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_03.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够控制password.txt文件的内容; 或攻击者能够通过stdin输入密码
- 触发路径: pFile = fopen("password.txt", "r"); @ line 42; fgets(password, PASSWORD_INPUT_SIZE, pFile); @ line (inferred, file read); if (!CryptCreateHash(hCryptProv, CALG_MD2, 0, 0, &hHash)) { ... } @ line 85-89; if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) { ... } @ line 94-98; if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0)) { ... } @ line (inferred, get hash)
- 结论: 代码使用MD2哈希算法（CALG_MD2）对密码进行哈希处理，MD2已被证明可产生碰撞且不是安全的单向哈希函数，攻击者可通过控制输入（文件或stdin）提供与目标哈希碰撞的密码，绕过验证，导致认证绕过漏洞。
- D验证: confirmed / ver_c939ce43
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 23. hyp_path_024cd3edbf1a

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_03.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够控制password.txt文件的内容; 或攻击者能够通过stdin输入密码
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) { CryptReleaseContext(hCryptProv, 0); exit(1); } ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (hHash) { CryptDestroyHash(hHash); } if (h... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_03.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_03.c::CWE328_Reversible_One_Way_Hash__w32_MD5_03_case0 @ route
- 结论: 代码使用MD2哈希算法（CALG_MD2）对密码进行哈希处理，MD2已被证明可产生碰撞且不是安全的单向哈希函数，攻击者可通过控制输入（文件或stdin）提供与目标哈希碰撞的密码，绕过验证，导致认证绕过漏洞。
- D验证: confirmed / ver_32c1d8c4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 24. hyp_path_c9f13fd239b6

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_03.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够控制password.txt文件的内容; 或攻击者能够通过stdin输入密码
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); ... if (hCryptProv)... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_03.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_03.c::CWE328_Reversible_One_Way_Hash__w32_SHA1_03_case0 @ route
- 结论: 代码使用MD2哈希算法（CALG_MD2）对密码进行哈希处理，MD2已被证明可产生碰撞且不是安全的单向哈希函数，攻击者可通过控制输入（文件或stdin）提供与目标哈希碰撞的密码，绕过验证，导致认证绕过漏洞。
- D验证: confirmed / ver_0ed4251e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 25. hyp_path_e96d040f19bc

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_05.c:48
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够通过stdin输入密码
- 触发路径: fgets(password, PASSWORD_INPUT_SIZE, stdin) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_05.c:48; CryptCreateHash(hCryptProv, CALG_MD2, 0, 0, &hHash) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_05.c:91; CryptHashData(hHash, (BYTE*)password, strlen(password), 0) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_05.c:100
- 结论: 使用弱哈希算法MD2处理用户密码，违反CWE-328（可逆单向哈希）
- D验证: confirmed / ver_bfa264d7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 26. hyp_path_09dfa67ca5f0

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_05.c:48
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够通过stdin输入密码
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); ... if (hHash) { Cr... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_05.c:48; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_05.c::CWE328_Reversible_One_Way_Hash__w32_MD5_05_case0 @ route
- 结论: 使用弱哈希算法MD2处理用户密码，违反CWE-328（可逆单向哈希）
- D验证: confirmed / ver_ee4e7222
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 27. hyp_path_dd14c385cfa5

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_05.c:48
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够通过stdin输入密码
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } } ... if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); ... { CryptDestroyHash(hHa... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_05.c:48; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_05.c::CWE328_Reversible_One_Way_Hash__w32_SHA1_05_case0 @ route
- 结论: 使用弱哈希算法MD2处理用户密码，违反CWE-328（可逆单向哈希）
- D验证: confirmed / ver_ad79ffb5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 28. hyp_path_53305edc015c

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_06.c:47
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取程序生成的MD2哈希值（例如通过文件读取、网络嗅探或内存泄露）
- 触发路径: pFile = fopen("password.txt", "r"); @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_06.c:47; if (!CryptCreateHash(hCryptProv, CALG_MD2, 0, 0, &hHash)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_06.c:90; if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_06.c:99; if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_06.c:106
- 结论: 代码使用MD2哈希算法（CALG_MD2）对密码进行哈希处理，该算法已知存在弱点，可被逆向或产生碰撞，违反了CWE328（可逆单向哈希）的安全要求。攻击者如果能够获取哈希值，可以通过预计算或碰撞攻击恢复原始密码。
- D验证: confirmed / ver_7a2b6b0a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 29. hyp_path_543978012933

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_06.c:47
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取程序生成的MD2哈希值（例如通过文件读取、网络嗅探或内存泄露）
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) { CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (hHash) { CryptDestroyHash(hHash); } if (h... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_06.c:47; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_06.c::CWE328_Reversible_One_Way_Hash__w32_MD5_06_case0 @ route
- 结论: 代码使用MD2哈希算法（CALG_MD2）对密码进行哈希处理，该算法已知存在弱点，可被逆向或产生碰撞，违反了CWE328（可逆单向哈希）的安全要求。攻击者如果能够获取哈希值，可以通过预计算或碰撞攻击恢复原始密码。
- D验证: confirmed / ver_2a684270
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 30. hyp_path_90f20e9b7a4f

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_06.c:47
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取程序生成的MD2哈希值（例如通过文件读取、网络嗅探或内存泄露）
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } } ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (!CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hHash)) { CryptReleaseContext(hCryptProv, 0... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_06.c:47; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_06.c::CWE328_Reversible_One_Way_Hash__w32_SHA1_06_case0 @ route
- 结论: 代码使用MD2哈希算法（CALG_MD2）对密码进行哈希处理，该算法已知存在弱点，可被逆向或产生碰撞，违反了CWE328（可逆单向哈希）的安全要求。攻击者如果能够获取哈希值，可以通过预计算或碰撞攻击恢复原始密码。
- D验证: confirmed / ver_80da9d22
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 31. hyp_path_3591d58c8aac

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_09.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取到calcHash中的哈希值。; 用于产生哈希的密码具有可猜测性或低复杂度。
- 触发路径: if (fgets(password, PASSWORD_INPUT_SIZE, stdin) == NULL) { ... } @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_09.c:67-70; if (!CryptCreateHash(hCryptProv, CALG_MD2, 0, 0, &hHash)) { ... } @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_09.c:85-89; if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) { ... } @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_09.c:94-98; if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0)) { ... } @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_09.c:100-104
- 结论: 代码使用弱哈希算法MD2（CALG_MD2）进行密码哈希，该算法存在可逆性风险，攻击者可以较容易地通过彩虹表或暴力破解获取原始密码。
- D验证: confirmed / ver_e15fedb0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 32. hyp_path_dd8e57292388

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_09.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取到calcHash中的哈希值。; 用于产生哈希的密码具有可猜测性或低复杂度。
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); ... if (!CryptCreat... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_09.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_09.c::CWE328_Reversible_One_Way_Hash__w32_MD5_09_case0 @ route
- 结论: 代码使用弱哈希算法MD2（CALG_MD2）进行密码哈希，该算法存在可逆性风险，攻击者可以较容易地通过彩虹表或暴力破解获取原始密码。
- D验证: confirmed / ver_955b5a99
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 33. hyp_path_f88aa6813ba9

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_09.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取到calcHash中的哈希值。; 用于产生哈希的密码具有可猜测性或低复杂度。
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } } ... if (!CryptGetHashParam(hHash, HP_H... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_09.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_09.c::CWE328_Reversible_One_Way_Hash__w32_SHA1_09_case0 @ route
- 结论: 代码使用弱哈希算法MD2（CALG_MD2）进行密码哈希，该算法存在可逆性风险，攻击者可以较容易地通过彩虹表或暴力破解获取原始密码。
- D验证: confirmed / ver_3dc08737
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 34. hyp_path_2517ac44ecae

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_07.c:47
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够控制密码输入（通过stdin）; 攻击者能够获取哈希计算结果（例如通过比较输出或文件）
- 触发路径: if (fgets(password, PASSWORD_INPUT_SIZE, stdin) == NULL) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_07.c:45-49; if (!CryptCreateHash(hCryptProv, CALG_MD2, 0, 0, &hHash)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_07.c:90-94
- 结论: 程序使用MD2哈希算法（CALG_MD2）进行密码哈希，MD2是一种可逆的弱哈希算法，攻击者可以获取哈希值并逆向出原始密码。
- D验证: confirmed / ver_06ffea85
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 35. hyp_path_5646536f3463

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_07.c:47
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够控制密码输入（通过stdin）; 攻击者能够获取哈希计算结果（例如通过比较输出或文件）
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } } ... if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) { CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... i... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_07.c:47; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_07.c::CWE328_Reversible_One_Way_Hash__w32_MD5_07_case0 @ route
- 结论: 程序使用MD2哈希算法（CALG_MD2）进行密码哈希，MD2是一种可逆的弱哈希算法，攻击者可以获取哈希值并逆向出原始密码。
- D验证: confirmed / ver_01045b56
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 36. hyp_path_42f6c7b13acb

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_07.c:47
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够控制密码输入（通过stdin）; 攻击者能够获取哈希计算结果（例如通过比较输出或文件）
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); ... if (!CryptGetHa... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_07.c:47; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_07.c::CWE328_Reversible_One_Way_Hash__w32_SHA1_07_case0 @ route
- 结论: 程序使用MD2哈希算法（CALG_MD2）进行密码哈希，MD2是一种可逆的弱哈希算法，攻击者可以获取哈希值并逆向出原始密码。
- D验证: confirmed / ver_c9553588
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 37. hyp_path_a9dc1c12ccb6

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_10.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取计算出的MD2哈希值（calcHash）
- 触发路径: pFile = fopen("password.txt", "r"); @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_10.c:42; if (!CryptCreateHash(hCryptProv, CALG_MD2, 0, 0, &hHash)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_10.c:85; if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_10.c:90; if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_10.c:93
- 结论: 使用可逆哈希算法MD2存储密码，攻击者可以逆向哈希获取原始密码。
- D验证: confirmed / ver_74c00e03
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 38. hyp_path_dff495e93ffc

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_10.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取计算出的MD2哈希值（calcHash）
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } } ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) { CryptDestroyHash(hHash); Cr... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_10.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_10.c::CWE328_Reversible_One_Way_Hash__w32_MD5_10_case0 @ route
- 结论: 使用可逆哈希算法MD2存储密码，攻击者可以逆向哈希获取原始密码。
- D验证: confirmed / ver_6165600c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 39. hyp_path_bf46063765db

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_10.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取计算出的MD2哈希值（calcHash）
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); ... if (!CryptGetHa... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_10.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_10.c::CWE328_Reversible_One_Way_Hash__w32_SHA1_10_case0 @ route
- 结论: 使用可逆哈希算法MD2存储密码，攻击者可以逆向哈希获取原始密码。
- D验证: confirmed / ver_444e2897
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 40. hyp_path_3994d003860b

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_13.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够访问存储的哈希值或传输中的哈希值。; 密码来源于外部输入（如fgets从stdin读取）。
- 触发路径: if (!CryptCreateHash(hCryptProv, CALG_MD2, 0, 0, &hHash)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_13.c:85; if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_13.c:94; if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_13.c:101
- 结论: 在密码哈希过程中使用了可逆的MD2哈希算法，该算法已被证明是不安全的，攻击者可以逆向哈希值或通过碰撞攻击破解密码。
- D验证: confirmed / ver_701100a8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 41. hyp_path_12a71174c4f3

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_13.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够访问存储的哈希值或传输中的哈希值。; 密码来源于外部输入（如fgets从stdin读取）。
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } } ... { CryptDestroyHash(hHa... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_13.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_13.c::CWE328_Reversible_One_Way_Hash__w32_MD5_13_case0 @ route
- 结论: 在密码哈希过程中使用了可逆的MD2哈希算法，该算法已被证明是不安全的，攻击者可以逆向哈希值或通过碰撞攻击破解密码。
- D验证: confirmed / ver_390997c1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 42. hyp_path_ad21c0630da2

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_13.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够访问存储的哈希值或传输中的哈希值。; 密码来源于外部输入（如fgets从stdin读取）。
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); ... if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0)) { CryptDestroyHash(... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_13.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_13.c::CWE328_Reversible_One_Way_Hash__w32_SHA1_13_case0 @ route
- 结论: 在密码哈希过程中使用了可逆的MD2哈希算法，该算法已被证明是不安全的，攻击者可以逆向哈希值或通过碰撞攻击破解密码。
- D验证: confirmed / ver_c79ddb06
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 43. hyp_path_aeee7f1914ce

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_16.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取password.txt文件内容或哈希值（如通过数据泄露）
- 触发路径: pFile = fopen("password.txt", "r"); @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_16.c:42; if (!CryptCreateHash(hCryptProv, CALG_MD2, 0, 0, &hHash)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_16.c:85; if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_16.c:94
- 结论: 代码使用可逆哈希算法MD2处理密码，违反了CWE-328（可逆单向哈希）的安全要求，攻击者可以逆向哈希值获得原始密码。
- D验证: confirmed / ver_041f9dde
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 44. hyp_path_964697badebc

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_16.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取password.txt文件内容或哈希值（如通过数据泄露）
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } } ... { CryptDestroyHash(hHash); Cryp... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_16.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_16.c::CWE328_Reversible_One_Way_Hash__w32_MD5_16_case0 @ route
- 结论: 代码使用可逆哈希算法MD2处理密码，违反了CWE-328（可逆单向哈希）的安全要求，攻击者可以逆向哈希值获得原始密码。
- D验证: confirmed / ver_60d97a5d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 45. hyp_path_3f15fb2cd389

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_16.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够获取password.txt文件内容或哈希值（如通过数据泄露）
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } } ... { CryptDestroyHash(hHa... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_16.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_16.c::CWE328_Reversible_One_Way_Hash__w32_SHA1_16_case0 @ route
- 结论: 代码使用可逆哈希算法MD2处理密码，违反了CWE-328（可逆单向哈希）的安全要求，攻击者可以逆向哈希值获得原始密码。
- D验证: confirmed / ver_d2e64b07
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 46. hyp_path_86e0a6f58660

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_14.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够访问到计算出的MD2哈希值（例如通过文件读取或网络拦截）
- 触发路径: pFile = fopen("password.txt", "r"); @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_14.c:40; fgets(password, PASSWORD_INPUT_SIZE, stdin); @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_14.c:42; if (!CryptCreateHash(hCryptProv, CALG_MD2, 0, 0, &hHash)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_14.c:64; if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_14.c:71; if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_14.c:78
- 结论: 代码使用了MD2哈希算法（CALG_MD2），该算法已被证明是可逆的、不安全的，容易受到碰撞和原像攻击。用于密码哈希时，攻击者可以逆向获取明文密码，导致敏感信息泄露。
- D验证: confirmed / ver_263bb256
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 47. hyp_path_f5a486fd15f0

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_14.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够访问到计算出的MD2哈希值（例如通过文件读取或网络拦截）
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } } ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (!CryptCreateHash(hCryptProv, C... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_14.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_14.c::CWE328_Reversible_One_Way_Hash__w32_MD5_14_case0 @ route
- 结论: 代码使用了MD2哈希算法（CALG_MD2），该算法已被证明是可逆的、不安全的，容易受到碰撞和原像攻击。用于密码哈希时，攻击者可以逆向获取明文密码，导致敏感信息泄露。
- D验证: confirmed / ver_4ada8eb0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 48. hyp_path_80114bb81022

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_14.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够访问到计算出的MD2哈希值（例如通过文件读取或网络拦截）
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); ... { CryptDestroyHash(hHash... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_14.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_14.c::CWE328_Reversible_One_Way_Hash__w32_SHA1_14_case0 @ route
- 结论: 代码使用了MD2哈希算法（CALG_MD2），该算法已被证明是可逆的、不安全的，容易受到碰撞和原像攻击。用于密码哈希时，攻击者可以逆向获取明文密码，导致敏感信息泄露。
- D验证: confirmed / ver_56b32e35
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 49. hyp_path_c7f21cb0d105

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_15.c:43
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够读取'password.txt'文件或截获计算出的MD2哈希值
- 触发路径: pFile = fopen("password.txt", "r"); @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_15.c:43; if (!CryptCreateHash(hCryptProv, CALG_MD2, 0, 0, &hHash)) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_15.c:86; CryptHashData(hHash, (BYTE*)password, strlen(password), 0) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_15.c:87; CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0) @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_15.c:88
- 结论: 程序使用可逆的MD2哈希算法（CALG_MD2）处理密码，导致哈希值可被逆向还原，违反CWE-328（可逆单向哈希）要求。
- D验证: confirmed / ver_30a65125
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 50. hyp_path_2dd5e5baa287

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_15.c:43
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够读取'password.txt'文件或截获计算出的MD2哈希值
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (!CryptCreat... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_15.c:43; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_15.c::CWE328_Reversible_One_Way_Hash__w32_MD5_15_case0 @ route
- 结论: 程序使用可逆的MD2哈希算法（CALG_MD2）处理密码，导致哈希值可被逆向还原，违反CWE-328（可逆单向哈希）要求。
- D验证: confirmed / ver_3796ba87
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 51. hyp_path_12f39cdf483f

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_15.c:43
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够读取'password.txt'文件或截获计算出的MD2哈希值
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } } ... if (!CryptGetHashParam(hHash, HP_HASHVAL, (BYTE*)calcHash, &hashSize, 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); ... if (!CryptCreateHash(h... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_15.c:43; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_15.c::CWE328_Reversible_One_Way_Hash__w32_SHA1_15_case0 @ route
- 结论: 程序使用可逆的MD2哈希算法（CALG_MD2）处理密码，导致哈希值可被逆向还原，违反CWE-328（可逆单向哈希）要求。
- D验证: confirmed / ver_cacd09f2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 52. hyp_path_447198cb946b

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_18.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够控制输入（密码）或能够访问计算出的MD2哈希值。
- 触发路径: if (fgets(password, PASSWORD_INPUT_SIZE, stdin) == NULL) @ 42; replace = strchr(password, '\r'); @ 43; if (replace) replace = strchr(password, '\n'); @ 44; if (!CryptCreateHash(hCryptProv, CALG_MD2, 0, 0, &hHash)) @ 85; if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) @ 94
- 结论: 代码使用MD2哈希算法（CALG_MD2），这是一种弱且可逆的哈希算法，违反了CWE328（可逆单向哈希）。如果该哈希用于密码存储或验证，攻击者可利用MD2的弱点逆向原始输入，导致密码泄露。
- D验证: confirmed / ver_f53a089d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 53. hyp_path_73a900f952c1

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_18.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够控制输入（密码）或能够访问计算出的MD2哈希值。
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (!CryptHashData(hHash, (BYTE*)password, strlen(password), 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } } ... { CryptDestroyHash(hHash); Cryp... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_18.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_18.c::CWE328_Reversible_One_Way_Hash__w32_MD5_18_case0 @ route
- 结论: 代码使用MD2哈希算法（CALG_MD2），这是一种弱且可逆的哈希算法，违反了CWE328（可逆单向哈希）。如果该哈希用于密码存储或验证，攻击者可利用MD2的弱点逆向原始输入，导致密码泄露。
- D验证: confirmed / ver_299a0161
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 54. hyp_path_dca32654a8e3

- 漏洞位置: juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_18.c:42
- 漏洞类型: CWE-328
- CWE: CWE-328
- 风险等级: P0
- 触发条件: 攻击者能够控制输入（密码）或能够访问计算出的MD2哈希值。
- 触发路径: char *replace; size_t i; pFile = fopen("password.txt", "r"); if (pFile == NULL) { ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } } ... { CryptDestroyHash(hHash); CryptReleaseContext(hCryptProv, 0); exit(1); } ... if (!CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hHash)) { CryptReleaseContext(hCryptProv, 0... @ juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_18.c:42; juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_18.c::CWE328_Reversible_One_Way_Hash__w32_SHA1_18_case0 @ route
- 结论: 代码使用MD2哈希算法（CALG_MD2），这是一种弱且可逆的哈希算法，违反了CWE328（可逆单向哈希）。如果该哈希用于密码存储或验证，攻击者可利用MD2的弱点逆向原始输入，导致密码泄露。
- D验证: confirmed / ver_ea19fe73
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

## Unconfirmed / Failed Verification

These records are not reported as confirmed vulnerabilities. See `verification.failed.jsonl` for full failure details.

- hyp_path_f26911a89d23 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_05.c:156 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_465f57dd27bf | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_05.c:156 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_ea2056a79b2e | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_05.c:156 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_ba89f5cc97b7 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_03.c:246 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_41dde37a4946 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_03.c:246 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_c134da620e9a | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_03.c:246 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_62208548c176 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_04.c:156 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_d409f6b04c9d | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_04.c:156 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_2cd49747c201 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_04.c:156 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_aadb6fde61d0 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_04.c:252 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_ac5e1e7e7578 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_04.c:252 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_5f659150e6c1 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_04.c:252 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_a98451c50340 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_05.c:252 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_41f3a0faa233 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_05.c:252 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_7e7ab203f7ab | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_05.c:252 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_e4f50b761bc1 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_14.c:246 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_9199e968450c | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_14.c:246 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_98b4232847ec | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_14.c:246 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_5066023e46b0 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_03.c:330 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_c7981ab5823d | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_03.c:330 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_1895d39e65c0 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_02.c:330 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_1d536902de12 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_02.c:330 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_2af4d9b429d1 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_05.c:336 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_3a75e04b6c84 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_04.c:337 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_3bbe5fa7ced7 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_04.c:337 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_04afeec1ac1b | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_06.c:335 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_108e06c74a7f | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_06.c:335 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_a0356d597de1 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_06.c:335 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_2a7c676491f4 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_07.c:335 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_072bd613ecd5 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_07.c:335 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_36044b36b8cd | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_07.c:335 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_4a7cd4245e0b | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_09.c:331 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_03674de24b0d | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_09.c:331 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_899e38786224 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_08.c:344 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_22735086d3ba | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_08.c:344 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_09d35c2f6876 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_13.c:330 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_b45ab599dd6a | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_13.c:330 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_9ee3bae460d4 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_10.c:331 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_2e61856a1990 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_10.c:331 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_00cffde173d4 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_10.c:331 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_98176250af36 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_14.c:331 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_7e96c0643b86 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_02.c:331 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_2313fb12599e | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_15.c:343 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_6baec2b762aa | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_15.c:343 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_102e04bc39da | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_05.c:337 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_c809f99182c2 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_05.c:337 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_c314067958a0 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_11.c:331 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_79ddd8e9986e | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_11.c:331 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_56cfc720f100 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_09.c:330 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_44576281df3c | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_04.c:336 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_35ca6041f535 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_14.c:330 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_75e0d8d7b3ff | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_14.c:330 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_dcf7570d02e6 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_03.c:331 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_89d9a088351a | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_13.c:331 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_1eaaa60abce4 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_01.c:222 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3b4e8d6b4620 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_01.c:222 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3d35396d1c17 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_01.c:222 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1e9512e28814 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_12.c:411 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f704d6e8b797 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_12.c:411 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_08b7f3763f7d | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_12.c:411 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_028f65c36e86 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_08.c:343 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_3dd4dca3b592 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_16.c:231 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9723fa6c6b33 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_16.c:231 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f035080d8be1 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_16.c:231 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2a5ea332ccc8 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_17.c:231 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e44f6559fcb3 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_17.c:231 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_74213af0e7bc | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_17.c:231 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9c1a91b0485f | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD2_18.c:227 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_826814e9c3e2 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_18.c:227 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3560fe4d5e35 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_18.c:227 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_05f3481be50c | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/main.cpp:100 | ENV_MISSING | payload did not satisfy oracle
- hyp_path_545be74813e7 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_MD5_11.c:246 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_1e1f0dbcd2f5 | juliet-api-misuse/testcases/CWE328_Reversible_One_Way_Hash/CWE328_Reversible_One_Way_Hash__w32_SHA1_11.c:246 | NOT_ROUTE_BOUND | payload did not satisfy oracle
