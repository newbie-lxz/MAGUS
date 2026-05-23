# MAGUS Final Vulnerability Report

- generated_at: 2026-05-22T13:31:58Z
- reportable_vulnerabilities: 54
- d_confirmed_vulnerabilities: 54
- stage_c_preserved_vulnerabilities: 0
- failed_verifications: 64
- source_confirmed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE327_Use_Broken_Crypto/verification.jsonl
- source_failed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE327_Use_Broken_Crypto/verification.failed.jsonl

## Confirmed Vulnerabilities

### 1. hyp_path_39c726df65ff

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_12.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够向encrypted.txt文件写入或控制其内容（例如通过文件上传、共享目录等）
- 触发路径: pFile = fopen("encrypted.txt", "rb"); @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_12.c:53-57; if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_12.c:58-60; if(!CryptDeriveKey(hCryptProv, CALG_3DES, hHash, 0, &hKey)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_12.c:55 (sink)
- 结论: 使用已破解的加密算法3DES对数据进行解密，违反了CWE327（使用已破解的加密算法）安全要求。
- D验证: confirmed / ver_cdb65343
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 2. hyp_path_429d9af72115

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_12.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够向encrypted.txt文件写入或控制其内容（例如通过文件上传、共享目录等）
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_12.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_12.c::CWE327_Use_Broken_Crypto__w32_DES_12_case0 @ route
- 结论: 使用已破解的加密算法3DES对数据进行解密，违反了CWE327（使用已破解的加密算法）安全要求。
- D验证: confirmed / ver_b4f09dce
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 3. hyp_path_5fa9975bb74e

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_12.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够向encrypted.txt文件写入或控制其内容（例如通过文件上传、共享目录等）
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_12.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_12.c::CWE327_Use_Broken_Crypto__w32_RC5_12_case0 @ route
- 结论: 使用已破解的加密算法3DES对数据进行解密，违反了CWE327（使用已破解的加密算法）安全要求。
- D验证: confirmed / ver_9ae9ffa7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 4. hyp_path_ee0c8b91fd9f

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_17.c:56
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够获取加密文件encrypted.txt的内容。; 加密数据使用3DES算法。
- 触发路径: pFile = fopen("encrypted.txt", "rb"); @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_17.c:56; if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_17.c:61; if(!CryptDeriveKey(hCryptProv, CALG_3DES, hHash, 0, &hKey)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_17.c:88; if(!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_17.c:95
- 结论: 程序使用CALG_3DES（3DES算法）进行解密操作，该算法已被认为是不安全的，存在弱加密漏洞。攻击者可能能够破解加密数据。
- D验证: confirmed / ver_44fb4e19
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 5. hyp_path_e9e15cb68f57

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_17.c:56
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够获取加密文件encrypted.txt的内容。; 加密数据使用3DES算法。
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_17.c:56; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_17.c::CWE327_Use_Broken_Crypto__w32_DES_17_case0 @ route
- 结论: 程序使用CALG_3DES（3DES算法）进行解密操作，该算法已被认为是不安全的，存在弱加密漏洞。攻击者可能能够破解加密数据。
- D验证: confirmed / ver_ec50e3fa
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 6. hyp_path_fc6b37375adc

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_17.c:56
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够获取加密文件encrypted.txt的内容。; 加密数据使用3DES算法。
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_17.c:56; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_17.c::CWE327_Use_Broken_Crypto__w32_RC5_17_case0 @ route
- 结论: 程序使用CALG_3DES（3DES算法）进行解密操作，该算法已被认为是不安全的，存在弱加密漏洞。攻击者可能能够破解加密数据。
- D验证: confirmed / ver_176b387b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 7. hyp_path_abb263941ea0

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_08.c:68
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够提供加密文件（encrypted.txt）或影响其内容，但漏洞核心在于使用弱加密算法，无需额外前提。
- 触发路径: pFile = fopen("encrypted.txt", "rb"); @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_08.c:68; if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_08.c:71; if(!CryptDeriveKey(hCryptProv, CALG_3DES, hHash, 0, &hKey)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_08.c:107; if(!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_08.c:107
- 结论: 使用已破解的加密算法3DES进行数据解密，违反了CWE-327（使用已破解的加密算法）。
- D验证: confirmed / ver_708bbe2e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 8. hyp_path_ef690651f85d

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_08.c:68
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够提供加密文件（encrypted.txt）或影响其内容，但漏洞核心在于使用弱加密算法，无需额外前提。
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_08.c:68; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_08.c::CWE327_Use_Broken_Crypto__w32_DES_08_case0 @ route
- 结论: 使用已破解的加密算法3DES进行数据解密，违反了CWE-327（使用已破解的加密算法）。
- D验证: confirmed / ver_71bb8c56
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 9. hyp_path_ddb42c50ffb6

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_08.c:68
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够提供加密文件（encrypted.txt）或影响其内容，但漏洞核心在于使用弱加密算法，无需额外前提。
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_08.c:68; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_08.c::CWE327_Use_Broken_Crypto__w32_RC5_08_case0 @ route
- 结论: 使用已破解的加密算法3DES进行数据解密，违反了CWE-327（使用已破解的加密算法）。
- D验证: confirmed / ver_fa2cb0ce
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 10. hyp_path_ca3a69e9c7a5

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_11.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够读取加密文件 'encrypted.txt'（例如通过网络共享或上传）; 攻击者能够通过stdin提供密码（例如在交互式环境中）或通过其他方式控制密码输入
- 触发路径: pFile = fopen("encrypted.txt", "rb"); if (pFile == NULL) { exit(1); } if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) { fclose(pFile); exit(1); } @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_11.c:58-62; if (fgets(password, 100, stdin) == NULL) { ... } if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { ... } if(!CryptHashData(hHash, (BYTE *) password, passwordLen, 0)) { ... } if(!CryptDeriveKey(hCryptProv, CALG_3DES, hHash, 0, &hKey)) { ... } @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_11.c:90-94; if(!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen)) { ... } printLine(toBeDecrypted); @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_11.c:94-96
- 结论: 代码使用了已损坏的加密算法3DES (CALG_3DES) 进行数据解密，违反了CWE-327 (使用已损坏的加密算法)。3DES已被认为不再安全，容易受到已知攻击。
- D验证: confirmed / ver_90ea4f14
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 11. hyp_path_ed4dc5a0659d

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_11.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够读取加密文件 'encrypted.txt'（例如通过网络共享或上传）; 攻击者能够通过stdin提供密码（例如在交互式环境中）或通过其他方式控制密码输入
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_11.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_11.c::CWE327_Use_Broken_Crypto__w32_DES_11_case0 @ route
- 结论: 代码使用了已损坏的加密算法3DES (CALG_3DES) 进行数据解密，违反了CWE-327 (使用已损坏的加密算法)。3DES已被认为不再安全，容易受到已知攻击。
- D验证: confirmed / ver_4db0e75a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 12. hyp_path_ee48287aa7dd

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_11.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够读取加密文件 'encrypted.txt'（例如通过网络共享或上传）; 攻击者能够通过stdin提供密码（例如在交互式环境中）或通过其他方式控制密码输入
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_11.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_11.c::CWE327_Use_Broken_Crypto__w32_RC5_11_case0 @ route
- 结论: 代码使用了已损坏的加密算法3DES (CALG_3DES) 进行数据解密，违反了CWE-327 (使用已损坏的加密算法)。3DES已被认为不再安全，容易受到已知攻击。
- D验证: confirmed / ver_9f9012cb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 13. hyp_path_af8228cf69ab

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_01.c:53
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够访问加密文件或密文数据。
- 触发路径: if(!CryptDeriveKey(hCryptProv, CALG_3DES, hHash, 0, &hKey)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_01.c:53; if(!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_01.c:92
- 结论: 使用破损的加密算法3DES（Triple DES），该算法已被视为不安全，存在被破解的风险，违反了CWE-327规范。
- D验证: confirmed / ver_63879714
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 14. hyp_path_54cd6cbb0606

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_01.c:53
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够访问加密文件或密文数据。
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_01.c:53; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_01.c::CWE327_Use_Broken_Crypto__w32_DES_01_case0 @ route
- 结论: 使用破损的加密算法3DES（Triple DES），该算法已被视为不安全，存在被破解的风险，违反了CWE-327规范。
- D验证: confirmed / ver_89c167a3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 15. hyp_path_5a3e95f55172

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_01.c:53
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够访问加密文件或密文数据。
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_01.c:53; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_01.c::CWE327_Use_Broken_Crypto__w32_RC5_01_case0 @ route
- 结论: 使用破损的加密算法3DES（Triple DES），该算法已被视为不安全，存在被破解的风险，违反了CWE-327规范。
- D验证: confirmed / ver_58971949
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 16. hyp_path_23331f075e18

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_02.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够提供加密数据文件（encrypted.txt）或控制解密输入，但漏洞存在与否不依赖攻击者输入，而是代码本身使用了弱加密算法。
- 触发路径: if(!CryptDeriveKey(hCryptProv, CALG_3DES, hHash, 0, &hKey)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_02.c:55; if(!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_02.c:94
- 结论: 程序使用3DES（CALG_3DES）作为解密算法，3DES被认为是被破坏的加密算法，存在安全漏洞（CWE-327：使用已被破坏的密码算法）。
- D验证: confirmed / ver_b7143e47
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 17. hyp_path_ecdadef4544c

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_02.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够提供加密数据文件（encrypted.txt）或控制解密输入，但漏洞存在与否不依赖攻击者输入，而是代码本身使用了弱加密算法。
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_02.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_02.c::CWE327_Use_Broken_Crypto__w32_DES_02_case0 @ route
- 结论: 程序使用3DES（CALG_3DES）作为解密算法，3DES被认为是被破坏的加密算法，存在安全漏洞（CWE-327：使用已被破坏的密码算法）。
- D验证: confirmed / ver_4523c0e9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 18. hyp_path_585242c61c24

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_02.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够提供加密数据文件（encrypted.txt）或控制解密输入，但漏洞存在与否不依赖攻击者输入，而是代码本身使用了弱加密算法。
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_02.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_02.c::CWE327_Use_Broken_Crypto__w32_RC5_02_case0 @ route
- 结论: 程序使用3DES（CALG_3DES）作为解密算法，3DES被认为是被破坏的加密算法，存在安全漏洞（CWE-327：使用已被破坏的密码算法）。
- D验证: confirmed / ver_7eb3db25
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 19. hyp_path_133aa2bf3865

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_03.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够获取encrypted.txt文件的内容。; 攻击者能够通过某种方式（如弱密码猜测）获得有效的3DES密钥或密码。
- 触发路径: pFile = fopen("encrypted.txt", "rb"); @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_03.c:53-57; if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_03.c:58-62; fgets(password, 100, stdin); @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_03.c:60-64; if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_03.c:65-69; if(!CryptHashData(hHash, (BYTE *)password, passwordLen, 0)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_03.c:70-74; if(!CryptDeriveKey(hCryptProv, CALG_3DES, hHash, 0, &hKey)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_03.c:75-79; if(!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_03.c:80-84; printLine(toBeDecrypted); @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_03.c:85-89
- 结论: 程序使用已损坏的加密算法3DES进行解密操作，违反了CWE-327（使用已损坏的加密算法）。攻击者可能利用3DES的已知弱点破解密文。
- D验证: confirmed / ver_fc4a6b79
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 20. hyp_path_595cdfa4697c

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_03.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够获取encrypted.txt文件的内容。; 攻击者能够通过某种方式（如弱密码猜测）获得有效的3DES密钥或密码。
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_03.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_03.c::CWE327_Use_Broken_Crypto__w32_DES_03_case0 @ route
- 结论: 程序使用已损坏的加密算法3DES进行解密操作，违反了CWE-327（使用已损坏的加密算法）。攻击者可能利用3DES的已知弱点破解密文。
- D验证: confirmed / ver_707f2004
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 21. hyp_path_7a205c930fe2

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_03.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够获取encrypted.txt文件的内容。; 攻击者能够通过某种方式（如弱密码猜测）获得有效的3DES密钥或密码。
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_03.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_03.c::CWE327_Use_Broken_Crypto__w32_RC5_03_case0 @ route
- 结论: 程序使用已损坏的加密算法3DES进行解密操作，违反了CWE-327（使用已损坏的加密算法）。攻击者可能利用3DES的已知弱点破解密文。
- D验证: confirmed / ver_9f9054e2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 22. hyp_path_2afecaa91c9c

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_04.c:61
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者必须能够获取加密文件或密文数据; 系统使用3DES算法，存在已知弱点
- 触发路径: pFile = fopen("encrypted.txt", "rb"); @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_04.c:59; if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_04.c:64; if(!CryptDeriveKey(hCryptProv, CALG_3DES, hHash, 0, &hKey)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_04.c:66; if(!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_04.c:67
- 结论: 使用已损坏的加密算法3DES进行解密操作，违反了CWE-327。攻击者可能利用3DES的已知弱点（如小密钥空间和SWEET32攻击）来破解加密数据。
- D验证: confirmed / ver_487f7475
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 23. hyp_path_064d67457869

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_04.c:61
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者必须能够获取加密文件或密文数据; 系统使用3DES算法，存在已知弱点
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_04.c:61; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_04.c::CWE327_Use_Broken_Crypto__w32_DES_04_case0 @ route
- 结论: 使用已损坏的加密算法3DES进行解密操作，违反了CWE-327。攻击者可能利用3DES的已知弱点（如小密钥空间和SWEET32攻击）来破解加密数据。
- D验证: confirmed / ver_59730471
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 24. hyp_path_f6065d18a4d0

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_04.c:61
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者必须能够获取加密文件或密文数据; 系统使用3DES算法，存在已知弱点
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_04.c:61; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_04.c::CWE327_Use_Broken_Crypto__w32_RC5_04_case0 @ route
- 结论: 使用已损坏的加密算法3DES进行解密操作，违反了CWE-327。攻击者可能利用3DES的已知弱点（如小密钥空间和SWEET32攻击）来破解加密数据。
- D验证: confirmed / ver_070530e9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 25. hyp_path_619e088ff864

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_05.c:61
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够获取密文文件（encrypted.txt）。; 攻击者能够通过某种方式（如网络嗅探、文件泄露）获得密文数据。
- 触发路径: pFile = fopen("encrypted.txt", "rb"); @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_05.c:61; if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_05.c:66; if(!CryptDeriveKey(hCryptProv, CALG_3DES, hHash, 0, &hKey)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_05.c:76; if(!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_05.c:100
- 结论: 使用已破损的3DES加密算法（CALG_3DES）进行解密操作，可能被破解。
- D验证: confirmed / ver_78474f98
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 26. hyp_path_5e1eaadcb377

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_05.c:61
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够获取密文文件（encrypted.txt）。; 攻击者能够通过某种方式（如网络嗅探、文件泄露）获得密文数据。
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_05.c:61; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_05.c::CWE327_Use_Broken_Crypto__w32_DES_05_case0 @ route
- 结论: 使用已破损的3DES加密算法（CALG_3DES）进行解密操作，可能被破解。
- D验证: confirmed / ver_d4195fe7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 27. hyp_path_604e2e08d3ae

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_05.c:61
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够获取密文文件（encrypted.txt）。; 攻击者能够通过某种方式（如网络嗅探、文件泄露）获得密文数据。
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_05.c:61; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_05.c::CWE327_Use_Broken_Crypto__w32_RC5_05_case0 @ route
- 结论: 使用已破损的3DES加密算法（CALG_3DES）进行解密操作，可能被破解。
- D验证: confirmed / ver_990c65f9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 28. hyp_path_5f4ac46bb74f

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_06.c:60
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够读取或提供加密文件encrypted.txt; 攻击者可能能够通过密码输入影响解密结果
- 触发路径: pFile = fopen("encrypted.txt", "rb"); @ 文件读取; fread(toBeDecrypted, sizeof(char), 100, pFile); @ 读取密文; fgets(password, 100, stdin); ... CryptCreateHash(hCryptProv, CALG_SHA_256, ...); CryptHashData(...); @ 密码输入与哈希; CryptDeriveKey(hCryptProv, CALG_3DES, hHash, 0, &hKey); @ 派生3DES密钥; CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen); @ 使用3DES解密
- 结论: 使用破损加密算法3DES进行解密操作，存在CWE-327使用破损加密漏洞。
- D验证: confirmed / ver_ce4eb769
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 29. hyp_path_32a8121cfde0

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_06.c:60
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够读取或提供加密文件encrypted.txt; 攻击者可能能够通过密码输入影响解密结果
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_06.c:60; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_06.c::CWE327_Use_Broken_Crypto__w32_DES_06_case0 @ route
- 结论: 使用破损加密算法3DES进行解密操作，存在CWE-327使用破损加密漏洞。
- D验证: confirmed / ver_9f96c216
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 30. hyp_path_5c01128d9661

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_06.c:60
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够读取或提供加密文件encrypted.txt; 攻击者可能能够通过密码输入影响解密结果
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_06.c:60; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_06.c::CWE327_Use_Broken_Crypto__w32_RC5_06_case0 @ route
- 结论: 使用破损加密算法3DES进行解密操作，存在CWE-327使用破损加密漏洞。
- D验证: confirmed / ver_4fd6cfc4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 31. hyp_path_9887ec2fbf68

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_07.c:60
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够获取加密文件'encrypted.txt'的内容，或者能够通过stdin输入影响解密密码
- 触发路径: pFile = fopen("encrypted.txt", "rb"); @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_07.c:60; fread(toBeDecrypted, sizeof(char), 100, pFile); @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_07.c:63-67; CryptDeriveKey(hCryptProv, CALG_3DES, hHash, 0, &hKey); @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_07.c:99; CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen); @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_07.c:99
- 结论: 代码使用3DES（CALG_3DES）进行解密，该算法已被视为弱加密算法，容易受到暴力破解攻击，违反CWE-327（使用已破损的加密算法）。
- D验证: confirmed / ver_c76beb30
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 32. hyp_path_a96e18222dab

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_07.c:60
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够获取加密文件'encrypted.txt'的内容，或者能够通过stdin输入影响解密密码
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_07.c:60; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_07.c::CWE327_Use_Broken_Crypto__w32_DES_07_case0 @ route
- 结论: 代码使用3DES（CALG_3DES）进行解密，该算法已被视为弱加密算法，容易受到暴力破解攻击，违反CWE-327（使用已破损的加密算法）。
- D验证: confirmed / ver_044bf69c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 33. hyp_path_aca71d72096c

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_07.c:60
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够获取加密文件'encrypted.txt'的内容，或者能够通过stdin输入影响解密密码
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_07.c:60; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_07.c::CWE327_Use_Broken_Crypto__w32_RC5_07_case0 @ route
- 结论: 代码使用3DES（CALG_3DES）进行解密，该算法已被视为弱加密算法，容易受到暴力破解攻击，违反CWE-327（使用已破损的加密算法）。
- D验证: confirmed / ver_ac65e5ed
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 34. hyp_path_ca8fdd2d32c1

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_09.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够读取目标系统上的加密文件 encrypted.txt; 攻击者能够获取或猜测用户输入的密码
- 触发路径: pFile = fopen("encrypted.txt", "rb"); @ CWE327_Use_Broken_Crypto__w32_3DES_09.c:55; fread(toBeDecrypted, sizeof(char), 100, pFile); @ CWE327_Use_Broken_Crypto__w32_3DES_09.c:60; if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) ... if(!CryptHashData(hHash, (BYTE *) password, passwordLen, 0)) @ CWE327_Use_Broken_Crypto__w32_3DES_09.c:70-77; if(!CryptDeriveKey(hCryptProv, CALG_3DES, hHash, 0, &hKey)) @ CWE327_Use_Broken_Crypto__w32_3DES_09.c:79; if(!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen)) @ CWE327_Use_Broken_Crypto__w32_3DES_09.c:94
- 结论: 代码使用3DES (CALG_3DES) 进行解密操作，3DES 属于破损加密算法，存在被破解的风险。
- D验证: confirmed / ver_cf040d4f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 35. hyp_path_36fcdc3339cf

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_09.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够读取目标系统上的加密文件 encrypted.txt; 攻击者能够获取或猜测用户输入的密码
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_09.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_09.c::CWE327_Use_Broken_Crypto__w32_DES_09_case0 @ route
- 结论: 代码使用3DES (CALG_3DES) 进行解密操作，3DES 属于破损加密算法，存在被破解的风险。
- D验证: confirmed / ver_368a01cd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 36. hyp_path_ada91c055ef2

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_09.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够读取目标系统上的加密文件 encrypted.txt; 攻击者能够获取或猜测用户输入的密码
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_09.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_09.c::CWE327_Use_Broken_Crypto__w32_RC5_09_case0 @ route
- 结论: 代码使用3DES (CALG_3DES) 进行解密操作，3DES 属于破损加密算法，存在被破解的风险。
- D验证: confirmed / ver_fc16cd65
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 37. hyp_path_f916c817d341

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_10.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够访问或控制加密文件encrypted.txt，或能够触发解密流程
- 触发路径: pFile = fopen("encrypted.txt", "rb"); @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_10.c:53-57; if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) { fclose(pFile); exit(1); } @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_10.c:58-60; if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_10.c:85-87; if(!CryptDeriveKey(hCryptProv, CALG_3DES, hHash, 0, &hKey)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_10.c:91-93; if(!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_10.c:94-95
- 结论: 程序使用了过时的弱加密算法3DES进行加解密操作，攻击者可能利用算法的弱点破解加密数据，导致敏感信息泄露。
- D验证: confirmed / ver_52a50979
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 38. hyp_path_7b9154dffaa6

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_10.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够访问或控制加密文件encrypted.txt，或能够触发解密流程
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_10.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_10.c::CWE327_Use_Broken_Crypto__w32_DES_10_case0 @ route
- 结论: 程序使用了过时的弱加密算法3DES进行加解密操作，攻击者可能利用算法的弱点破解加密数据，导致敏感信息泄露。
- D验证: confirmed / ver_9c167a67
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 39. hyp_path_063db3557119

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_10.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够访问或控制加密文件encrypted.txt，或能够触发解密流程
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_10.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_10.c::CWE327_Use_Broken_Crypto__w32_RC5_10_case0 @ route
- 结论: 程序使用了过时的弱加密算法3DES进行加解密操作，攻击者可能利用算法的弱点破解加密数据，导致敏感信息泄露。
- D验证: confirmed / ver_f676b8d5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 40. hyp_path_6a60fc8503db

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_13.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者可能获取加密文件，或能够利用弱加密算法破解密文。
- 触发路径: pFile = fopen("encrypted.txt", "rb"); @ line 53-57; if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) { fclose(pFile); exit(1); } @ line 58-62; if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) ... @ line 64-72; if (fgets(password, 100, stdin) == NULL) ... passwordLen = strlen(password); @ line 73-79; if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) ... @ line 80-84; if(!CryptHashData(hHash, (BYTE *) password, passwordLen, 0)) ... @ line 85-88; if(!CryptDeriveKey(hCryptProv, CALG_3DES, hHash, 0, &hKey)) ... @ line 89-92; if(!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen)) ... @ line 93-96
- 结论: 使用弱加密算法3DES进行数据解密，存在CWE-327漏洞。
- D验证: confirmed / ver_1c40652c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 41. hyp_path_1ad1ed3670d1

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_13.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者可能获取加密文件，或能够利用弱加密算法破解密文。
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_13.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_13.c::CWE327_Use_Broken_Crypto__w32_DES_13_case0 @ route
- 结论: 使用弱加密算法3DES进行数据解密，存在CWE-327漏洞。
- D验证: confirmed / ver_4d019f67
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 42. hyp_path_7c1765c8a2ed

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_13.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者可能获取加密文件，或能够利用弱加密算法破解密文。
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_13.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_13.c::CWE327_Use_Broken_Crypto__w32_RC5_13_case0 @ route
- 结论: 使用弱加密算法3DES进行数据解密，存在CWE-327漏洞。
- D验证: confirmed / ver_2a218dfd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 43. hyp_path_d48a1f5c2fe1

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_14.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够访问程序加密或解密的数据（例如通过文件读取）
- 触发路径: if(!CryptDeriveKey(hCryptProv, CALG_3DES, hHash, 0, &hKey)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_14.c:55; if(!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_14.c:94
- 结论: 代码使用CALG_3DES（3DES）进行加解密操作，3DES已被视为不安全的加密算法，存在使用弱加密算法的安全漏洞。
- D验证: confirmed / ver_dcf0a358
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 44. hyp_path_458f03b3334c

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_14.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够访问程序加密或解密的数据（例如通过文件读取）
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_14.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_14.c::CWE327_Use_Broken_Crypto__w32_DES_14_case0 @ route
- 结论: 代码使用CALG_3DES（3DES）进行加解密操作，3DES已被视为不安全的加密算法，存在使用弱加密算法的安全漏洞。
- D验证: confirmed / ver_337f8397
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 45. hyp_path_7563e3183d35

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_14.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够访问程序加密或解密的数据（例如通过文件读取）
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_14.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_14.c::CWE327_Use_Broken_Crypto__w32_RC5_14_case0 @ route
- 结论: 代码使用CALG_3DES（3DES）进行加解密操作，3DES已被视为不安全的加密算法，存在使用弱加密算法的安全漏洞。
- D验证: confirmed / ver_cf867a9a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 46. hyp_path_98fdacf59f33

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_15.c:56
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者可能能够获取加密文件或中间数据。
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_15.c:56; if(!CryptDeriveKey(hCryptProv, CALG_3DES, hHash, 0, &hKey)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_15.c:95; if(!CryptDecrypt(hKey, 0, 1, 0, (BYTE *)toBeDecrypted, &toBeDecryptedLen)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_15.c:95
- 结论: 代码使用了弱加密算法Triple DES (CALG_3DES)，违反了CWE327（使用已损坏的加密算法）。攻击者可能能够破解加密数据。
- D验证: confirmed / ver_b6c82d4a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 47. hyp_path_cdc451327108

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_15.c:56
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者可能能够获取加密文件或中间数据。
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_15.c:56; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_15.c::CWE327_Use_Broken_Crypto__w32_DES_15_case0 @ route
- 结论: 代码使用了弱加密算法Triple DES (CALG_3DES)，违反了CWE327（使用已损坏的加密算法）。攻击者可能能够破解加密数据。
- D验证: confirmed / ver_8bc70dfa
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 48. hyp_path_b2920aeb6276

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_15.c:56
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者可能能够获取加密文件或中间数据。
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_15.c:56; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_15.c::CWE327_Use_Broken_Crypto__w32_RC5_15_case0 @ route
- 结论: 代码使用了弱加密算法Triple DES (CALG_3DES)，违反了CWE327（使用已损坏的加密算法）。攻击者可能能够破解加密数据。
- D验证: confirmed / ver_a44c6523
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 49. hyp_path_91466a9bbd41

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_16.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够获取被3DES加密的数据文件（encrypted.txt）
- 触发路径: if(!CryptDeriveKey(hCryptProv, CALG_3DES, hHash, 0, &hKey)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_16.c:55
- 结论: 使用已损坏的加密算法3DES进行解密，存在CWE-327漏洞。
- D验证: confirmed / ver_7388c748
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 50. hyp_path_94bbfcfccf24

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_16.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够获取被3DES加密的数据文件（encrypted.txt）
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_16.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_16.c::CWE327_Use_Broken_Crypto__w32_DES_16_case0 @ route
- 结论: 使用已损坏的加密算法3DES进行解密，存在CWE-327漏洞。
- D验证: confirmed / ver_eeded034
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 51. hyp_path_5704d0b11e9a

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_16.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够获取被3DES加密的数据文件（encrypted.txt）
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_16.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_16.c::CWE327_Use_Broken_Crypto__w32_RC5_16_case0 @ route
- 结论: 使用已损坏的加密算法3DES进行解密，存在CWE-327漏洞。
- D验证: confirmed / ver_1f24b0d8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 52. hyp_path_26b3df959f0e

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_18.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够控制或读取加密文件encrypted.txt（任意数据源）; 攻击者能够获取或推导出用于密钥派生的密码（通过键盘输入或其它方式）
- 触发路径: pFile = fopen("encrypted.txt", "rb"); @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_18.c:53-57; if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) { fclose(pFile); exit(1); } @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_18.c:58-62; if(!CryptDeriveKey(hCryptProv, CALG_3DES, hHash, 0, &hKey)) @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_18.c:55
- 结论: 代码使用3DES（CWE-327：使用破损密码算法）进行加密操作，尽管密钥通过SHA-256派生，但3DES本身已被认为不安全，易受攻击。
- D验证: confirmed / ver_1bdca09b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 53. hyp_path_62cd061d5e59

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_18.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够控制或读取加密文件encrypted.txt（任意数据源）; 攻击者能够获取或推导出用于密钥派生的密码（通过键盘输入或其它方式）
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_18.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_18.c::CWE327_Use_Broken_Crypto__w32_DES_18_case0 @ route
- 结论: 代码使用3DES（CWE-327：使用破损密码算法）进行加密操作，尽管密钥通过SHA-256派生，但3DES本身已被认为不安全，易受攻击。
- D验证: confirmed / ver_0562576d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 54. hyp_path_5d795de1d5eb

- 漏洞位置: juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_18.c:55
- 漏洞类型: CWE-327
- CWE: CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够控制或读取加密文件encrypted.txt（任意数据源）; 攻击者能够获取或推导出用于密钥派生的密码（通过键盘输入或其它方式）
- 触发路径: if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) fclose(pFile); ... if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) ... if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } if (pFile) ... if (fread(toBeDecrypted, sizeof(char), 100, pFile) != 100) ... @ juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_18.c:55; juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_18.c::CWE327_Use_Broken_Crypto__w32_RC5_18_case0 @ route
- 结论: 代码使用3DES（CWE-327：使用破损密码算法）进行加密操作，尽管密钥通过SHA-256派生，但3DES本身已被认为不安全，易受攻击。
- D验证: confirmed / ver_f2d62910
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

## Unconfirmed / Failed Verification

These records are not reported as confirmed vulnerabilities. See `verification.failed.jsonl` for full failure details.

- hyp_path_336d970c6089 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_06.c:167 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_474de805ad70 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_06.c:167 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7dbed0bde3b9 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_06.c:167 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3e7a3cb58ee9 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_02.c:330 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_175c23154c01 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_02.c:330 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2b22e15dc565 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_03.c:330 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_15a70e4a2794 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_03.c:330 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4655e1e909ca | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_04.c:336 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2c8d8c3f4e5e | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_04.c:336 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8dcf2618f627 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_05.c:336 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3ae2d0d4dda3 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_05.c:336 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_248be15f9f6e | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_07.c:335 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0aa71f9c5a43 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_07.c:335 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_71389963bca2 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_06.c:335 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c599ce4403cb | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_08.c:343 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_46b4ba3b83d8 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_08.c:343 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_05fe272da889 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_09.c:331 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_425686bc804b | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_09.c:331 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_922ea92d4080 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_11.c:331 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_12a243ad8ea4 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_10.c:331 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_226d1a423431 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_10.c:331 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4dfde524519e | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_14.c:330 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_364bc83c5ce5 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_13.c:331 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f12335d798d9 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_13.c:331 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_53d3dac9f3d3 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_15.c:343 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_696f24943f22 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_15.c:343 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_90c27ff9c0d9 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_10.c:330 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1c4d18cfa50c | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_03.c:331 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b3c945e3945b | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_05.c:337 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_172e58c2814c | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_06.c:336 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_22e0a6da44f2 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_06.c:336 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3f3d46a68b1c | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_04.c:337 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_338c04f36d1f | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_11.c:330 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4bb54957f502 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_11.c:330 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_05ddd17c007a | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_14.c:331 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_76095f3205d5 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_14.c:331 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bdc28dd3b2c6 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_02.c:331 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_004dcec0dc3f | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_07.c:336 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_393feb88b218 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_09.c:330 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_15cf554db454 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_13.c:330 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_24bd9d3f6214 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_15.c:344 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e2c698f5e561 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_01.c:220 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_232c52f9d9ad | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_01.c:220 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_55318c0d2cfa | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_01.c:220 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1227f6a6bd56 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_08.c:344 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0a9c31b501e4 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_12.c:413 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_27fffa16e347 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_12.c:413 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b2eb622b5673 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_12.c:413 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_01ab564d0f4c | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_17.c:229 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_86fe0add6d51 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_17.c:229 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8812ef82b8c3 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_17.c:229 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ab5ef0d9c9d2 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_18.c:225 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_48629d9971aa | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_18.c:225 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f3d17da44072 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_18.c:225 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0cba572360f2 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_3DES_16.c:229 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_68c25fad68fe | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_16.c:229 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4b999daad882 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_16.c:229 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_029478068013 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/main.cpp:166 | ENV_MISSING | payload did not satisfy oracle
- hyp_path_8e11bd0a0fd5 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_DES_05.c:266 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_78e6a2c6d459 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_05.c:266 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1c049901c314 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_04.c:168 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8f684e16f752 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_09.c:260 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9b95d19c889b | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_14.c:260 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f1f9f13bcb35 | juliet-api-misuse/testcases/CWE327_Use_Broken_Crypto/CWE327_Use_Broken_Crypto__w32_RC5_16.c:158 | NOT_EXPLOITABLE | payload did not satisfy oracle
