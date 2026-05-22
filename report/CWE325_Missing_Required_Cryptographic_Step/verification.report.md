# MAGUS Final Vulnerability Report

- generated_at: 2026-05-22T12:50:57Z
- reportable_vulnerabilities: 72
- d_confirmed_vulnerabilities: 18
- stage_c_preserved_vulnerabilities: 54
- failed_verifications: 89
- source_confirmed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE325_Missing_Required_Cryptographic_Step/verification.jsonl
- source_failed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE325_Missing_Required_Cryptographic_Step/verification.failed.jsonl

## Confirmed Vulnerabilities

### 1. hyp_path_b739e531985b

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_17.c:70
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够访问程序执行时的输出（如printBytesLine的终端或日志），或程序将明文数据存储到可被攻击者读取的位置。
- 触发路径: 入口点 @ L29; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ L59-63; if (hKey) { CryptDestroyKey(hKey); } @ L70; if (hHash) { CryptDestroyHash(hHash); } @ L72-76; if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } @ L76-80; printBytesLine(payload, payloadLen); @ L81
- 结论: 程序使用了加密API（CryptAcquireContext、CryptCreateHash、CryptDeriveKey），但未调用CryptEncrypt对数据进行加密，导致payload以明文形式输出，违反了CWE-325缺失必要加密步骤的要求。
- D验证: stage_c_preserved / ver_b8145814
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 2. hyp_path_0724beb002bb

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_12.c:73
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够触发包含该加密逻辑的代码路径，且无需提供有效的哈希输入数据即可派生密钥。
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_12.c:29; if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_12.c:57; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_12.c:62; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_12.c:70
- 结论: 在调用CryptCreateHash后，未调用CryptHashData将输入数据哈希化，就直接调用CryptDeriveKey派生密钥，导致密钥派生不依赖于实际输入数据，可能使用未初始化的哈希值，满足CWE-325（缺失必需加密步骤）漏洞定义。
- D验证: stage_c_preserved / ver_85d116fa
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 3. hyp_path_881a316cdf96

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_12.c:77
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 程序执行到条件分支且globalReturnsTrueOrFalse返回false时，跳过CryptCreateHash调用，导致后续加密步骤基于无效句柄
- 触发路径: 进入CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_12_case0 @ 入口行29; if(globalReturnsTrueOrFalse()) 可能导致跳过CryptCreateHash @ 条件分支代码（约行50-60）; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) 使用无效hKey加密 @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_12.c:116-120
- 结论: 在加密过程中，由于条件分支（globalReturnsTrueOrFalse）导致必需的CryptCreateHash步骤被跳过，使得hHash无效，后续CryptHashData和CryptDeriveKey操作失败或使用无效句柄，最终CryptEncrypt使用未正确初始化的密钥，数据以明文形式加密。
- D验证: confirmed / ver_9c977517
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 4. hyp_path_cc069f13e07d

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_12.c:74
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P1
- 触发条件: 攻击者能够影响全局条件函数（如globalReturnsTrueOrFalse）的返回值，或触发特定的执行路径（例如通过某种外部输入影响随机数生成）。
- 触发路径: if (globalReturnsTrueOrFalse()) { ... } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_12.c:29; 缺少CryptDeriveKey的调用点（可能的跳过分支） @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_12.c:在条件分支中缺失CryptDeriveKey调用; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_12.c:60-64
- 结论: 在特定条件下，程序可能跳过必要的加密步骤CryptDeriveKey，导致后续CryptEncrypt使用无效或未初始化的密钥句柄，从而未能正确加密数据。
- D验证: stage_c_preserved / ver_6f27c60c
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 5. hyp_path_e0720eb24fa1

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_08.c:82
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 程序未对payload进行加密即输出，可能导致敏感信息泄露
- 触发路径: if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_08.c:71-75; printBytesLine(payload, payloadLen); @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_08.c:93
- 结论: 在加密过程中，成功创建了哈希和密钥，但未调用CryptEncrypt对数据进行加密，导致加密步骤缺失。
- D验证: stage_c_preserved / ver_cf200632
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 6. hyp_path_b1ad9a814824

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_11.c:69
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P1
- 触发条件: 攻击者可能通过观察输出获取明文payload，或者payload本身是敏感数据。
- 触发路径: if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_11.c:58-62; } /* Do something with the encrypted data */ printBytesLine(payload, payloadLen);} @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_11.c:78-82
- 结论: 缺失必需的加密步骤：在派生AES密钥后，未调用CryptEncrypt对payload进行加密，而是直接输出明文数据。
- D验证: stage_c_preserved / ver_49b3f5ca
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 7. hyp_path_aa2c3d639d60

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_12.c:69
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P1
- 触发条件: 攻击者能够影响globalReturnsTrueOrFalse()的返回值（如通过环境或输入触发特定分支）
- 触发路径: 调用CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_12_case0 @ 入口第29行; if(globalReturnsTrueOrFalse()) { /* 执行Hash步骤 */ } else { /* 跳过Hash */ } @ 约第42行（globalReturnsTrueOrFalse调用处）; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_12.c:69
- 结论: 在CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_12.c中，由于条件分支（如globalReturnsTrueOrFalse()）可能导致必要的加密步骤（如CryptHashData或CryptDeriveKey）被跳过，但后续仍调用CryptEncrypt，从而造成缺少必要加密步骤的漏洞。
- D验证: stage_c_preserved / ver_634c0075
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 8. hyp_path_35f0dedccef0

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_01.c:67
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够获取到打印输出的明文数据（payload为固定字符串PAYLOAD），或数据本身需要保密但未加密。
- 触发路径: CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0) @ 第29行附近（入口）; CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey) @ 第56-60行; if (hKey) { CryptDestroyKey(hKey); } if (hHash) ... @ 第65-69行; printBytesLine(payload, payloadLen); @ 第76-80行
- 结论: 在使用Windows CryptoAPI进行加密操作时，派生密钥后未调用CryptEncrypt对数据进行加密，导致敏感数据以明文形式输出（通过printBytesLine打印）。这违反了必需的加密步骤。
- D验证: stage_c_preserved / ver_47d020f1
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 9. hyp_path_17e6f6f9432f

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_02.c:69
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够触发该代码路径，且payload中包含敏感信息。
- 触发路径: if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_02.c:58-62; /* Do something with the encrypted data */ printBytesLine(payload, payloadLen); @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_02.c:78-82
- 结论: 代码在执行加密操作前缺少必需的加密步骤（CryptEncrypt），导致敏感数据以明文形式输出。
- D验证: stage_c_preserved / ver_eb091620
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 10. hyp_path_7dc5aa2069df

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_04.c:75
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P2
- 触发条件: 攻击者能够控制输入数据（hashData）或观察到程序输出。
- 触发路径: if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_04.c:64-68; printBytesLine(payload, payloadLen); @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_04.c:86
- 结论: 缺少必要的加密步骤（CryptEncrypt），导致敏感数据以明文形式输出，可能泄露信息。
- D验证: stage_c_preserved / ver_e032fd0c
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 11. hyp_path_f3f64752a84f

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_03.c:69
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P1
- 触发条件: 攻击者能够访问printBytesLine的输出（例如日志、网络响应等）。
- 触发路径: if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_03.c:58-62; if (hKey) { CryptDestroyKey(hKey); } if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_03.c:67-77; printBytesLine(payload, payloadLen); @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_03.c:78-82
- 结论: 代码在派生AES密钥后未调用CryptEncrypt对明文数据进行加密，直接通过printBytesLine输出明文payload，导致敏感数据泄露，违反CWE-325（缺少必需加密步骤）的要求。
- D验证: stage_c_preserved / ver_ada080b4
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 12. hyp_path_c47838fde2f1

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_05.c:75
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够观察或获取程序输出的payload（例如通过标准输出、日志或调试接口）。
- 触发路径: if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ 64-68; memcpy(payload, PAYLOAD, payloadLen); @ 63; cleanup code: CryptDestroyKey, CryptDestroyHash, CryptReleaseContext; then printBytesLine(payload, payloadLen); @ 73-86
- 结论: 程序在加密过程中缺少必要的加密步骤（CryptEncrypt），导致数据以明文形式被处理。虽然代码调用了CryptAcquireContext、CryptCreateHash、CryptHashData和CryptDeriveKey派生密钥，但未调用CryptEncrypt对数据进行加密，随后直接打印payload。这违反了CWE-325的要求，使得机密数据未被保护。
- D验证: stage_c_preserved / ver_f30fbd48
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 13. hyp_path_946e98d0ba4d

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_06.c:74
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够观察程序的输出（如日志、网络传输）或访问内存中的payload
- 触发路径: CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0); @ 62-66; CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash); @ 67-70; CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0); @ 71-73; CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey); @ 74-76; printBytesLine(payload, payloadLen); // 打印未加密的payload @ 85
- 结论: 代码调用了CryptAcquireContext、CryptCreateHash、CryptHashData、CryptDeriveKey进行密钥派生，但缺少必需的CryptEncrypt调用对payload进行加密，导致敏感数据以明文形式处理，违反了CWE-325 (Missing Required Cryptographic Step)。
- D验证: stage_c_preserved / ver_82db7cec
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 14. hyp_path_619bfbfa1c8b

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_07.c:74
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: Attacker does not need to control input; the vulnerability exists by design as the encryption step is omitted.
- 触发路径: CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0) @ line 63; CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash) @ line 66; CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0) @ line 68; CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey) @ line 71; printBytesLine(payload, payloadLen) // payload is output without encryption @ line 85
- 结论: Missing required cryptographic step: the code performs key derivation and hashing but never calls CryptEncrypt to encrypt the payload, resulting in unencrypted sensitive data being output or stored.
- D验证: stage_c_preserved / ver_63696d5b
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 15. hyp_path_efe5dfd002f6

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_13.c:69
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者可以触发代码执行路径，但不需直接控制输入；漏洞存在即数据泄露风险。
- 触发路径: if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_13.c:61-62; printBytesLine(payload, payloadLen); @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_13.c:80
- 结论: 缺少必要的加密步骤：在调用CryptDeriveKey派生密钥后，未调用CryptEncrypt对数据进行加密，导致数据以明文形式被使用或输出。
- D验证: stage_c_preserved / ver_4e7d1fe8
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 16. hyp_path_9a7dba72b4e7

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_09.c:69
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: N/A
- 触发路径: if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_09.c:58-62; if (hKey) { CryptDestroyKey(hKey); } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_09.c:67-71; printBytesLine(payload, payloadLen); @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_09.c:80
- 结论: 代码在派生AES密钥后，未调用CryptEncrypt对数据进行加密，而是直接销毁密钥并输出明文payload，导致敏感数据以明文形式处理，违反了CWE-325 Missing Required Cryptographic Step。
- D验证: stage_c_preserved / ver_e98ae000
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 17. hyp_path_ce9dc0c3a5b8

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_10.c:69
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P1
- 触发条件: 攻击者能够触发该函数执行（如通过接口调用），但无需直接控制输入。
- 触发路径: 函数入口，开始加密流程。 @ 入口:29; 调用CryptDeriveKey派生密钥，但未调用CryptEncrypt加密payload。 @ 58-62; 清理资源（销毁密钥、哈希、释放上下文）。 @ 67-79; 调用printBytesLine(payload, payloadLen)直接输出未加密的payload。 @ 78-82
- 结论: 程序在Windows加密API使用中，创建了哈希和密钥，但缺失了必要的CryptEncrypt步骤，导致硬编码的敏感数据未加密就被输出（printBytesLine），可能泄露敏感信息。
- D验证: stage_c_preserved / ver_24fb5a91
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 18. hyp_path_12dd5e02c1d0

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_15.c:70
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 无额外前提，代码存在逻辑缺失
- 触发路径: 入口函数被调用 @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_15.c:29; CryptAcquireContext, CryptCreateHash, CryptHashData, CryptDeriveKey成功执行，但未调用CryptEncrypt @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_15.c:59-63; 直接使用printBytesLine输出明文payload @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_15.c:81
- 结论: 代码中缺少必需的加密步骤：调用了CryptAcquireContext、CryptCreateHash、CryptHashData、CryptDeriveKey，但未调用CryptEncrypt进行数据加密，导致payload以明文形式存储或传输。
- D验证: stage_c_preserved / ver_2bb2e691
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 19. hyp_path_95fde5eb6447

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_14.c:69
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P1
- 触发条件: 攻击者具有执行该程序的权限，并能够观察到程序的标准输出（printBytesLine输出到控制台或日志）。; 攻击者能够通过内存读取或其他方式获取未加密的payload数据（如调试、核心转储等）。
- 触发路径: char hashData[16] = "ABCDEFGH12345678"; ... memcpy(payload, PAYLOAD, payloadLen); @ 入口处初始化hashData和PAYLOAD; if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; } @ CryptAcquireContext创建加密服务提供者; if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break; } @ CryptCreateHash创建哈希对象; if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) { break; } @ CryptHashData哈希输入数据; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ CryptDeriveKey从哈希派生AES密钥; if (hKey) { CryptDestroyKey(hKey); } if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } @ 缺少CryptEncrypt调用，直接销毁密钥和哈希对象; printBytesLine(payload, payloadLen); @ 输出未加密的payload
- 结论: 应用程序在使用Windows CryptoAPI进行加密时，完成了密钥派生等步骤，但缺少关键的CryptEncrypt调用，导致数据未被加密直接输出，敏感信息可能泄露。
- D验证: stage_c_preserved / ver_f8905d91
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 20. hyp_path_85dcec7fae9d

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_16.c:69
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够控制或观察加密前的输入数据（如hashData）; 程序路径执行到break分支后的printBytesLine
- 触发路径: if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_16.c:62; printBytesLine(payload, payloadLen); @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_16.c:80
- 结论: 缺少必需的加密步骤：在派生AES密钥后未调用CryptEncrypt对数据进行加密，直接打印明文数据，违反了CWE-325（Missing Required Cryptographic Step）。
- D验证: stage_c_preserved / ver_4890d491
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 21. hyp_path_5364ade5750d

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_18.c:69
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够拦截或监听通信，获取明文payload
- 触发路径: 入口:29行 @ 函数入口; if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; } @ 获取上下文; if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break; @ 创建哈希; if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) { break; @ 哈希数据; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; @ 派生密钥; printBytesLine(payload, payloadLen); @ 未调用CryptEncrypt，直接打印明文payload
- 结论: 缺少必需的加密步骤：代码在派生密钥后未调用CryptEncrypt对数据进行加密，导致敏感数据以明文形式处理，违反了CWE-325。
- D验证: stage_c_preserved / ver_1928b3e1
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 22. hyp_path_d9da4298c974

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_08.c:87
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 无需攻击者控制输入，该漏洞由代码逻辑缺失导致。
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_08.c:42; 未调用CryptDeriveKey或CryptGenKey @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_08.c:?; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_08.c:75
- 结论: 代码在调用CryptEncrypt之前缺少必需的CryptDeriveKey或CryptGenKey步骤，导致使用未正确初始化的密钥句柄，可能使得加密操作无效或使用弱密钥，违背安全加密要求。
- D验证: stage_c_preserved / ver_9803144a
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 23. hyp_path_de6fc58b9590

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_17.c:75
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够观察到加密输出，但由于密钥派生缺失，加密实质上可能使用无效或默认密钥，导致数据保护失效。
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_17.c:79; if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_17.c:75; if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_17.c:75; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_17.c:63
- 结论: 程序在使用CryptEncrypt进行加密之前，没有调用CryptDeriveKey从哈希派生密钥，导致加密操作使用了未正确初始化的密钥，破坏了加密的安全性。
- D验证: stage_c_preserved / ver_6ca5878f
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 24. hyp_path_31bb4b3fb8fd

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_17.c:78
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者无需控制输入，代码路径自然执行即可触发漏洞。
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; } @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_17.c:29; /* NOTE: Missing required step (CryptCreateHash) causes the payload to remain in plaintext form */ @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_17.c:? (注释行); /* Hash the input string */ if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) { break; } @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_17.c:? (假设的CryptHashData调用); /* Derive an AES key from the hash */ if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_17.c:? (CryptDeriveKey); /* Encrypt the payload */ if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_17.c:62
- 结论: 代码缺少对CryptCreateHash的调用，导致CryptHashData和CryptDeriveKey使用未初始化的hHash句柄，最终CryptEncrypt加密无效，数据以明文形式保留。
- D验证: confirmed / ver_15056479
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 25. hyp_path_ccebaedcb3e2

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_11.c:74
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 无外部输入依赖，漏洞由代码逻辑缺失导致。
- 触发路径: CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_11_case0() @ L29; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ L62; if (hKey) { CryptDestroyKey(hKey); } @ L74
- 结论: 代码缺少必要的加密步骤：未调用CryptDeriveKey或CryptGenKey生成加密密钥，导致CryptEncrypt使用未初始化或无效的密钥hKey，加密可能失败或产生不安全结果。
- D验证: stage_c_preserved / ver_cabacbe6
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 26. hyp_path_633de673de00

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_04.c:80
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够控制payload数据，但核心漏洞在于密钥派生步骤缺失，可能导致加密强度不足。
- 触发路径: /* Encrypt the payload */ if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_04.c:66-70
- 结论: 缺少必要的加密步骤（CryptDeriveKey），导致加密密钥未正确派生，加密操作可能无效或使用弱密钥。
- D验证: stage_c_preserved / ver_039ba327
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 27. hyp_path_43f09dfa06a2

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_02.c:74
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 无外部攻击者控制输入；漏洞为代码逻辑缺失，在正常执行路径中即可触发。
- 触发路径: 调用CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_02_case0 @ 入口:29; CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0) @ 行78; CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash) @ 行? (CryptAcquireContext之后); CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0) @ 行? (CryptCreateHash之后); 缺少调用CryptDeriveKey从哈希派生密钥 @ 缺失; CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload)) // 使用未正确派生的密钥 @ 行62
- 结论: 缺少必需的加密步骤：在调用CryptEncrypt之前未调用CryptDeriveKey派生密钥，可能导致使用未初始化或默认密钥进行加密，违反密码学安全要求。
- D验证: stage_c_preserved / ver_a62c4ec5
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 28. hyp_path_e979fc56e8ad

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_01.c:72
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: Program executes the code path without early break from any of the prior cryptographic API calls.
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; ... } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_01.c:76; if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break; ... } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_01.c:72; if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) { break; ... } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_01.c:70; /* Missing call to CryptDeriveKey */ @ Missing: CryptDeriveKey should be called before CryptEncrypt; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; ... } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_01.c:60
- 结论: Missing call to CryptDeriveKey after CryptCreateHash and CryptHashData, resulting in use of an uninitialized or incorrect key for encryption. This violates the required cryptographic step (CWE-325).
- D验证: stage_c_preserved / ver_4d1ad62e
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 29. hyp_path_3c47a17b67fe

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_03.c:74
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 程序正常执行路径，无需攻击者特殊控制。
- 触发路径: 入口函数，调用CryptAcquireContext @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_03.c:29; 创建hHash并哈希数据，但缺失CryptDeriveKey调用 @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_03.c:68-72; 直接调用CryptEncrypt，hKey未正确派生 @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_03.c:60-64
- 结论: 缺少必要的加密步骤：未调用CryptDeriveKey派生密钥，导致CryptEncrypt使用无效或未初始化的密钥，加密无效。
- D验证: stage_c_preserved / ver_a90f8bb4
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 30. hyp_path_e073923e16c0

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_05.c:80
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 无外部输入控制，属于代码逻辑缺陷。
- 触发路径: CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0) @ 84; CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash) @ 78-80; CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0) @ 82; CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload)) @ 66-70
- 结论: 在加密流程中缺少必需的CryptDeriveKey调用，导致加密密钥hKey未被正确初始化，CryptEncrypt可能使用无效密钥或未加密数据。
- D验证: stage_c_preserved / ver_ffd87f76
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 31. hyp_path_e86859932dfc

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_06.c:79
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者可能控制hashData输入，但缺失派生步骤不影响加密结果，而是导致加密使用错误的密钥。
- 触发路径: CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_06.c:34; CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash) @ 同上:70; CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0) @ 同上:73; CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload)) // 缺少CryptDeriveKey调用 @ 同上:67
- 结论: 代码中缺失了必要的加密步骤：在使用CryptEncrypt加密之前，未调用CryptDeriveKey从哈希派生密钥，导致密钥可能未正确初始化或使用弱密钥，违反了CWE-325的要求。
- D验证: stage_c_preserved / ver_a8b0e5aa
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 32. hyp_path_d19721061a00

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_07.c:79
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者可能通过控制hashData输入来影响哈希值，但主要漏洞在于缺少派生密钥步骤，而非直接利用输入。
- 触发路径: if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_07.c:65-69; 之前未在代码中显示调用CryptDeriveKey，但存在CryptCreateHash和CryptHashData（约在第55-60行）; 上下文：CryptAcquireContextA, CryptCreateHash, CryptHashData被调用，但缺少CryptDeriveKey
- 结论: 缺少必需的加密步骤：在使用CryptEncrypt之前，未调用CryptDeriveKey从哈希派生密钥，导致加密可能使用无效或默认密钥。
- D验证: stage_c_preserved / ver_0d573933
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 33. hyp_path_3eec1579b8a4

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_10.c:74
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 代码执行到达CryptEncrypt调用，且hKey未通过CryptDeriveKey或CryptGenKey正确初始化。
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; ... } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_10.c:29; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_10.c:62
- 结论: 缺少必要的加密步骤：未调用CryptDeriveKey或CryptGenKey生成会话密钥，直接使用未初始化或无效的hKey调用CryptEncrypt，导致加密无效或使用错误密钥。
- D验证: stage_c_preserved / ver_75e51230
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 34. hyp_path_b295526c5f92

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_09.c:74
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P1
- 触发条件: 攻击者能够提供输入数据（hashData）以影响哈希值，但无法控制密钥派生过程; 代码中未实现CryptDeriveKey调用，导致加密密钥无效
- 触发路径: 入口函数调用处 @ 入口: 29行; if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; } @ 78行附近; if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break; } @ 后续行; if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) { break; } @ 后续行; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ 62行附近
- 结论: 代码在加密过程中缺少必需的密钥派生步骤（CryptDeriveKey），导致加密可能使用未正确初始化的密钥，从而无法提供有效的机密性保护。
- D验证: stage_c_preserved / ver_cd8b5704
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 35. hyp_path_dca17e995f07

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_15.c:75
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 代码正常执行，未跳过加密步骤。
- 触发路径: if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_15.c:63; 应在此之前调用CryptDeriveKey，但缺失。 @ 之前缺失
- 结论: 在使用CryptEncrypt加密数据之前，未调用CryptDeriveKey从哈希派生密钥，导致加密操作使用无效或未初始化的密钥句柄，违反了必要的加密步骤。
- D验证: stage_c_preserved / ver_c5d4bb49
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 36. hyp_path_cebd3174cb8e

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_13.c:74
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者可能能够观察加密输出或提供部分加密数据，但漏洞主要源于编码错误，无需特定输入即可触发。
- 触发路径: /* Encrypt the payload */ if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_13.c:60-64
- 结论: 代码中使用了Windows CryptoAPI进行加密，但缺少必需的CryptDeriveKey步骤来从哈希派生加密密钥。虽然存在CryptAcquireContext、CryptCreateHash和CryptHashData调用，但CryptEncrypt直接使用了未正确初始化的hKey（未通过CryptDeriveKey派生）。这违反了CWE-325“Missing Required Cryptographic Step”，导致加密操作可能使用无效或未正确生成的密钥，从而破坏加密的有效性。
- D验证: stage_c_preserved / ver_5a7b496c
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 37. hyp_path_2e32033f3e19

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_14.c:74
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者可以控制hashData输入（影响哈希值，但密钥派生缺失导致密钥无效）
- 触发路径: CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0) @ line29附近; CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash) @ line74附近; CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0) @ line74附近; CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload)) // 缺少CryptDeriveKey派生密钥 @ line60-64
- 结论: 缺少必需的加密步骤：未调用CryptDeriveKey从哈希派生密钥，直接使用CryptEncrypt加密，可能导致加密使用无效密钥句柄，加密无效。
- D验证: stage_c_preserved / ver_1516fcbe
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 38. hyp_path_7cad8c7e7c87

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_16.c:74
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P1
- 触发条件: 攻击者无需外部输入控制；漏洞由编码错误导致，任何使用此加密函数的场景均受影响
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_16.c:28-34; if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_16.c:38-42; if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_16.c:44-48; /* Encrypt the payload */ if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_16.c:60-62
- 结论: 代码中缺少必需的加密步骤：未调用CryptDeriveKey从哈希导出会话密钥，直接使用hKey进行CryptEncrypt，可能导致加密使用无效或未初始化的密钥，从而无法正确加密数据。
- D验证: stage_c_preserved / ver_8ced0c2c
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 39. hyp_path_a49740b56fe5

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_18.c:74
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P1
- 触发条件: 攻击者可能能够控制hashData输入以影响哈希结果，但更关键的是利用缺失密钥派生的漏洞来破坏加密的有效性；即使没有外部输入，未正确派生的hKey也会导致加密无效。
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_18.c:78; if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break; } @ 同一文件（未显示具体行，但从合并证据推断存在）; if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) { break; } @ 同一文件（未显示具体行，但从合并证据推断存在）; // 缺少: if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ 缺失步骤（未调用CryptDeriveKey）; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_18.c:62
- 结论: 代码在加密前缺少对CryptDeriveKey的调用，导致CryptEncrypt使用未正确派生的密钥，违反CWE-325（缺少必需加密步骤）。攻击者可能利用此漏洞解密或篡改数据。
- D验证: stage_c_preserved / ver_60d906b3
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 40. hyp_path_3b098f7a6875

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_08.c:90
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者无需控制输入，漏洞由代码路径逻辑缺陷自动触发（当staticReturnsTrue()为真时）
- 触发路径: if(staticReturnsTrue()) { @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_08.c:42; if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; } @ 同上文件行71; if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) { break; } // NOTE: Missing required step (CryptCreateHash) causes the payload to remain in plaintext form @ 同上文件行85; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ 同上文件行88; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ 同上文件行74
- 结论: 缺少必要的加密步骤：未调用CryptCreateHash创建哈希对象，直接使用未初始化的hHash句柄调用CryptHashData，导致加密操作无效或失败，payload保持明文。
- D验证: confirmed / ver_224b9000
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 41. hyp_path_f13f11bbcb39

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_11.c:77
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: An adversary may trigger this code path by providing input that causes the application to encrypt data. The missing cryptographic step results in ineffective encryption, exposing sensitive data.
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_11.c:29; if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) // hHash not created @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_11.c:?; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_11.c:?; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_11.c:61
- 结论: CWE-325 Missing Required Cryptographic Step: the code calls CryptHashData and CryptDeriveKey without a preceding CryptCreateHash call, leaving hHash uninitialized. This causes encryption to fail silently or use an invalid hash handle, so plaintext data is not properly encrypted.
- D验证: confirmed / ver_3533962b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 42. hyp_path_be9ab0223d97

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_01.c:75
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够触发代码路径，但payload和hashData为硬编码常量，实际攻击场景需控制这些输入
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; } @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_01.c:29; /* NOTE: Missing required step (CryptCreateHash) causes the payload to remain in plaintext form */ @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_01.c:43; if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) { break; } @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_01.c:44; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_01.c:48; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_01.c:57
- 结论: 代码缺失必需加密步骤CryptCreateHash，导致CryptHashData使用未初始化的hHash，可能使CryptDeriveKey生成无效密钥，进而CryptEncrypt加密失败，数据以明文形式保留。此缺陷属于CWE-325缺失必需加密步骤，可导致加密被绕过。
- D验证: confirmed / ver_afebecb7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 43. hyp_path_6ab5f8d7e98a

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_02.c:77
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 程序执行到该代码路径，且未提前拦截或错误处理。
- 触发路径: 入口点 @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_02.c:29; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_02.c:59-63; if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_02.c:77
- 结论: 缺少必要的加密步骤：未调用 CryptCreateHash 创建哈希对象，导致后续 CryptHashData 使用未初始化的 hHash 句柄可能失败，或即使侥幸成功，也未正确派生密钥，从而使加密无效，敏感数据以明文形式暴露。
- D验证: confirmed / ver_5b0b71eb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 44. hyp_path_bed6b148d9da

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_04.c:83
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者无需控制输入，漏洞因代码中缺失 CryptCreateHash 调用导致，属于逻辑缺陷。
- 触发路径: if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_04.c:65; if (hKey) { CryptDestroyKey(hKey); } if (hHash) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_04.c:73-77; if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } /* Do something with the encrypted data */ @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_04.c:81-85
- 结论: 代码中缺少必要的密码学步骤 CryptCreateHash，导致哈希对象未正确创建，进而使后续的 CryptHashData 和 CryptDeriveKey 操作基于无效句柄，最终 CryptEncrypt 可能使用错误密钥或失败，敏感数据可能以明文形式处理。
- D验证: confirmed / ver_19ef1fca
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 45. hyp_path_f6281724a155

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_03.c:77
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够观察到程序输出（如通过日志、网络或存储）。
- 触发路径: if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ L59-61; printBytesLine(payload, payloadLen); // 输出的是未加密的明文 @ L77-79
- 结论: 在加密过程中缺失了必要的CryptCreateHash步骤，导致CryptHashData使用未初始化的哈希句柄，加密操作失败，敏感数据以明文形式保留，可能被攻击者获取。
- D验证: confirmed / ver_2db08dcd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 46. hyp_path_1d49384a1014

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_05.c:83
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够控制payload数据（例如通过输入或网络数据包）; 程序执行路径进入缺少CryptCreateHash的分支（staticFalse=0或等价条件）
- 触发路径: int staticFalse = 0; if(staticFalse) { ... } else { /* 执行缺失步骤的分支 */ } @ L35; if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; } @ L83; /* 注释: Missing required step (CryptCreateHash) */ @ 缺失CryptCreateHash; if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) { break; } @ 后续调用CryptHashData; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ 后续调用CryptDeriveKey; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ L67
- 结论: 代码缺少必需的加密步骤CryptCreateHash，导致后续的CryptHashData和CryptDeriveKey操作使用未初始化的哈希句柄hHash，使得加密实际未生效，payload以明文形式处理，违反了CWE-325。
- D验证: confirmed / ver_fde1d73a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 47. hyp_path_e67242c3f018

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_06.c:82
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者不需要控制输入，该漏洞是代码编写错误导致的，攻击者可能通过诱导程序处理敏感数据（如payload）而利用信息泄露。
- 触发路径: if(staticReturnsTrue()) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_06.c:34; if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_06.c:58; 缺少：if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break; } @ 缺失行; if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) { break; } // 使用未初始化的hHash @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_06.c:70; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_06.c:74; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } // 使用无效密钥加密，实际未加密 @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_06.c:66
- 结论: 在加密流程中，缺少对CryptCreateHash的调用（步骤缺失），导致哈希对象hHash未初始化，后续CryptHashData和CryptDeriveKey可能失败，但最终CryptEncrypt被调用时使用无效密钥，实际导致payload以明文形式处理，违反了加密步骤的必要性。
- D验证: confirmed / ver_999be2a4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 48. hyp_path_347d86fdd9c2

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_07.c:82
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够访问网络传输或存储的加密数据，但由于实际未加密，可以直接读取明文。
- 触发路径: 入口：CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_07_case0 @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_07.c:34; CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0) @ line 62; /* NOTE: Missing required step (CryptCreateHash) causes the payload to remain in plaintext form */ @ line 64; CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0) // hHash未初始化 @ line 66; CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey) @ line 68; CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload)) // 加密无效 @ line 70-72
- 结论: 代码缺少必要的加密步骤：在调用CryptHashData之前未调用CryptCreateHash创建哈希对象，导致后续加密操作无效，加密数据实际以明文形式存在，损害机密性。
- D验证: confirmed / ver_52751ba9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 49. hyp_path_6f06f83c79aa

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_13.c:77
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够访问加密后的数据（payload），由于加密步骤缺失，payload实际为明文。
- 触发路径: int CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_13_case0() { @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_13.c:29; if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_13.c:77; /* NOTE: Missing required step (CryptCreateHash) */ @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_13.c:77; if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_13.c:77; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_13.c:77; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_13.c:61
- 结论: 缺少必需的加密步骤（CryptCreateHash），导致加密操作无效，敏感数据以明文形式存在。
- D验证: confirmed / ver_51af9a11
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 50. hyp_path_1cecc95c501a

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_10.c:77
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够控制加密使用的输入数据或观察加密输出，但本漏洞主要导致加密步骤缺失，无需攻击者主动输入即可触发加密失效。
- 触发路径: 入口处开始执行 @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_10.c:29; CryptAcquireContext获取加密上下文 @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_10.c:77; 应调用CryptCreateHash创建哈希对象，但未调用 @ 缺失步骤; CryptHashData使用未初始化的hHash @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_10.c:73; CryptDeriveKey派生密钥，可能失败 @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_10.c:61; CryptEncrypt使用可能无效的密钥加密数据 @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_10.c:61
- 结论: 缺少必需的加密步骤：代码中未调用CryptCreateHash创建哈希对象，导致CryptHashData和CryptDeriveKey操作使用未初始化的hHash，最终CryptEncrypt可能使用未正确派生的密钥进行加密，造成加密失效，可能泄露明文数据。
- D验证: confirmed / ver_ae8d0636
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 51. hyp_path_75ab8da32751

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_14.c:77
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 代码通过该路径执行，且未在CryptHashData前创建哈希句柄
- 触发路径: 入口调用CryptAcquireContext @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_14.c:29; 缺少 CryptCreateHash(&hHash) 步骤 @ 缺失调用CryptCreateHash; if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) // hHash未创建 @ juliet-api-misuse/testcases/..._14.c:58; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) @ juliet-api-misuse/testcases/..._14.c:61; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) @ juliet-api-misuse/testcases/..._14.c:61
- 结论: 缺失必需的加密步骤：在使用CryptHashData之前未调用CryptCreateHash创建哈希对象，导致哈希句柄hHash未初始化或无效，后续的哈希操作和密钥派生可能失败或使用错误状态，最终加密操作可能使用未正确派生的密钥，从而使加密无效或数据保持明文。
- D验证: confirmed / ver_26da1a8b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 52. hyp_path_6de1e97e36af

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_15.c:78
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够访问程序输出的payload数据（在代码中为常量PAYLOAD，但漏洞仍导致明文暴露）
- 触发路径: 入口: 函数CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_15_case0 @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_15.c:29; if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } /* Do something with the encrypted data */ ... 但之前未调用CryptCreateHash，导致hHash未初始化，后续加密无效 @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_15.c:78; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; ... } // 加密操作，但由于缺少CryptCreateHash，加密实际未生效 @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_15.c:60-64; /* Do something with the encrypted data */ printBytesLine(payload, payloadLen); // 输出明文数据 @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_15.c:78
- 结论: 代码缺少对CryptCreateHash的调用，导致后续加密操作实际上没有对数据进行加密，数据以明文形式处理，违反了必需的加密步骤。
- D验证: confirmed / ver_699bd6c6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 53. hyp_path_a5099e5b5c62

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_16.c:77
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够向程序提供payload数据，程序试图加密但实际未加密，payload以明文形式处理。
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_16.c:29; /* NOTE: Missing required step (CryptCreateHash) causes the payload to remain in plaintext form */ @ （缺失步骤）; if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) { break; } @ （直接调用）; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_16.c:61; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_16.c:61
- 结论: 缺少CryptCreateHash步骤，导致hHash未初始化，CryptHashData调用失败，密钥派生无效，加密未执行，payload以明文形式处理。
- D验证: confirmed / ver_1a5a957d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 54. hyp_path_110a3bf20d30

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_18.c:77
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 程序执行到达加密代码路径，且未调用 CryptCreateHash 创建哈希对象。
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_18.c:72-73; // NOTE: Missing required step (CryptCreateHash) causes the payload to remain in plaintext form @ 76-77 (缺少 CryptCreateHash); if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) { break; } @ 78-79; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ 80-81; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ 59-63
- 结论: 在加密流程中缺少了对 CryptCreateHash 的调用，导致 hHash 未正确初始化，后续 CryptHashData 和 CryptDeriveKey 操作可能失败或在未初始化状态下执行，最终 CryptEncrypt 可能使用无效密钥，加密失败，敏感数据以明文形式暴露。
- D验证: confirmed / ver_fb28b4d3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 55. hyp_path_7cfa12263e39

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_17.c:74
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: No specific attacker control required; vulnerability exists in the code logic itself.
- 触发路径: /* Create hash handle */ if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break;} @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_17.c:60-64; /* NOTE: Missing required step (CryptHashData) does not use hash input when generating AES key */ /* Derive an AES key from the hash */ if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break;} @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_17.c:68-72; /* Encrypt the payload */ if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break;} @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_17.c:60-64
- 结论: Missing required cryptographic step: CryptHashData is not called before CryptDeriveKey, resulting in AES key derived from an empty/unhashed hash object, weakening encryption.
- D验证: stage_c_preserved / ver_018d48ce
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 56. hyp_path_0aea1b64c533

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_09.c:77
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者无需控制任何输入；漏洞由代码逻辑缺失自动触发。
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; } @ L29; /* NOTE: Missing required step (CryptCreateHash) causes the payload to remain in plaintext form */ @ 缺失; if(!CryptHashData(hHash, (BYTE*)hashData, strlen(hashData), 0)) { break; } @ L36（推测）; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ L40（推测）; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ L61
- 结论: 缺少必需的加密步骤CryptCreateHash，导致密钥派生无效，进而加密操作可能失败或使用无效句柄，最终数据可能以明文形式存储或传输，违反CWE325。
- D验证: confirmed / ver_cfe665f5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 57. hyp_path_bad7aa931d16

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_08.c:86
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者无需控制特定输入，漏洞由代码逻辑缺失自动触发。但若需实际利用，攻击者可能需获取密文或观察加密输出。
- 触发路径: if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break; ... /* NOTE: Missing required step (CryptHashData) does not use hash input when generating AES key */ /* Derive an AES key from the hash */ if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; ... } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_08.c:86-92; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; ... } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_08.c:72-76
- 结论: 在加密过程中，缺少必需的CryptHashData步骤，导致派生密钥时使用的哈希对象未填充实际数据，从而派生出的AES密钥可能基于未初始化的哈希值，使得加密强度大大降低，攻击者可能恢复明文或密钥。
- D验证: stage_c_preserved / ver_98efe5ab
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 58. hyp_path_f7d1c2b29cfa

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_11.c:73
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者不需要控制输入，漏洞由代码逻辑缺陷自动触发；但若攻击者可影响加密数据，则可能利用弱密钥
- 触发路径: if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_11.c:约54行; // NOTE: Missing required step (CryptHashData) does not use hash input when generating AES key @ 同一文件约55行; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ 同一文件约59行
- 结论: CWE325: 缺少必需的加密步骤 - 在调用CryptCreateHash后未调用CryptHashData，直接使用未初始化的哈希对象派生密钥，导致密钥推导不完整，可能降低加密强度。
- D验证: stage_c_preserved / ver_e6217da6
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 59. hyp_path_b04f049e67cd

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_01.c:71
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够获取到加密后的数据（payload）; 攻击者了解算法实现细节（CALG_SHA_256 with empty hash）
- 触发路径: CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_01.c:71; CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_01.c:71; // 缺少 CryptHashData(hHash, data, dataLen, 0) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_01.c:71 (缺少); CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_01.c:71; CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload)) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_01.c:59
- 结论: 缺少必需的密码步骤：在调用CryptDeriveKey之前未调用CryptHashData，导致用于派生AES密钥的哈希句柄未包含任何数据，可能使加密密钥可预测或弱化。
- D验证: stage_c_preserved / ver_f7e515a0
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 60. hyp_path_218bc10a503a

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_03.c:73
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者不需要直接控制输入，但漏洞的存在使加密强度降低，可能通过分析输出恢复密钥。
- 触发路径: if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_03.c:73; /* NOTE: Missing required step (CryptHashData) does not use hash input when generating AES key */ @ 同一文件行（缺失CryptHashData调用）; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ 同一文件行; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_03.c:61
- 结论: 在CryptDeriveKey之前缺少CryptHashData调用，导致派生AES密钥时未使用任何数据（例如密码或会话数据），密钥可预测或弱化，违反加密步骤完整性。
- D验证: stage_c_preserved / ver_05bb45d7
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 61. hyp_path_8781d59a6730

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_04.c:79
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者不需要任何输入控制，漏洞存在于正常执行路径中
- 触发路径: if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break; } @ L79; /* NOTE: Missing required step (CryptHashData) does not use hash input when generating AES key */ @ 缺失行; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ L79后; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ L67
- 结论: 代码缺失必要的密码学步骤：在创建哈希句柄后未调用CryptHashData添加数据，直接使用空哈希派生密钥，违背了CWE-325（缺失必要的密码学步骤）。这可能导致密钥生成基于未初始化的哈希值，削弱加密强度。
- D验证: stage_c_preserved / ver_89dc282f
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 62. hyp_path_6b5fe82b8893

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_02.c:73
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够访问程序的加密输出（例如密文），并可能通过已知明文攻击等方式利用弱密钥。
- 触发路径: CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_02.c:37; CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_02.c:43; CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_02.c:50; CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload)) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_02.c:61
- 结论: 在加密操作中缺少必需的CryptHashData步骤，导致AES密钥派生未使用哈希数据，从而削弱加密强度，可能被攻击者利用以恢复明文。
- D验证: stage_c_preserved / ver_c351ece6
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 63. hyp_path_cf0fd02d2f72

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_06.c:78
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者可能能够观察加密输出或获得解密能力，但无需直接控制输入；漏洞本身存在即可破坏加密可靠性
- 触发路径: if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break; ... } /* NOTE: Missing required step (CryptHashData) does not use hash input when generating AES key */ if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; ... } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_06.c:78; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; ... } @ same file, line 66
- 结论: 缺少必需的加密步骤：在调用CryptDeriveKey之前未调用CryptHashData，导致派生密钥未基于实际数据，可能生成弱密钥，破坏加密安全性。
- D验证: stage_c_preserved / ver_1454507c
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 64. hyp_path_ebc7f3f1b2f2

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_05.c:79
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够观察使用该弱密钥加密的数据（payload固定，但加密结果可观测），从而可能恢复明文或密钥。
- 触发路径: if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_05.c:79; /* NOTE: Missing required step (CryptHashData) does not use hash input when generating AES key */ @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_05.c:79-80; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_05.c:81; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_05.c:67
- 结论: 缺少必需的加密步骤：在调用CryptDeriveKey之前未调用CryptHashData，导致密钥派生基于未初始化的哈希对象，可能产生弱密钥，进而削弱加密强度。
- D验证: stage_c_preserved / ver_59097b0f
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 65. hyp_path_4956f5b52c97

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_07.c:78
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: The program executes the code path that includes CryptCreateHash and CryptDeriveKey without calling CryptHashData.
- 触发路径: if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break; ... } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_07.c:78; /* NOTE: Missing required step (CryptHashData) does not use hash input when generating AES key */ @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_07.c:78; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; ... } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_07.c:78
- 结论: Missing required cryptographic step: CryptHashData is not called before CryptDeriveKey, resulting in weak AES key derivation.
- D验证: stage_c_preserved / ver_442d948b
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 66. hyp_path_1763ff8979aa

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_10.c:73
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者可能通过控制payload影响加密结果，但当前payload固定；漏洞本身是代码逻辑缺失。
- 触发路径: 入口 @ 29; CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash) @ 73; CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey) // 缺少CryptHashData @ 73; CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload)) @ 61
- 结论: 在加密过程中缺少必要的CryptHashData调用，导致生成的AES密钥未基于输入数据进行哈希，可能使用未初始化的哈希值，从而削弱加密强度。
- D验证: stage_c_preserved / ver_e77d0873
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 67. hyp_path_295f16430c3c

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_09.c:73
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: No external input required; the code path is unconditional.
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; ... } @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_09.c:36; if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break; ... } @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_09.c:40; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; ... } @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_09.c:49; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; ... } @ CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_09.c:61
- 结论: Missing required cryptographic step: CryptHashData is not called before CryptDeriveKey, resulting in an AES key derived from an empty hash. This weakens encryption and may allow predictable keys.
- D验证: stage_c_preserved / ver_13fa0ec8
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 68. hyp_path_a0d3a622a9df

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_13.c:73
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够获取加密后的数据，并具备破解弱密钥的能力
- 触发路径: if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_13.c:73; /* NOTE: Missing required step (CryptHashData) does not use hash input when generating AES key */ @ 同文件约73行后; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) @ 同文件约73行后; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) @ 同文件约61行
- 结论: 在Windows加密API中，创建哈希对象后未调用CryptHashData添加数据，直接使用CryptDeriveKey派生密钥，导致派生出的密钥基于未初始化或空哈希值，严重削弱加密强度，可能被攻击者破解。
- D验证: stage_c_preserved / ver_67f69372
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 69. hyp_path_7f7d75e628c6

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_14.c:73
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P1
- 触发条件: 攻击者不直接控制输入，但漏洞本身导致加密密钥脆弱，可能被攻击者利用（如明文攻击、密钥恢复）
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; ... } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_14.c:29; if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break; ... /* NOTE: Missing required step (CryptHashData) does not use hash input when generating AES key */ @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_14.c:73; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; ... } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_14.c:73-74; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; ... } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_14.c:59-63
- 结论: 代码缺少调用CryptHashData来初始化哈希对象，导致CryptDeriveKey基于未初始化的哈希派生密钥，可能生成弱密钥或可预测密钥，破坏加密安全性。
- D验证: stage_c_preserved / ver_823c862d
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 70. hyp_path_4d10db0ca147

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_16.c:73
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者可能通过控制加密数据（如payload）来利用此漏洞，但更关键的是密钥派生过程缺少必要输入，导致密钥强度降低。
- 触发路径: if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break; } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_16.c:73; /* NOTE: Missing required step (CryptHashData) does not use hash input when generating AES key */ @ 同上文件:73 (注释); if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; } @ 同上文件:73; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; } @ 同上文件:61
- 结论: 在加密操作中，调用CryptCreateHash后缺少必要的CryptHashData步骤，导致派生密钥时未使用预期哈希输入，可能生成弱密钥或可预测密钥。
- D验证: stage_c_preserved / ver_1d4a2a82
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 71. hyp_path_ddd7b58424ae

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_18.c:73
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: The attacker does not need to control input; the vulnerability is in the cryptographic logic itself, which uses an unhashed (empty) hash to derive the key.
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; @ line 73 (approx) in the source file, see A-phase evidence: CryptAcquireContext; if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break; @ line 73: CryptCreateHash; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; @ line 73: CryptDeriveKey (missing CryptHashData); if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; @ line 61: CryptEncrypt
- 结论: Missing required cryptographic step: CryptHashData is not called before CryptDeriveKey, so the derived AES key is not based on any actual data (e.g., a password or session key), weakening encryption.
- D验证: stage_c_preserved / ver_e3a81412
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 72. hyp_path_db2e12b6b2c2

- 漏洞位置: juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_15.c:74
- 漏洞类型: CWE-325
- CWE: CWE-325
- 风险等级: P0
- 触发条件: 攻击者能够访问由该程序加密的密文（payload加密结果）
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) { break; ... } @ 入口函数内; if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { break; ... } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_15.c:74; /* NOTE: Missing required step (CryptHashData) does not use hash input when generating AES key */ @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_15.c:74; if(!CryptDeriveKey(hCryptProv, CALG_AES_256, hHash, 0, &hKey)) { break; ... } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_15.c:74; if(!CryptEncrypt(hKey, 0, 1, 0, payload, &payloadLen, sizeof(payload))) { break; ... } @ juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_15.c:62
- 结论: 代码中使用了CryptCreateHash创建哈希对象，但缺少必要的CryptHashData步骤来为哈希对象提供数据，随后直接使用CryptDeriveKey从该未初始化的哈希对象派生AES密钥。这导致派生出的密钥可能是基于未初始化或不可预测的值，严重削弱加密安全性。攻击者如果能够获取加密后的数据，可能更容易破解密钥。
- D验证: stage_c_preserved / ver_b37877b6
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

## Unconfirmed / Failed Verification

These records are not reported as confirmed vulnerabilities. See `verification.failed.jsonl` for full failure details.

- hyp_path_3c88d59bc040 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_12.c:253 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5cc937cd3800 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_12.c:253 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_219ef60a47df | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_12.c:253 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_37d622c142a4 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_08.c:157 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3d1912fc3ced | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_08.c:157 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0ca8a7ac26ea | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_08.c:157 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9aaa2324c013 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_17.c:129 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cc62b245d152 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_17.c:129 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_860cd3125d0c | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_17.c:129 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_77f9793daf32 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_11.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_97418078d44e | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_11.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_67236fe1a91a | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_11.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_be086a367f5e | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_14.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6ac126b5502c | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_14.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_15c738c2451b | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_14.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b50adc0dbf14 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_09.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0814066d5120 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_09.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bd5bfd80e7bb | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_09.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a8538384929e | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_09.c:145 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2c91e51a5a6b | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_14.c:145 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3321955eacf9 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_01.c:133 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d01b6815be74 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_01.c:133 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_233d010368a5 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_01.c:133 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_042a61894ec7 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_03.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c8e08acebd53 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_03.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_40c57ade51f1 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_03.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_01d2a947ac72 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_02.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6a98ba241a6e | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_02.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8b53cf40f564 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_02.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3273ead7910f | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_07.c:211 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fb31b8e55df7 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_07.c:211 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_29e4123bd2e4 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_07.c:211 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_01e0b7bf0ef5 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_06.c:211 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b59eab986ddd | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_06.c:211 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1bb0d6370258 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_06.c:211 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_320b55c4f9bb | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_10.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e4f43899bed2 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_10.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_40bb0000f216 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_10.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ff3c57e770cd | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_15.c:214 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9b1023e161b5 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_15.c:214 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4eb5f05de4f4 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_15.c:214 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_acfe6c10afb8 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptCreateHash_14.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_05455aa85c36 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_14.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6cef1d260e97 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_14.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d392c822321b | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_02.c:207 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8bc03341d079 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_09.c:207 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6047435ae3ed | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_06.c:212 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d48e93eca8b7 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_10.c:207 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a41fcccc7b89 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_13.c:207 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d6f301ae0ab1 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptDeriveKey_16.c:141 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0bb251f13046 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_05.c:150 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_33263547638e | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_05.c:150 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_458fa0ff3236 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_10.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a3f840939bf3 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_10.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dd9fdac173d9 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_08.c:219 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1f5496ae97a1 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_08.c:219 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_769d16720797 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_07.c:149 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e3f3b209ecf4 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_07.c:149 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c6fecbf07a18 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_11.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c35216fd54af | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_11.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_61a513ce1a58 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_04.c:150 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bb6c24719327 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_04.c:150 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bea74129839a | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_02.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c68cc83b6c41 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_02.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5ba1c9fd30a8 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_13.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f42f55bcbcfa | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_13.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6d54cf7312e8 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_03.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_484891a13138 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_03.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_338e7d54faab | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_04.c:212 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d3a90c6de78a | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_04.c:212 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_48f3976fcb55 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_05.c:212 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9e46ee36bae5 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_05.c:212 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a569235b87c2 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_06.c:149 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_51de374a7e45 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_06.c:149 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f2a5250389da | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_09.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_69521a747804 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_09.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_42f2ba148228 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_13.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a179cfac2c26 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_13.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_11235902c6e4 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_16.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9ba285620fe5 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_16.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_16a95b76d643 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_02.c:220 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_381cfa44a6ed | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_02.c:220 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0c836f9d2c8f | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_06.c:225 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2081636398b0 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_06.c:225 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a860dab1b20d | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_04.c:226 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_97cf0393976d | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_04.c:226 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8fca711f0124 | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_05.c:226 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_03148b2e293c | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptEncrypt_13.c:220 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b4c2c3e9ad4d | juliet-api-misuse/testcases/CWE325_Missing_Required_Cryptographic_Step/CWE325_Missing_Required_Cryptographic_Step__w32_CryptHashData_18.c:138 | NOT_EXPLOITABLE | payload did not satisfy oracle
