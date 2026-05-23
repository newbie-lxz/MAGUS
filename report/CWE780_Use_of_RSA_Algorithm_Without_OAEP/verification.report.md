# MAGUS Final Vulnerability Report

- generated_at: 2026-05-22T13:52:01Z
- reportable_vulnerabilities: 18
- d_confirmed_vulnerabilities: 18
- stage_c_preserved_vulnerabilities: 0
- failed_verifications: 21
- source_confirmed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE780_Use_of_RSA_Algorithm_Without_OAEP/verification.jsonl
- source_failed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE780_Use_of_RSA_Algorithm_Without_OAEP/verification.failed.jsonl

## Confirmed Vulnerabilities

### 1. hyp_path_67b7d9b2e7d3

- 漏洞位置: juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_17.c:72
- 漏洞类型: command_injection
- CWE: CWE-780
- 风险等级: P0
- 触发条件: 攻击者能够获取加密数据或参与通信，从而利用缺少OAEP的弱点进行填充预言攻击。
- 触发路径: /* NOTE: Do not use OAEP padding */ if(!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, (BYTE *)payload, &payloadLen, sizeof(payload))) @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_17.c:70-74
- 结论: 使用RSA算法但未使用OAEP填充，可能导致填充预言攻击。
- D验证: confirmed / ver_dafb1268
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 2. hyp_path_557eac599989

- 漏洞位置: juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_12.c:152
- 漏洞类型: command_injection
- CWE: CWE-780
- 风险等级: P0
- 触发条件: 攻击者能够控制CryptoAPI加密操作中的明文数据（payload变量）
- 触发路径: if(!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, (BYTE *)payload, &payloadLen, sizeof(payload))) { printLine("Error in CryptEncryptData"); } /* NOTE: Do not use OAEP padding */ @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_12.c:69-73
- 结论: 代码使用RSA算法进行加密时，未使用OAEP填充（CRYPT_OAEP标志为0），违反了CWE-780。攻击者如果能控制加密的明文，则可能导致密文可预测性增加，甚至泄露密钥信息。
- D验证: confirmed / ver_1622b30a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 3. hyp_path_11e9a190f232

- 漏洞位置: juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_08.c:101
- 漏洞类型: command_injection
- CWE: CWE-780
- 风险等级: P0
- 触发条件: 攻击者能够获取由该密钥加密的密文; 攻击者能够向系统发送密文并观察解密成功/失败的响应
- 触发路径: 入口点，进入case0 @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_08.c:41; CryptAcquireContext, CryptCreateHash, CryptHashData, CryptDeriveKey @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_08.c:~60-80; /* NOTE: Do not use OAEP padding */ if(!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, (BYTE *)payload, &payloadLen, sizeof(payload))) @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_08.c:82-86
- 结论: 代码使用RSA加密时未设置OAEP填充，导致CWE-780漏洞。CryptEncrypt调用中第四个参数为0，明确表示使用PKCS#1 v1.5填充而非OAEP，易受填充预言攻击。
- D验证: confirmed / ver_c724d074
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 4. hyp_path_4d727ab4e9cb

- 漏洞位置: juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_11.c:84
- 漏洞类型: command_injection
- CWE: CWE-780
- 风险等级: P0
- 触发条件: 攻击者能够获取或观察加密后的密文，且能够进行选择明文攻击或填充预言攻击。
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0)) { ... } @ CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_11.c:84-86; if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { ... } @ CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_11.c:84-86; if(!CryptHashData(hHash, (BYTE *) HASH_INPUT, strlen(HASH_INPUT)*sizeof(char), 0)) { ... } @ CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_11.c:84-86; if(!CryptDeriveKey(hCryptProv, CALG_RSA_SIGN, hHash, 0, &hKey)) { ... } @ CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_11.c:84-86; /* NOTE: Do not use OAEP padding */ ... if(!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, (BYTE *)payload, &payloadLen, sizeof(payload))) { ... } @ CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_11.c:69-73
- 结论: 使用RSA算法但没有使用OAEP填充，导致加密强度不足，可能被选择明文攻击或填充预言攻击。
- D验证: confirmed / ver_a03a331d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 5. hyp_path_4d51d6108c2d

- 漏洞位置: juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_01.c:82
- 漏洞类型: command_injection
- CWE: CWE-780; CWE-327
- 风险等级: P0
- 触发条件: 攻击者能够获取加密后的密文或进行选择明文攻击
- 触发路径: if(!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, (BYTE *)payload, &payloadLen, sizeof(payload))) @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_01.c:67-71
- 结论: 使用RSA算法而不采用OAEP填充，导致密文可被选择明文攻击或已知明文攻击，违反CWE-780。
- D验证: confirmed / ver_14c4572e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 6. hyp_path_61d283b91437

- 漏洞位置: juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_02.c:88
- 漏洞类型: command_injection
- CWE: CWE-780
- 风险等级: P0
- 触发条件: 攻击者能够获取密文并能够触发解密操作（例如通过解密预言机）; 攻击者能够进行选择密文攻击，利用无OAEP填充的RSA的弱点
- 触发路径: /* NOTE: Do not use OAEP padding */ /* Use the derived key to encrypt something */ if(!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, (BYTE *)payload, &payloadLen, sizeof(payload))) { printLine("Error in CryptEncryptData"); } @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_02.c:69-73; CryptEncrypt调用中dwFlags参数为0，未使用OAEP填充 @ 同上
- 结论: 代码使用RSA加密时未设置OAEP填充，导致API误用漏洞（CWE-780），可能遭受padding oracle攻击。
- D验证: confirmed / ver_dcb5d21a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 7. hyp_path_61adef8ae8a6

- 漏洞位置: juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_03.c:88
- 漏洞类型: command_injection
- CWE: CWE-780
- 风险等级: P0
- 触发条件: 攻击者能够获取加密后的数据，并且RSA加密未使用OAEP填充可能导致选择密文攻击等风险
- 触发路径: /* NOTE: Do not use OAEP padding */ /* Use the derived key to encrypt something */ if(!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, (BYTE *)payload, &payloadLen, sizeof(payload))) @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_03.c:69-73
- 结论: 代码中使用RSA算法进行加密，但未使用OAEP填充，导致CWE-780漏洞。
- D验证: confirmed / ver_d889783a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 8. hyp_path_bc83fd98ab2c

- 漏洞位置: juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_04.c:90
- 漏洞类型: command_injection
- CWE: CWE-780
- 风险等级: P0
- 触发条件: 攻击者需要能够访问密文输出，但无需控制输入
- 触发路径: /* NOTE: Do not use OAEP padding */ /* Use the derived key to encrypt something */ if(!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, (BYTE *)payload, &payloadLen, sizeof(payload))) { printLine("Error in CryptEncryptData"); ... } @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_04.c:75-79
- 结论: 使用RSA算法进行加密时未使用OAEP填充，违反CWE-780规范，可能导致加密数据易于受到填充预言攻击。代码中CryptEncrypt的第四个参数为0，明确注释不使用OAEP填充。
- D验证: confirmed / ver_5f0848af
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 9. hyp_path_16db587b2095

- 漏洞位置: juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_05.c:90
- 漏洞类型: command_injection
- CWE: CWE-780
- 风险等级: P0
- 触发条件: 攻击者能够获取加密后的密文，并可能发起padding oracle攻击。
- 触发路径: /* NOTE: Do not use OAEP padding */ /* Use the derived key to encrypt something */ if(!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, (BYTE *)payload, &payloadLen, sizeof(payload))) { @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_05.c:75-79
- 结论: 代码中调用CryptEncrypt时使用了PKCS#1 v1.5填充（默认），而非更安全的OAEP填充，这可能导致选择密文攻击（padding oracle攻击）或密文可预测性风险。
- D验证: confirmed / ver_3a36686a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 10. hyp_path_26375bd09810

- 漏洞位置: juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_06.c:76
- 漏洞类型: command_injection
- CWE: CWE-780
- 风险等级: P0
- 触发条件: 攻击者能够获取密文或通过其他方式利用填充预言漏洞。
- 触发路径: /* NOTE: Do not use OAEP padding */ /* Use the derived key to encrypt something */ if(!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, (BYTE *)payload, &payloadLen, sizeof(payload))) @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_06.c:74-78
- 结论: 使用RSA算法时未启用OAEP填充，导致加密强度不足，可能受到填充预言攻击。
- D验证: confirmed / ver_62e34468
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 11. hyp_path_18bfc35ec371

- 漏洞位置: juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_07.c:76
- 漏洞类型: command_injection
- CWE: CWE-780
- 风险等级: P0
- 触发条件: 攻击者能够获取加密后的密文。
- 触发路径: if(!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, (BYTE *)payload, &payloadLen, sizeof(payload))) @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_07.c:76
- 结论: 使用RSA算法但不使用OAEP填充，导致加密缺乏语义安全，符合CWE-780漏洞。
- D验证: confirmed / ver_efec1e5c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 12. hyp_path_46dd5a15405a

- 漏洞位置: juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_09.c:71
- 漏洞类型: command_injection
- CWE: CWE-780
- 风险等级: P0
- 触发条件: 攻击者能够获取或观察到加密后的密文，并且能够利用RSA不使用OAEP的漏洞实施选择密文攻击。
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0)) @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_09.c:46-47; if(!CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hHash)) @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_09.c:55-57; if(!CryptHashData(hHash, (BYTE *) HASH_INPUT, strlen(HASH_INPUT)*sizeof(char), 0)) @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_09.c:60-62; if(!CryptDeriveKey(hCryptProv, CALG_RSA_SIGN, hHash, 0, &hKey)) @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_09.c:65-67; /* NOTE: Do not use OAEP padding */ if(!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, (BYTE *)payload, &payloadLen, sizeof(payload))) @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_09.c:69-72
- 结论: 使用RSA算法时未使用OAEP填充，可能导致针对RSA加密的选择密文攻击（如Bleichenbacher攻击）。
- D验证: confirmed / ver_ac06bf78
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 13. hyp_path_2bcba131011c

- 漏洞位置: juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_10.c:84
- 漏洞类型: command_injection
- CWE: CWE-780
- 风险等级: P0
- 触发条件: 攻击者能够获取或观察到加密后的密文，并且可以通过选择明文攻击恢复明文或密钥信息。
- 触发路径: /* NOTE: Do not use OAEP padding */ /* Use the derived key to encrypt something */ if(!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, (BYTE *)payload, &payloadLen, sizeof(payload))) @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_10.c:69-73; if (hHash) { CryptDestroyHash(hHash); } if (hCryptProv) { CryptReleaseContext(hCryptProv, 0); } ... if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0)) { ... } if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) { ... } if(!CryptHashData(hHash, (BYTE*)hashData, strlen((char*)hashData), 0)) { ... } if(!CryptDeriveKey(hCryptProv, CALG_RSA_SIGN, hHash, 0, &hKey)) { ... } @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_10.c:84-88
- 结论: 使用RSA算法进行加密但没有使用OAEP填充，容易受到选择明文攻击，违反了安全最佳实践。
- D验证: confirmed / ver_c09e2b88
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 14. hyp_path_4615be1814ad

- 漏洞位置: juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_13.c:84
- 漏洞类型: command_injection
- CWE: CWE-780
- 风险等级: P0
- 触发条件: 攻击者可能通过其他方式影响加密数据或观察密文，但API误用本身即构成漏洞；payload虽为常量，但漏洞在于未使用OAEP填充。
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0)) @ 通过CryptAcquireContext获取加密上下文; if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) @ 创建SHA-256哈希; if(!CryptDeriveKey(hCryptProv, CALG_RSA_SIGN, hHash, 0, &hKey)) @ 从哈希派生RSA密钥; /* NOTE: Do not use OAEP padding */ CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, (BYTE *)payload, &payloadLen, sizeof(payload)) @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_13.c:69-73
- 结论: 使用RSA算法时未使用OAEP填充，可能导致选择密文攻击等安全风险。
- D验证: confirmed / ver_e00dc0b2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 15. hyp_path_264b93055386

- 漏洞位置: juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_15.c:85
- 漏洞类型: command_injection
- CWE: CWE-780
- 风险等级: P0
- 触发条件: 系统使用RSA加密时，调用者未主动指定OAEP填充参数。
- 触发路径: /* NOTE: Do not use OAEP padding */ /* Use the derived key to encrypt something */ if(!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, (BYTE *)payload, &payloadLen, sizeof(payload))) @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_15.c:70
- 结论: 使用RSA算法时未使用OAEP填充，违反了CWE-780安全编码要求，可能导致加密数据易受选择明文攻击。
- D验证: confirmed / ver_cd82d867
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 16. hyp_path_42509a22f22d

- 漏洞位置: juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_14.c:71
- 漏洞类型: command_injection
- CWE: CWE-780
- 风险等级: P0
- 触发条件: 攻击者能够获取或观察RSA加密后的密文
- 触发路径: /* NOTE: Do not use OAEP padding */ if(!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, (BYTE *)payload, &payloadLen, sizeof(payload))) { printLine("Error in CryptEncryptData"); @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_14.c:69-73
- 结论: CryptEncrypt调用时未使用OAEP填充，违反了CWE-780，攻击者可能利用选择密文攻击破解RSA加密。
- D验证: confirmed / ver_ccb90db4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 17. hyp_path_18b69a6dcc87

- 漏洞位置: juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_16.c:71
- 漏洞类型: command_injection
- CWE: CWE-780
- 风险等级: P0
- 触发条件: 攻击者可能获取到加密后的数据，并利用无OAEP的RSA加密弱点进行攻击
- 触发路径: /* NOTE: Do not use OAEP padding */ /* Use the derived key to encrypt something */ if(!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, (BYTE *)payload, &payloadLen, sizeof(payload))) { printLine("Error in CryptEncryptData"); } @ CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_16.c:69-73
- 结论: 使用RSA算法进行加密时没有使用OAEP填充，降低了加密安全性，可能受到选择密文攻击等威胁。
- D验证: confirmed / ver_aad0cae0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 18. hyp_path_39a438878da4

- 漏洞位置: juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_18.c:88
- 漏洞类型: command_injection
- CWE: CWE-780
- 风险等级: P0
- 触发条件: 攻击者能够观察或获取使用此方式加密的密文（例如通过中间人攻击或访问加密数据存储）
- 触发路径: if(!CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0)) @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_18.c:28; if(!CryptCreateHash(hCryptProv, CALG_SHA_256, 0, 0, &hHash)) @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_18.c:40; if(!CryptHashData(hHash, (BYTE *) HASH_INPUT, strlen(HASH_INPUT)*sizeof(char), 0)) @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_18.c:50; if(!CryptDeriveKey(hCryptProv, CALG_RSA_SIGN, hHash, 0, &hKey)) @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_18.c:60; if(!CryptEncrypt(hKey, (HCRYPTHASH)NULL, 1, 0, (BYTE *)payload, &payloadLen, sizeof(payload))) @ juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_18.c:71
- 结论: 使用RSA算法进行加密时，未使用OAEP填充，违反了CWE-780规范。代码注释中明确写道'NOTE: Do not use OAEP padding'，并且CryptEncrypt调用中第四个参数为0（而非CRYPT_OAEP标志），导致加密操作缺乏安全的OAEP填充，可能使密文易受选择明文攻击。
- D验证: confirmed / ver_511ecea7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

## Unconfirmed / Failed Verification

These records are not reported as confirmed vulnerabilities. See `verification.failed.jsonl` for full failure details.

- hyp_path_028f5b6d644c | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_05.c:168 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3806de71262c | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_08.c:179 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b6b991ddde52 | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_02.c:162 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7838af8cc46d | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_03.c:245 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_782788e2351d | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_02.c:245 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9ad8f39f3c67 | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_04.c:251 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2b4549e86985 | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_06.c:250 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_46355b1a321c | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_07.c:250 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_041fce74cbde | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_05.c:252 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5d1450ea7bdb | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_08.c:259 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_15c5de346009 | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_09.c:245 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0bcf005a1346 | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_11.c:246 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_974f26e1edbc | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_14.c:246 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1d7406e88316 | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_15.c:258 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6c2bb339383c | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_13.c:245 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_356968008411 | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_12.c:299 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_288c9f8e35fe | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_16.c:173 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c76ab66e945a | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_17.c:173 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_20fbcba6633e | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_01.c:164 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c87f15d1f5e9 | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/CWE780_Use_of_RSA_Algorithm_Without_OAEP__w32_18.c:169 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0a109bd9a4a5 | juliet-api-misuse/testcases/CWE780_Use_of_RSA_Algorithm_Without_OAEP/main.cpp:28 | ENV_MISSING | payload did not satisfy oracle
