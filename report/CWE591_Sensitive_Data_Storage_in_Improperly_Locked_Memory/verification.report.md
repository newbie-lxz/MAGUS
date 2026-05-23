# MAGUS Final Vulnerability Report

- generated_at: 2026-05-22T14:19:29Z
- reportable_vulnerabilities: 156
- d_confirmed_vulnerabilities: 156
- stage_c_preserved_vulnerabilities: 0
- failed_verifications: 218
- source_confirmed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/verification.jsonl
- source_failed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/verification.failed.jsonl

## Confirmed Vulnerabilities

### 1. hyp_path_c84c2747bb53

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_43.cpp:31
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能访问系统内存交换文件或通过其他方式获取进程内存转储。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_43.cpp:31; strcpy(password, "Password1234!"); @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_43.cpp:39; /* NOTE: Do not lock the memory */ @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_43.cpp:41
- 结论: 敏感数据（硬编码密码）存储在未锁定的内存中，可能导致攻击者通过内存交换或转储获取密码。
- D验证: confirmed / ver_4536e687
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 2. hyp_path_f887a7c9d11f

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_43.cpp:31
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能访问系统内存交换文件或通过其他方式获取进程内存转储。
- 触发路径: static void case0Source(wchar_t * &password) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); } ... { printLine("Memory could not be allocated"); exit(1); } /* NOTE: D... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_43.cpp:31; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_43.cpp::_ZN73CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_43L11case0SourceERPw @ route
- 结论: 敏感数据（硬编码密码）存储在未锁定的内存中，可能导致攻击者通过内存交换或转储获取密码。
- D验证: confirmed / ver_bd4907e0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 3. hyp_path_7f84548f57f6

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_62b.cpp:29
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者需要能够获取进程内存转储或读取交换文件。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ 27; strcpy(password, "Password1234!"); @ 37; /* NOTE: Do not lock the memory */ @ 注释
- 结论: 敏感数据（密码）存储在未锁定的堆内存中，可能导致内存泄露。
- D验证: confirmed / ver_536e179b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 4. hyp_path_75e18249941d

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_62b.cpp:29
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者需要能够获取进程内存转储或读取交换文件。
- 触发路径: void case0Source(wchar_t * &password) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); } ... if (password == NULL) { printLine("Memory could not be allocated"); exit(1... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_62b.cpp:29; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_62b.cpp::_ZN73CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_6211case0SourceERPw @ route
- 结论: 敏感数据（密码）存储在未锁定的堆内存中，可能导致内存泄露。
- D验证: confirmed / ver_db9827df
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 5. hyp_path_3f47a555d276

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_83_case0.cpp:28
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 程序正常运行，无需攻击者输入即可触发漏洞（硬编码密码）。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_83_case0.cpp:28; strcpy(password, "Password1234!"); // 未锁定内存直接存储密码 @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_83_case0.cpp:36
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能导致数据被交换到磁盘而泄露。
- D验证: confirmed / ver_514f335c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 6. hyp_path_d31dfda20435

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_83_case0.cpp:28
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 程序正常运行，无需攻击者输入即可触发漏洞（硬编码密码）。
- 触发路径: { password = passwordCopy; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); } ... if (password == NULL) { printLine("Memory could not be allocated"); exit(1); } ... { pr... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_83_case0.cpp:28; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_83_case0.cpp::_ZN73CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_8379CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_83_case0C2EPw @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能导致数据被交换到磁盘而泄露。
- D验证: confirmed / ver_f8a475e9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 7. hyp_path_111932dd89cb

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_84_case0.cpp:28
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 程序在 Windows 环境下运行，且系统存在分页文件。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_84_case0.cpp:28; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_84_case0.cpp:36
- 结论: 敏感数据（密码）存储在未锁定的内存中，可能被交换到磁盘，导致敏感信息泄露。
- D验证: confirmed / ver_7e471692
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 8. hyp_path_a277a9107687

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_84_case0.cpp:28
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 程序在 Windows 环境下运行，且系统存在分页文件。
- 触发路径: { password = passwordCopy; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); } ... { printLine("Memory could not be allocated"); exit(1); } /* NOTE: Do not lock the memor... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_84_case0.cpp:28; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_84_case0.cpp::_ZN73CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_8479CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_84_case0C2EPw @ route
- 结论: 敏感数据（密码）存储在未锁定的内存中，可能被交换到磁盘，导致敏感信息泄露。
- D验证: confirmed / ver_0035ba4e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 9. hyp_path_a85ffcb0c3c6

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_74a.cpp:39
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够读取目标进程的内存（例如通过调试、核心转储或内核漏洞）
- 触发路径: password = (char *)malloc(100*sizeof(char)); ... /* NOTE: Do not lock the memory */ @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_74a.cpp:37-38; strcpy(password, "Password1234!"); /* Put password in a map */ @ 同一文件:45-46
- 结论: 敏感数据存储在未正确锁定的内存中。程序使用malloc分配内存存储密码，且未调用任何锁定内存的函数（如VirtualLock），导致密码可能被攻击者通过内存转储等方式获取。
- D验证: confirmed / ver_6226fb91
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 10. hyp_path_61cc7c50817f

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_74a.cpp:39
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够读取目标进程的内存（例如通过调试、核心转储或内核漏洞）
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... { printLine("Memory could not be allocated"); exit(1); } /* NOTE: Do not lock the memory */ ... if (password == NULL) { printLine("Memory could not be allocated"); exit(1); } ... /* NOTE: Do not lock the... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_74a.cpp:39; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_74a.cpp::_ZN73CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_745case0Ev @ route
- 结论: 敏感数据存储在未正确锁定的内存中。程序使用malloc分配内存存储密码，且未调用任何锁定内存的函数（如VirtualLock），导致密码可能被攻击者通过内存转储等方式获取。
- D验证: confirmed / ver_3e0303ed
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 11. hyp_path_72b8237a5f22

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_72a.cpp:39
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存或交换文件，以读取未锁定的敏感数据。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_72a.cpp:39; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_72a.cpp:46; passwordVector.insert(passwordVector.end(), 1, password); /* NOTE: Do not lock the memory */ @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_72a.cpp:47-48
- 结论: 敏感数据（密码）存储在未锁定的堆内存中，可能导致敏感数据泄露。
- D验证: confirmed / ver_3938c1ba
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 12. hyp_path_895885d246f0

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_72a.cpp:39
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存或交换文件，以读取未锁定的敏感数据。
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... { printLine("Memory could not be allocated"); exit(1); } /* NOTE: Do not lock the memory */ ... if (password == NULL) { printLine("Memory could not be allocated"); exit(1); } ... /* NOTE: Do not lock the... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_72a.cpp:39; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_72a.cpp::_ZN73CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_725case0Ev @ route
- 结论: 敏感数据（密码）存储在未锁定的堆内存中，可能导致敏感数据泄露。
- D验证: confirmed / ver_512beded
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 13. hyp_path_ca520cec5e63

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_73a.cpp:39
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够访问系统交换文件或崩溃转储，从而从磁盘中恢复未锁定的敏感内存数据。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_73a.cpp:39; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_73a.cpp:45; passwordList.push_back(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_73a.cpp:46
- 结论: 敏感数据（密码）存储在堆内存中，但未使用VirtualLock等API锁定内存，可能被交换到磁盘，导致敏感信息泄露。
- D验证: confirmed / ver_1d368351
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 14. hyp_path_4ef0517749f8

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_73a.cpp:39
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够访问系统交换文件或崩溃转储，从而从磁盘中恢复未锁定的敏感内存数据。
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... { printLine("Memory could not be allocated"); exit(1); } /* NOTE: Do not lock the memory */ ... if (password == NULL) { printLine("Memory could not be allocated"); exit(1); } ... /* NOTE: Do not lock the... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_73a.cpp:39; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_73a.cpp::_ZN73CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_735case0Ev @ route
- 结论: 敏感数据（密码）存储在堆内存中，但未使用VirtualLock等API锁定内存，可能被交换到磁盘，导致敏感信息泄露。
- D验证: confirmed / ver_7ecdcdfc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 15. hyp_path_286dddf0f911

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_12.c:52
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: N/A
- 触发路径: password = (char *)malloc(100*sizeof(char)); if (password == NULL) { ... } strcpy(password, "Password1234!"); @ 行31-35; if(!VirtualLock(password, 100*sizeof(char))) { printLine("Memory could not be locked"); } @ 行50-54; free(password); @ 行79-83
- 结论: 敏感数据（密码）可能存储在未锁定的堆内存中，导致内存交换或转储时泄露。
- D验证: confirmed / ver_eec65f50
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 16. hyp_path_68aa0234cd39

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_12.c:52
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: N/A
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... if(globalReturnsTrueOrFalse()) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... else { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... } /* ALT: Use VirtualLock() to lock the bu... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_12.c:52; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_12.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_12_case0 @ route
- 结论: 敏感数据（密码）可能存储在未锁定的堆内存中，导致内存交换或转储时泄露。
- D验证: confirmed / ver_55f87997
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 17. hyp_path_2d4471011d65

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_17.c:34
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者需要能够访问系统交换文件、核心转储或通过其他方式读取未锁定的进程内存。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_17.c:34; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_17.c:44; if (LogonUserA( username, domain, password, ... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_17.c:58; free(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_17.c:65
- 结论: CWE591: 敏感数据（密码）存储在未正确锁定的内存中。程序使用malloc分配内存存储密码，但未使用VirtualLock等机制将内存锁定在物理RAM中，导致密码可能被交换到磁盘或通过核心转储泄露。
- D验证: confirmed / ver_733f5f41
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 18. hyp_path_33b3f3668aa1

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_17.c:34
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者需要能够访问系统交换文件、核心转储或通过其他方式读取未锁定的进程内存。
- 触发路径: for(i = 0; i < 1; i++) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); } { ... wchar_t... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_17.c:34; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_17.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_17_case0 @ route
- 结论: CWE591: 敏感数据（密码）存储在未正确锁定的内存中。程序使用malloc分配内存存储密码，但未使用VirtualLock等机制将内存锁定在物理RAM中，导致密码可能被交换到磁盘或通过核心转储泄露。
- D验证: confirmed / ver_2aa2e2e3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 19. hyp_path_45f002c3ea76

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_08.c:78
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问进程内存或系统交换文件（如通过管理员权限或物理访问）
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_08.c:47; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_08.c:55; if (LogonUserA(username, domain, password, ...)) @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_08.c:71; free(password); /* NOTE: Sensitive data possibly improperly locked */ @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_08.c:78
- 结论: 敏感数据（密码）存储在未锁定内存中，可能导致内存交换或进程转储泄露密码。
- D验证: confirmed / ver_d508aac0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 20. hyp_path_0f7f8fdd6b8c

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_08.c:78
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问进程内存或系统交换文件（如通过管理员权限或物理访问）
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... if(staticReturnsTrue()) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); } { ... wchar_... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_08.c:78; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_08.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_08_case0 @ route
- 结论: 敏感数据（密码）存储在未锁定内存中，可能导致内存交换或进程转储泄露密码。
- D验证: confirmed / ver_95962ed9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 21. hyp_path_61de9d1d7dfd

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_01.c:61
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够读取系统内存交换文件或进行内存转储
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ line 31; strcpy(password, "Password1234!"); @ line 39-41; if (LogonUserA(username, domain, password, ...) != 0) @ line 54; free(password); @ line 61
- 结论: 敏感数据（密码）存储在未锁定内存中，可能被交换到磁盘导致泄露
- D验证: confirmed / ver_6a879857
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 22. hyp_path_930fb4eaa570

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_01.c:61
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够读取系统内存交换文件或进行内存转储
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); { ... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_01.c:61; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_01.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_01_case0 @ route
- 结论: 敏感数据（密码）存储在未锁定内存中，可能被交换到磁盘导致泄露
- D验证: confirmed / ver_625fd495
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 23. hyp_path_e92d92f13234

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_11.c:64
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存或交换文件以读取敏感数据; 程序在运行时将密码存储在未锁定的堆内存中
- 触发路径: if(globalReturnsTrue()) { password = (char *)malloc(100*sizeof(char)); if (password == NULL) { ... } @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_11.c:31-35; /* NOTE: Do not lock the memory */ strcpy(password, "Password1234!"); @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_11.c:39-43; if (LogonUserA(username, domain, password, ...)) @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_11.c:46-57; /* NOTE: Sensitive data possibly improperly locked */ free(password); @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_11.c:62-66
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘导致泄露。
- D验证: confirmed / ver_6834138e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 24. hyp_path_ba2854318655

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_11.c:64
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存或交换文件以读取敏感数据; 程序在运行时将密码存储在未锁定的堆内存中
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... if(globalReturnsTrue()) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); } { ... wchar_... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_11.c:64; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_11.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_11_case0 @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘导致泄露。
- D验证: confirmed / ver_6a31cbc7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 25. hyp_path_252ab0916f90

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_02.c:64
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者需要能够访问系统的交换文件或内存转储，以从页面文件中提取敏感数据。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_02.c:33; /* NOTE: Do not lock the memory */ strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_02.c:41-42; if (LogonUserA( username, domain, password, ... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_02.c:57; free(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_02.c:64
- 结论: 敏感数据（密码）存储在未锁定（可能被交换到磁盘）的内存中，导致潜在的信息泄露。
- D验证: confirmed / ver_5e1124a9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 26. hyp_path_00ab5c5bd0f9

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_02.c:64
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者需要能够访问系统的交换文件或内存转储，以从页面文件中提取敏感数据。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... if(1) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); } { ... wchar_t * domain = L"Dom... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_02.c:64; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_02.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_02_case0 @ route
- 结论: 敏感数据（密码）存储在未锁定（可能被交换到磁盘）的内存中，导致潜在的信息泄露。
- D验证: confirmed / ver_cd522498
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 27. hyp_path_7c91c1bd0a00

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_03.c:64
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存或页面文件，通过物理访问、权限提升或其他方式读取交换空间。
- 触发路径: password = (char *)malloc(100*sizeof(char)); if (password == NULL) @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_03.c:33-34; /* NOTE: Do not lock the memory */ strcpy(password, "Password1234!"); @ 同文件:39-41; char * domain = "Domain"; ... if (LogonUserA( username, domain, password, ... ) @ 同文件:46-57; } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } @ 同文件:62-66
- 结论: 程序分配内存存储敏感密码，但未使用适当的内存锁定机制（如VirtualLock），可能导致密码被分页到磁盘，从而泄露敏感信息。
- D验证: confirmed / ver_d5728bfc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 28. hyp_path_ce9d293220e1

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_03.c:64
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存或页面文件，通过物理访问、权限提升或其他方式读取交换空间。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... if(5==5) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); } { ... wchar_t * domain = L"... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_03.c:64; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_03.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_03_case0 @ route
- 结论: 程序分配内存存储敏感密码，但未使用适当的内存锁定机制（如VirtualLock），可能导致密码被分页到磁盘，从而泄露敏感信息。
- D验证: confirmed / ver_1b931aff
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 29. hyp_path_9aa575a4d7d3

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_04.c:71
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够访问进程内存（如通过调试、崩溃转储或系统交换文件）
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_04.c:40; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_04.c:49; LogonUserA(username, domain, password, ...); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_04.c:64; free(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_04.c:71
- 结论: 敏感数据存储在未正确锁定的内存中，密码以明文形式存储在堆内存中，可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_b5932cba
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 30. hyp_path_806ca3df7e98

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_04.c:71
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够访问进程内存（如通过调试、崩溃转储或系统交换文件）
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... if(STATIC_CONST_TRUE) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); } { ... wchar_t ... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_04.c:71; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_04.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_04_case0 @ route
- 结论: 敏感数据存储在未正确锁定的内存中，密码以明文形式存储在堆内存中，可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_be533723
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 31. hyp_path_1c325dc4c14f

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_05.c:71
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够利用系统漏洞访问进程内存或核心转储文件，或通过交换文件获取敏感数据。
- 触发路径: if(staticTrue) { password = (char *)malloc(100*sizeof(char)); if (password == NULL) { ... } @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_05.c:38-42; /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ strcpy(password, "Password1234!"); } { @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_05.c:46-50; char * domain = "Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserA( username, domain, ... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_05.c:53-57; } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_05.c:71
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能导致敏感信息泄露。
- D验证: confirmed / ver_fbc30391
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 32. hyp_path_90b507125a6f

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_05.c:71
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够利用系统漏洞访问进程内存或核心转储文件，或通过交换文件获取敏感数据。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... if(staticTrue) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); } { ... wchar_t * domai... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_05.c:71; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_05.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_05_case0 @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能导致敏感信息泄露。
- D验证: confirmed / ver_4ac48209
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 33. hyp_path_a0d190173574

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_06.c:68
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者具有访问内存转储或页面文件的能力
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_06.c:37; /* NOTE: Do not lock the memory */ ... strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_06.c:43-44; if (LogonUserA( username, domain, password, ... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_06.c:61; free(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_06.c:68
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘或内存转储泄露
- D验证: confirmed / ver_fc7121f1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 34. hyp_path_b6bdfea06426

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_06.c:68
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者具有访问内存转储或页面文件的能力
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... if(STATIC_CONST_FIVE==5) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); } { ... wchar... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_06.c:68; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_06.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_06_case0 @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘或内存转储泄露
- D验证: confirmed / ver_f9a62b67
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 35. hyp_path_9aaa97a49c13

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_09.c:64
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 无外部输入控制，但密码本身为硬编码敏感数据，未锁定内存导致泄露风险。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_09.c:32; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_09.c:43; free(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_09.c:64
- 结论: 密码存储在未锁定的内存中，敏感数据可能被交换到磁盘，导致信息泄露。
- D验证: confirmed / ver_0bf8744d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 36. hyp_path_c293c89d6484

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_09.c:64
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 无外部输入控制，但密码本身为硬编码敏感数据，未锁定内存导致泄露风险。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... if(GLOBAL_CONST_TRUE) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); } { ... wchar_t ... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_09.c:64; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_09.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_09_case0 @ route
- 结论: 密码存储在未锁定的内存中，敏感数据可能被交换到磁盘，导致信息泄露。
- D验证: confirmed / ver_a0f9d8fa
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 37. hyp_path_a4c64f008812

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_07.c:70
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统的页面文件或内存转储，从而获取未锁定的敏感数据。
- 触发路径: password = (char *)malloc(100*sizeof(char)); if (password == NULL) { @ L39-41; strcpy(password, "Password1234!"); // 硬编码密码，未锁定内存 @ L48-49; if (LogonUserA(username, domain, password, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &pHandle) != 0) @ L52-63; free(password); // 释放前未锁定，敏感数据可被交换 @ L70
- 结论: 敏感数据（密码）存储在未正确锁定内存中，导致可能被交换到磁盘，从而泄露敏感信息。
- D验证: confirmed / ver_14ee6174
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 38. hyp_path_74e626fa3c12

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_07.c:70
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统的页面文件或内存转储，从而获取未锁定的敏感数据。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... if(staticFive==5) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); } { ... wchar_t * do... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_07.c:70; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_07.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_07_case0 @ route
- 结论: 敏感数据（密码）存储在未正确锁定内存中，导致可能被交换到磁盘，从而泄露敏感信息。
- D验证: confirmed / ver_fb5dc9e7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 39. hyp_path_bc6b90ed6053

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_13.c:64
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问目标系统的页面交换文件或核心转储文件，或能够通过其他方式获取未锁定的内存内容。
- 触发路径: if(GLOBAL_CONST_FIVE==5) { password = (char *)malloc(100*sizeof(char)); if (password == NULL) { @ L32-L34; /* NOTE: Do not lock the memory */ strcpy(password, "Password1234!"); @ L39-L41; if (LogonUserA( username, domain, password, ... ) != 0) { ... } @ L46-L57; free(password); @ L64
- 结论: 敏感数据（密码）存储在通过malloc分配的内存中，但未使用VirtualLock或类似机制锁定内存，导致密码可能被交换到磁盘，攻击者可通过获取交换文件或内存转储窃取敏感数据。
- D验证: confirmed / ver_1f84130d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 40. hyp_path_8224a796934d

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_13.c:64
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问目标系统的页面交换文件或核心转储文件，或能够通过其他方式获取未锁定的内存内容。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... if(GLOBAL_CONST_FIVE==5) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); } { ... wchar... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_13.c:64; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_13.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_13_case0 @ route
- 结论: 敏感数据（密码）存储在通过malloc分配的内存中，但未使用VirtualLock或类似机制锁定内存，导致密码可能被交换到磁盘，攻击者可通过获取交换文件或内存转储窃取敏感数据。
- D验证: confirmed / ver_2ba68704
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 41. hyp_path_29a8e891d228

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_10.c:64
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统的交换文件或内存转储以提取敏感数据。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_10.c:33; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_10.c:43; LogonUserA(username, domain, password, ...); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_10.c:57; free(password); // NOTE: Sensitive data possibly improperly locked @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_10.c:64
- 结论: 敏感数据（密码）存储在未锁定内存中，可能被交换到磁盘，导致敏感信息泄露。
- D验证: confirmed / ver_18b8b412
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 42. hyp_path_4719eecf41f4

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_10.c:64
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统的交换文件或内存转储以提取敏感数据。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... if(globalTrue) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); } { ... wchar_t * domai... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_10.c:64; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_10.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_10_case0 @ route
- 结论: 敏感数据（密码）存储在未锁定内存中，可能被交换到磁盘，导致敏感信息泄露。
- D验证: confirmed / ver_f983a5cb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 43. hyp_path_d23c8fbb2e3b

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_14.c:64
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 无外部攻击者输入控制，但密码硬编码在代码中，任何能够访问进程内存或页面文件的攻击者均可利用。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_14.c:33; /* NOTE: Do not lock the memory */ strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_14.c:39-40; if (LogonUserA( username, domain, password, ... )) @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_14.c:57; free(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_14.c:64
- 结论: 敏感数据（密码）存储在堆内存中，但未使用VirtualLock或类似机制锁定内存，导致密码可能被交换到磁盘或被其他进程读取，违反CWE591。
- D验证: confirmed / ver_49a74c19
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 44. hyp_path_a1d5477b4fee

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_14.c:64
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 无外部攻击者输入控制，但密码硬编码在代码中，任何能够访问进程内存或页面文件的攻击者均可利用。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... if(globalFive==5) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); } { ... wchar_t * do... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_14.c:64; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_14.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_14_case0 @ route
- 结论: 敏感数据（密码）存储在堆内存中，但未使用VirtualLock或类似机制锁定内存，导致密码可能被交换到磁盘或被其他进程读取，违反CWE591。
- D验证: confirmed / ver_da4cf3a6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 45. hyp_path_ccd17d02c323

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_15.c:70
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统交换文件或内存转储。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ 34; strcpy(password, "Password1234!"); @ 42; if (LogonUserA( username, domain, password, ...) != 0) @ 63; free(password); @ 70
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能导致信息泄露。
- D验证: confirmed / ver_9a971a45
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 46. hyp_path_e312a7517aa4

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_15.c:70
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统交换文件或内存转储。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... { case 6: password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); break; default: ... wchar_t * ... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_15.c:70; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_15.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_15_case0 @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能导致信息泄露。
- D验证: confirmed / ver_8adaf8dc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 47. hyp_path_9c7462ace646

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_16.c:65
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 无外部攻击者输入，漏洞由代码自身行为导致，但敏感数据可能被具有本地访问权限的攻击者利用（如读取交换文件）。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_16.c:33; /* NOTE: Do not lock the memory */ strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_16.c:39-43; LogonUserA(username, domain, password, ...); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_16.c:58; free(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_16.c:65
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘或被其他进程读取。
- D验证: confirmed / ver_37e6640c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 48. hyp_path_a00cc40edf0f

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_16.c:65
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 无外部攻击者输入，漏洞由代码自身行为导致，但敏感数据可能被具有本地访问权限的攻击者利用（如读取交换文件）。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... while(1) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); break; } ... wchar_t * domain... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_16.c:65; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_16.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_16_case0 @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘或被其他进程读取。
- D验证: confirmed / ver_877df1ab
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 49. hyp_path_506090f182fd

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_18.c:63
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者需要能够访问系统的交换文件或内存转储。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_18.c:33; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_18.c:42; if (LogonUserA(username, domain, password, ...)) @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_18.c:46-56; free(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_18.c:63
- 结论: 敏感数据（密码）存储在未锁定的内存中，可能导致内存交换到磁盘泄露敏感信息。
- D验证: confirmed / ver_759c317f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 50. hyp_path_3a65d89742d2

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_18.c:63
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者需要能够访问系统的交换文件或内存转储。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... goto source; source: password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); { HANDLE pHandle; .... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_18.c:63; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_18.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_18_case0 @ route
- 结论: 敏感数据（密码）存储在未锁定的内存中，可能导致内存交换到磁盘泄露敏感信息。
- D验证: confirmed / ver_fe51dc18
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 51. hyp_path_ea8e8a9c7002

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_33.cpp:35
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够访问系统页面文件或内存转储；密码为硬编码，无需攻击者输入控制。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_33.cpp:35; /* NOTE: Do not lock the memory */ strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_33.cpp:41-45; if (LogonUserA(username, domain, password, ...)) @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_33.cpp:60; free(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_33.cpp:67
- 结论: 敏感数据（密码）存储在未锁定内存中，可能被交换到磁盘导致泄露，且密码为硬编码。
- D验证: confirmed / ver_8b9141a1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 52. hyp_path_b247197172c1

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_33.cpp:35
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够访问系统页面文件或内存转储；密码为硬编码，无需攻击者输入控制。
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); { ... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_33.cpp:35; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_33.cpp::_ZN73CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_335case0Ev @ route
- 结论: 敏感数据（密码）存储在未锁定内存中，可能被交换到磁盘导致泄露，且密码为硬编码。
- D验证: confirmed / ver_2aa1717c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 53. hyp_path_52d765ac45ad

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_31.c:31
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者需要能够读取进程内存或获取内存转储。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_31.c:31; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_31.c:38; LogonUserA( username, domain, password, ... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_31.c:57; free(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_31.c:64
- 结论: 敏感数据（密码）存储在未锁定的内存中，可能导致敏感信息泄露。
- D验证: confirmed / ver_6fa59c38
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 54. hyp_path_56dbd733290f

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_31.c:31
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者需要能够读取进程内存或获取内存转储。
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); { ... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_31.c:31; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_31.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_31_case0 @ route
- 结论: 敏感数据（密码）存储在未锁定的内存中，可能导致敏感信息泄露。
- D验证: confirmed / ver_f97146a0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 55. hyp_path_524d645cb245

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_34.c:38
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问目标进程的内存空间（如通过调试、崩溃转储）或操作系统页面文件，且系统未对敏感内存区域进行锁定。
- 触发路径: password = (char *)malloc(100*sizeof(char)); if (password == NULL) { ... } @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_34.c:36-38; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_34.c:44-45; if (LogonUserA( username, domain, password, ... ) @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_34.c:55-64; free(password); /* NOTE: Sensitive data possibly improperly locked */ @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_34.c:69-71
- 结论: 敏感数据（密码）存储在堆内存中，但未使用VirtualLock等锁定内存，导致内存可能被交换到磁盘或由其他进程读取，违反CWE-591。
- D验证: confirmed / ver_3c8cf67a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 56. hyp_path_7c3726f2e85b

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_34.c:38
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问目标进程的内存空间（如通过调试、崩溃转储）或操作系统页面文件，且系统未对敏感内存区域进行锁定。
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); my... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_34.c:38; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_34.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_34_case0 @ route
- 结论: 敏感数据（密码）存储在堆内存中，但未使用VirtualLock等锁定内存，导致内存可能被交换到磁盘或由其他进程读取，违反CWE-591。
- D验证: confirmed / ver_097df136
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 57. hyp_path_31d71937e46c

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_32.c:35
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够以相同或更高权限访问进程内存（如本地用户或通过漏洞获取内存访问权限）。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_32.c:35; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_32.c:43; LogonUserA(username, domain, password, ...); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_32.c:62; free(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_32.c:69
- 结论: 敏感数据（密码）存储在未锁定的内存中，可能导致密码泄露。代码使用malloc分配内存存储密码，但未调用VirtualLock或类似函数锁定内存，使得密码可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_f030a063
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 58. hyp_path_87b7a272a163

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_32.c:35
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够以相同或更高权限访问进程内存（如本地用户或通过漏洞获取内存访问权限）。
- 触发路径: { wchar_t * password = *passwordPtr1; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( use... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_32.c:35; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_32.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_32_case0 @ route
- 结论: 敏感数据（密码）存储在未锁定的内存中，可能导致密码泄露。代码使用malloc分配内存存储密码，但未调用VirtualLock或类似函数锁定内存，使得密码可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_7f9a186c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 59. hyp_path_f015f9819c58

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_41.c:49
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够获取进程的内存转储（如通过崩溃转储、调试、或系统交换文件）
- 触发路径: password = (char *)malloc(100*sizeof(char)); /* NOTE: Do not lock the memory */ strcpy(password, "Password1234!"); @ L49-L56; CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_41_case0Sink(password); @ L65-L69; LogonUserA(username, domain, password, ...); /* NOTE: Sensitive data possibly improperly locked */ free(password); @ L36-L49
- 结论: 敏感数据（硬编码密码）存储在通过malloc分配的堆内存中，但未使用VirtualLock等机制锁定内存，可能导致敏感数据被交换到磁盘或在内存转储中泄露。
- D验证: confirmed / ver_1a6292fd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 60. hyp_path_8c7862dc2f69

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_41.c:49
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够获取进程的内存转储（如通过崩溃转储、调试、或系统交换文件）
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_41_case0Sin... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_41.c:49; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_41.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_41_case0 @ route
- 结论: 敏感数据（硬编码密码）存储在通过malloc分配的堆内存中，但未使用VirtualLock等机制锁定内存，可能导致敏感数据被交换到磁盘或在内存转储中泄露。
- D验证: confirmed / ver_65c71c07
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 61. hyp_path_32ca557c4be7

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_41.c:49
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够获取进程的内存转储（如通过崩溃转储、调试、或系统交换文件）
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... char * domain = "Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserA( username, domain, ... { printLine("User logged in successfully."); CloseHandle(pHandle); } else ... &pHandle) != 0) { printL... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_41.c:49; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_41.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_41_case0Sink @ route
- 结论: 敏感数据（硬编码密码）存储在通过malloc分配的堆内存中，但未使用VirtualLock等机制锁定内存，可能导致敏感数据被交换到磁盘或在内存转储中泄露。
- D验证: confirmed / ver_a2805fef
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 62. hyp_path_a425068dc373

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_41.c:49
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够获取进程的内存转储（如通过崩溃转储、调试、或系统交换文件）
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... { printLine("User logged in successfully."); CloseHandle(pHandle); } else ... &pHandle) != 0) { pr... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_41.c:49; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_41.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_41_case0Sink @ route
- 结论: 敏感数据（硬编码密码）存储在通过malloc分配的堆内存中，但未使用VirtualLock等机制锁定内存，可能导致敏感数据被交换到磁盘或在内存转储中泄露。
- D验证: confirmed / ver_611bef1d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 63. hyp_path_edc424171cef

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_21.c:74
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够获取进程内存转储或系统交换文件，或通过调试器附加到进程。
- 触发路径: password = (char *)malloc(100*sizeof(char)); ... strcpy(password, "Password1234!"); @ case0Source函数内; password = case0Source(password); @ main函数中调用case0Source后; if (LogonUserA( username, domain, password, ... @ LogonUserA调用，使用密码; free(password); @ 使用后释放，但未锁定或清零
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘或出现在核心转储中，导致敏感信息泄露。
- D验证: confirmed / ver_bfe50ff0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 64. hyp_path_9a03105fba28

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_21.c:74
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够获取进程内存转储或系统交换文件，或通过调试器附加到进程。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... password = L""; case0Static = 1; /* true */ password = case0Source(password); { HANDLE pHandle; ..... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_21.c:74; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_21.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_21_case0 @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘或出现在核心转储中，导致敏感信息泄露。
- D验证: confirmed / ver_73af2685
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 65. hyp_path_345ffd85a030

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_42.c:67
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存（如通过调试器或核心转储），或系统交换文件包含内存页。
- 触发路径: /* Initialize Data */ password = ""; password = case0Source(password); @ L43-46; if (LogonUserA( username, domain, password, ... ) != 0) @ L49-53; /* NOTE: Sensitive data possibly improperly locked */ free(password); @ L65-67
- 结论: 敏感数据（密码）存储在未锁定的内存中，可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_d0f19424
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 66. hyp_path_6c6d6bea99f7

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_42.c:67
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存（如通过调试器或核心转储），或系统交换文件包含内存页。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... /* Initialize Data */ password = L""; password = case0Source(password); { HANDLE pHandle; ... { pr... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_42.c:67; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_42.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_42_case0 @ route
- 结论: 敏感数据（密码）存储在未锁定的内存中，可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_0bbde755
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 67. hyp_path_37c384b80638

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_51a.c:34
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统交换文件或通过物理手段获取内存数据。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_51a.c:34; strcpy(password, "Password1234!"); @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_51a.c:41; CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_51b_case0Sink(password); @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_51a.c:43
- 结论: 敏感数据（密码）存储在未锁定的内存中，可能被换出到交换文件，导致信息泄露。
- D验证: confirmed / ver_565f8170
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 68. hyp_path_35b445f4325e

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_51a.c:34
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统交换文件或通过物理手段获取内存数据。
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_51b_case0Si... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_51a.c:34; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_51a.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_51_case0 @ route
- 结论: 敏感数据（密码）存储在未锁定的内存中，可能被换出到交换文件，导致信息泄露。
- D验证: confirmed / ver_6e778923
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 69. hyp_path_98bea42aabd7

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_52a.c:34
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够物理访问系统或获取核心转储/内存交换文件。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_52a.c:33; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_52a.c:42; CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_52b_case0Sink(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_52a.c:43
- 结论: 敏感数据（硬编码密码）存储在未使用VirtualLock锁定的内存中，可能导致密码被交换到磁盘或通过核心转储泄露。
- D验证: confirmed / ver_1c1a2271
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 70. hyp_path_2b53c8e31884

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_52a.c:34
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够物理访问系统或获取核心转储/内存交换文件。
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_52b_case0Si... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_52a.c:34; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_52a.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_52_case0 @ route
- 结论: 敏感数据（硬编码密码）存储在未使用VirtualLock锁定的内存中，可能导致密码被交换到磁盘或通过核心转储泄露。
- D验证: confirmed / ver_fa3db018
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 71. hyp_path_dd95e9acc24c

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53a.c:34
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够获取进程内存转储（如本地登录、调试器或系统漏洞）或访问系统交换文件
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53a.c:34; /* NOTE: Do not lock the memory */ strcpy(password, "Password1234!"); CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53b_case0Sink(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53a.c:40-44; CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53b_case0Sink(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53a.c:43
- 结论: 敏感数据（密码）存储在通过malloc分配的堆内存中，但没有使用VirtualLock等机制锁定内存，导致敏感数据可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_9a61e921
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 72. hyp_path_6b9bdadfe714

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53a.c:34
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够获取进程内存转储（如本地登录、调试器或系统漏洞）或访问系统交换文件
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53b_case0Si... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53a.c:34; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53a.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53_case0 @ route
- 结论: 敏感数据（密码）存储在通过malloc分配的堆内存中，但没有使用VirtualLock等机制锁定内存，导致敏感数据可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_fa7ceb2d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 73. hyp_path_f2f9c898f21e

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_64a.c:34
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够读取目标进程的内存（例如通过本地调试器、内存转储、或物理访问）
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_64a.c:34; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_64a.c:42; CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_64b_case0Sink(&password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_64a.c:43
- 结论: 敏感数据（密码）存储在未锁定内存中，可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_6b0b6b56
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 74. hyp_path_22bf6357570b

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_64a.c:34
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够读取目标进程的内存（例如通过本地调试器、内存转储、或物理访问）
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_64b_case0Si... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_64a.c:34; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_64a.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_64_case0 @ route
- 结论: 敏感数据（密码）存储在未锁定内存中，可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_2b22886c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 75. hyp_path_44a216c86b61

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_63a.c:34
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 代码执行到达malloc调用并成功分配内存，且程序继续执行到strcpy和sink调用。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_63a.c:34; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_63a.c:42; CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_63b_case0Sink(&password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_63a.c:43
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_526cd492
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 76. hyp_path_39121dd5811a

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_63a.c:34
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 代码执行到达malloc调用并成功分配内存，且程序继续执行到strcpy和sink调用。
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_63b_case0Si... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_63a.c:34; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_63a.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_63_case0 @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_f6ad1124
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 77. hyp_path_2a02600ebb3c

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_54a.c:34
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 无特殊前提；敏感数据（硬编码密码）直接存在于内存中。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_54a.c:34; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_54a.c:42; CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_54b_case0Sink(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_54a.c:43
- 结论: 敏感数据（硬编码密码）存储在未锁定的堆内存中，可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_7acf023c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 78. hyp_path_2fdf499c27b7

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54a.c:34
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 无特殊前提；敏感数据（硬编码密码）直接存在于内存中。
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54b_case0Si... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54a.c:34; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54a.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54_case0 @ route
- 结论: 敏感数据（硬编码密码）存储在未锁定的堆内存中，可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_36fd3ff4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 79. hyp_path_025157bd173a

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_43.cpp:69
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够读取目标进程的内存（例如通过调试器、核心转储或页面文件）
- 触发路径: static void case0Source(char * &password) { password = (char *)malloc(100*sizeof(char)); if (password == NULL) { printLine("Memory could not be allocated"); exit(1); } /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ strcpy(password, "Password1234!"); } @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_43.cpp:29-40; password = ""; case0Source(password); @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_43.cpp:45; if (LogonUserA( username, domain, password, ... )) @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_43.cpp:51-55; /* NOTE: Sensitive data possibly improperly locked */ free(password); @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_43.cpp:69
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能导致密码泄露到交换文件或核心转储中。
- D验证: confirmed / ver_6da8c574
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 80. hyp_path_1ac3fd7829f0

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_43.cpp:69
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够读取目标进程的内存（例如通过调试器、核心转储或页面文件）
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... /* Initialize Data */ password = L""; case0Source(password); { HANDLE pHandle; ... { printLine("Us... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_43.cpp:69; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_43.cpp::_ZN73CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_435case0Ev @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能导致密码泄露到交换文件或核心转储中。
- D验证: confirmed / ver_6f38806a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 81. hyp_path_5f235e3ea76d

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_22a.c:59
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者可能通过内存转储、交换文件或调试接口获取未锁定的密码数据。
- 触发路径: password = ""; CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_22_case0Global = 1; /* true */ password = CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_22_case0Source(password); @ 35-39; } /* NOTE: Sensitive data possibly improperly locked */ free(password); } @ 57-61
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能导致敏感信息泄露。密码在分配后未被锁定（如使用VirtualLock），随后被释放，数据可能残留在内存或交换文件中。
- D验证: confirmed / ver_01f0b841
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 82. hyp_path_31e99af887f5

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_22a.c:59
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者可能通过内存转储、交换文件或调试接口获取未锁定的密码数据。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... password = L""; CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_22_case0Glo... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_22a.c:59; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_22a.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_22_case0 @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能导致敏感信息泄露。密码在分配后未被锁定（如使用VirtualLock），随后被释放，数据可能残留在内存或交换文件中。
- D验证: confirmed / ver_0a454443
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 83. hyp_path_2e777148b876

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_82a.cpp:30
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够获取系统内存转储或访问交换文件（例如通过物理访问或权限提升）。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_82a.cpp:28-30; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_82a.cpp:38; CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_82_base* baseObject = new CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_82_case0; baseObject->action(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_82a.cpp:39-40
- 结论: 敏感数据（硬编码密码）存储在未正确锁定的内存中，可能导致敏感信息被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_5e4685f0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 84. hyp_path_9bb898e842f4

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_82a.cpp:30
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够获取系统内存转储或访问交换文件（例如通过物理访问或权限提升）。
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_82_base* baseObject = new CWE591_Sensitive_Dat... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_82a.cpp:30; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_82a.cpp::_ZN73CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_825case0Ev @ route
- 结论: 敏感数据（硬编码密码）存储在未正确锁定的内存中，可能导致敏感信息被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_0a9ccb9f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 85. hyp_path_9f63ecb1a1ad

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_61a.c:56
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者具有本地访问权限或能够运行内存分析工具
- 触发路径: password = ""; password = CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_61b_case0Source(password); @ juliet-api-misuse/.../CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_61a.c:33; if (LogonUserA( username, domain, password, ..., &pHandle) != 0) { printLine("User logged in successfully."); CloseHandle(pHandle); } @ juliet-api-misuse/.../CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_61a.c:41-49; free(password); @ juliet-api-misuse/.../CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_61a.c:56
- 结论: 敏感数据（密码）存储在未锁定内存中，释放后仍可能被其他进程读取，导致信息泄露。
- D验证: confirmed / ver_8952df68
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 86. hyp_path_b4747a19ddb3

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_61a.c:56
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者具有本地访问权限或能够运行内存分析工具
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... /* Initialize Data */ password = L""; password = CWE591_Sensitive_Data_Storage_in_Improperly_Locke... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_61a.c:56; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_61a.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_61_case0 @ route
- 结论: 敏感数据（密码）存储在未锁定内存中，释放后仍可能被其他进程读取，导致信息泄露。
- D验证: confirmed / ver_1af3835a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 87. hyp_path_593ab285a1c3

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_62a.cpp:59
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问进程内存（如通过调试器或内存转储），或在free后内存未重用前获取敏感数据。
- 触发路径: password = ""; @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_62a.cpp:35; case0Source(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_62a.cpp:36; if (LogonUserA( username, domain, password, ... ) @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_62a.cpp:42-43; free(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_62a.cpp:59
- 结论: 敏感数据（密码）存储在未锁定内存中，调用free释放后可能被其他进程读取，导致信息泄露。
- D验证: confirmed / ver_ebe83477
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 88. hyp_path_bb052e8a42c9

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_62a.cpp:59
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问进程内存（如通过调试器或内存转储），或在free后内存未重用前获取敏感数据。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... /* Initialize Data */ password = L""; case0Source(password); { HANDLE pHandle; ... { printLine("Us... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_62a.cpp:59; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_62a.cpp::_ZN73CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_625case0Ev @ route
- 结论: 敏感数据（密码）存储在未锁定内存中，调用free释放后可能被其他进程读取，导致信息泄露。
- D验证: confirmed / ver_8f8b75fa
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 89. hyp_path_4d8628aca1aa

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_81a.cpp:30
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存或交换文件（例如通过物理访问或特权提升）
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_81a.cpp:30; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_81a.cpp:38; /* NOTE: Do not lock the memory */ @ same file, comment
- 结论: 敏感数据（密码）存储在未正确锁定的堆内存中，可能导致内存交换到磁盘时泄露。同时使用了硬编码密码。
- D验证: confirmed / ver_d3eff754
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 90. hyp_path_13761fe9c6bb

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_81a.cpp:30
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存或交换文件（例如通过物理访问或特权提升）
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); const CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_81_ba... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_81a.cpp:30; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_81a.cpp::_ZN73CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_815case0Ev @ route
- 结论: 敏感数据（密码）存储在未正确锁定的堆内存中，可能导致内存交换到磁盘时泄露。同时使用了硬编码密码。
- D验证: confirmed / ver_d9a8773a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 91. hyp_path_5a86668fbecf

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_65a.c:36
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者具有访问系统内存交换文件或能够进行内存转储的能力。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ L36; strcpy(password, "Password1234!"); @ L44; 未调用任何内存锁定函数（如VirtualLock）。 @ L34-46
- 结论: 敏感数据（密码）存储在未锁定的内存中，可能导致密码被操作系统交换到磁盘，从而泄露给其他进程。
- D验证: confirmed / ver_94402fd0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 92. hyp_path_7ac02611a932

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_65a.c:36
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者具有访问系统内存交换文件或能够进行内存转储的能力。
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); /* use the function pointer */ funcPtr(password); ... if (password == NULL) { prin... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_65a.c:36; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_65a.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_65_case0 @ route
- 结论: 敏感数据（密码）存储在未锁定的内存中，可能导致密码被操作系统交换到磁盘，从而泄露给其他进程。
- D验证: confirmed / ver_50bbd92f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 93. hyp_path_6bdca5d38151

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_44.c:60
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存（如通过调试工具、核心转储、交换文件等）
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_44.c:59-60; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_44.c:68; /* NOTE: Do not lock the memory */ ... funcPtr(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_44.c:66-70
- 结论: 敏感数据（密码）存储在未锁定的内存中，攻击者可能通过内存转储或交换文件获取敏感信息。
- D验证: confirmed / ver_00c1ff9c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 94. hyp_path_dcca1c6490ae

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_44.c:60
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存（如通过调试工具、核心转储、交换文件等）
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); /* use the function pointer */ funcPtr(password); ... if (password == NULL) { prin... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_44.c:60; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_44.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_44_case0 @ route
- 结论: 敏感数据（密码）存储在未锁定的内存中，攻击者可能通过内存转储或交换文件获取敏感信息。
- D验证: confirmed / ver_eeef70ae
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 95. hyp_path_a57027930a34

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_22b.c:31
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问进程内存（例如通过调试、内存转储或交换文件）。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_22b.c:31; strcpy(password, "Password1234!"); @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_22b.c:39
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_ba0c3758
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 96. hyp_path_83e293cbb4a5

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_22b.c:31
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问进程内存（例如通过调试、内存转储或交换文件）。
- 触发路径: if(CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_22_case0Global) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); } return password; ... if (p... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_22b.c:31; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_22b.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_22_case0Source @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_91933f7a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 97. hyp_path_13832bd26f9e

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_21.c:33
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者需要能够访问系统内存或交换文件（本地或通过漏洞）
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_21.c:33; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_21.c:41; /* NOTE: Do not lock the memory */ @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_21.c:注释
- 结论: 敏感数据（硬编码密码）存储在未锁定内存中，可能导致敏感数据泄露到交换文件或其他进程内存中。
- D验证: confirmed / ver_cf92334c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 98. hyp_path_a6dce3f97b32

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_21.c:33
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者需要能够访问系统内存或交换文件（本地或通过漏洞）
- 触发路径: if(case0Static) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); } return password; ... { printLine("Memory could not be allocated"); exit(1); } /* NOTE: Do not lock t... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_21.c:33; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_21.c::case0Source @ route
- 结论: 敏感数据（硬编码密码）存储在未锁定内存中，可能导致敏感数据泄露到交换文件或其他进程内存中。
- D验证: confirmed / ver_8549c3a5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 99. hyp_path_f920331cc44f

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_61b.c:28
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够获取进程内存快照（例如通过核心转储、调试、交换空间等）
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ L28; strcpy(password, "Password1234!"); @ L36; return password; @ L37
- 结论: 敏感数据（硬编码密码）存储在未正确锁定的内存中，可能被攻击者读取。
- D验证: confirmed / ver_42f0e85b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 100. hyp_path_45219daa8627

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_61b.c:28
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够获取进程内存快照（例如通过核心转储、调试、交换空间等）
- 触发路径: wchar_t * CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_61b_case0Source(wchar_t * password) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); r... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_61b.c:28; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_61b.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_61b_case0Source @ route
- 结论: 敏感数据（硬编码密码）存储在未正确锁定的内存中，可能被攻击者读取。
- D验证: confirmed / ver_73ef49d4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 101. hyp_path_2a5d26cc573d

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_42.c:28
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够访问系统的交换文件或内存转储。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_42.c:28; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_42.c:36; return password; @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_42.c:37
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘导致泄露。
- D验证: confirmed / ver_735b46de
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 102. hyp_path_f364fea2bc85

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_42.c:28
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够访问系统的交换文件或内存转储。
- 触发路径: static wchar_t * case0Source(wchar_t * password) { password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); return password; } ... { printLine("Memory could not be allocated"); ... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_42.c:28; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_42.c::case0Source @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘导致泄露。
- D验证: confirmed / ver_6a6423f1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 103. hyp_path_febc1de4fd84

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_66a.c:35
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够读取进程内存或系统交换文件
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ 35; strcpy(password, "Password1234!"); @ 43; passwordArray[2] = password; @ 44; CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_66b_case0Sink(passwordArray); @ 46
- 结论: 密码存储在未锁定内存中，可能被交换到磁盘导致敏感数据泄露
- D验证: confirmed / ver_810d8c65
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 104. hyp_path_e20c5f0f0d61

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_66a.c:35
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够读取进程内存或系统交换文件
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* put password in array */ passwordArray[2] = password; CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_66b_case0Sink(passwordArray); } ... /* NOTE: Do not lock the memory */ /* I... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_66a.c:35; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_66a.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_66_case0 @ route
- 结论: 密码存储在未锁定内存中，可能被交换到磁盘导致敏感数据泄露
- D验证: confirmed / ver_a3164550
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 105. hyp_path_d52659f60dcb

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_45.c:62
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 无外部输入，但硬编码密码存储于未锁定内存，敏感数据生命周期内内存可被换出。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_45.c:62; strcpy(password, "Password1234!"); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_45.c:70; case0Sink(); // 内部使用LogonUserA处理密码 @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_45.c:72
- 结论: 敏感数据（密码）存储在未锁定的内存中，可能被换出到磁盘或通过其他方式泄露，违反了CWE-591。
- D验证: confirmed / ver_fdfbfe3c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 106. hyp_path_43b04db9578e

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_45.c:62
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 无外部输入，但硬编码密码存储于未锁定内存，敏感数据生命周期内内存可被换出。
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... /* NOTE: Do not lock the memory */ /* INCIDENTAL NOTE: CWE-259 Hardcoded Password */ wcscpy(password, L"Password1234!"); CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_45_case0Dat... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_45.c:62; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_45.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_45_case0 @ route
- 结论: 敏感数据（密码）存储在未锁定的内存中，可能被换出到磁盘或通过其他方式泄露，违反了CWE-591。
- D验证: confirmed / ver_1a3f1139
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 107. hyp_path_68f72ecc77a4

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_67a.c:40
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够获取系统内存转储或访问交换文件。
- 触发路径: password = (char *)malloc(100*sizeof(char)); @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_67a.c:40; strcpy(password, "Password1234!"); @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_67a.c:48; /* NOTE: Do not lock the memory */ @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_67a.c:46
- 结论: 在未锁定内存中存储敏感数据（密码），可能导致敏感数据被交换到磁盘或被其他进程读取。
- D验证: confirmed / ver_0d8788c2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 108. hyp_path_713040dd5312

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_67a.c:40
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够获取系统内存转储或访问交换文件。
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... wcscpy(password, L"Password1234!"); myStruct.structFirst = password; CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_67b_case0Sink(myStruct); } ... /* NOTE: Do not lock the memory ... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_67a.c:40; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_67a.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_67_case0 @ route
- 结论: 在未锁定内存中存储敏感数据（密码），可能导致敏感数据被交换到磁盘或被其他进程读取。
- D验证: confirmed / ver_c649b65a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 109. hyp_path_bb4a46a6e2fe

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_68a.c:37
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存转储或利用页面交换文件读取进程内存。
- 触发路径: password = (char *)malloc(100*sizeof(char)); if (password == NULL) { ... } @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_68a.c:35-37; strcpy(password, "Password1234!"); @ 同一文件:45; CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_68_case0Data = password; @ 同一文件:46; CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_68b_case0Sink(); (sink函数可能处理未锁定内存中的数据) @ 同一文件:47
- 结论: 敏感数据（密码）存储在未锁定内存中，可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_4f5ec47c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 110. hyp_path_a328a2e2e5a9

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_68a.c:37
- 漏洞类型: CWE-591, CWE-259
- CWE: CWE-591; CWE-259
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存转储或利用页面交换文件读取进程内存。
- 触发路径: /* Initialize Data */ password = L""; password = (wchar_t *)malloc(100*sizeof(wchar_t)); if (password == NULL) { ... wcscpy(password, L"Password1234!"); CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_68_case0Data = password; CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_68a.c:37; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_68a.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_68_case0 @ route
- 结论: 敏感数据（密码）存储在未锁定内存中，可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_51728939
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 111. hyp_path_f4b170be3f3b

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_72b.cpp:57
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问目标进程的内存（例如通过调试器、崩溃转储、页面交换文件或物理内存访问）。
- 触发路径: char * password = passwordVector[2]; { HANDLE pHandle; @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_72b.cpp:33-37; char * domain = "Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserA( username, domain, @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_72b.cpp:39-43; } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_72b.cpp:55-59
- 结论: 函数`CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_72b`中，敏感数据（密码）被存储在通过`malloc`或类似方式分配的内存中（`password`指针），并在使用后通过`free(password)`释放，但没有调用任何内存锁定函数（如`VirtualLock`、`CryptProtectMemory`等）来防止敏感数据被交换到磁盘或转储。攻击者若能够读取进程内存（例如通过调试器、崩溃转储或页面交换文件），可能获取密码明文。
- D验证: confirmed / ver_cab58e13
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 112. hyp_path_fdaf6c8303b3

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_72b.cpp:57
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问目标进程的内存（例如通过调试器、崩溃转储、页面交换文件或物理内存访问）。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... { /* copy password out of passwordVector */ wchar_t * password = passwordVector[2]; { HANDLE pHand... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_72b.cpp:57; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_72b.cpp::_ZN73CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_729case0SinkESt6vectorIPwSaIS1_EE @ route
- 结论: 函数`CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_72b`中，敏感数据（密码）被存储在通过`malloc`或类似方式分配的内存中（`password`指针），并在使用后通过`free(password)`释放，但没有调用任何内存锁定函数（如`VirtualLock`、`CryptProtectMemory`等）来防止敏感数据被交换到磁盘或转储。攻击者若能够读取进程内存（例如通过调试器、崩溃转储或页面交换文件），可能获取密码明文。
- D验证: confirmed / ver_0fa85f64
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 113. hyp_path_aee77a8a19ac

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_73b.cpp:57
- 漏洞类型: CWE-591, CWE-316
- CWE: CWE-591; CWE-316
- 风险等级: P0
- 触发条件: 攻击者需要能够获取系统核心转储或交换文件来读取密码数据
- 触发路径: { /* copy password out of passwordList */ char * password = passwordList.back(); { HANDLE pHandle; @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_73b.cpp:33-37; char * domain = "Domain"; /* Use the password in LogonUser() to establish that it is 'sensitive' */ if (LogonUserA( username, domain, @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_73b.cpp:39-43; } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_73b.cpp:55-59
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘或核心转储中，导致信息泄露。同时，使用free释放内存后未清除密码内容，存在敏感数据残留风险。
- D验证: confirmed / ver_6545dcce
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 114. hyp_path_282aec8da547

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_73b.cpp:57
- 漏洞类型: CWE-591, CWE-316
- CWE: CWE-591; CWE-316
- 风险等级: P0
- 触发条件: 攻击者需要能够获取系统核心转储或交换文件来读取密码数据
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... { /* copy password out of passwordList */ wchar_t * password = passwordList.back(); { HANDLE pHandle; ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, doma... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_73b.cpp:57; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_73b.cpp::_ZN73CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_739case0SinkENSt7__cxx114listIPwSaIS2_EEE @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘或核心转储中，导致信息泄露。同时，使用free释放内存后未清除密码内容，存在敏感数据残留风险。
- D验证: confirmed / ver_5c5c792d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 115. hyp_path_ea51f73d045c

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_74b.cpp:57
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够获取系统的交换文件或进程转储文件，并从中提取未锁定的敏感数据。
- 触发路径: char * password = passwordMap[2]; @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_74b.cpp:35; if (LogonUserA( username, domain, password, ... ) @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_74b.cpp:43; free(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_74b.cpp:57
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，并且在使用后未清除就直接释放，导致敏感信息可能被交换到磁盘，攻击者可通过访问交换文件或内存转储获取密码。
- D验证: confirmed / ver_a8d1b16e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 116. hyp_path_ef99089debf5

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_74b.cpp:57
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够获取系统的交换文件或进程转储文件，并从中提取未锁定的敏感数据。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... { /* copy password out of passwordMap */ wchar_t * password = passwordMap[2]; { HANDLE pHandle; ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ..... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_74b.cpp:57; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_74b.cpp::_ZN73CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_749case0SinkESt3mapIiPwSt4lessIiESaISt4pairIKiS1_EEE @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，并且在使用后未清除就直接释放，导致敏感信息可能被交换到磁盘，攻击者可通过访问交换文件或内存转储获取密码。
- D验证: confirmed / ver_4e45f3b9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 117. hyp_path_2361891a6c02

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_83_case0.cpp:62
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统页面文件或内存转储
- 触发路径: char * domain = "Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserA( username, domain, @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_83_case0.cpp:44-48; } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_83_case0.cpp:60-64
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能导致敏感信息泄露。代码中密码被用于LogonUserA后直接free，未使用VirtualLock锁定内存，且未在释放前清零，符合CWE-591特征。
- D验证: confirmed / ver_41627966
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 118. hyp_path_96df0d2de4bf

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_83_case0.cpp:62
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统页面文件或内存转储
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... { printLine("User logged in successfully."); CloseHandle(pHandle); } else ... else { printLine("Un... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_83_case0.cpp:62; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_83_case0.cpp::_ZN73CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_8379CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_83_case0D2Ev @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能导致敏感信息泄露。代码中密码被用于LogonUserA后直接free，未使用VirtualLock锁定内存，且未在释放前清零，符合CWE-591特征。
- D验证: confirmed / ver_eea186c7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 119. hyp_path_ad699666f46a

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_84_case0.cpp:62
- 漏洞类型: memory_leak
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够获取进程内存转储或利用内存泄漏漏洞读取未释放的内存区域。
- 触发路径: if (LogonUserA( username, domain, password, ... )){ ... } @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_84_case0.cpp:55-57; free(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_84_case0.cpp:62
- 结论: 在释放密码缓冲区之前未清除敏感数据，且密码内存未锁定（如未调用VirtualLock），可能导致敏感信息残留在内存中，可以被其他进程或内存转储获取。
- D验证: confirmed / ver_a26fb75b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 120. hyp_path_c7fb2b779c13

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_84_case0.cpp:62
- 漏洞类型: memory_leak
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够获取进程内存转储或利用内存泄漏漏洞读取未释放的内存区域。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... { printLine("User logged in successfully."); CloseHandle(pHandle); } else ... else { printLine("Un... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_84_case0.cpp:62; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_84_case0.cpp::_ZN73CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_8479CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_84_case0D2Ev @ route
- 结论: 在释放密码缓冲区之前未清除敏感数据，且密码内存未锁定（如未调用VirtualLock），可能导致敏感信息残留在内存中，可以被其他进程或内存转储获取。
- D验证: confirmed / ver_8ff9a395
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 121. hyp_path_a57931db0702

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_44.c:49
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者可能通过获取内存转储或页面交换文件读取敏感密码
- 触发路径: char * password = malloc(100*sizeof(char)); @ L31; password = strcpy(password, data); @ L32; if (LogonUserA(username, domain, password, ...)) @ L36-L38; free(password); /* NOTE: Sensitive data possibly improperly locked */ @ L49
- 结论: 密码数据存储在未锁定内存中，可能被交换到磁盘导致敏感信息泄露
- D验证: confirmed / ver_8630852d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 122. hyp_path_85720c77e22e

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_44.c:49
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者可能通过获取内存转储或页面交换文件读取敏感密码
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... { printLine("User logged in successfully."); CloseHandle(pHandle); } else ... else { printLine("Un... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_44.c:49; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_44.c::case0Sink @ route
- 结论: 密码数据存储在未锁定内存中，可能被交换到磁盘导致敏感信息泄露
- D验证: confirmed / ver_8f8448a0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 123. hyp_path_de8807ea3980

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_45.c:53
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够获取进程内存转储（如通过本地访问、崩溃转储或调试）
- 触发路径: free(password); @ L53; LogonUserA(username, domain, password, ...); @ L46附近
- 结论: 敏感数据（密码）存储在未锁定内存中，free释放前未清零，可能被攻击者通过内存转储获取。
- D验证: confirmed / ver_c21bf178
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 124. hyp_path_56d37cc60af0

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_45.c:53
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够获取进程内存转储（如通过本地访问、崩溃转储或调试）
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... { printLine("User logged in successfully."); CloseHandle(pHandle); } else ... else { printLine("Un... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_45.c:53; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_45.c::case0Sink @ route
- 结论: 敏感数据（密码）存储在未锁定内存中，free释放前未清零，可能被攻击者通过内存转储获取。
- D验证: confirmed / ver_5749478b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 125. hyp_path_8f36c04721fa

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_51b.c:51
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 程序使用 LogonUserA 函数，并将密码作为参数传入；密码内存未通过 VirtualLock 或类似机制锁定，也未在释放前清零。
- 触发路径: if (LogonUserA(username, domain, password, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &pHandle) != 0) @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_51b.c:44; free(password); @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_51b.c:51
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，释放前未清零，可能导致敏感数据泄露。
- D验证: confirmed / ver_96be0a00
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 126. hyp_path_d07198dc2eb3

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_51b.c:51
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 程序使用 LogonUserA 函数，并将密码作为参数传入；密码内存未通过 VirtualLock 或类似机制锁定，也未在释放前清零。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... { printLine("User logged in successfully."); CloseHandle(pHandle); } else ... &pHandle) != 0) { pr... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_51b.c:51; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_51b.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_51b_case0Sink @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，释放前未清零，可能导致敏感数据泄露。
- D验证: confirmed / ver_921713ea
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 127. hyp_path_eb4378979539

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_52c.c:51
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存（如通过内存转储、调试工具或物理访问）。
- 触发路径: free(password); @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_52c.c:51
- 结论: 敏感数据（如密码）在释放前未正确锁定内存，可能导致敏感数据残留在内存中，被攻击者获取。
- D验证: confirmed / ver_f9df5ac8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 128. hyp_path_0a75c5af4f63

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_52c.c:51
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存（如通过内存转储、调试工具或物理访问）。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... { printLine("User logged in successfully."); CloseHandle(pHandle); } else ... else { printLine("Un... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_52c.c:51; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_52c.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_52c_case0Sink @ route
- 结论: 敏感数据（如密码）在释放前未正确锁定内存，可能导致敏感数据残留在内存中，被攻击者获取。
- D验证: confirmed / ver_d131960f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 129. hyp_path_e9f213c8e572

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53d.c:51
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够读取进程内存（如通过崩溃转储或调试）
- 触发路径: free(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53d.c:51
- 结论: 敏感数据（密码）存储在堆内存中，未使用VirtualLock锁定，释放后未被清零，可能导致敏感数据残留。
- D验证: confirmed / ver_58e19c11
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 130. hyp_path_312fb9636d67

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53d.c:51
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够读取进程内存（如通过崩溃转储或调试）
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... { printLine("User logged in successfully."); CloseHandle(pHandle); } else ... &pHandle) != 0) { pr... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53d.c:51; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53d.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53d_case0Sink @ route
- 结论: 敏感数据（密码）存储在堆内存中，未使用VirtualLock锁定，释放后未被清零，可能导致敏感数据残留。
- D验证: confirmed / ver_d5ab17dd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 131. hyp_path_afd0c62f9584

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_54e.c:51
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问进程内存（例如通过调试、崩溃转储或内存扫描）
- 触发路径: free(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_54e.c:51
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，调用free后数据可能残留在内存中，导致敏感信息泄露。
- D验证: confirmed / ver_f7e41e26
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 132. hyp_path_2d91df5e7c23

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54e.c:51
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问进程内存（例如通过调试、崩溃转储或内存扫描）
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... { printLine("User logged in successfully."); CloseHandle(pHandle); } else ... &pHandle) != 0) { pr... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54e.c:51; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54e.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54e_case0Sink @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，调用free后数据可能残留在内存中，导致敏感信息泄露。
- D验证: confirmed / ver_3cbb3def
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 133. hyp_path_0551d1cd26ce

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_63b.c:50
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统交换文件或内存转储（如通过物理访问、崩溃转储或特权进程）。
- 触发路径: password = (char*)malloc(sizeof(char)*PASSWORD_LEN); // 假设分配在堆内存 @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_63b.c（假设分配行）; LogonUserA(username, domain, password, ...); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_63b.c:43; free(password); /* NOTE: Sensitive data possibly improperly locked */ @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_63b.c:50
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘，导致敏感信息泄露。
- D验证: confirmed / ver_46f2934e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 134. hyp_path_f3f87bdb29bb

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_63b.c:50
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统交换文件或内存转储（如通过物理访问、崩溃转储或特权进程）。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... { printLine("User logged in successfully."); CloseHandle(pHandle); } else ... else { printLine("Un... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_63b.c:50; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_63b.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_63b_case0Sink @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘，导致敏感信息泄露。
- D验证: confirmed / ver_040c20db
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 135. hyp_path_edabc67472a6

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_65b.c:49
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够读取目标进程的内存（例如通过崩溃转储、内存分析、交换文件或调试接口）。
- 触发路径: char * password = ...; /* 假设从外部获取密码 */ @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_65b.c:31-35; LogonUserA(username, domain, password, ...) @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_65b.c:42; free(password); /* NOTE: Sensitive data possibly improperly locked */ @ CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_65b.c:49
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘或被进程转储，导致信息泄露。
- D验证: confirmed / ver_9524c3dd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 136. hyp_path_28c2a480a441

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_65b.c:49
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够读取目标进程的内存（例如通过崩溃转储、内存分析、交换文件或调试接口）。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... { printLine("User logged in successfully."); CloseHandle(pHandle); } else ... else { printLine("Un... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_65b.c:49; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_65b.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_65b_case0Sink @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘或被进程转储，导致信息泄露。
- D验证: confirmed / ver_1b6bec0c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 137. hyp_path_21a5c1b18c75

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_64b.c:53
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存转储或通过其他方式读取未锁定内存中的敏感数据。
- 触发路径: char * domain = "Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserA( username, domain, @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_64b.c:35-39; &pHandle) != 0) { printLine("User logged in successfully."); CloseHandle(pHandle); } @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_64b.c:43-47; } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_64b.c:51-55
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能导致数据被交换到磁盘或被攻击者读取。密码通过malloc分配，但未使用VirtualLock锁定，也未在释放前擦除。
- D验证: confirmed / ver_262d1d0c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 138. hyp_path_77f2ee4823a9

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_64b.c:53
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存转储或通过其他方式读取未锁定内存中的敏感数据。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... { printLine("User logged in successfully."); CloseHandle(pHandle); } else ... &pHandle) != 0) { pr... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_64b.c:53; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_64b.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_64b_case0Sink @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能导致数据被交换到磁盘或被攻击者读取。密码通过malloc分配，但未使用VirtualLock锁定，也未在释放前擦除。
- D验证: confirmed / ver_2749f365
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 139. hyp_path_4edc2e9f2814

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_66b.c:51
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够获得对系统内存的访问权限（如通过调试、崩溃转储、页面交换等）。
- 触发路径: if (LogonUserA( username, domain, password, ... ) @ 第44行; free(password); @ 第51行
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能导致敏感信息泄露。
- D验证: confirmed / ver_a5d31e1b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 140. hyp_path_1195580944ca

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_66b.c:51
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够获得对系统内存的访问权限（如通过调试、崩溃转储、页面交换等）。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... { printLine("User logged in successfully."); CloseHandle(pHandle); } else ... &pHandle) != 0) { pr... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_66b.c:51; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_66b.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_66b_case0Sink @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能导致敏感信息泄露。
- D验证: confirmed / ver_91509c1a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 141. hyp_path_c43f486c043c

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_67b.c:55
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够获取进程的内存转储（如通过调试、崩溃转储或交换文件）。; 密码变量password在堆上分配（未显式锁定），且释放前未清零。
- 触发路径: char * domain = "Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserA( username, domain, @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_67b.c:37-41; } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_67b.c:55
- 结论: 敏感数据（密码）存储在未正确锁定的堆内存中，未调用VirtualLock等API锁定内存页，且在释放前未清零，攻击者通过内存转储可获取密码。
- D验证: confirmed / ver_89e121a3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 142. hyp_path_4fc2b8553b91

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_67b.c:55
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够获取进程的内存转储（如通过调试、崩溃转储或交换文件）。; 密码变量password在堆上分配（未显式锁定），且释放前未清零。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... { printLine("User logged in successfully."); CloseHandle(pHandle); } else ... else { printLine("Un... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_67b.c:55; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_67b.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_67b_case0Sink @ route
- 结论: 敏感数据（密码）存储在未正确锁定的堆内存中，未调用VirtualLock等API锁定内存页，且在释放前未清零，攻击者通过内存转储可获取密码。
- D验证: confirmed / ver_74900eb3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 143. hyp_path_4b72928b00b0

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_68b.c:55
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存转储（如核心转储文件）或交换文件（如pagefile.sys）。; 或攻击者能够通过其他方式读取进程内存空间（如调试权限）。
- 触发路径: char * password = (char *)malloc(100*sizeof(char)); /* 假设密码通过某种方式填充 */ @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_68b.c; char * domain = "Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserA( username, domain, ... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_68b.c:37-41; } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_68b.c:55
- 结论: 密码以明文形式存储在未锁定的堆内存中，未使用如VirtualLock或CryptProtectMemory等机制锁定，可能导致敏感数据被交换到磁盘或暴露给具有系统内存访问权限的攻击者。
- D验证: confirmed / ver_2dbcf4f9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 144. hyp_path_d96f9b62a3a0

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_68b.c:55
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存转储（如核心转储文件）或交换文件（如pagefile.sys）。; 或攻击者能够通过其他方式读取进程内存空间（如调试权限）。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... { printLine("User logged in successfully."); CloseHandle(pHandle); } else ... &pHandle) != 0) { pr... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_68b.c:55; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_68b.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_68b_case0Sink @ route
- 结论: 密码以明文形式存储在未锁定的堆内存中，未使用如VirtualLock或CryptProtectMemory等机制锁定，可能导致敏感数据被交换到磁盘或暴露给具有系统内存访问权限的攻击者。
- D验证: confirmed / ver_bfd51252
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 145. hyp_path_927bf9c6ce92

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_81_case0.cpp:49
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存或交换文件，或能够利用内存转储等手段读取敏感数据。
- 触发路径: free(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_81_case0.cpp:49
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，调用free释放前未使用VirtualLock等机制防止交换到磁盘，可能导致敏感信息泄露。
- D验证: confirmed / ver_62288d46
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 146. hyp_path_13b4de4dc26b

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_81_case0.cpp:49
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够访问系统内存或交换文件，或能够利用内存转储等手段读取敏感数据。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... { printLine("User logged in successfully."); CloseHandle(pHandle); } else ... else { printLine("Un... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_81_case0.cpp:49; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_81_case0.cpp::_ZNK73CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_8179CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_81_case06actionEPw @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，调用free释放前未使用VirtualLock等机制防止交换到磁盘，可能导致敏感信息泄露。
- D验证: confirmed / ver_d878c901
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 147. hyp_path_74813fadca6d

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_82_case0.cpp:49
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够读取目标进程的内存（例如通过调试、崩溃转储或交换文件分析）。
- 触发路径: char * domain = "Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserA( username, domain, @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_82_case0.cpp:31-35; { printLine("User logged in successfully."); CloseHandle(pHandle); } else @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_82_case0.cpp:42; } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_82_case0.cpp:49
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_9f64e024
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 148. hyp_path_0336123b05d9

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_82_case0.cpp:49
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够读取目标进程的内存（例如通过调试、崩溃转储或交换文件分析）。
- 触发路径: } /* NOTE: Sensitive data possibly improperly locked */ free(password); } } ... wchar_t * domain = L"Domain"; /* Use the password in LogonUser() to establish that it is "sensitive" */ if (LogonUserW( username, domain, ... { printLine("User logged in successfully."); CloseHandle(pHandle); } else ... &pHandle) != 0) { pr... @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_82_case0.cpp:49; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_82_case0.cpp::_ZN73CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_8279CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_82_case06actionEPw @ route
- 结论: 敏感数据（密码）存储在未正确锁定的内存中，可能被交换到磁盘或通过内存转储泄露。
- D验证: confirmed / ver_bf16208d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 149. hyp_path_aa58f0c847bd

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53b.c:33
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够控制password字符串的内容或指针值。; 下游函数CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53c_case0Sink使用malloc分配内存且未调用VirtualLock。
- 触发路径: CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53c_case0Sink(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53b.c:33
- 结论: 存在CWE-591漏洞：密码（敏感数据）存储在未正确锁定的内存中，可能被交换到磁盘或泄露。但当前代码片段的A阶段证据仅展示函数转发，未直接闭合从攻击者可控源到实际未锁定内存存储的路径。
- D验证: confirmed / ver_07f8d2fc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 150. hyp_path_69810170a511

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53b.c:33
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够控制password字符串的内容或指针值。; 下游函数CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53c_case0Sink使用malloc分配内存且未调用VirtualLock。
- 触发路径: void CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53b_case0Sink(wchar_t * password) { CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53c_case0Sink(password); } @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53b.c:33; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53b.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53b_case0Sink @ route
- 结论: 存在CWE-591漏洞：密码（敏感数据）存储在未正确锁定的内存中，可能被交换到磁盘或泄露。但当前代码片段的A阶段证据仅展示函数转发，未直接闭合从攻击者可控源到实际未锁定内存存储的路径。
- D验证: confirmed / ver_41878b45
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 151. hyp_path_8b4df515b551

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53c.c:33
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够获取进程内存转储、交换文件或核心转储，从而读取密码数据。
- 触发路径: void CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53c_case0Sink(char * password) { CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53d_case0Sink(password); } @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53c.c:31-33
- 结论: 密码数据可能存储在未正确锁定的内存中，存在敏感数据泄露风险。
- D验证: confirmed / ver_0506fe01
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 152. hyp_path_9e7cf8c4e36a

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53c.c:33
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够获取进程内存转储、交换文件或核心转储，从而读取密码数据。
- 触发路径: void CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53c_case0Sink(wchar_t * password) { CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53d_case0Sink(password); } @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53c.c:33; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53c.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53c_case0Sink @ route
- 结论: 密码数据可能存储在未正确锁定的内存中，存在敏感数据泄露风险。
- D验证: confirmed / ver_a06e0352
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 153. hyp_path_f9a1e280b648

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_54b.c:33
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够读取进程内存（例如通过交换文件、核心转储或附加调试器）
- 触发路径: void CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_54b_case0Sink(char * password) { CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_54c_case0Sink(password); } @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_54b.c:31-35
- 结论: 密码存储在未正确锁定的内存中，可能导致敏感数据泄露。
- D验证: confirmed / ver_dd8ee66a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 154. hyp_path_c1ba09d42660

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54b.c:33
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: 攻击者能够读取进程内存（例如通过交换文件、核心转储或附加调试器）
- 触发路径: void CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54b_case0Sink(wchar_t * password) { CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54c_case0Sink(password); } @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54b.c:33; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54b.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54b_case0Sink @ route
- 结论: 密码存储在未正确锁定的内存中，可能导致敏感数据泄露。
- D验证: confirmed / ver_b037c37c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 155. hyp_path_cf07e093df4b

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_54c.c:33
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: Attacker can control the 'password' argument passed to the sink function.
- 触发路径: CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_54d_case0Sink(password); @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_54c.c:33
- 结论: Potential CWE-591 vulnerability: sensitive data may be stored in improperly locked memory via sink function call chain, but evidence is incomplete.
- D验证: confirmed / ver_dfb913b1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 156. hyp_path_91d5ddcdc620

- 漏洞位置: juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54c.c:33
- 漏洞类型: CWE-591
- CWE: CWE-591
- 风险等级: P0
- 触发条件: Attacker can control the 'password' argument passed to the sink function.
- 触发路径: void CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54c_case0Sink(wchar_t * password) { CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54d_case0Sink(password); } @ juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54c.c:33; juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54c.c::CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54c_case0Sink @ route
- 结论: Potential CWE-591 vulnerability: sensitive data may be stored in improperly locked memory via sink function call chain, but evidence is incomplete.
- D验证: confirmed / ver_e5644237
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

## Unconfirmed / Failed Verification

These records are not reported as confirmed vulnerabilities. See `verification.failed.jsonl` for full failure details.

- hyp_path_72acb02e61e5 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_62b.cpp:47 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d8a2c7ec902c | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_62b.cpp:47 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_10f0aa39cc1b | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_84_case1V1.cpp:28 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8670c2e83243 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_84_case1V1.cpp:28 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aa909cbe9321 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_72a.cpp:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e48a41c89e2f | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_72a.cpp:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c0e165d56032 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_73a.cpp:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1b837d57f8c7 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_73a.cpp:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_46960f8a9bc4 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_12.c:105 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c062223a1902 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_12.c:105 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_98b5ca3d04a6 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_17.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_30e7d1cbb2ef | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_17.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_875990186c6f | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_08.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dae2cac25eee | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_08.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2e55abf60202 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_11.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c2c8f326cf0d | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_11.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c0ee748a7cf8 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_07.c:98 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fff9b5a650f8 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_07.c:98 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_da1f21e98983 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_05.c:99 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_63a052028370 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_05.c:99 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_93e3a6d66496 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_09.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cee3f7377733 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_09.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d467171c10d3 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_08.c:154 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_46276126609c | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_08.c:154 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4a360f80fa73 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_11.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bed1be342758 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_11.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7ffd390db1c1 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_13.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d4874c711966 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_13.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ab643aa8ffeb | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_14.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ad891fc07d70 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_14.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_894f14f4828b | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_10.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a9bf3ddf6f24 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_10.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_94971a2f2bb9 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_01.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_29e23538572e | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_01.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_617ecc910fb4 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_02.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_578589fb5ff9 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_02.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_154532b39c1e | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_02.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_722a6079d282 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_02.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7019306fc2bb | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_03.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_015ce71c2e40 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_03.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_01439ad50396 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_04.c:99 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_224757078e00 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_04.c:99 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3afd55056d37 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_04.c:147 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3a1a1e0499db | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_04.c:147 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9b3ab0c07510 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_05.c:147 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e8d5923bf25d | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_05.c:147 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_63eae0b97cdb | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_06.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c7c921881ea8 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_06.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5144bbb12fdc | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_06.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dcedda3b0ea7 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_06.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8f28e7a8b07a | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_07.c:146 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_71f76e04ef46 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_07.c:146 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_87243153fd74 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_09.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_edf7a87d0233 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_09.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_03506e45a3ff | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_03.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ff81e74e05f8 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_03.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_db4952b97dee | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_13.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_11de9376b4e8 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_13.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_abd759aa424e | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_10.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ab11313176c8 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_10.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5e82d3dbfe9f | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_14.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2840d14eadf1 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_14.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b655dfe7b257 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_15.c:148 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ab6611aa896c | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_15.c:148 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_845e6a2e2c32 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_15.c:98 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5edb7e277219 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_15.c:98 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ba99aa2f80d9 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_31.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d26430fcfcb7 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_31.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_55f2333b16f7 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_18.c:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_522fb3fde22e | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_18.c:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_02f4e43e9894 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_16.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_358e3d191182 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_16.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_92543d5ed422 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_33.cpp:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8b83969a9138 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_33.cpp:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8ef4104be5da | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_34.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8f3bf9582739 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_34.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_882e40aef825 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_32.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_19bfbddc2a5c | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_32.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_25012ef9b1ee | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_82a.cpp:61 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b0ef185e73af | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_82a.cpp:61 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b58a9c40e821 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_41.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_130bc18f6c57 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_41.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a04648ff43b9 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_41.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f27bee2e62ea | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_41.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8f413bb438ee | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_51a.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3ad5670e2f24 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_51a.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e167c4eb9fc1 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_54a.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b467f1a96da0 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54a.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_af4c2318fc23 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_52a.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1f58f93ae9c6 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_52a.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cd53dd3dd12e | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_63a.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_83b96c79e6e7 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_63a.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_61a124f4f4f5 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53a.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_51b0bae28f0c | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53a.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5a80eb133147 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_22b.c:62 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_edb8dd701f44 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_22b.c:62 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e34a28cd6c8b | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_64a.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d6f798fe08dc | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_64a.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b6953ef485ef | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_81a.cpp:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_adbad1d85b06 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_81a.cpp:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_655b58cf681a | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_67a.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2796cee3a338 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_67a.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f32d9a27d098 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_45.c:113 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7ba45784e17e | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_45.c:113 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cded29206a97 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_66a.c:62 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d01431e8621b | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_66a.c:62 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4f90325a9292 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_21.c:158 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_011d06047e6e | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_21.c:158 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_24277b8423b1 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_22a.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_08ef7ff920fe | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_22a.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f8603bf26e2a | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_21.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b7daecfc6036 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_21.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_983bf3da17b1 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_22a.c:137 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e9692c7a6fba | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_22a.c:137 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d4bed0f4ab7f | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_42.c:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_23fe2d12b322 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_42.c:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_44edc9f4f898 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_61a.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b37342301508 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_61a.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_038503b35722 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_62a.cpp:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_63190cde89bc | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_62a.cpp:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4624b1be117a | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_43.cpp:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5cd3a4a02277 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_43.cpp:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ee9009ec5582 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_44.c:118 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a05601561b03 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_44.c:118 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7f5663710218 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_42.c:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3c38a9c21a4d | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_42.c:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c84118939d9f | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_65a.c:69 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bc30e2f45177 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_65a.c:69 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e153704073e6 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_22b.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ae4043a49311 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_22b.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c730a8889dd7 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_61b.c:47 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a2dcf7d143a1 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_61b.c:47 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6980b4ec1811 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_72b.cpp:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_834f1b86bf6f | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_72b.cpp:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_03c1bc8139e3 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_73b.cpp:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c1c46aee81f8 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_73b.cpp:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8de2d0fa0e40 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_74b.cpp:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8b2a6215739e | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_74b.cpp:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b69502bd1588 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_83_case1V1.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c892f2ccbf92 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_83_case1V1.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_572e09f7be3e | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_84_case1V1.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d68b96fb7482 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_84_case1V1.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c4a7fe90f398 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_44.c:101 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f777620d9aaa | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_44.c:101 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f21d433f1d8b | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_45.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e797de37c63e | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_45.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c527aabf6e7a | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_51b.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9a7c9028daef | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_51b.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4baf208066d4 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_52c.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c28bd768edb1 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_52c.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8372c8557442 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53d.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ba60fd7af069 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53d.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6f1bd45ce0e6 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_54e.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7c488698b557 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54e.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_27f03df5c0f6 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_63b.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_da360d5c5824 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_63b.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_825f7f930dcc | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_64b.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_611e927495f2 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_64b.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f172a03c6097 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_65b.c:81 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cc80067c74b5 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_65b.c:81 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7c6cba544cdc | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_66b.c:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7eca2581f0b1 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_66b.c:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_07d6441f959d | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_67b.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3ae30b64baba | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_67b.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a5c3ab0126f5 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_68b.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0657388a1a90 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_68b.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4b4435e1707d | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_81_case1V1.cpp:49 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0ee24ff5844c | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_81_case1V1.cpp:49 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_84827cedc4a9 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_82_case1V1.cpp:49 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0d9d18cbfd66 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_82_case1V1.cpp:49 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a30ee8ceb852 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_02.c:176 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_511a8f0bb035 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_06.c:179 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ae0668745c20 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_21.c:203 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_794681981263 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_22a.c:143 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4422a41f2bee | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_22a.c:143 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3fc64e35cae8 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_04.c:183 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1f33e9891947 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_21.c:204 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b0a9bfaaff31 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_01.c:116 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_05f8b0ea6d32 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_01.c:116 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_eef1ddb56d1c | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_16.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6e2e36e2623d | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_16.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f4d5cd6fd994 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_18.c:120 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f164d31116f6 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_18.c:120 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_60221a824fa5 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_42.c:128 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d24b3f7989d1 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_42.c:128 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1a3cfb08d1ad | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_43.cpp:129 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3eab5cfb03f8 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_43.cpp:129 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0d96b96d7e64 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_44.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_26c9d9ab0c8a | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_44.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_92e71e8821a2 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_45.c:133 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c40c1d175e5d | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_45.c:133 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_839d4d8b3cb4 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_53c.c:46 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_104f4083f7a2 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_53c.c:46 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_38f5d369cee9 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_54a.c:78 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e98c7d7ec8fc | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54a.c:78 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_97e8ee77e04e | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_62a.cpp:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5c9de6357531 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_62a.cpp:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f2ef18e37264 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_61a.c:100 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e3fa0a983a6d | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_61a.c:100 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f6caa01acaac | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_64a.c:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a5e4389c22c6 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_64a.c:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a6be67d03d3e | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_67a.c:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_42d56c77a4b1 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_67a.c:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_45b6910ab8a3 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_68a.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_24ae612c3346 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_68a.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_526c5750fd3c | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_char_72a.cpp:93 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e446b641862a | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_72a.cpp:93 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d02836b40225 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_84a.cpp:44 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_301a2a04c363 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_21.c:151 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_19eefefa6526 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_15.c:189 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cd8d2e5f40f3 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_31.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_634df728c4f7 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_13.c:176 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_40dfadde2db9 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_17.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_68b7c4e454f6 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_51a.c:78 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1a7b2b2ae95d | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_54b.c:46 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_62d0ad4d5773 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_82a.cpp:75 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a2e7b1bdb125 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_84a.cpp:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9de7ff1d33b0 | juliet-api-misuse/testcases/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory/CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory__w32_wchar_t_66a.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
