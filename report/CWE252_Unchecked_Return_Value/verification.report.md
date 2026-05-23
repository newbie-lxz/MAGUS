# MAGUS Final Vulnerability Report

- generated_at: 2026-05-22T17:45:56Z
- reportable_vulnerabilities: 401
- d_confirmed_vulnerabilities: 71
- stage_c_preserved_vulnerabilities: 330
- failed_verifications: 37
- source_confirmed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE252_Unchecked_Return_Value/verification.jsonl
- source_failed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE252_Unchecked_Return_Value/verification.failed.jsonl

## Confirmed Vulnerabilities

### 1. hyp_path_1c18bc704c71

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_12.c:36
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 程序从stdin读取输入，fgetws调用可能失败返回NULL
- 触发路径: /* NOTE: Do not check the return value */ fgetws(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_12.c:36
- 结论: CWE252: 未检查 fgetws 返回值
- D验证: stage_c_preserved / ver_a741b4d1
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 2. hyp_path_d57008d119e7

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_12.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够导致stdin错误或提前关闭，使得fgets返回NULL。
- 触发路径: fgets(data, 100, stdin); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_12.c:35
- 结论: 未检查fgets返回值，可能导致fgets失败时使用未修改或部分填充的缓冲区，造成信息泄漏或未定义行为。
- D验证: stage_c_preserved / ver_68f5a51f
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 3. hyp_path_bc2d43c99df8

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_12.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者可能无法直接控制输入，但管道名称可能受外部影响（未在代码片段中明确）
- 触发路径: CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_12_case0() @ 入口; if(globalReturnsTrueOrFalse()) @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_12.c:27; /* NOTE: Do not check the return value */ CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_12.c:48-52
- 结论: 在特定分支下，ConnectNamedPipe的返回值未被检查，可能导致未正确处理管道连接状态，进而导致后续操作基于错误的假设。
- D验证: confirmed / ver_623fdeca
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 4. hyp_path_1d415eb4bace

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_17.c:36
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够通过stdin提供输入，导致fgets可能失败或部分读取，但返回值未被检查
- 触发路径: fgets(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_17.c:36
- 结论: CWE252_Unchecked_Return_Value: fgets返回值未被检查，可能导致未检测到的读取错误或部分读取
- D验证: stage_c_preserved / ver_ce82e078
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 5. hyp_path_d8a06003c566

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_11.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: fgets执行时出现错误条件（如输入流错误或EOF）
- 触发路径: fgets(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_11.c:35
- 结论: 未检查fgets返回值，可能导致未检测到的输入错误，但后续仅打印数据，未造成实际安全影响。
- D验证: stage_c_preserved / ver_7f9b81b0
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 6. hyp_path_5cf537b4ce95

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_08.c:48
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 程序从stdin读取用户输入，fgets返回值可能为NULL或表示读取失败，但未检查后续使用data
- 触发路径: fgets(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_08.c:48
- 结论: CWE-252: Unchecked Return Value - fgets返回值未检查，可能导致使用无效数据
- D验证: stage_c_preserved / ver_65819b4d
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 7. hyp_path_6aad80687b6b

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_01.c:33
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 标准输入流遇到EOF或发生读取错误
- 触发路径: fgets(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_01.c:33; printLine(data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_01.c:34
- 结论: 未检查fgets()的返回值，若读取失败（如遇到EOF或错误），data缓冲区内容未定义，但后续程序仍使用data，可能导致意外行为。
- D验证: stage_c_preserved / ver_25bdf231
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 8. hyp_path_5fa270b7ad8b

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_02.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制标准输入使fgets读取失败或返回EOF
- 触发路径: fgets(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_02.c:35
- 结论: fgets返回值未检查，若读取失败或EOF，data可能保持空字符串，但违反CWE-252规范，存在潜在信息泄漏或程序行为异常风险，但风险较低且需攻击者控制标准输入。
- D验证: stage_c_preserved / ver_e228507b
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 9. hyp_path_d8b304f8964f

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_03.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够使fgets()调用失败（例如通过输入EOF或关闭stdin）
- 触发路径: fgets(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_03.c:35
- 结论: 存在未检查fgets()返回值的漏洞，可能导致使用无效数据或意外行为
- D验证: stage_c_preserved / ver_8b79fea0
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 10. hyp_path_d4ff554a9a59

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_05.c:41
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够通过stdin输入数据
- 触发路径: fgets(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_05.c:41
- 结论: CWE-252: fgets返回值未检查，导致未处理错误
- D验证: stage_c_preserved / ver_057082db
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 11. hyp_path_6f2cfba04963

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_04.c:41
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 程序未检查fgets返回值，fgets可能失败
- 触发路径: fgets(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_04.c:41
- 结论: CWE-252: 未检查fgets返回值，可能导致程序行为异常或潜在安全风险
- D验证: stage_c_preserved / ver_baa469e1
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 12. hyp_path_1c4ec764592d

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_07.c:40
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Standard input is available to the attacker
- 触发路径: fgets(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_07.c:40
- 结论: CWE252: Unchecked Return Value - fgets return value not checked
- D验证: stage_c_preserved / ver_a40fa6af
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 13. hyp_path_3918b4cb2637

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_06.c:40
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够导致fgets失败（如关闭标准输入流）
- 触发路径: fgets(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_06.c:40; printLine(data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_06.c:41
- 结论: 未检查fgets的返回值，如果fgets失败，data数组内容可能为未定义，随后printLine使用该数据可能导致信息泄露或未定义行为。
- D验证: stage_c_preserved / ver_ad9d2ea8
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 14. hyp_path_b970fac6d5f1

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_09.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 程序通过标准输入读取数据，且未检查fgets返回值
- 触发路径: fgets(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_09.c:35
- 结论: 未检查fgets函数返回值，可能导致后续处理基于不完整或错误的数据
- D验证: stage_c_preserved / ver_4201eb18
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 15. hyp_path_6133038dc45b

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_13.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Attacker may cause fgets to fail (e.g., EOF or error), leaving data uninitialized or stale, which is then used by printLine.
- 触发路径: fgets(data, 100, stdin); @ L35; printLine(data); @ L36
- 结论: VULNERABILITY_FOUND: Unchecked return value of fgets, leading to potential use of uninitialized or stale data.
- D验证: stage_c_preserved / ver_3cb4bceb
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 16. hyp_path_2ae7a37c1e36

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_10.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 标准输入可能被关闭或到达文件末尾导致fgets失败
- 触发路径: fgets(data, 100, stdin); @ CWE252_Unchecked_Return_Value__char_fgets_10.c:35
- 结论: fgets返回值未检查，可能导致无法检测输入失败，但数据不会未初始化，属于CWE-252漏洞但风险较低
- D验证: stage_c_preserved / ver_92a6f805
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 17. hyp_path_a83d721c1d20

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_15.c:36
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够使fgets返回NULL，例如通过关闭标准输入或提供EOF信号
- 触发路径: printLine("Please enter a string: "); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_15.c:34; fgets(data, 100, stdin); // 返回值未被检查 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_15.c:36; printLine(data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_15.c:37
- 结论: 在fgets函数调用后未检查返回值，若fgets失败（如遇到EOF或错误），则数据缓冲区可能未更新，但程序仍继续使用，可能导致未初始化的数据被打印或后续逻辑错误。尽管缓冲区已初始化为空字符串，但仍违反了CWE-252规范。
- D验证: stage_c_preserved / ver_5cca5fc2
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 18. hyp_path_7277b322501c

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_16.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够提前关闭标准输入或发送EOF信号，导致fgets返回NULL。
- 触发路径: fgets(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_16.c:35
- 结论: 未检查fgets返回值，可能导致程序在读取失败时使用默认或无效数据，引发逻辑错误或未定义行为。
- D验证: stage_c_preserved / ver_074c0362
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 19. hyp_path_3efee1f6a7f0

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_14.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够使标准输入流发生EOF或错误，导致fgets返回NULL。
- 触发路径: fgets(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_14.c:35
- 结论: 未检查fgets函数的返回值，可能导致程序在fgets失败时使用未定义或空的数据，存在逻辑错误风险。
- D验证: stage_c_preserved / ver_0e78a2ef
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 20. hyp_path_da82a146c4f3

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fgets_18.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者可通过关闭stdin或发送EOF使fgets返回NULL，导致data缓冲区内容未初始化。
- 触发路径: fgets(data, 100, stdin); @ L35
- 结论: 存在未检查返回值漏洞（CWE-252）：fgets函数返回值未被检查，可能导致读取失败时使用未初始化的缓冲区。
- D验证: stage_c_preserved / ver_bafd4c79
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 21. hyp_path_0c0b36c32f3b

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_17.c:37
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 程序以标准输入读取数据，fgetws可能因输入错误或EOF而失败。
- 触发路径: fgetws(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_17.c:36
- 结论: 未检查fgetws返回值，若读取失败可能导致后续使用未定义状态的缓冲区，但实际风险较低。
- D验证: stage_c_preserved / ver_584cec99
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 22. hyp_path_77c78b672c30

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_08.c:48
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够控制stdin输入，使其产生错误或提前结束，导致fgetws返回NULL或空字符串。
- 触发路径: fgetws(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_08.c:48
- 结论: 未检查fgetws返回值，可能导致在读取失败时使用未定义或无效的数据，但缓冲区已初始化为空字符串，实际影响有限。
- D验证: stage_c_preserved / ver_f6761a1d
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 23. hyp_path_42013b5e5e3f

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_11.c:36
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够使stdin处于EOF或错误状态
- 触发路径: fgetws(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_11.c:35
- 结论: 未检查fgetws返回值，如果fgetws失败（例如EOF或错误），data内容可能未更新，但后续仍使用data。
- D验证: stage_c_preserved / ver_027b1bda
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 24. hyp_path_f0a90b634bda

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_17.c:51
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: CreateNamedPipeA调用失败（例如管道名称无效或系统资源不足），无需外部输入控制
- 触发路径: HANDLE hPipe = INVALID_HANDLE_VALUE; ... hPipe = CreateNamedPipeA( pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ...); @ 34-38; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ 46-50; CloseHandle(hPipe); @ 51
- 结论: CreateNamedPipeA的返回值未被检查，若函数失败则hPipe为INVALID_HANDLE_VALUE，后续ConnectNamedPipe和CloseHandle使用无效句柄可能导致程序崩溃或未定义行为。
- D验证: confirmed / ver_2821c13e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 25. hyp_path_210fa0932798

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_01.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够通过标准输入影响程序行为，但本漏洞的利用依赖于fgetws失败（如EOF或错误），此时未检查返回值导致程序可能基于未预期的数据继续执行，但实际影响有限。
- 触发路径: fgetws(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_01.c:33; printWLine(data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_01.c:34
- 结论: 调用fgetws后未检查返回值，可能导致在读取失败时使用未初始化或无效数据。
- D验证: stage_c_preserved / ver_f2bd994b
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 26. hyp_path_f05e449bafc8

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_02.c:36
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Attacker provides input via stdin; fgetws may fail or truncate but return value is ignored.
- 触发路径: fgetws(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_02.c:36; /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_02.c:35
- 结论: CWE252: Unchecked Return Value - fgetws return value not checked, potentially leading to truncated input or error state.
- D验证: stage_c_preserved / ver_79b2ed2a
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 27. hyp_path_3850a5180d4c

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_17.c:51
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者无法直接控制，但系统条件（如资源不足）可能导致API调用失败
- 触发路径: hPipe = CreateNamedPipeW(...); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_17.c:34-38; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); /* ConnectNamedPipe返回值通过GetLastError部分检查，但hPipe可能无效 */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_17.c:46-50; CloseHandle(hPipe); /* 使用可能无效的句柄 */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_17.c:49-53
- 结论: 函数CreateNamedPipeW的返回值未被检查，可能导致在管道创建失败时后续使用无效句柄进行ConnectNamedPipe和CloseHandle操作，违反CWE-252（未检查返回值）。ConnectNamedPipe的返回值通过GetLastError进行了部分检查，但主要问题在于CreateNamedPipeW未检查。
- D验证: confirmed / ver_46b7b705
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 28. hyp_path_4bbe230afc58

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_05.c:42
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: fgetws may fail due to end-of-file or error, leaving data in an undefined state
- 触发路径: /* NOTE: Do not check the return value */ fgetws(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_05.c:42
- 结论: CWE-252: Unchecked Return Value of fgetws
- D验证: stage_c_preserved / ver_bd79b666
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 29. hyp_path_55a8d47f5649

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_03.c:36
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Attacker provides input via stdin, but function may fail (e.g., EOF, error) causing return value to be NULL.
- 触发路径: fgetws(data, 100, stdin); @ L35
- 结论: CWE-252: Unchecked Return Value of fgetws
- D验证: stage_c_preserved / ver_9ebc0e4a
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 30. hyp_path_5ffe4d784b58

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_04.c:42
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Attacker can provide input via stdin, but vulnerability is independent of attacker control; fgetws can fail (e.g., EOF) and return value is unchecked, leading to use of uninitialized buffer.
- 触发路径: fgetws(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_04.c:41; printWLine(data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_04.c:42
- 结论: API misuse: fgetws return value not checked, leading to potential use of uninitialized data
- D验证: stage_c_preserved / ver_5f9c1d35
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 31. hyp_path_2b902497db96

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_06.c:41
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够导致 fgetws 失败（例如通过关闭 stdin 或发送 EOF）
- 触发路径: printLine("Please enter a string: "); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_06.c:38; fgetws(data, 100, stdin); // 未检查返回值 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_06.c:40; printWLine(data); // 使用可能未定义的数据 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_06.c:41
- 结论: 未检查 fgetws 的返回值，如果 fgetws 失败（例如 stdin 关闭或读取错误），则 dataBuffer 内容未定义，后续 printWLine 可能输出未定义数据，但更关键的是未处理错误条件，违反了 CWE-252。
- D验证: stage_c_preserved / ver_e2dd5704
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 32. hyp_path_1d5a8fbdba47

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_07.c:41
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Attacker can provide input via stdin, potentially causing fgetws to fail (e.g., EOF) and leave data buffer partially filled or unchanged.
- 触发路径: fgetws(data, 100, stdin); @ L40; printWLine(data); @ L41
- 结论: Unchecked return value of fgetws may lead to use of uninitialized or incomplete data, potentially causing undefined behavior or information disclosure.
- D验证: stage_c_preserved / ver_56151815
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 33. hyp_path_7d922c2da694

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_10.c:36
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够使fgetws返回NULL，例如通过关闭stdin或发送EOF
- 触发路径: fgetws(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_10.c:35; printWLine(data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_10.c:36
- 结论: 未检查fgetws的返回值可能导致后续使用未定义数据或程序崩溃
- D验证: stage_c_preserved / ver_b8aa83e1
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 34. hyp_path_4088a1cd74e7

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_09.c:35
- 漏洞类型: null_deref
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够导致fgetws的输入流（stdin）发生错误，如提前关闭标准输入或提供无效输入
- 触发路径: fgetws(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_09.c:35; printWLine(data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_09.c:36
- 结论: 未检查fgetws返回值，若输入失败（如stdin关闭或读取错误），fgetws返回NULL，但data仍指向有效缓冲区，不会导致空指针解引用，但忽略错误状态可能导致后续逻辑不可靠或数据未更新，违反安全编码规范。
- D验证: stage_c_preserved / ver_d1dff26f
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 35. hyp_path_7bed55d58722

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_13.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够通过控制stdin的输入状态（如提前关闭流）使fgetws失败。
- 触发路径: fgetws(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_13.c:35
- 结论: 在调用fgetws后未检查其返回值，可能导致在发生读取错误或EOF时，data缓冲区内容未更新，程序继续使用未预期数据，违背了CWE-252（未检查返回值）安全要求。
- D验证: stage_c_preserved / ver_ac32ffb4
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 36. hyp_path_eb8461f71d8c

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_15.c:36
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制标准输入，且 fgetws 可能失败返回 NULL
- 触发路径: fgetws(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_15.c:36
- 结论: 调用 fgetws 后未检查返回值，可能导致使用无效数据
- D验证: stage_c_preserved / ver_75e0eab2
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 37. hyp_path_15bf32e7315c

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_14.c:36
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: fgetws调用可能失败（如EOF或错误）
- 触发路径: fgetws(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_14.c:35; printWLine(data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_14.c:36
- 结论: 未检查fgetws返回值，可能导致读取失败时使用未初始化的缓冲区数据
- D验证: stage_c_preserved / ver_6478f836
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 38. hyp_path_515cb33f0dc7

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_16.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够通过标准输入提供输入，但fgetws可能因错误或EOF返回NULL，导致data内容未定义。
- 触发路径: fgetws(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_16.c:35
- 结论: 未检查fgetws的返回值，函数调用失败时data可能未正确初始化，导致后续使用未定义数据，存在CWE-252漏洞。
- D验证: stage_c_preserved / ver_6c89bb2c
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 39. hyp_path_6f3e9f73a7d9

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_18.c:36
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Attacker can provide input via stdin, possibly causing fgetws to fail (EOF or error)
- 触发路径: fgetws(data, 100, stdin); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_18.c:35; printWLine(data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fgets_18.c:36
- 结论: Unchecked return value of fgetws leading to potential use of data in an error state, possibly containing garbage or truncation
- D验证: stage_c_preserved / ver_fe570c5e
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 40. hyp_path_72dc700dd266

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_08.c:63
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: N/A
- 触发路径: hPipe = CreateNamedPipeA(pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ...); // 未检查返回值 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_08.c:46-50; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); // 使用可能无效的 hPipe @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_08.c:58-62; CloseHandle(hPipe); // 未检查句柄有效性 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_08.c:63
- 结论: CreateNamedPipeA 的返回值未检查，可能导致在管道创建失败时继续使用无效句柄，符合 CWE-252（未检查返回值）
- D验证: confirmed / ver_508fc043
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 41. hyp_path_ac4651c7c92b

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_08.c:63
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者能够影响 CreateNamedPipeW 的调用结果（例如通过耗尽系统资源或使管道创建失败）
- 触发路径: hPipe = CreateNamedPipeW(...); // NOTE: Do not check the return value @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_08.c:46-50; CloseHandle(hPipe); // 使用未检查的句柄 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_08.c:61-65
- 结论: CreateNamedPipeW 的返回值未被检查，如果管道创建失败，后续对 hPipe 的操作（如 CloseHandle）可能基于无效句柄，导致未定义行为或资源泄漏。
- D验证: confirmed / ver_bb001564
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 42. hyp_path_3896704b8014

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_11.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: CreateNamedPipeA因资源耗尽、权限不足或其他原因失败，返回INVALID_HANDLE_VALUE
- 触发路径: HANDLE hPipe = INVALID_HANDLE_VALUE; BOOL fConnected = FALSE; hPipe = CreateNamedPipeA(...); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_11.c:33-35; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_11.c:45-47; CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_11.c:50
- 结论: 未检查CreateNamedPipeA返回值，导致在管道创建失败后使用无效句柄（INVALID_HANDLE_VALUE），后续调用ConnectNamedPipe和CloseHandle的行为未定义，存在潜在安全风险。
- D验证: confirmed / ver_c9b8f3b5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 43. hyp_path_0a55dd2a42d3

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_02.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者能够导致CreateNamedPipeA失败，例如耗尽系统资源或权限不足。
- 触发路径: hPipe = CreateNamedPipeA(pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ..., NULL); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_02.c:50
- 结论: CreateNamedPipeA的返回值未被检查，如果函数失败返回INVALID_HANDLE_VALUE，后续ConnectNamedPipe将使用无效句柄，可能导致拒绝服务或未定义行为。
- D验证: confirmed / ver_0844da49
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 44. hyp_path_d914dd2cd2c7

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_11.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: No specific precondition; the vulnerability is inherent in the code logic.
- 触发路径: hPipe = CreateNamedPipeW(pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ... NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_11.c:35; /* NOTE: Do not check the return value */ fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_11.c:45-48; CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_11.c:50
- 结论: CWE252: Unchecked return value of CreateNamedPipeW, which may return INVALID_HANDLE_VALUE and lead to undefined behavior when used in ConnectNamedPipe or CloseHandle.
- D验证: confirmed / ver_821ce37a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 45. hyp_path_7ae34ecb10b5

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_01.c:48
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 函数可能因系统资源不足或管道名冲突等正常原因失败，但返回值未被检查，导致后续使用INVALID_HANDLE_VALUE。
- 触发路径: hPipe = CreateNamedPipeA(pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ... NULL); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_01.c:48; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_01.c:45; CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_01.c:48
- 结论: CreateNamedPipeA的返回值未被检查，如果函数失败，后续对hPipe的ConnectNamedPipe和CloseHandle调用可能导致未定义行为或资源泄漏。
- D验证: confirmed / ver_f2d1742b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 46. hyp_path_f3c44e30ac31

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_04.c:56
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者不需要直接控制输入，但系统资源不足或权限限制可能导致CreateNamedPipeA失败。
- 触发路径: hPipe = CreateNamedPipeA(pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ...); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_04.c:56; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_04.c:53; CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_04.c:56
- 结论: 未检查CreateNamedPipeA函数的返回值，可能导致使用无效句柄进行后续操作，如ConnectNamedPipe或CloseHandle，从而引发未定义行为或拒绝服务。
- D验证: confirmed / ver_c4970b57
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 47. hyp_path_8269fc65d3a9

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_03.c:50
- 漏洞类型: CWE-252, CWE-703
- CWE: CWE-252; CWE-703
- 风险等级: P0
- 触发条件: 攻击者能够导致CreateNamedPipeA失败（如创建同名的已存在管道实例）
- 触发路径: hPipe = CreateNamedPipeA(...); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_03.c:45-49; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_03.c:45-49; CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_03.c:48-52
- 结论: CreateNamedPipeA的返回值未被检查，若函数失败返回INVALID_HANDLE_VALUE，后续ConnectNamedPipe和CloseHandle将操作无效句柄，可能导致未定义行为或拒绝服务。
- D验证: confirmed / ver_53dbeea4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 48. hyp_path_10abbabb0b5f

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_07.c:55
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者可能通过影响系统资源或命名管道名称导致CreateNamedPipeA失败，但具体前提取决于环境
- 触发路径: hPipe = CreateNamedPipeA( pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ... NULL); /* NOTE: Do not check the return value */ @ 42; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ 50; CloseHandle(hPipe); @ 55
- 结论: 未检查CreateNamedPipeA和ConnectNamedPipe的返回值，可能导致使用无效句柄进行后续操作，造成程序异常或资源泄漏。
- D验证: confirmed / ver_327d0369
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 49. hyp_path_f3974e3260be

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_09.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者不需要外部输入，漏洞由未检查返回值直接触发
- 触发路径: hPipe = CreateNamedPipeA(pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ...); @ CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_09.c:37; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_09.c:47
- 结论: 未检查CreateNamedPipeA返回值，可能导致后续ConnectNamedPipe使用无效句柄
- D验证: confirmed / ver_c7a6b289
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 50. hyp_path_55d2aeab1283

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_05.c:56
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 系统资源不足或命名管道创建失败的情况
- 触发路径: hPipe = CreateNamedPipeA(pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ...); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_05.c:39-43; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_05.c:51-55; CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_05.c:54-58
- 结论: 函数CreateNamedPipeA的返回值未检查，若函数失败则hPipe为INVALID_HANDLE_VALUE，后续使用该句柄调用ConnectNamedPipe和CloseHandle可能导致程序行为异常或被利用。
- D验证: confirmed / ver_ea490f01
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 51. hyp_path_4d4a7596e604

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_10.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者无需直接控制，但系统条件可能导致 CreateNamedPipeA 失败（如管道名冲突、权限不足等）
- 触发路径: HANDLE hPipe = INVALID_HANDLE_VALUE; BOOL fConnected = FALSE; hPipe = CreateNamedPipeA( pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ...); /* NOTE: Do not check the return value */ @ L33-L37; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); /* 使用未检查返回值的 hPipe */ @ L45-L49; CloseHandle(hPipe); /* 关闭可能无效的句柄 */ @ L48-L52
- 结论: CreateNamedPipeA 的返回值未被检查，如果函数失败返回 INVALID_HANDLE_VALUE，后续 ConnectNamedPipe 和 CloseHandle 将使用无效句柄，可能导致未定义行为或资源泄露。
- D验证: confirmed / ver_9c38e4e3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 52. hyp_path_9130273a3e4c

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_06.c:55
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者可通过消耗系统命名管道资源或竞争条件使CreateNamedPipeA失败
- 触发路径: HANDLE hPipe = INVALID_HANDLE_VALUE; BOOL fConnected = FALSE; hPipe = CreateNamedPipeA( pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ...); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_06.c:38-42; NULL); /* NOTE: Do not check the return value */ fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_06.c:50-54; CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_06.c:53-57
- 结论: 未检查CreateNamedPipeA的返回值，若函数失败返回INVALID_HANDLE_VALUE，后续对无效句柄调用ConnectNamedPipe和CloseHandle可能导致程序崩溃或安全风险。
- D验证: confirmed / ver_137695f2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 53. hyp_path_827b443827b9

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_14.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者能够导致CreateNamedPipeA失败（如通过创建同名管道实例或耗尽系统资源）。
- 触发路径: hPipe = CreateNamedPipeA(pipeName, ...); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_14.c:44; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_14.c:47; CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_14.c:50
- 结论: 在CreateNamedPipeA函数调用后未检查返回值，若函数失败返回INVALID_HANDLE_VALUE，后续ConnectNamedPipe和CloseHandle将使用无效句柄，可能导致程序行为异常或崩溃。
- D验证: confirmed / ver_01e6bf44
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 54. hyp_path_8db831139a56

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_18.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: CreateNamedPipeA因资源不足、权限不足或管道名称冲突等原因失败。
- 触发路径: hPipe = CreateNamedPipeA(pipeName, ...); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_18.c:45; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_18.c:47; CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_18.c:50
- 结论: 未检查CreateNamedPipeA的返回值，如果管道创建失败，后续对无效句柄的操作可能导致未定义行为或资源泄漏。
- D验证: confirmed / ver_b94cc604
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 55. hyp_path_ee0765d3b821

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_15.c:51
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者可能通过耗尽系统资源或权限限制导致CreateNamedPipeA失败。
- 触发路径: hPipe = CreateNamedPipeA( pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ... NULL); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_15.c:36-38; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_15.c:48; CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_15.c:51
- 结论: CreateNamedPipeA的返回值未检查，可能导致后续ConnectNamedPipe和CloseHandle使用无效句柄，造成未定义行为或拒绝服务。
- D验证: confirmed / ver_7c0b2d99
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 56. hyp_path_fa2725ff9c3c

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_16.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者无需特殊控制，调用失败是正常运行时可能发生的情况。
- 触发路径: HANDLE hPipe = INVALID_HANDLE_VALUE; ... hPipe = CreateNamedPipeA(...); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_16.c:33-37; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_16.c:45-49
- 结论: 未检查 CreateNamedPipeA 的返回值，可能导致后续使用无效句柄，造成程序异常或未定义行为。
- D验证: confirmed / ver_834ce881
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 57. hyp_path_6d2963f10dfe

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_01.c:48
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: CreateNamedPipeW因系统资源不足、权限不足等原因失败
- 触发路径: hPipe = CreateNamedPipeW(...); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_01.c:33; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_01.c:44; CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_01.c:48
- 结论: CreateNamedPipeW返回值未检查，若函数失败则hPipe为INVALID_HANDLE_VALUE，后续ConnectNamedPipe和CloseHandle可能导致未定义行为或资源泄漏。
- D验证: confirmed / ver_55b84931
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 58. hyp_path_1048cd692e09

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_04.c:56
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 无需攻击者控制输入，任何导致CreateNamedPipeW失败的条件（如管道名称冲突、权限不足等）即可触发
- 触发路径: HANDLE hPipe = INVALID_HANDLE_VALUE; @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_04.c:39; hPipe = CreateNamedPipeW(pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ...); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_04.c:39-43; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_04.c:51-53; CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_04.c:56
- 结论: 未检查CreateNamedPipeW的返回值，如果函数失败返回INVALID_HANDLE_VALUE，后续ConnectNamedPipe和CloseHandle使用无效句柄可能导致未定义行为或拒绝服务。
- D验证: confirmed / ver_c5cf264e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 59. hyp_path_0f8dfa6b408b

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_02.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 无特殊攻击前提，仅需代码执行至此路径，依赖CreateNamedPipeW可能失败（如资源不足、权限不足等）。
- 触发路径: hPipe = CreateNamedPipeW( pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ... NULL); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_02.c:50
- 结论: 函数CreateNamedPipeW的返回值未被检查，可能导致后续操作使用无效的管道句柄，违反CWE-252未检查返回值的要求。
- D验证: confirmed / ver_ef2587e9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 60. hyp_path_5abbbb3d1715

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_03.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: CreateNamedPipeW执行失败（如系统资源不足），返回INVALID_HANDLE_VALUE，但代码未检查该返回值。
- 触发路径: HANDLE hPipe = INVALID_HANDLE_VALUE; ... hPipe = CreateNamedPipeW(...); // 返回值未检查 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_03.c:33-37; /* NOTE: Do not check the return value */ fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_03.c:45-49; CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_03.c:48-52
- 结论: 函数CreateNamedPipeW的返回值未被检查，可能导致后续操作使用无效句柄，引发未定义行为或资源泄露。
- D验证: confirmed / ver_fd893a4b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 61. hyp_path_054850cd50f2

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_13.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: CreateNamedPipeA可能因系统资源耗尽或管道名冲突而失败，但攻击者无需直接控制输入即可触发漏洞。
- 触发路径: hPipe = CreateNamedPipeA(pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ..., NULL); /* NOTE: Do not check the return value */ @ CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_13.c:36; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_13.c:47; CloseHandle(hPipe); @ CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_13.c:50
- 结论: 函数CreateNamedPipeA的返回值未检查，如果管道创建失败，后续ConnectNamedPipe和CloseHandle将使用无效句柄（INVALID_HANDLE_VALUE），可能导致程序崩溃或异常行为。
- D验证: confirmed / ver_7b2050e9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 62. hyp_path_43d410e96345

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_05.c:56
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: CreateNamedPipeW函数返回失败（返回INVALID_HANDLE_VALUE），但程序未检查返回值
- 触发路径: hPipe = CreateNamedPipeW(...); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_05.c:56; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_05.c:56; CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_05.c:58
- 结论: 未检查CreateNamedPipeW的返回值，可能导致在管道创建失败时使用无效句柄，引发未定义行为。
- D验证: confirmed / ver_7a2eb938
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 63. hyp_path_7d98b9e3e2e8

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_09.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: CreateNamedPipeW执行时系统资源不足或参数非法，导致返回INVALID_HANDLE_VALUE
- 触发路径: hPipe = CreateNamedPipeW(pipeName, ...); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_09.c:50; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_09.c:47; CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_09.c:52
- 结论: 未检查CreateNamedPipeW的返回值，如果管道创建失败（例如系统资源不足或参数错误），后续ConnectNamedPipe和CloseHandle操作无效句柄可能导致程序崩溃或未定义行为。
- D验证: confirmed / ver_771183bb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 64. hyp_path_6690cc151378

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_07.c:55
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者能够导致CreateNamedPipeW失败，例如通过耗尽系统管道资源或创建同名管道
- 触发路径: HANDLE hPipe = INVALID_HANDLE_VALUE; ... hPipe = CreateNamedPipeW( pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ... NULL); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_07.c:38-42; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); ... CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_07.c:50-54
- 结论: CreateNamedPipeW的返回值未检查，如果调用失败则hPipe为INVALID_HANDLE_VALUE，后续ConnectNamedPipe和CloseHandle操作无效句柄可能导致程序崩溃或未定义行为。
- D验证: confirmed / ver_2cf26382
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 65. hyp_path_f417ec881f78

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_06.c:55
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 无攻击者控制输入，仅依赖API调用失败条件
- 触发路径: HANDLE hPipe = INVALID_HANDLE_VALUE; ... hPipe = CreateNamedPipeW(...); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_06.c:38-42; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_06.c:53; CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_06.c:55
- 结论: 在CreateNamedPipeW调用后未检查返回值，若函数失败则hPipe为INVALID_HANDLE_VALUE，后续ConnectNamedPipe和CloseHandle使用无效句柄，导致未处理错误或未定义行为，符合CWE-252典型示例。
- D验证: confirmed / ver_e21ce31e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 66. hyp_path_9a814fe807b8

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_10.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: CreateNamedPipeW调用失败（如管道名冲突、权限不足）
- 触发路径: HANDLE hPipe = INVALID_HANDLE_VALUE; ... hPipe = CreateNamedPipeW(pipeName, ...); /* NOTE: Do not check the return value */ @ 33-37; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); /* 使用可能无效的hPipe */ @ 45-49; CloseHandle(hPipe); /* 关闭可能无效的句柄 */ @ 48-52
- 结论: 未检查CreateNamedPipeW的返回值，如果函数失败返回INVALID_HANDLE_VALUE，后续ConnectNamedPipe和CloseHandle操作无效句柄可能导致未定义行为或拒绝服务。
- D验证: confirmed / ver_da92e784
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 67. hyp_path_e8d12a9c7869

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_13.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: CreateNamedPipeW调用因权限不足、管道名冲突等原因失败
- 触发路径: hPipe = CreateNamedPipeW(pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ...); // 返回值未检查 @ 行45-49; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); // 使用可能无效的hPipe @ 行45-49; CloseHandle(hPipe); // 关闭可能无效的句柄 @ 行48-52
- 结论: CreateNamedPipeW函数的返回值未被检查，可能导致后续对无效句柄的操作，符合CWE-252未检查返回值漏洞。
- D验证: confirmed / ver_c4dd44cb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 68. hyp_path_1b3f45bb0814

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_14.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者无法直接控制CreateNamedPipeW是否成功，但代码存在未检查返回值的缺陷，可能导致程序在管道创建失败时仍继续执行后续操作。
- 触发路径: HANDLE hPipe = INVALID_HANDLE_VALUE; BOOL fConnected = FALSE; hPipe = CreateNamedPipeW( pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ... NULL); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_14.c:33-37; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_14.c:45-49
- 结论: 未检查CreateNamedPipeW的返回值，若函数失败返回INVALID_HANDLE_VALUE，则后续ConnectNamedPipe可能使用无效句柄导致意外行为或资源泄漏。
- D验证: confirmed / ver_cb9712de
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 69. hyp_path_3c9cf19c5758

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_18.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 无，攻击者无需控制输入；但调用可能因系统资源不足等失败
- 触发路径: hPipe = CreateNamedPipeW(pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ... NULL); /* NOTE: Do not check the return value */ @ 行37; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); /* 返回值未充分检查 */ @ 行45; CloseHandle(hPipe); // 可能关闭无效句柄 @ 行50
- 结论: 未检查CreateNamedPipeW和ConnectNamedPipe的返回值，可能导致后续操作基于无效句柄，造成资源未正确处理或安全功能失效。
- D验证: confirmed / ver_55bf7352
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 70. hyp_path_4c3c173364d1

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_16.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者能够影响CreateNamedPipeW的调用结果，例如通过资源耗尽或权限限制使其失败
- 触发路径: hPipe = CreateNamedPipeW(...); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_16.c:50; fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_16.c:50; CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_16.c:52
- 结论: CreateNamedPipeW返回值未检查，可能导致后续对无效句柄的操作（如ConnectNamedPipe、CloseHandle），引发程序崩溃或意外行为。
- D验证: confirmed / ver_4456a676
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 71. hyp_path_a9378d529cdd

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_15.c:51
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者能够导致CreateNamedPipeW失败，例如通过占用管道名称或耗尽系统资源
- 触发路径: HANDLE hPipe = INVALID_HANDLE_VALUE; BOOL fConnected = FALSE; hPipe = CreateNamedPipeW( pipeName, FILE_FLAG_FIRST_PIPE_INSTANCE, ... NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_15.c:34-38; /* NOTE: Do not check the return value */ fConnected = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_15.c:46-50; CloseHandle(hPipe); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_15.c:49-53
- 结论: 未检查CreateNamedPipeW的返回值，如果函数失败返回INVALID_HANDLE_VALUE，后续对hPipe的ConnectNamedPipe和CloseHandle操作将使用无效句柄，可能导致未定义行为或拒绝服务。
- D验证: confirmed / ver_6f865f26
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 72. hyp_path_ada1eb33bda7

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_17.c:38
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者无法直接控制CreateMutexA的输入，但系统资源不足或权限问题可能导致函数失败。
- 触发路径: hMutex = CreateMutexA(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_17.c:37; CloseHandle(hMutex); /* hMutex可能为NULL */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_17.c:38
- 结论: 调用CreateMutexA后未检查返回值，如果函数失败返回NULL，则后续CloseHandle(NULL)可能导致程序崩溃或未定义行为。
- D验证: confirmed / ver_de5d7643
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 73. hyp_path_716cc5add5ae

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_17.c:38
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 无需攻击者输入，为开发者忽视返回值检查。
- 触发路径: hMutex = CreateMutexW(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_17.c:38; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_17.c:40
- 结论: 函数CreateMutexW调用后未检查返回值，若创建失败则hMutex为NULL，尽管CloseHandle(NULL)在Windows上安全，但未检查返回值违反了安全编码规范，符合CWE-252定义。
- D验证: confirmed / ver_500c6140
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 74. hyp_path_c56e33c836d2

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_12.c:37
- 漏洞类型: null_deref
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者可能通过资源耗尽等方式导致CreateMutexA失败，但更常见的是由于系统资源不足或权限问题，但代码未检查返回值，无论原因如何都构成漏洞
- 触发路径: HANDLE hMutex = NULL; hMutex = CreateMutexA(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_12.c:31-32; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_12.c:37
- 结论: 调用CreateMutexA后未检查返回值，当创建互斥体失败返回NULL时，后续直接使用NULL句柄调用CloseHandle，可能导致空指针解引用或未定义行为。
- D验证: confirmed / ver_a7a7042f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 75. hyp_path_ca58f7236aa7

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_08.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: CreateMutexA调用未检查返回值，系统可能因资源不足返回NULL
- 触发路径: hMutex = CreateMutexA(NULL, FALSE, NULL); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_08.c:44-48; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_08.c:50
- 结论: CreateMutexA调用后未检查返回值，若创建互斥量失败则hMutex为NULL，后续CloseHandle(hMutex)违反CWE-252，可能掩盖资源分配失败，需检查返回值。
- D验证: confirmed / ver_46e128d9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 76. hyp_path_dc39dc7d2b34

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_12.c:37
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 系统资源耗尽或权限不足导致CreateMutexW失败
- 触发路径: hMutex = CreateMutexW(NULL, FALSE, NULL); /* NOTE: Do not check the return value */ @ 32-33行; CloseHandle(hMutex); @ 36-37行
- 结论: 未检查CreateMutexW返回值，若创建互斥体失败（返回NULL），后续CloseHandle(NULL)可能导致程序异常或未定义行为（CWE-252）。
- D验证: confirmed / ver_3e303d85
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 77. hyp_path_ba2afcc11fa9

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_11.c:37
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 系统资源不足可导致CreateMutexA失败，但攻击者无法直接控制
- 触发路径: hMutex = CreateMutexA(NULL, FALSE, NULL); @ 37; CloseHandle(hMutex); @ 37
- 结论: 未检查CreateMutexA返回值，如果函数失败返回NULL，后续CloseHandle传入NULL句柄虽然不会导致崩溃，但违反了安全编码规范，可能掩藏资源管理错误。
- D验证: confirmed / ver_13ffcabb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 78. hyp_path_1002df721d28

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_08.c:50
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 系统资源不足或互斥体创建失败，导致CreateMutexW返回NULL
- 触发路径: hMutex = CreateMutexW(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_08.c:45; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_08.c:50
- 结论: 未检查CreateMutexW返回值，如果函数失败返回NULL，后续CloseHandle使用NULL句柄可能导致未定义行为或资源管理问题。
- D验证: confirmed / ver_c2c638d7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 79. hyp_path_b079ee88366e

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_11.c:37
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 系统资源耗尽等场景可能导致CreateMutexW失败返回NULL
- 触发路径: hMutex = CreateMutexW(NULL, FALSE, NULL); @ CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_11.c:37; CloseHandle(hMutex); @ CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_11.c:39
- 结论: 未检查CreateMutexW的返回值，如果函数失败返回NULL，后续调用CloseHandle传入NULL句柄会导致无效句柄异常或未定义行为。
- D验证: confirmed / ver_4a8f066e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 80. hyp_path_3b0328620392

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_01.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: CreateMutexA调用失败（例如系统资源不足）
- 触发路径: hMutex = CreateMutexA(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_01.c:35; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_01.c:35-37
- 结论: 未检查CreateMutexA的返回值，若函数失败则hMutex为NULL，后续调用CloseHandle(NULL)可能导致未定义行为或程序崩溃
- D验证: confirmed / ver_ecdab749
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 81. hyp_path_aad143189113

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_02.c:37
- 漏洞类型: null_deref
- CWE: CWE-252; CWE-476
- 风险等级: P0
- 触发条件: 系统资源不足导致CreateMutexA失败
- 触发路径: hMutex = CreateMutexA(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_02.c:35; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_02.c:37
- 结论: 在CreateMutexA调用后未检查返回值，如果函数失败返回NULL，则传递给CloseHandle可能导致空指针解引用或未定义行为。
- D验证: confirmed / ver_2ae1512f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 82. hyp_path_0b8e40e94378

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_03.c:37
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: N/A
- 触发路径: hMutex = CreateMutexA(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_03.c:37; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_03.c:37
- 结论: 未检查CreateMutexA函数的返回值，如果CreateMutexA失败返回NULL，后续CloseHandle(NULL)可能导致程序异常或未定义行为，属于CWE-252未检查返回值漏洞。
- D验证: confirmed / ver_79595dda
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 83. hyp_path_483ab5e2891f

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_05.c:43
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: CreateMutexA returns NULL (failure)
- 触发路径: hMutex = CreateMutexA(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_05.c:39; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_05.c:43
- 结论: CWE-252: Unchecked Return Value - CreateMutexA return value not checked, leading to potential use of invalid handle in CloseHandle.
- D验证: confirmed / ver_7e88be27
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 84. hyp_path_6a6239dcf595

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_04.c:43
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: CreateMutexA执行失败（例如系统资源不足或权限不足）
- 触发路径: hMutex = CreateMutexA(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_04.c:43; CloseHandle(hMutex); // hMutex可能为NULL @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_04.c:43
- 结论: 调用CreateMutexA后未检查返回值，如果函数失败则hMutex为NULL，后续调用CloseHandle(NULL)是安全的（不会崩溃），但违反了安全编码规范（未检查返回值），属于CWE-252缺陷。
- D验证: confirmed / ver_c42bfc5e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 85. hyp_path_21244b631046

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_09.c:37
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: CreateMutexA执行失败，返回NULL
- 触发路径: hMutex = CreateMutexA(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_09.c:35; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_09.c:39
- 结论: CreateMutexA的返回值未被检查，如果函数失败返回NULL，则后续CloseHandle调用可能传入无效句柄，尽管CloseHandle可以接受NULL，但未检查返回值违反了安全编程规范，可能导致资源管理错误。
- D验证: confirmed / ver_76ea5f30
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 86. hyp_path_333460f9783a

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_06.c:42
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: N/A
- 触发路径: hMutex = CreateMutexA(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_06.c:41; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_06.c:44
- 结论: CreateMutexA的返回值未被检查，如果创建互斥体失败，hMutex将为NULL，后续CloseHandle调用可能无效，且程序无法正确处理失败情况，导致逻辑错误。
- D验证: confirmed / ver_652830b3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 87. hyp_path_63bfb605f040

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_07.c:42
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: CreateMutexA因系统资源不足或权限拒绝而失败，返回NULL。
- 触发路径: HANDLE hMutex = NULL; hMutex = CreateMutexA(NULL, FALSE, NULL); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_07.c:36-40; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_07.c:42
- 结论: 未检查CreateMutexA的返回值，若函数失败返回NULL句柄，后续CloseHandle虽安全，但未检查返回值可能导致未检测到的资源分配失败，符合CWE-252模式。
- D验证: confirmed / ver_d4a2e607
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 88. hyp_path_89f789840ebc

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_13.c:37
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 无额外攻击者控制条件，仅依赖CreateMutexA非预期失败
- 触发路径: hMutex = CreateMutexA(NULL, FALSE, NULL); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_13.c:37; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_13.c:39
- 结论: CreateMutexA返回值未检查，若函数失败返回NULL，后续CloseHandle(NULL)可能导致程序崩溃（访问冲突）。
- D验证: confirmed / ver_174d8903
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 89. hyp_path_aa628d13dc82

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_10.c:37
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者可能通过耗尽系统资源等方式导致CreateMutexA失败
- 触发路径: hMutex = CreateMutexA(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_10.c:37; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_10.c:37
- 结论: 未检查CreateMutexA的返回值，如果函数失败返回NULL，后续CloseHandle(NULL)可能导致程序错误或未定义行为，违反了CWE-252。
- D验证: confirmed / ver_786369c7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 90. hyp_path_155753c8bb03

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_16.c:37
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者能够导致系统资源耗尽，使CreateMutexA失败
- 触发路径: hMutex = CreateMutexA(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_16.c:37; /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_16.c:37; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_16.c:37
- 结论: 未检查CreateMutexA返回值，若创建互斥体失败则hMutex为NULL，导致CloseHandle(NULL)引发未定义行为（如段错误）。
- D验证: confirmed / ver_74adf239
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 91. hyp_path_d05e823a916d

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_18.c:37
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: CreateMutexA函数调用失败，返回NULL
- 触发路径: hMutex = CreateMutexA(NULL, FALSE, NULL); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_18.c:37; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_18.c:37
- 结论: 对CreateMutexA的返回值未进行检查，如果函数调用失败（返回NULL），则后续CloseHandle调用可能传入无效句柄，虽然CloseHandle(NULL)不会导致崩溃，但违反了安全实践，属于API误用，符合CWE-252未检查返回值。
- D验证: confirmed / ver_6f72dc98
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 92. hyp_path_fd5b1a1a1e53

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_15.c:38
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 系统资源不足或互斥体名称冲突导致CreateMutexA失败
- 触发路径: hMutex = CreateMutexA(NULL, FALSE, NULL); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_15.c:38; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_15.c:38
- 结论: 未检查CreateMutexA的返回值，若函数失败返回NULL，后续CloseHandle(NULL)虽不会引发崩溃，但忽略了错误状态，导致程序行为不可预测，违反安全编程规范，符合CWE-252。
- D验证: confirmed / ver_9e2b82d6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 93. hyp_path_d5fbde7ae03d

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_14.c:37
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者可能通过资源耗尽等方式使CreateMutexA失败，但通常不可控
- 触发路径: hMutex = CreateMutexA(NULL, FALSE, NULL); // 未检查返回值 @ CWE252_Unchecked_Return_Value__char_w32CreateMutex_14.c:37; CloseHandle(hMutex); // 若hMutex为NULL，行为未定义 @ CWE252_Unchecked_Return_Value__char_w32CreateMutex_14.c:37
- 结论: 未检查CreateMutexA返回值，若函数失败返回NULL，则后续CloseHandle传入NULL句柄可能导致未定义行为，但Windows上CloseHandle(NULL)通常仅返回错误而不崩溃，风险较低。
- D验证: confirmed / ver_ca8880ad
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 94. hyp_path_b4e15dd0771d

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_01.c:35
- 漏洞类型: null_deref
- CWE: CWE-252; CWE-476
- 风险等级: P0
- 触发条件: 攻击者可通过耗尽系统资源或触发特定条件（如低内存）使CreateMutexW失败。
- 触发路径: hMutex = CreateMutexW(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_01.c:33; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_01.c:35
- 结论: CreateMutexW的返回值未检查，如果函数失败返回NULL，则后续CloseHandle(NULL)将导致未定义行为（如程序崩溃）。
- D验证: confirmed / ver_b74b9e77
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 95. hyp_path_f69e15f0e1fb

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_02.c:37
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 系统资源不足或权限不足可导致CreateMutexW失败，无需攻击者输入
- 触发路径: hMutex = CreateMutexW(NULL, FALSE, NULL); @ CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_02.c:32; CloseHandle(hMutex); @ CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_02.c:37
- 结论: 调用CreateMutexW后未检查返回值，可能导致后续CloseHandle操作在互斥体创建失败时处理无效句柄。虽然CloseHandle(NULL)不会导致崩溃，但违反了安全编码规范，可能掩盖真正的错误，符合CWE-252。
- D验证: confirmed / ver_a12e0212
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 96. hyp_path_2d6731186703

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_04.c:43
- 漏洞类型: CWE-252, CWE-754
- CWE: CWE-252; CWE-754
- 风险等级: P0
- 触发条件: 攻击者无法直接控制CreateMutexW的参数，但可能导致系统资源不足使CreateMutexW失败（如耗尽内核对象）
- 触发路径: hMutex = CreateMutexW(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_04.c:43
- 结论: CreateMutexW的返回值未检查，若创建互斥体失败，则hMutex为NULL，后续调用CloseHandle(NULL)将导致未定义行为（如程序崩溃）。
- D验证: confirmed / ver_de7cbcbe
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 97. hyp_path_1234c074f02e

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_03.c:37
- 漏洞类型: null_deref
- CWE: CWE-252; CWE-476
- 风险等级: P0
- 触发条件: 系统资源不足导致CreateMutexW失败返回NULL
- 触发路径: hMutex = CreateMutexW(NULL, FALSE, NULL); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_03.c:33; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_03.c:37
- 结论: CreateMutexW返回值未检查，若调用失败返回NULL，后续直接使用NULL句柄调用CloseHandle导致空指针解引用（访问冲突）。
- D验证: confirmed / ver_6f30d2d5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 98. hyp_path_b6a734cfa501

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_06.c:42
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: CreateMutexW执行环境可能导致函数失败（例如内存不足、权限不足等）。
- 触发路径: HANDLE hMutex = NULL; @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_06.c:37; hMutex = CreateMutexW(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_06.c:38; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_06.c:42
- 结论: 未检查CreateMutexW的返回值，如果函数失败返回NULL，则后续的CloseHandle(NULL)虽然不会导致崩溃，但违反了安全最佳实践，且可能隐藏错误条件。
- D验证: confirmed / ver_4d1ed9e8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 99. hyp_path_1dd7539e7a0f

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_05.c:43
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者可能通过耗尽系统资源（如大量创建互斥体）来触发CreateMutexW失败，但通常需要本地或特定环境条件。
- 触发路径: hMutex = CreateMutexW(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_05.c:42; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_05.c:43
- 结论: 未检查CreateMutexW返回值，当创建互斥体失败时返回NULL，随后将NULL句柄传递给CloseHandle，可能导致未定义行为或程序崩溃。
- D验证: confirmed / ver_b146c3e4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 100. hyp_path_cdb5d7549a7b

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_07.c:42
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 系统资源不足或权限限制可导致CreateMutexW失败
- 触发路径: hMutex = CreateMutexW(NULL, FALSE, NULL); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_07.c:38; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_07.c:42
- 结论: 调用CreateMutexW后未检查返回值，若函数失败返回NULL，则后续CloseHandle(NULL)虽不崩溃但可能掩盖错误，且不符合安全编程规范，符合CWE-252。
- D验证: confirmed / ver_79d7a3ea
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 101. hyp_path_332297b69493

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_09.c:37
- 漏洞类型: null_deref
- CWE: CWE-252; CWE-476
- 风险等级: P0
- 触发条件: 攻击者无法直接控制，但系统资源受限可能触发；无需攻击者输入
- 触发路径: hMutex = CreateMutexW(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_09.c:37; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_09.c:37
- 结论: 未检查CreateMutexW的返回值，若函数失败则返回NULL，随后在CloseHandle中解引用空指针，导致未定义行为。
- D验证: confirmed / ver_0caff34e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 102. hyp_path_0c1696f8ac1e

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_13.c:37
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 无外部输入依赖，仅需程序执行到此代码路径。
- 触发路径: hMutex = CreateMutexW(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_13.c:37; CloseHandle(hMutex); // 未检查hMutex是否为NULL @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_13.c:39
- 结论: 未检查CreateMutexW的返回值，可能导致在互斥体创建失败时对无效句柄调用CloseHandle，引发程序崩溃或意外行为。
- D验证: confirmed / ver_4222ff4b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 103. hyp_path_a7461a489dd2

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_10.c:37
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者无法直接控制CreateMutexW参数，但系统资源不足或权限问题可能导致函数失败
- 触发路径: hMutex = CreateMutexW(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_10.c:37; CloseHandle(hMutex); // 未检查hMutex是否为NULL @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_10.c:37
- 结论: CreateMutexW函数的返回值未被检查，若函数失败返回NULL，则后续CloseHandle调用将传入无效句柄，可能导致程序异常或未定义行为。
- D验证: confirmed / ver_29cf2d52
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 104. hyp_path_20fe0a68db98

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_14.c:37
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 系统资源不足，导致CreateMutexW返回NULL
- 触发路径: hMutex = CreateMutexW(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_14.c:37; CloseHandle(hMutex); @ 同文件:39
- 结论: 未检查CreateMutexW返回值，若创建互斥体失败则hMutex为NULL，后续CloseHandle传入NULL句柄，虽然CloseHandle(NULL)本身安全，但违反CWE-252未检查返回值的要求。
- D验证: confirmed / ver_9eca05a6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 105. hyp_path_19cd4770e030

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_15.c:38
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 系统资源不足或权限问题导致CreateMutexW失败
- 触发路径: hMutex = CreateMutexW(NULL, FALSE, NULL); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_15.c:33; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_15.c:38
- 结论: 未检查CreateMutexW的返回值，若创建互斥量失败，后续CloseHandle虽不会崩溃，但违反了安全编码规范，可能掩盖资源泄漏或状态错误。
- D验证: confirmed / ver_56dd2581
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 106. hyp_path_5204677026bc

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_18.c:37
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: CreateMutexW函数因资源不足或权限等原因返回NULL
- 触发路径: hMutex = CreateMutexW(NULL, FALSE, NULL); @ L37; CloseHandle(hMutex); // 未检查hMutex是否为NULL @ L37
- 结论: 未检查CreateMutexW的返回值，如果函数失败则hMutex为NULL，导致后续CloseHandle(NULL)调用，虽不会造成安全漏洞但违背安全编程规范。
- D验证: confirmed / ver_a4309dda
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 107. hyp_path_040026fc224f

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_16.c:37
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者能够通过资源耗尽等方式使CreateMutexW失败
- 触发路径: hMutex = CreateMutexW(NULL, FALSE, NULL); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_16.c:37; CloseHandle(hMutex); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_16.c:37
- 结论: 未检查CreateMutexW的返回值，如果函数失败返回NULL，则后续CloseHandle(NULL)会导致未定义行为（如程序崩溃）。
- D验证: confirmed / ver_7516bea2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 108. hyp_path_c09e55527b38

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_12.c:40
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者无法直接控制globalReturnsTrueOrFalse()的返回值，但该值随机，可能导致代码执行到未检查返回值的路径。
- 触发路径: void CWE252_Unchecked_Return_Value__char_remove_12_case0() { @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_12.c:30; if(globalReturnsTrueOrFalse()) { /* NOTE: Do not check the return value */ REMOVE("removemecase0.txt"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_12.c:33-37
- 结论: 在函数globalReturnsTrueOrFalse()返回true时，未检查REMOVE()函数的返回值，可能导致文件删除操作失败而未被发现，属于未检查返回值漏洞。
- D验证: stage_c_preserved / ver_d92f08a2
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 109. hyp_path_37196f4276ce

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_12.c:43
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: globalReturnsTrueOrFalse()返回true（函数行为取决于内部状态，通常无需额外攻击条件）
- 触发路径: void CWE252_Unchecked_Return_Value__char_rename_12_case0() { if(globalReturnsTrueOrFalse()) { /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_12.c:33-35; RENAME(OLD_CASE0_FILE_NAME, "newcase0filename.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_12.c:40
- 结论: 在globalReturnsTrueOrFalse()返回true时，调用RENAME(OLD_CASE0_FILE_NAME, "newcase0filename.txt")后未检查返回值，可能导致文件重命名失败而未被检测，属于未检查返回值漏洞。
- D验证: stage_c_preserved / ver_caf54467
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 110. hyp_path_7b9dcea254f1

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_11.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 程序在`globalReturnsTrue()`为真时执行该代码路径
- 触发路径: REMOVE("removemecase0.txt"); @ 35
- 结论: 未检查remove()函数的返回值，可能导致文件删除失败未被发现
- D验证: stage_c_preserved / ver_88ed6508
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 111. hyp_path_034ded9dc558

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_08.c:48
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 无外部输入，调用该函数即可触发未检查返回值的删除操作
- 触发路径: void CWE252_Unchecked_Return_Value__char_remove_08_case0() { if(staticReturnsTrue()) { @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_08.c:43-44; REMOVE("removemecase0.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_08.c:48
- 结论: 存在未检查返回值的漏洞：在函数CWE252_Unchecked_Return_Value__char_remove_08_case0中，调用REMOVE宏删除文件时未检查其返回值，若删除失败将导致程序无法感知错误，可能引发文件残留或状态不一致。
- D验证: stage_c_preserved / ver_f5feb839
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 112. hyp_path_44a160f55c66

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_11.c:38
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者可能通过控制文件系统状态（如设置低权限、耗尽空间）使rename失败；或程序运行环境满足失败条件。
- 触发路径: RENAME(OLD_CASE0_FILE_NAME, "newcase0filename.txt"); @ CWE252_Unchecked_Return_Value__char_rename_11.c:38
- 结论: 未检查rename()的返回值，可能导致文件重命名操作静默失败，影响文件完整性和后续逻辑。
- D验证: stage_c_preserved / ver_029f02cc
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 113. hyp_path_9f7f2dd731e0

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_08.c:51
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: rename 失败条件（如文件不存在、权限不足）可被触发
- 触发路径: RENAME(OLD_CASE0_FILE_NAME, "newcase0filename.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_08.c:51
- 结论: 函数 rename 的返回值未被检查，可能导致文件重命名失败后程序继续执行，引发后续逻辑错误或数据不一致。
- D验证: stage_c_preserved / ver_0c6f7541
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 114. hyp_path_1263265c7ee4

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_17.c:58
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者提供导致sscanf返回0的输入（如空字符串或仅空白字符）; dataBuffer在sscanf前未初始化或初始值不可控
- 触发路径: if (sscanf(SRC, "%99s\0", data) == EOF) { printLine("sscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_17.c:58
- 结论: sscanf返回值未完全检查：仅检查EOF，未检查是否成功匹配1项。若sscanf返回0，dataBuffer未更新，后续使用未初始化数据。
- D验证: stage_c_preserved / ver_6f85a6d3
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 115. hyp_path_0bce0087d572

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_sscanf_17.c:58
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制输入导致swscanf返回非EOF错误值（如负值）或0
- 触发路径: if (swscanf(SRC, L"%99s\0", data) == EOF) { printLine("swscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_sscanf_17.c:58
- 结论: 未完全检查swscanf返回值：仅检查EOF，未处理其他负值（如输入错误）或零值（未匹配），可能导致未检测到的错误。
- D验证: stage_c_preserved / ver_7afcd1ee
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 116. hyp_path_61426197f4ed

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_01.c:33
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部输入控制文件路径，但remove()调用结果未被检查
- 触发路径: REMOVE("removemecase0.txt"); @ CWE252_Unchecked_Return_Value__char_remove_01.c:33
- 结论: 未检查remove()函数的返回值，如果文件删除失败，程序可能继续执行导致状态不一致或后续逻辑错误（CWE-252）。
- D验证: stage_c_preserved / ver_9a04c06b
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 117. hyp_path_56949a726742

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_02.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 无特殊前提，代码直接调用且不检查返回值。
- 触发路径: REMOVE("removemecase0.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_02.c:35
- 结论: 未检查remove()函数的返回值，可能导致文件删除失败未被检测，影响程序正确性或导致不一致状态。
- D验证: stage_c_preserved / ver_82271939
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 118. hyp_path_bf69c686927c

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_03.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部输入要求，漏洞在于忽略返回值
- 触发路径: { /* NOTE: Do not check the return value */ REMOVE("removemecase0.txt"); } @ L35
- 结论: 未检查remove()的返回值，可能导致文件删除失败被忽略
- D验证: stage_c_preserved / ver_924e89f3
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 119. hyp_path_20c9a9b0ee03

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_scanf_17.c:56
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够提供导致wscanf返回0的输入（如空白行）
- 触发路径: if (wscanf(L"%99s\0", data) == EOF) @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_scanf_17.c:56
- 结论: wscanf的返回值未完全检查，仅检查了EOF，未处理返回0的情况，导致在输入不匹配时data可能未初始化，后续使用可能导致未定义行为。
- D验证: stage_c_preserved / ver_8f93ff92
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 120. hyp_path_746aa38ce0f1

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_05.c:41
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者无法直接控制文件名，但可影响文件系统状态（如修改权限或锁定文件）以导致删除失败。
- 触发路径: 调用入口 @ 入口函数第36行; REMOVE("removemecase0.txt"); @ 第41行
- 结论: 调用remove函数未检查返回值，可能导致删除操作失败时程序继续执行，造成逻辑错误或后续资源泄露。尽管文件名固定，但若文件系统权限异常或文件被锁定，删除失败可能影响程序状态。
- D验证: stage_c_preserved / ver_85c26449
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 121. hyp_path_9a5e60079761

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_07.c:40
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部输入控制，但调用 REMOVE 后未检查返回值
- 触发路径: REMOVE("removemecase0.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_07.c:40
- 结论: 未检查 remove 函数的返回值，可能导致文件删除操作失败而未处理
- D验证: stage_c_preserved / ver_99d3a333
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 122. hyp_path_69262e29434d

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_06.c:40
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够影响文件系统状态（如创建/删除文件、修改权限）或通过其他方式使remove失败。
- 触发路径: /* NOTE: Do not check the return value */ REMOVE("removemecase0.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_06.c:40
- 结论: 函数remove未检查返回值，如果删除文件失败，程序可能继续执行导致后续逻辑错误或安全假设失效。
- D验证: stage_c_preserved / ver_ba73bf87
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 123. hyp_path_fc7b3d43bc23

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_09.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: /* NOTE: Do not check the return value */ REMOVE("removemecase0.txt"); @ L35
- 结论: Unchecked return value of REMOVE function, leading to potential failure to detect file removal errors.
- D验证: stage_c_preserved / ver_977998f1
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 124. hyp_path_6669778b5c7d

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_13.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 无，文件路径硬编码，但删除操作可能失败。
- 触发路径: REMOVE("removemecase0.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_13.c:35
- 结论: CWE252漏洞：调用remove函数删除文件时未检查返回值，可能导致删除失败但程序继续执行，造成状态不一致或后续逻辑错误。
- D验证: stage_c_preserved / ver_5b9b350c
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 125. hyp_path_43ac9bddb263

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_10.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者可能通过影响文件系统状态（如权限、路径存在性）导致remove失败，但无需直接控制参数。
- 触发路径: REMOVE("removemecase0.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_10.c:35
- 结论: 函数remove()的返回值未被检查，可能导致文件删除操作失败时无法感知，从而影响后续逻辑或安全状态。
- D验证: stage_c_preserved / ver_0a33fe46
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 126. hyp_path_2837613035ce

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_14.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: REMOVE("removemecase0.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_14.c:35
- 结论: Unchecked return value of remove() function
- D验证: stage_c_preserved / ver_d552910f
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 127. hyp_path_9c214aa3aedd

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_15.c:36
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部输入，但函数返回值可能指示错误（如文件不存在或权限不足），未检查返回值可能导致程序忽略错误状态
- 触发路径: REMOVE("removemecase0.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_15.c:36
- 结论: 未检查remove函数的返回值，可能导致遗漏错误处理
- D验证: stage_c_preserved / ver_d6fc5cb4
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 128. hyp_path_36e87d05d661

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_16.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: REMOVE("removemecase0.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_16.c:35
- 结论: CWE252: Unchecked Return Value - REMOVE function return value not checked
- D验证: stage_c_preserved / ver_a4b9e907
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 129. hyp_path_7e6a77657898

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_17.c:36
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 文件系统中存在或不存在目标文件（"removemecase0.txt"），但无需攻击者主动控制输入。
- 触发路径: REMOVE("removemecase0.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_17.c:36
- 结论: 调用remove函数删除文件后未检查返回值，可能导致删除失败而未被察觉，属于未检查返回值的漏洞。
- D验证: stage_c_preserved / ver_7dcdf222
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 130. hyp_path_2f766f3682fb

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_remove_18.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者可能通过其他手段影响删除操作的成功与否（如权限、文件存在性等），但无需用户输入控制。
- 触发路径: /* NOTE: Do not check the return value */ REMOVE("removemecase0.txt"); @ 35
- 结论: 未检查 remove() 函数的返回值，可能导致删除操作失败而不被察觉。
- D验证: stage_c_preserved / ver_b795b5c4
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 131. hyp_path_2230864d397f

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_01.c:36
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: N/A
- 触发路径: RENAME(OLD_CASE0_FILE_NAME, "newcase0filename.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_01.c:36
- 结论: 调用rename函数未检查返回值，违反CWE-252规范，可能导致文件操作失败时程序状态不一致
- D验证: stage_c_preserved / ver_269732d4
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 132. hyp_path_4282ddbd4175

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_03.c:38
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够导致rename操作失败（例如通过影响文件系统状态，如创建同名目录或调整权限）
- 触发路径: RENAME(OLD_CASE0_FILE_NAME, "newcase0filename.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_03.c:38
- 结论: 未检查rename函数返回值，可能导致文件重命名操作失败时程序继续执行，造成文件状态不一致或后续逻辑错误
- D验证: stage_c_preserved / ver_c7363318
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 133. hyp_path_8ae402115899

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_05.c:44
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 存在文件系统操作，函数返回值未被检查
- 触发路径: RENAME(OLD_CASE0_FILE_NAME, "newcase0filename.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_05.c:44
- 结论: API misuse: rename函数返回值未检查，可能导致文件操作失败未被处理
- D验证: stage_c_preserved / ver_7c2011d8
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 134. hyp_path_99de7ba45c24

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_02.c:38
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者无法直接控制RENAME的参数（均为硬编码字符串），但可影响文件系统状态（如删除源文件或修改权限）以触发错误。
- 触发路径: RENAME(OLD_CASE0_FILE_NAME, "newcase0filename.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_02.c:38
- 结论: 在调用RENAME函数后未检查其返回值，违反了CWE-252。如果重命名操作失败，程序无法感知，但当前代码片段无后续操作依赖该返回值，因此实际安全影响较低。
- D验证: stage_c_preserved / ver_427d4f6b
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 135. hyp_path_03aba10f7c72

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_04.c:44
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 无特殊前提，任何调用场景下返回值均被忽略。
- 触发路径: RENAME(OLD_CASE0_FILE_NAME, "newcase0filename.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_04.c:44
- 结论: 未检查rename函数的返回值，可能导致文件重命名失败时程序继续执行，造成逻辑错误或资源状态不一致。
- D验证: stage_c_preserved / ver_b4978222
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 136. hyp_path_0ef902126b30

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_06.c:43
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: RENAME(OLD_CASE0_FILE_NAME, "newcase0filename.txt"); @ 43
- 结论: 未检查rename函数的返回值，可能导致文件重命名失败不被察觉，违反CWE-252。
- D验证: stage_c_preserved / ver_b62b1d79
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 137. hyp_path_9e5ddf7407a9

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_07.c:43
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无直接攻击者输入，但文件系统状态可能由外部因素改变，如并发操作或权限变更。
- 触发路径: RENAME(OLD_CASE0_FILE_NAME, "newcase0filename.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_07.c:43
- 结论: 未检查rename函数的返回值，可能导致文件重命名操作失败而不被察觉，影响后续文件操作逻辑或数据完整性。
- D验证: stage_c_preserved / ver_26bd0f52
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 138. hyp_path_7ff8d26f6238

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_09.c:38
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: No external input required; the vulnerability is inherent in the API misuse pattern.
- 触发路径: RENAME(OLD_CASE0_FILE_NAME, "newcase0filename.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_09.c:38
- 结论: CWE252: Unchecked Return Value in rename() - The return value of rename() is not checked, which can lead to silent failures or data loss.
- D验证: stage_c_preserved / ver_c8b3e09e
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 139. hyp_path_5260aa63482b

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_14.c:38
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者可能通过影响文件系统状态（如权限、空间）导致RENAME失败，但无需直接控制输入。
- 触发路径: RENAME(OLD_CASE0_FILE_NAME, "newcase0filename.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_14.c:38
- 结论: 未检查RENAME函数的返回值，如果重命名失败，程序可能继续执行，导致后续逻辑错误或安全风险。
- D验证: stage_c_preserved / ver_2f692ecb
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 140. hyp_path_2ee39fc1be53

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_15.c:39
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: RENAME(OLD_CASE0_FILE_NAME, "newcase0filename.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_15.c:39
- 结论: Unchecked return value of RENAME (rename) function
- D验证: stage_c_preserved / ver_e35fdd0c
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 141. hyp_path_2424d329d4da

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_10.c:38
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者无法直接控制rename的参数（为硬编码常量），但可能通过文件系统状态或权限间接影响操作结果。
- 触发路径: RENAME(OLD_CASE0_FILE_NAME, "newcase0filename.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_10.c:38
- 结论: 未检查rename()的返回值，可能导致程序忽略错误，在文件操作失败后继续执行，进而引发不可预测的行为或状态不一致。
- D验证: stage_c_preserved / ver_70e5034b
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 142. hyp_path_68cd8e7db8c3

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_16.c:38
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者能够通过某种方式使rename失败，例如具有文件系统操作权限或竞争条件。
- 触发路径: RENAME(OLD_CASE0_FILE_NAME, "newcase0filename.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_16.c:38
- 结论: 未检查rename函数返回值，如果重命名失败（例如文件不存在、权限不足或路径错误），程序无法获知错误，可能导致后续操作基于错误的文件状态，造成数据不一致或安全漏洞。
- D验证: stage_c_preserved / ver_78f3937a
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 143. hyp_path_39dcc1ded72f

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_17.c:39
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 无外部输入控制，但程序本身忽略返回值，任何重命名失败事件均可触发漏洞。
- 触发路径: RENAME(OLD_CASE0_FILE_NAME, "newcase0filename.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_17.c:39
- 结论: CWE252: 未检查rename函数的返回值，可能导致重命名操作失败后程序状态不一致或后续错误。
- D验证: stage_c_preserved / ver_f37c0200
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 144. hyp_path_8dfc6e1b9cd2

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_13.c:38
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: rename调用可能因文件系统状态（如权限不足、磁盘满载等）而失败，但返回值未被检查。
- 触发路径: RENAME(OLD_CASE0_FILE_NAME, "newcase0filename.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_13.c:38
- 结论: 未检查rename函数返回值，可能导致操作失败时程序继续执行，引发数据不一致或逻辑错误。但缺乏攻击者可控输入，利用难度高。
- D验证: stage_c_preserved / ver_edaefcaf
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 145. hyp_path_a0cd44daa387

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_18.c:38
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P0
- 触发条件: 攻击者需要能够影响文件系统状态（如创建竞争条件）或提供特殊环境导致rename失败。但更直接地，漏洞本身不需要攻击者主动控制输入，而是代码可靠性缺陷。
- 触发路径: /* NOTE: Do not check the return value */ RENAME(OLD_CASE0_FILE_NAME, "newcase0filename.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_rename_18.c:38
- 结论: 存在未检查rename函数返回值的漏洞。调用rename时未检查其返回值，如果rename失败（例如权限不足、文件不存在等），程序无法感知错误，可能导致后续操作基于错误的状态，进而引发安全风险，如文件被篡改或竞态条件利用。
- D验证: stage_c_preserved / ver_2914f76e
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 146. hyp_path_1f8b92d4b416

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_12.c:68
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够通过stdin输入，使得fscanf返回0或非EOF的负值（即未成功读取任何字段），导致返回值未被充分检查，后续使用dataBuffer中的未初始化数据。
- 触发路径: char * data = dataBuffer; /* ALT: check the return value */ if (fscanf(stdin, "%99s\0", data) == EOF) { printLine("fscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_12.c:66-70; char * data = dataBuffer; /* ALT: check the return value */ if (fscanf(stdin, "%99s\0", data) == EOF) { printLine("fscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_12.c:80-84
- 结论: 未完全检查fscanf返回值，仅检查EOF，未检查成功读取的项目数（应为1），导致可能使用未初始化数据或忽略错误状态。
- D验证: stage_c_preserved / ver_74e3fb2c
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 147. hyp_path_9bf9626872f1

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_12.c:70
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Attacker can control SRC input to sscanf
- 触发路径: if (sscanf(SRC, "%99s\0", data) == EOF) { printLine("sscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_12.c:70
- 结论: Unchecked return value of sscanf: only checked for EOF, other failure cases (e.g., return 0) not handled, leading to potential use of uninitialized or incorrect data if sscanf fails partially (e.g., no match). No sink usage of 'data' observed in this snippet, so vulnerability path is incomplete, requiring dynamic confirmation.
- D验证: stage_c_preserved / ver_3d490dcc
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 148. hyp_path_04e5009d8479

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_12.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者无法直接控制globalReturnsTrueOrFalse()的返回值，该函数为随机返回；但若攻击者能影响全局状态（如环境变量）改变该函数行为，则可能触发漏洞分支
- 触发路径: void CWE252_Unchecked_Return_Value__char_fprintf_12_case0() { if(globalReturnsTrueOrFalse()) { @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_12.c:24-25; /* NOTE: Do not check the return value */ fprintf(stdout, "%s\n", "string"); } else @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_12.c:29-31
- 结论: 存在CWE-252未检查返回值漏洞：在特定条件下（globalReturnsTrueOrFalse()返回true），fprintf的返回值未被检查，可能导致输出不完整或错误未被处理。
- D验证: stage_c_preserved / ver_d28c82dd
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 149. hyp_path_fdff3e8b1560

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_12.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无需外部输入，漏洞在任意调用时存在（取决于执行路径）
- 触发路径: fputc((int)'A', stdout); // 未检查返回值 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_12.c:34
- 结论: 存在CWE-252: 未检查返回值漏洞：在CWE252_Unchecked_Return_Value__char_fputc_12.c中，存在对fputc()的返回值未检查的情况（第34行），但也在同一函数中提供了检查返回值的替代路径（第32-36行）。由于存在未检查返回值的分支，可能导致写入失败未被检测。
- D验证: stage_c_preserved / ver_9ad23e6c
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 150. hyp_path_0fc57a7ccf15

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_12.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: globalReturnsTrueOrFalse() 返回 true，进入不检查返回值的分支
- 触发路径: fputs("string", stdout); @ L34
- 结论: CWE252_Unchecked_Return_Value: fputs 返回值在分支中未检查
- D验证: stage_c_preserved / ver_40b15de7
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 151. hyp_path_8c8113204613

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_12.c:45
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够控制stdin输入流，使得fscanf调用失败（例如提供空输入或提前EOF）。
- 触发路径: void CWE252_Unchecked_Return_Value__char_fscanf_12_case0() @ 入口函数; if(globalReturnsTrueOrFalse()) @ 分支判断; fscanf(stdin, "%99s", data); // 第34行，无返回值检查 @ 未检查返回值的fscanf调用
- 结论: 在CWE252_Unchecked_Return_Value__char_fscanf_12_case0函数中，当globalReturnsTrueOrFalse()返回true时，存在一条未检查fscanf返回值的路径（第34行），违反CWE-252。尽管当前代码片段未展示后续对data的使用，但未检查返回值本身构成代码缺陷，且Juliet测试用例通常包含后续操作，因此存在潜在安全风险。
- D验证: stage_c_preserved / ver_f38e439e
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 152. hyp_path_c0d6b3973ed2

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_11.c:59
- 漏洞类型: CWE-252, CWE-561
- CWE: CWE-252; CWE-561
- 风险等级: P1
- 触发条件: 攻击者能够向stdin提供输入，使得fscanf返回EOF或错误。
- 触发路径: static void case11() { @ case11函数入口 (line 44); if(globalReturnsFalse()) { /* INCIDENTAL: CWE 561 Dead Code */ @ if(globalReturnsFalse()) 条件 (line 45); （未提供代码片段，推测为无检查的fscanf调用） @ 条件为false，进入else分支，但else分支未提供，推测存在无检查的fscanf调用; fscanf(stdin, "%99s\0", data); // 返回值未检查 @ 实际执行到的fscanf调用（假设在else分支或后续代码中）
- 结论: 在case11函数中，由于globalReturnsFalse()返回false，导致检查fscanf返回值的代码成为死代码（CWE 561），实际执行路径未检查fscanf的返回值，从而存在未检查返回值的漏洞（CWE-252）。攻击者可通过提供非法输入使fscanf失败，程序未处理错误状态，可能引发未定义行为。
- D验证: stage_c_preserved / ver_d0c5bbbc
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 153. hyp_path_de9ce5de83e2

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_12.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够影响stdout状态（如关闭标准输出）使putc调用失败并返回EOF，但通常需要一定权限；更常见的是作为内部错误被忽略。
- 触发路径: void CWE252_Unchecked_Return_Value__char_putc_12_case0() { @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_12.c:24; if(globalReturnsTrueOrFalse()) { @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_12.c:26; /* NOTE: Do not check the return value */ putc((int)'A', stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_12.c:28-29
- 结论: 在代码路径中，当globalReturnsTrueOrFalse()返回真时，putc()的返回值未被检查，可能导致未检测到的输出错误，符合CWE-252未检查返回值漏洞。
- D验证: stage_c_preserved / ver_6b4ac4c8
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 154. hyp_path_92f8966634cc

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_12.c:40
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: The function globalReturnsTrueOrFalse() must return true to enter the branch that does not check the return value.
- 触发路径: /* NOTE: Do not check the return value */ PUTS("string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_12.c:33-37
- 结论: Unchecked return value of puts() in one branch, leading to potential failure to detect I/O error (CWE-252).
- D验证: stage_c_preserved / ver_e4bdd10f
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 155. hyp_path_fb10e456c47e

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_12.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者无需特殊输入，程序正常执行即可触发此分支，但分支由随机函数决定。
- 触发路径: void CWE252_Unchecked_Return_Value__char_putchar_12_case0() @ 函数入口; if(globalReturnsTrueOrFalse()) @ 条件判断; putchar((int)'A'); // 没有检查返回值 @ 未检查返回值分支
- 结论: 未检查putchar的返回值，可能导致输出失败，符合CWE-252未检查返回值漏洞，但路径由随机函数决定，实际风险较低。
- D验证: stage_c_preserved / ver_10e8b24d
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 156. hyp_path_da2b257bc3fd

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_12.c:45
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Attacker provides input via stdin
- 触发路径: char * data = dataBuffer; /* NOTE: Do not check the return value */ scanf("%99s\0", data); @ L32-36
- 结论: CWE-252: Unchecked Return Value of scanf in bad path
- D验证: stage_c_preserved / ver_cd4f097e
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 157. hyp_path_9d7719cebcb3

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_08.c:74
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够提供恶意输入给SRC，使得sscanf解析失败或返回异常
- 触发路径: static void case11() { if(staticReturnsFalse()) { ... } else { ... } } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_08.c:59-63; if (sscanf(SRC, "%99s\0", data) == EOF) { printLine("sscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_08.c:74; 实际执行时跳过该if，sscanf返回值未检查 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_08.c:74
- 结论: 在staticReturnsFalse()永远返回false的死代码分支中，sscanf返回值被检查（if (sscanf(...) == EOF)），但实际执行路径未检查sscanf返回值，导致未处理输入错误或解析失败，可能引发后续操作使用未初始化的数据。
- D验证: stage_c_preserved / ver_51d49e1d
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 158. hyp_path_e85d4ce81182

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_11.c:59
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Attacker provides input via stdin
- 触发路径: if (scanf("%99s\0", data) == EOF) @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_11.c:59
- 结论: CWE-252: Unchecked Return Value of scanf - only checks for EOF, not for successful read (return value should be 1)
- D验证: stage_c_preserved / ver_d33fc6ce
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 159. hyp_path_62940eaf865e

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_11.c:67
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够控制SRC的内容，使其长度接近缓冲区限制，导致snprintf可能失败。
- 触发路径: static void case11() { if(globalReturnsFalse()) { /* 死代码 */ } else { /* 实际执行路径，但代码未显示 */ } @ case11函数入口; if (SNPRINTF(data,100-strlen(SRC)-1, "%s\n", SRC) < 0) { printLine("snprintf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_11.c:67
- 结论: 在CWE252测试案例中，snprintf的返回值在不可达分支中被检查，而实际执行路径（else分支）未显示对返回值的检查，导致可能未检测到snprintf失败，从而引发未检查返回值漏洞。
- D验证: stage_c_preserved / ver_cdfbea84
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 160. hyp_path_a8bf36b6c6e9

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_12.c:53
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: globalReturnsTrueOrFalse() returns true (unpredictable, but path exists)
- 触发路径: void CWE252_Unchecked_Return_Value__char_snprintf_12_case0() { if(globalReturnsTrueOrFalse()) { @ L32-36; SNPRINTF(data,100-strlen(SRC)-1, "%s\n", SRC); @ L42
- 结论: CWE252: Unchecked Return Value of snprintf
- D验证: stage_c_preserved / ver_926591ce
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 161. hyp_path_b21555494345

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_12.c:47
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制输入字符串SRC（如果SRC来自外部用户输入）
- 触发路径: void CWE252_Unchecked_Return_Value__char_sscanf_12_case0() { if(globalReturnsTrueOrFalse()) { @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_12.c:26-30; char * data = dataBuffer; /* NOTE: Do not check the return value */ sscanf(SRC, "%99s\0", data); } } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_12.c:34-38
- 结论: 未检查sscanf返回值，可能导致数据读取失败或使用未初始化数据
- D验证: stage_c_preserved / ver_ad4bb229
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 162. hyp_path_fc5feab6f7d9

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__w32ImpersonateSelf_12.c:33
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: globalReturnsTrueOrFalse()返回真
- 触发路径: if(globalReturnsTrueOrFalse()) { @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__w32ImpersonateSelf_12.c:25; ImpersonateSelf(SecurityImpersonation); // 未检查返回值 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__w32ImpersonateSelf_12.c:28
- 结论: 存在未检查ImpersonateSelf函数返回值的路径，可能导致权限模拟失败后程序仍然继续运行，造成安全漏洞。
- D验证: stage_c_preserved / ver_54b341df
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 163. hyp_path_9d0fc44e874e

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fprintf_12.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: fwprintf(stdout, L"%s\n", L"string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fprintf_12.c:29
- 结论: Unchecked return value of fwprintf
- D验证: stage_c_preserved / ver_362bd812
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 164. hyp_path_2a4c439d7f54

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fputc_12.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部输入控制，该缺陷在特定分支路径下自动触发
- 触发路径: void CWE252_Unchecked_Return_Value__wchar_t_fputc_12_case0() { @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fputc_12.c:24; if(globalReturnsTrueOrFalse()) { @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fputc_12.c:25; { /* NOTE: Do not check the return value */ fputwc((wchar_t)L'A', stdout); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fputc_12.c:27-31
- 结论: 在CWE252_Unchecked_Return_Value__wchar_t_fputc_12_case0函数中，当globalReturnsTrueOrFalse()返回true时，执行fputwc并忽略其返回值，未检查写入是否成功，可能导致未检测到的写入错误，符合CWE-252未检查返回值缺陷。
- D验证: stage_c_preserved / ver_540d85eb
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 165. hyp_path_c3f7b66e579e

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fputs_12.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 程序执行路径进入globalReturnsTrueOrFalse()为真的分支
- 触发路径: void CWE252_Unchecked_Return_Value__wchar_t_fputs_12_case0() { @ 函数入口; if(globalReturnsTrueOrFalse()) { @ 条件判断; fputws(L"string", stdout); @ 未检查返回值调用
- 结论: 在globalReturnsTrueOrFalse()返回真值时，fputws函数的返回值未被检查，可能导致未检测到的写入错误，符合CWE-252未检查返回值漏洞。
- D验证: stage_c_preserved / ver_5825c142
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 166. hyp_path_7091f22f8926

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fscanf_12.c:45
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够影响stdin输入流，使fwscanf失败；或环境导致输入错误
- 触发路径: if(globalReturnsTrueOrFalse()) @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fscanf_12.c:26; fwscanf(stdin, L"%99s", data); // 返回值未检查 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fscanf_12.c:34
- 结论: 在CWE252_Unchecked_Return_Value__wchar_t_fscanf_12_case0函数中，当globalReturnsTrueOrFalse()返回true时，执行未检查fwscanf返回值的分支，若fwscanf失败，dataBuffer内容未定义，但后续代码未使用data，因此实际风险较低。
- D验证: stage_c_preserved / ver_c7710081
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 167. hyp_path_c4acb472ec6b

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_putc_12.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者可能影响globalReturnsTrueOrFalse的返回值（但此处为固定逻辑，取决于运行环境）或依赖运行环境使得putwc可能失败
- 触发路径: void CWE252_Unchecked_Return_Value__wchar_t_putc_12_case0() { if(globalReturnsTrueOrFalse()) { /* NOTE: Do not check the return value */ @ 24-28; putwc((wchar_t)L'A', stdout); @ 27-31
- 结论: 在函数CWE252_Unchecked_Return_Value__wchar_t_putc_12_case0中，当globalReturnsTrueOrFalse()返回真时，执行未检查putwc返回值的分支，违反CWE-252（未检查返回值），可能导致写入失败不被察觉。
- D验证: stage_c_preserved / ver_927d4523
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 168. hyp_path_71e494132fa7

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_putchar_12.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者无法直接控制globalReturnsTrueOrFalse()的返回值，但依赖运行时环境；当该函数返回true时，进入未检查返回值的分支。
- 触发路径: void CWE252_Unchecked_Return_Value__wchar_t_putchar_12_case0() { if(globalReturnsTrueOrFalse()) { /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_putchar_12.c:24-28; putwchar((wchar_t)L'A'); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_putchar_12.c:29
- 结论: 存在未检查putwchar返回值的漏洞，可能导致在写失败时程序未正确处理。
- D验证: stage_c_preserved / ver_e3d9a7e4
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 169. hyp_path_ed9c23ef1e4b

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_puts_12.c:40
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: globalReturnsTrueOrFalse() returns true
- 触发路径: void CWE252_Unchecked_Return_Value__wchar_t_puts_12_case0() { if(globalReturnsTrueOrFalse()) { /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_puts_12.c:30-34; PUTS(L"string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_puts_12.c:35
- 结论: CWE-252 Unchecked Return Value: PUTS return value not checked in the bad branch
- D验证: stage_c_preserved / ver_2db6ff37
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 170. hyp_path_ad83327d1614

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_remove_12.c:40
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者无法直接控制文件名，但可能通过影响文件系统状态（如权限、磁盘满等）导致删除操作失败，而失败未被检测到。
- 触发路径: /* NOTE: Do not check the return value */ REMOVE(L"removemecase0.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_remove_12.c:33-37
- 结论: 存在未检查函数返回值的漏洞，代码中有一条路径（当globalReturnsTrueOrFalse()返回真时）未检查REMOVE函数的返回值，可能导致删除操作失败未被正确处理。
- D验证: stage_c_preserved / ver_93b5120b
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 171. hyp_path_fd47f4312f68

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_rename_12.c:43
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 程序执行流进入globalReturnsTrueOrFalse()返回true的分支，该分支未检查RENAME返回值；虽无外部输入控制，但分支内部逻辑即构成漏洞
- 触发路径: void CWE252_Unchecked_Return_Value__wchar_t_rename_12_case0() @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_rename_12.c:33; if(globalReturnsTrueOrFalse()) { /* NOTE: Do not check the return value */ RENAME(OLD_CASE0_FILE_NAME, L"newcase0filename.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_rename_12.c:35-36; RENAME(OLD_CASE0_FILE_NAME, L"newcase0filename.txt"); // 返回值未检查 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_rename_12.c:36
- 结论: 在CWE252_Unchecked_Return_Value__wchar_t_rename_12_case0函数中，当globalReturnsTrueOrFalse()返回true时，RENAME函数的返回值未被检查，违反了CWE252（未检查返回值）规范，可能导致重命名操作失败时无法及时发现并处理错误。
- D验证: stage_c_preserved / ver_71217638
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 172. hyp_path_20d9dcecf213

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_scanf_12.c:45
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够影响输入流，使得wscanf调用失败（例如关闭标准输入或提供非法数据导致错误）
- 触发路径: void CWE252_Unchecked_Return_Value__wchar_t_scanf_12_case0() { if(globalReturnsTrueOrFalse()) { @ L24-28; wchar_t * data = dataBuffer; /* NOTE: Do not check the return value */ wscanf(L"%99s\0", data); } } @ L32-36
- 结论: 在未检查wscanf返回值的代码路径中，如果wscanf失败（返回EOF），程序会继续使用可能未初始化的dataBuffer，导致未定义行为，可能被攻击者利用造成信息泄露或程序崩溃。
- D验证: stage_c_preserved / ver_47315657
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 173. hyp_path_11005ec82ded

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_snprintf_12.c:53
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部输入控制，但程序执行路径进入bad分支（globalReturnsTrueOrFalse返回false时）即可触发。
- 触发路径: SNPRINTF(data,100-wcslen(SRC)-1, L"%s\n", SRC); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_snprintf_12.c:42
- 结论: 在bad分支中，swprintf的返回值未被检查，可能导致部分输出或错误未被处理，符合CWE-252（未检查返回值）漏洞。
- D验证: stage_c_preserved / ver_f8d71a6c
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 174. hyp_path_d64e3b1fe343

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_sscanf_11.c:61
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者无法直接控制globalReturnsFalse()的返回值，但假设内部逻辑或环境导致其返回true
- 触发路径: static void case11() { if(globalReturnsFalse()) { @ 46-48; wchar_t * data = dataBuffer; /* ALT: check the return value */ if (swscanf(SRC, L"%99s\0", data) == EOF) { printLine("swscanf failed!"); } @ 59-61
- 结论: 在死代码分支中，swscanf的返回值仅检查了EOF，忽略了其他失败情况（如返回0），可能导致后续使用未初始化的data缓冲区。但该分支实际不可达，需要假设globalReturnsFalse()返回true。
- D验证: stage_c_preserved / ver_dd5b065e
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 175. hyp_path_2ee88aceba92

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_sscanf_12.c:47
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够控制输入SRC，使得swscanf返回非EOF（但未检查返回值导致data可能未被正确写入）
- 触发路径: wchar_t * data = dataBuffer; /* NOTE: Do not check the return value */ swscanf(SRC, L"%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_sscanf_12.c:34-38
- 结论: 未检查swscanf返回值，可能导致后续使用未初始化的数据
- D验证: stage_c_preserved / ver_50947e05
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 176. hyp_path_2d8123bba826

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_09.c:59
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Attacker can provide input via stdin
- 触发路径: if (fscanf(stdin, "%99s\0", data) == EOF) { printLine("fscanf failed!"); } @ 59
- 结论: Unchecked return value of fscanf: only checks for EOF, but not for other failure conditions (e.g., input mismatch)
- D验证: stage_c_preserved / ver_ca0c3468
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 177. hyp_path_c9e947abf4f6

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_11.c:78
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制stdin输入
- 触发路径: if (fscanf(stdin, "%99s\0", data) == EOF) { printLine("fscanf failed!"); } @ L78
- 结论: CWE-252: 未检查返回值 - fscanf返回值仅检查EOF，未检查成功匹配数，可能导致未初始化数据使用
- D验证: stage_c_preserved / ver_c712c624
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 178. hyp_path_c9e2808d383a

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_10.c:59
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够提供输入，使得fscanf匹配失败（返回0），例如输入以空格开头或非字符串格式。
- 触发路径: if (fscanf(stdin, "%99s\0", data) == EOF) { printLine("fscanf failed!"); } @ 59; 假设后续使用data，但证据中无对应代码 @ 未明确
- 结论: fscanf函数的返回值检查不完整，仅检查了EOF错误，未检查其他错误（如匹配失败返回0），可能导致后续使用未初始化的缓冲区。
- D验证: stage_c_preserved / ver_418e07c5
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 179. hyp_path_cca844278fcf

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_11.c:78
- 漏洞类型: CWE-252, CWE-457
- CWE: CWE-252; CWE-457
- 风险等级: P1
- 触发条件: 攻击者能够输入导致scanf返回0（如空输入），导致data未正常写入，后续可能使用未初始化内容
- 触发路径: if (scanf("%99s\0", data) == EOF) { printLine("scanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_11.c:78
- 结论: 未完全检查scanf返回值，可能使用未初始化内存
- D验证: stage_c_preserved / ver_2aab54a3
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 180. hyp_path_8451bc0898a0

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_05.c:73
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制SRC的内容或长度，导致snprintf输出截断，但返回值非负从而不被检测
- 触发路径: if (SNPRINTF(data,100-strlen(SRC)-1, "%s\n", SRC) < 0) { printLine("snprintf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_05.c:73
- 结论: snprintf返回值检查不完整，仅检查了负值（失败情况），未检查截断情况（返回值小于缓冲区大小但非负），可能导致数据丢失或未正确处理，符合CWE-252未检查返回值。
- D验证: stage_c_preserved / ver_1345ebb5
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 181. hyp_path_1d6d0216dc55

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_08.c:93
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制sscanf的输入（SRC），使得sscanf返回0（例如输入为空或格式不匹配），导致实际未读取任何数据，但程序未处理该情况。
- 触发路径: static void case12() { if(staticReturnsTrue()) { @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_08.c:83; if (sscanf(SRC, "%99s\0", data) == EOF) { printLine("sscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_08.c:93
- 结论: CWE-252: Unchecked Return Value - sscanf返回值检查不完整，仅检查EOF，未检查返回0的情况，导致未读取数据时仍使用未更新的缓冲区。
- D验证: stage_c_preserved / ver_95ebc413
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 182. hyp_path_0766317f1001

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_05.c:67
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Attacker can control the input via SRC (e.g., command line or file input in Juliet context)
- 触发路径: if (sscanf(SRC, "%99s\0", data) == EOF) { printLine("sscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_05.c:67
- 结论: Vulnerability: Unchecked return value of sscanf - only checking for EOF, not for other failure values (e.g., 0 when input does not match format).
- D验证: stage_c_preserved / ver_0adb4c71
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 183. hyp_path_2db23bdcd876

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_09.c:61
- 漏洞类型: CWE-252, CWE-253
- CWE: CWE-252; CWE-253
- 风险等级: P1
- 触发条件: 攻击者能够控制SRC的内容
- 触发路径: if (sscanf(SRC, "%99s\0", data) == EOF) { printLine("sscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_09.c:61
- 结论: sscanf返回值检查不完整，只检查了EOF，未检查返回0的情况，导致当输入不匹配格式时data未更新，存在未正确处理返回值的漏洞。
- D验证: stage_c_preserved / ver_904c906e
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 184. hyp_path_66cbfbc3b04a

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_14.c:61
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够直接或间接控制SRC的内容; sscanf返回0（非EOF）时未处理
- 触发路径: if (sscanf(SRC, "%99s\0", data) == EOF) { printLine("sscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_14.c:61
- 结论: sscanf返回值检查不充分：仅检查是否等于EOF，未检查返回0的情况。如果sscanf返回0（输入为空或格式不匹配），则data保持未初始化状态，可能导致后续使用未初始化数据。
- D验证: stage_c_preserved / ver_b34d074a
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 185. hyp_path_6a80a775aecf

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fscanf_08.c:91
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够通过stdin提供输入，使得fwscanf返回非EOF的错误码（如输入格式不匹配）。
- 触发路径: static void case12() { if(staticReturnsTrue()) { { @ L81-85; wchar_t * data = dataBuffer; if (fwscanf(stdin, L"%99s\0", data) == EOF) { printLine("fwscanf failed!"); } @ L89-93
- 结论: fwscanf返回值检查不完整：只处理了EOF情况，忽略了其他错误返回值（如匹配失败或输入错误），可能导致未处理的错误状态。
- D验证: stage_c_preserved / ver_79c086be
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 186. hyp_path_63da5901c190

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_snprintf_08.c:99
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够通过某种方式影响SRC字符串的长度或内容，使其超过缓冲区可容纳的大小。
- 触发路径: static void case12() { @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_snprintf_08.c:89; if(staticReturnsTrue()) { @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_snprintf_08.c:91; if (SNPRINTF(data,100-wcslen(SRC)-1, L"%s\n", SRC) < 0) { printLine("snwprintf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_snprintf_08.c:99
- 结论: 函数case12中调用SNPRINTF（实际为swprintf或snwprintf）时，返回值仅检查了负值（错误），但未检查返回值是否等于或大于缓冲区大小，导致数据截断时无法被感知，可能引发后续字符串处理漏洞或信息泄露。
- D验证: stage_c_preserved / ver_37134a16
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 187. hyp_path_0c108cea27cc

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_sscanf_11.c:80
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够控制SRC的内容，使其不匹配格式字符串，导致swscanf返回0而未被检测。
- 触发路径: if (swscanf(SRC, L"%99s\0", data) == EOF) @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_sscanf_11.c:80; 当SRC内容不匹配格式时，swscanf返回0，不等于EOF，因此不执行错误处理。 @ 同上
- 结论: swscanf的返回值检查不完整，仅检查是否等于EOF，但忽略了其他可能的错误返回值（如0表示匹配失败），可能导致未处理的错误状态。
- D验证: stage_c_preserved / ver_64802198
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 188. hyp_path_e8bd86a460e7

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_sscanf_13.c:61
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: SRC变量由外部输入控制或可被攻击者影响
- 触发路径: if (swscanf(SRC, L"%99s\0", data) == EOF) { printLine("swscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_sscanf_13.c:61
- 结论: CWE-252: Unchecked Return Value - 对swscanf的返回值仅检查了EOF，未检查实际匹配项数，可能导致未检测到的输入错误
- D验证: stage_c_preserved / ver_57edf6d8
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 189. hyp_path_176ad5d5414a

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_03.c:78
- 漏洞类型: CWE-252, CWE-456
- CWE: CWE-252; CWE-456
- 风险等级: P2
- 触发条件: 攻击者能够通过stdin提供输入，使fscanf返回0（例如输入空行）且未触发EOF，并假设后续代码存在对data的未初始化使用（但当前代码片段未展示）。
- 触发路径: if (fscanf(stdin, "%99s\0", data) == EOF) { printLine("fscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_03.c:78
- 结论: fscanf返回值检查不完整，仅检查EOF而未检查成功读取数，若fscanf返回0（例如输入空行未达EOF），则data缓冲区内容未被更新；但后续代码中未发现对data的进一步使用，漏洞路径未闭合。
- D验证: stage_c_preserved / ver_32ca0d3b
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 190. hyp_path_c736fb8a1a35

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_06.c:83
- 漏洞类型: CWE-252, CWE-457
- CWE: CWE-252; CWE-457
- 风险等级: P2
- 触发条件: 攻击者能够控制程序的标准输入(stdin)内容
- 触发路径: if (fscanf(stdin, "%99s\0", data) == EOF) { printLine("fscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_06.c:83; 后续未显示但假设data被使用，例如 printf("%s", data); @ L85 或后续使用data处
- 结论: 存在未完全检查fscanf返回值的安全漏洞。代码只检查了fscanf返回值为EOF的情况，但未检查返回值是否等于1（期望读取一个字符串），导致当fscanf返回0（如输入为空白或格式不匹配）时，dataBuffer未初始化，后续使用data可能导致未初始化内存读取或信息泄露。
- D验证: stage_c_preserved / ver_d224cd72
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 191. hyp_path_65dbd9c480bd

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_13.c:78
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够通过stdin输入字符串，且该字符串不满足格式"%99s"（如包含空白或特殊字符），导致fscanf返回0。
- 触发路径: if (fscanf(stdin, "%99s\0", data) == EOF) { printLine("fscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_13.c:78
- 结论: 代码检查了fscanf的返回值是否为EOF，但未处理返回值0（输入不匹配格式）的情况，可能导致dataBuffer包含未初始化数据，后续使用可能造成信息泄露或未定义行为。
- D验证: stage_c_preserved / ver_b5470f7c
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 192. hyp_path_9ad549a979d5

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_15.c:65
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够通过stdin提供输入，使得fscanf返回值不为EOF但读取项目数为0（例如输入不匹配格式的字符串），导致data未正确初始化而被后续使用。
- 触发路径: if (fscanf(stdin, "%99s\0", data) == EOF) { printLine("fscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_15.c:65
- 结论: 检测到fscanf返回值检查不充分：仅检查是否等于EOF，未检查成功读取的项目数（应等于1），可能导致未检测到读取失败（如格式匹配0项）或使用未初始化的数据。
- D验证: stage_c_preserved / ver_b2f8d829
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 193. hyp_path_81dcf4b30a66

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_02.c:78
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够控制输入流（如stdin）产生非预期的输入，使scanf返回0而不是1; dataBuffer未初始化，后续使用data可能导致未定义行为
- 触发路径: if (scanf("%99s\0", data) == EOF) { printLine("scanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_02.c:78
- 结论: scanf返回值未完全检查：仅检查EOF，未检查是否成功读取输入项（应返回1），可能导致data未更新而使用未初始化数据，造成信息泄漏或崩溃。
- D验证: stage_c_preserved / ver_51052f18
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 194. hyp_path_3987db2b5147

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_06.c:83
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够提供导致scanf返回0的输入（如空输入或格式不匹配）
- 触发路径: if (scanf("%99s\0", data) == EOF) { printLine("scanf failed!"); } @ 83
- 结论: scanf返回值检查不完整，仅检查EOF，未检查返回0（未匹配输入）的情况，但dataBuffer已初始化为空，实际利用风险较低。
- D验证: stage_c_preserved / ver_e4f7768f
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 195. hyp_path_bb1c6084ffb5

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_16.c:55
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够提供输入到stdin，且scanf返回非EOF的错误码（例如通过输入空字符或格式不匹配）。
- 触发路径: if (scanf("%99s\0", data) == EOF) { printLine("scanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_16.c:55
- 结论: 代码中检查了scanf的返回值是否为EOF，但未处理其他错误返回值（如0或负值），导致未完全检查返回值漏洞。攻击者可通过提供无效输入使scanf返回非EOF错误码，程序继续执行，可能使用未初始化的dataBuffer（但后续未使用data，实际危害较低）。
- D验证: stage_c_preserved / ver_e193772d
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 196. hyp_path_f2b12a9f2aa7

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_06.c:85
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制sscanf的输入字符串SRC。
- 触发路径: char * data = dataBuffer; if (sscanf(SRC, "%99s\0", data) == EOF) { printLine("sscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_06.c:83-87
- 结论: sscanf函数返回值未完全检查，仅检查了EOF，未处理返回0的情况，可能导致数据未正确读取，后续使用未初始化的数据或逻辑错误。
- D验证: stage_c_preserved / ver_a29187c9
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 197. hyp_path_398b49a9a1e0

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_06.c:66
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Attackers can control the SRC string (source) provided to sscanf
- 触发路径: if (sscanf(SRC, "%99s\0", data) == EOF) { printLine("sscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_06.c:66
- 结论: CWE-252: Unchecked Return Value - sscanf return value only checked for EOF, not for 0 (no items matched)
- D验证: stage_c_preserved / ver_d76bde82
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 198. hyp_path_9125ecd32031

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_05.c:86
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够控制SRC输入，使其匹配失败（如空字符串）导致sscanf返回0
- 触发路径: if (sscanf(SRC, "%99s\0", data) == EOF) { printLine("sscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_05.c:86
- 结论: sscanf返回值检查不完整：仅检查了EOF，未检查匹配项数为0的情况，可能导致dataBuffer保持未初始化状态。但后续代码未直接使用未初始化数据（仅调用printLine），实际漏洞风险较低。
- D验证: stage_c_preserved / ver_9f53667d
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 199. hyp_path_8fd2d9914c59

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_04.c:86
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够提供影响sscanf返回值的外部输入（如控制SRC的内容）
- 触发路径: if (sscanf(SRC, "%99s\0", data) == EOF) @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_04.c:86
- 结论: 对sscanf函数的返回值检查不完整：仅检查了EOF错误，未检查返回值为0（表示匹配失败）的情况，导致数据可能未被正确填充，后续使用存在风险。
- D验证: stage_c_preserved / ver_325bc267
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 200. hyp_path_f83ad2f1c4b9

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_07.c:85
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够控制输入SRC（例如通过环境变量或外部输入）
- 触发路径: if (sscanf(SRC, "%99s\0", data) == EOF) { printLine("sscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_07.c:85
- 结论: sscanf返回值未完全检查：仅检查是否等于EOF，而未检查是否成功匹配并赋值了预期数量的项（应为1）。如果用户输入空字符串或匹配失败（返回0），dataBuffer将保持未初始化的内容，后续使用可能导致未初始化内存读取或不可预测行为。
- D验证: stage_c_preserved / ver_9772ed9b
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 201. hyp_path_1e6d3461bea7

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_14.c:80
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够控制输入SRC（例如通过环境变量或用户输入）
- 触发路径: if (sscanf(SRC, "%99s\0", data) == EOF) { printLine("sscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_14.c:80
- 结论: sscanf返回值检查不完整：仅检查EOF，未检查返回值0（无匹配），导致输入为空字符串时data未写入，后续使用可能操作未初始化数据。
- D验证: stage_c_preserved / ver_e2d07da9
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 202. hyp_path_ad5233971d29

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_10.c:80
- 漏洞类型: CWE-252, CWE-457
- CWE: CWE-252; CWE-457
- 风险等级: P1
- 触发条件: 攻击者能够控制sscanf的输入源SRC，使其产生不匹配格式或为空字符串的输入（假设SRC外部可控）。
- 触发路径: if (sscanf(SRC, "%99s\0", data) == EOF) { printLine("sscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_10.c:80; 若sscanf返回0，未进入if块，data可能保持未初始化，后续使用data（如printLine等）导致未初始化内存访问。 @ 同一文件后续行（未完全展示）
- 结论: 在sscanf调用中，仅检查了返回值是否为EOF，未检查是否成功读取到数据（返回值应为1）。若输入为空或不匹配格式，sscanf将返回0，此时data缓冲区未被写入，后续使用可能导致未初始化数据或逻辑错误。
- D验证: stage_c_preserved / ver_3ca229a1
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 203. hyp_path_a87f11dc347d

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_15.c:88
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够通过某种方式控制SRC的值，使其不匹配"%99s"格式，导致sscanf返回0。
- 触发路径: if (sscanf(SRC, "%99s\0", data) == EOF) { printLine("sscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_15.c:88; sscanf返回0（非EOF），条件不成立，未进入失败分支，但data未被更新。 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_15.c:88; 假设后续有使用data的语句（如printLine(data)），则使用未初始化值。 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_15.c:90
- 结论: sscanf函数的返回值仅检查了EOF，但未检查是否成功匹配（即返回值是否等于1）。如果输入字符串不匹配格式，sscanf返回0，data未被写入，后续使用data可能导致未初始化数据读取或信息泄露。
- D验证: stage_c_preserved / ver_e4084f44
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 204. hyp_path_5a365d4f75f2

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fscanf_04.c:65
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够通过stdin提供输入，使得fwscanf返回0或非EOF非1的值
- 触发路径: if (fwscanf(stdin, L"%99s\0", data) == EOF) { printLine("fwscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fscanf_04.c:65
- 结论: 在fwscanf调用中，返回值仅检查是否等于EOF，未检查是否成功读取到预期数量的项（1个）。若fwscanf返回0（如输入为空或格式不匹配），则dataBuffer未被正确更新，后续使用dataBuffer可能导致未初始化数据访问。
- D验证: stage_c_preserved / ver_5f500673
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 205. hyp_path_a8b1b406d03b

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fscanf_09.c:78
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者提供导致fwscanf返回0（非EOF）的输入
- 触发路径: if (fwscanf(stdin, L"%99s\0", data) == EOF) { printLine("fwscanf failed!"); } @ L78
- 结论: 不完整的返回值检查：fwscanf只检查EOF，未检查成功读取数，可能导致使用未初始化的数据
- D验证: stage_c_preserved / ver_f0ea61f7
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 206. hyp_path_014291bf969c

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fscanf_16.c:55
- 漏洞类型: CWE-252, CWE-457
- CWE: CWE-252; CWE-457
- 风险等级: P1
- 触发条件: 攻击者能够向stdin输入数据，且输入不满足格式要求，导致fwscanf返回0而非EOF，从而dataBuffer未被正确初始化。
- 触发路径: if (fwscanf(stdin, L"%99s\0", data) == EOF) { printLine("fwscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fscanf_16.c:55-57
- 结论: fwscanf返回值仅检查了EOF，未检查其他可能的失败返回值（如0表示匹配失败），当输入不匹配格式时，dataBuffer未初始化，后续使用data指向的未初始化内存可能导致未定义行为。
- D验证: stage_c_preserved / ver_db3e1722
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 207. hyp_path_8b112ba44c76

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_scanf_04.c:65
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够提供特定输入，使wscanf返回0（无匹配项）而非EOF，导致程序误认为读取成功
- 触发路径: if (wscanf(L"%99s\0", data) == EOF) { printLine("wscanf failed!"); } @ 65
- 结论: CWE252: Unchecked Return Value - wscanf return value not fully checked (only checked for EOF, not for successful read count)
- D验证: stage_c_preserved / ver_602d192f
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 208. hyp_path_3dc054006849

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_scanf_06.c:83
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够向标准输入提供无法匹配%99s格式的输入，导致wscanf返回0
- 触发路径: void case12() @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_scanf_06.c:73; if (wscanf(L"%99s\0", data) == EOF) { printLine("wscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_scanf_06.c:83
- 结论: 未完全检查wscanf返回值，仅检查EOF，忽略返回0的情况，可能导致dataBuffer未初始化数据被后续代码使用，但缺乏后续使用证据，路径不闭合。
- D验证: stage_c_preserved / ver_c0e2bd17
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 209. hyp_path_22465c0d2547

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_scanf_10.c:78
- 漏洞类型: CWE-252, CWE-457
- CWE: CWE-252; CWE-457
- 风险等级: P2
- 触发条件: 攻击者能够控制输入流，使得wscanf无法成功读取数据（例如提供无效输入或导致EOF）
- 触发路径: wchar_t * data = dataBuffer; @ 76; if (wscanf(L"%99s\0", data) == EOF) { printLine("wscanf failed!"); } @ 78; // 如果wscanf失败，data保持未初始化，后续可能使用 @ 80
- 结论: 未完整检查wscanf的返回值，可能导致在输入失败时使用未初始化的dataBuffer，存在未初始化内存读取风险。
- D验证: stage_c_preserved / ver_16b36dc8
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 210. hyp_path_7fa8d828af26

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_scanf_18.c:53
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者可以控制标准输入，使wscanf返回0（例如输入空字符串或空格），而代码未捕获此情况，导致未处理的错误状态。
- 触发路径: if (wscanf(L"%99s\0", data) == EOF) { printLine("wscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_scanf_18.c:53
- 结论: 对wscanf的返回值检查不完整，仅检查了EOF，未检查返回0等错误情况，可能导致未检测到的输入失败。
- D验证: stage_c_preserved / ver_b6569849
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 211. hyp_path_cce609694a14

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_snprintf_02.c:86
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者无法直接控制输入，SRC为常量，故实际触发条件为内部错误导致返回负值（罕见）或截断但未被检测。
- 触发路径: if (SNPRINTF(data,100-wcslen(SRC)-1, L"%s\n", SRC) < 0) { printLine("snwprintf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_snprintf_02.c:86
- 结论: 函数snwprintf的返回值只检查了负值（错误情况），但未检查返回值是否大于等于缓冲区大小（截断情况），可能导致输出被截断而未被检测到，但截断本身不直接引发安全漏洞，且缓冲区大小计算可能正确，风险较低。
- D验证: stage_c_preserved / ver_31ac6abd
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 212. hyp_path_1894cfe007dd

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_sscanf_03.c:61
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: swscanf返回值不是EOF但也不是成功匹配数（如返回0）时，data保持未初始化状态
- 触发路径: if (swscanf(SRC, L"%99s\0", data) == EOF) { printLine("swscanf failed!"); } @ L61
- 结论: 未充分检查swscanf返回值，若返回0（无匹配项）则data未更新，可能导致后续使用未初始化数据。
- D验证: stage_c_preserved / ver_b17b66cf
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 213. hyp_path_1649c2140e36

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fwrite_12.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: `globalReturnsTrueOrFalse()`返回真，使程序执行未检查返回值的fwrite分支。
- 触发路径: void CWE252_Unchecked_Return_Value__wchar_t_fwrite_12_case0() { @ CWE252_Unchecked_Return_Value__wchar_t_fwrite_12.c:24; if(globalReturnsTrueOrFalse()) { @ CWE252_Unchecked_Return_Value__wchar_t_fwrite_12.c:25; /* NOTE: Do not check the return value */ fwrite((wchar_t *)L"string", sizeof(wchar_t), wcslen(L"string"), stdout); @ CWE252_Unchecked_Return_Value__wchar_t_fwrite_12.c:27-28
- 结论: 在fwrite调用后未检查返回值，可能导致写入失败未被正确处理，属于CWE-252未检查返回值漏洞。
- D验证: stage_c_preserved / ver_8b9e6f3f
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 214. hyp_path_a5b3759c412d

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_12.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者需要使globalReturnsTrueOrFalse()返回true（该函数随机返回，攻击者可能无法直接控制，但可通过多次调用或环境因素间接影响）; 攻击者可能通过某种方式使stdout写入失败（例如关闭标准输出流或触发写入错误）
- 触发路径: void CWE252_Unchecked_Return_Value__char_fwrite_12_case0() { @ CWE252_Unchecked_Return_Value__char_fwrite_12.c:24; if(globalReturnsTrueOrFalse()) { @ CWE252_Unchecked_Return_Value__char_fwrite_12.c:25; /* NOTE: Do not check the return value */ fwrite((char *)"string", sizeof(char), strlen("string"), stdout); @ CWE252_Unchecked_Return_Value__char_fwrite_12.c:27
- 结论: 在函数CWE252_Unchecked_Return_Value__char_fwrite_12_case0中，当globalReturnsTrueOrFalse()返回true时，调用fwrite写入stdout但未检查返回值，可能导致未检测到的写入失败，违反CWE-252（未检查返回值）
- D验证: stage_c_preserved / ver_87bddad3
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 215. hyp_path_46efe34ea736

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_08.c:39
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: if(staticReturnsTrue()) { /* NOTE: Do not check the return value */ fprintf(stdout, "%s\n", "string"); } @ CWE252_Unchecked_Return_Value__char_fprintf_08.c:39
- 结论: fprintf函数返回值未检查，可能导致写入失败时程序未正确处理，引发数据丢失或不一致。
- D验证: stage_c_preserved / ver_2f93cc96
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 216. hyp_path_010998978cd6

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_11.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: void CWE252_Unchecked_Return_Value__char_fprintf_11_case0() { @ 24; fprintf(stdout, "%s\n", "string"); @ 29
- 结论: Unchecked return value of fprintf
- D验证: stage_c_preserved / ver_8c16131e
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 217. hyp_path_69cbd7c9b230

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_08.c:42
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部输入依赖，但fputc可能因stdout关闭等失败
- 触发路径: void CWE252_Unchecked_Return_Value__char_fputc_08_case0() { if(staticReturnsTrue()) { /* NOTE: Do not check the return value */ fputc((int)'A', stdout); } } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_08.c:37-44
- 结论: fputc返回值未检查，可能导致写入失败时数据丢失
- D验证: stage_c_preserved / ver_8f4d1142
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 218. hyp_path_091536aafc82

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_11.c:26
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 函数被调用，且globalReturnsTrue()返回真
- 触发路径: void CWE252_Unchecked_Return_Value__char_fputc_11_case0() { @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_11.c:24; if(globalReturnsTrue()) { @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_11.c:25; fputc((int)'A', stdout); // 返回值未检查 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_11.c:29
- 结论: 未检查fputc的返回值，可能无法检测到写入错误，导致数据丢失或不完整。
- D验证: stage_c_preserved / ver_4baa83c4
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 219. hyp_path_3cb1e909f573

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_08.c:42
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: fputs("string", stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_08.c:42
- 结论: 存在未检查返回值漏洞：fputs的返回值未被检查，可能导致未检测到的写入失败，违反CWE-252。
- D验证: stage_c_preserved / ver_4904943a
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 220. hyp_path_56a8d0112355

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_11.c:26
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: No external input control required; failure to check return value may cause silent output errors
- 触发路径: fputs("string", stdout); @ line 27-29
- 结论: CWE-252: Unchecked Return Value - fputs return value not checked
- D验证: stage_c_preserved / ver_3010c186
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 221. hyp_path_ae0c6d043107

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_08.c:47
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够使stdin的读取操作失败（如提前关闭stdin或输入无效数据）
- 触发路径: void CWE252_Unchecked_Return_Value__char_fscanf_08_case0() { if(staticReturnsTrue()) { @ 37-41; char * data = dataBuffer; /* NOTE: Do not check the return value */ fscanf(stdin, "%99s\0", data); @ 46-47
- 结论: 未检查fscanf的返回值，如果fscanf失败（如遇到EOF或错误），dataBuffer可能保持未初始化，后续使用可能导致未定义行为或信息泄露。
- D验证: stage_c_preserved / ver_80005e28
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 222. hyp_path_351feac3b98f

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_11.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制stdin输入流，导致fscanf返回失败（如提前关闭stdin或输入格式不匹配）
- 触发路径: fscanf(stdin, "%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_11.c:34
- 结论: 未检查fscanf返回值，可能导致dataBuffer未初始化或包含部分数据，若后续使用dataBuffer则造成未初始化数据使用
- D验证: stage_c_preserved / ver_cff440ee
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 223. hyp_path_0a04b49c5c00

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_08.c:39
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: fwrite可能因I/O错误而失败，但代码未检查返回值
- 触发路径: fwrite((char *)"string", sizeof(char), strlen("string"), stdout); @ CWE252_Unchecked_Return_Value__char_fwrite_08.c:39
- 结论: 调用fwrite时未检查返回值，可能导致未处理的错误状态。
- D验证: stage_c_preserved / ver_67b622c5
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 224. hyp_path_3964298b2ed9

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_11.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: The function CWE252_Unchecked_Return_Value__char_fwrite_11_case0 is called and globalReturnsTrue() returns true (which it does in Juliet tests).
- 触发路径: void CWE252_Unchecked_Return_Value__char_fwrite_11_case0() { if(globalReturnsTrue()) { /* NOTE: Do not check the return value */ fwrite((char *)"string", sizeof(char), strlen("string"), stdout); } } @ L24-L29
- 结论: CWE-252: Unchecked Return Value in fwrite call
- D验证: stage_c_preserved / ver_ddf06eeb
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 225. hyp_path_b6ebdfab8fdd

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_08.c:42
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: None (no external input required)
- 触发路径: putc((int)'A', stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_08.c:42
- 结论: Unchecked return value of putc() leading to potential write errors
- D验证: stage_c_preserved / ver_d2b12191
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 226. hyp_path_a4b0a82541d5

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_11.c:26
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: No specific preconditions; the vulnerability is inherent in the code pattern.
- 触发路径: if(globalReturnsTrue()) @ 24; putc((int)'A', stdout); // return value not checked @ 29
- 结论: Vulnerability: Unchecked return value of putc() can lead to undetected write errors.
- D验证: stage_c_preserved / ver_cdbf1e13
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 227. hyp_path_01457bc3adb4

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_08.c:39
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: putchar((int)'A'); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_08.c:39
- 结论: 存在未检查返回值的漏洞：putchar函数的返回值未被检查，可能导致部分写入失败时未被发现。
- D验证: stage_c_preserved / ver_022782cc
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 228. hyp_path_26e1cdc8fce8

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_11.c:26
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: The function globalReturnsTrue() returns true, ensuring the code path is executed.
- 触发路径: putchar((int)'A'); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_11.c:29
- 结论: Unchecked return value of putchar (CWE-252)
- D验证: stage_c_preserved / ver_afd93fc7
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 229. hyp_path_181c45ce9581

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_08.c:48
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: No input control required; the bug is unconditional in this test case
- 触发路径: PUTS("string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_08.c:48
- 结论: CWE252: Unchecked Return Value - put returns a value that is not checked
- D验证: stage_c_preserved / ver_ee432341
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 230. hyp_path_370a36d4ed60

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_11.c:32
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 程序执行到 if(globalReturnsTrue()) 且 globalReturnsTrue() 返回 true
- 触发路径: void CWE252_Unchecked_Return_Value__char_puts_11_case0() { if(globalReturnsTrue()) { /* NOTE: Do not check the return value */ PUTS("string"); } } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_11.c:30-34; PUTS("string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_11.c:32
- 结论: 函数puts的返回值未被检查，可能导致未处理错误，符合CWE-252未检查返回值漏洞。
- D验证: stage_c_preserved / ver_993c5de6
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 231. hyp_path_1a1c0cd5a698

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_08.c:39
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够通过标准输入提供内容或触发读取失败情况（如关闭输入流）
- 触发路径: if(staticReturnsTrue()) @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_08.c:37; scanf("%99s\0", data); // 返回值未检查 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_08.c:39
- 结论: 未检查scanf返回值，可能导致使用未初始化数据或程序行为异常，但缺少后续数据使用的sink证据，需动态验证。
- D验证: stage_c_preserved / ver_6a5bd41f
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 232. hyp_path_152d288b0b6a

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_11.c:26
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制标准输入流，使其产生错误（例如关闭输入流或提供非预期输入），导致scanf返回0或EOF。
- 触发路径: void CWE252_Unchecked_Return_Value__char_scanf_11_case0() { if(globalReturnsTrue()) { @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_11.c:24; scanf("%99s\0", data); // 未检查返回值 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_11.c:26
- 结论: 函数未检查scanf返回值，可能因输入失败导致data变量未初始化，违反CWE-252安全编码要求。
- D验证: stage_c_preserved / ver_f4c4636e
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 233. hyp_path_3f8e2946cec7

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_08.c:55
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 函数staticReturnsTrue()返回1确保代码执行
- 触发路径: SNPRINTF(data,100-strlen(SRC)-1, "%s\n", SRC); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_08.c:55
- 结论: snprintf函数的返回值未被检查，可能导致在写入失败或截断时无法及时发现。
- D验证: stage_c_preserved / ver_26cfe9cf
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 234. hyp_path_cb0b811ce1de

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_07.c:102
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够导致fgets失败（如关闭stdin）
- 触发路径: fgets(data, 100, stdin); // 返回值未检查 @ case11函数体内; fgets(data, 100, stdin); // 返回值未检查 @ case12函数体内; SNPRINTF(data, 100-strlen(SRC)-1, "%s\n", SRC); // 依赖fgets填充的data @ SNPRINTF调用处
- 结论: fgets函数返回值未检查，可能导致后续使用无效数据，但实际缓冲区已初始化为空字符串，风险较低。
- D验证: stage_c_preserved / ver_8bb76929
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 235. hyp_path_0b5ca5c3c481

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_11.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 无外部可控输入，SRC为常量字符串，但返回值未检查的缺陷模式存在。
- 触发路径: SNPRINTF(data,100-strlen(SRC)-1, "%s\n", SRC); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_11.c:34
- 结论: 未检查snprintf的返回值，可能导致数据截断或写入失败未被发现，属于CWE-252缺陷模式，但当前样本中SRC为固定字符串，实际利用风险低，证据不完整。
- D验证: stage_c_preserved / ver_c4ee74a1
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 236. hyp_path_2d252bf9841c

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_11.c:97
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: fgets因文件结束或错误返回NULL，或SNPRINTF输出截断
- 触发路径: fgets(data, ...) @ case12或case11中fgets调用处; SNPRINTF(data, 100-strlen(SRC)-1, "%s\n", SRC) @ 随后SNPRINTF调用
- 结论: 在case12和case11中，fgets的返回值未被检查，可能导致在读取失败时使用未初始化的数据；SNPRINTF的返回值虽然检查了负数，但未检查截断情况，不满足CWE252的完整要求，但实际风险较低。
- D验证: stage_c_preserved / ver_b1841f4a
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 237. hyp_path_6a6d1cfd816e

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_08.c:49
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制SRC输入（尽管本例中SRC可能是常量，但漏洞模式仍存在）
- 触发路径: sscanf(SRC, "%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_08.c:49
- 结论: 未检查sscanf返回值，导致可能使用未初始化或部分写入的数据，违反CWE-252。
- D验证: stage_c_preserved / ver_280a9964
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 238. hyp_path_2a2948e7bd3e

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_11.c:28
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: sscanf的源输入SRC可能产生解析错误，但代码不处理返回值。
- 触发路径: sscanf(SRC, "%99s\0", data); // 未检查返回值 @ L28
- 结论: 函数sscanf的返回值未被检查，可能导致后续代码在输入错误时使用未初始化的数据，构成CWE252漏洞。
- D验证: stage_c_preserved / ver_af6e3630
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 239. hyp_path_78ff3227e179

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_14.c:91
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够控制数据源SRC的内容，使其满足sscanf格式匹配失败的条件（例如空输入）。
- 触发路径: if (sscanf(SRC, "%99s\0", data) == EOF) { printLine("sscanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_14.c:90-91（case11或case12）
- 结论: sscanf返回值检查不完整：仅检查了EOF，未检查返回值为0的情况（即输入不匹配格式）。这可能导致后续使用未初始化的数据（但本代码中dataBuffer已初始化为空字符串，实际影响有限），符合CWE-252（未检查返回值）的定义。
- D验证: stage_c_preserved / ver_2a78e061
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 240. hyp_path_0bc204252460

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__w32ImpersonateSelf_08.c:41
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Windows环境下调用ImpersonateSelf可能因安全上下文不足而失败
- 触发路径: ImpersonateSelf(SecurityImpersonation); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__w32ImpersonateSelf_08.c:41
- 结论: 未检查ImpersonateSelf()的返回值，可能导致模拟失败但继续执行，后续操作可能以错误权限运行，造成权限处理错误。
- D验证: stage_c_preserved / ver_bf0763e1
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 241. hyp_path_0f406f1a0247

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__w32ImpersonateSelf_11.c:28
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: ImpersonateSelf(SecurityImpersonation); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__w32ImpersonateSelf_11.c:28
- 结论: 未检查ImpersonateSelf()的返回值，可能导致权限提升失败后继续执行后续操作，引发权限相关的安全问题。
- D验证: stage_c_preserved / ver_0b1ea9d0
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 242. hyp_path_1f41a788383a

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fprintf_08.c:39
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 程序运行环境可能导致fwprintf失败（如stdout关闭、磁盘满、权限不足）
- 触发路径: fwprintf(stdout, L"%s\n", L"string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fprintf_08.c:40
- 结论: fwprintf返回值未检查，可能因输出流错误导致数据未完全写入或丢失，影响数据完整性或引发信息泄露
- D验证: stage_c_preserved / ver_c685f3ca
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 243. hyp_path_1e314bacb99a

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fprintf_11.c:26
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: globalReturnsTrue()返回true
- 触发路径: fwprintf(stdout, L"%s\n", L"string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fprintf_11.c:26
- 结论: 未检查fwprintf返回值，可能导致数据丢失或错误状态丢失
- D验证: stage_c_preserved / ver_b082ce9c
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 244. hyp_path_6a4f00e340ef

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fputc_08.c:39
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部可控条件，仅依赖fputwc内部错误
- 触发路径: fputwc((wchar_t)L'A', stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fputc_08.c:39
- 结论: fputwc返回值未检查，可能导致未处理错误，属于CWE-252漏洞，但无外部可控输入，利用难度高。
- D验证: stage_c_preserved / ver_da949f78
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 245. hyp_path_90bea588c0f3

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fputc_11.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 代码执行到 CWE252_Unchecked_Return_Value__wchar_t_fputc_11_case0 函数且 globalReturnsTrue() 返回真
- 触发路径: fputwc((wchar_t)L'A', stdout); // return value not checked @ L29
- 结论: Unchecked return value of fputwc (CWE-252)
- D验证: stage_c_preserved / ver_236d72e6
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 246. hyp_path_1dd53a565066

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fputs_08.c:42
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: staticReturnsTrue恒真，路径必达，无需外部输入
- 触发路径: void CWE252_Unchecked_Return_Value__wchar_t_fputs_08_case0() { @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fputs_08.c:37; if(staticReturnsTrue()) { @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fputs_08.c:39; fputws(L"string", stdout); // return value ignored @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fputs_08.c:42
- 结论: 未检查fputws返回值，违反CWE-252，存在可触发漏洞路径
- D验证: stage_c_preserved / ver_7d7d4174
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 247. hyp_path_43dd01cd9b35

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fputs_11.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部输入控制，仅函数调用后未检查返回值。
- 触发路径: fputws(L"string", stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fputs_11.c:29
- 结论: 调用fputws后未检查其返回值，可能导致未处理错误状态。
- D验证: stage_c_preserved / ver_4a7923f2
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 248. hyp_path_534362411f9b

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fscanf_08.c:47
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者可通过stdin输入，但无法直接控制fwscanf的返回值；若输入失败，dataBuffer内容未定义。
- 触发路径: void CWE252_Unchecked_Return_Value__wchar_t_fscanf_08_case0() { if(staticReturnsTrue()) { @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fscanf_08.c:37; wchar_t * data = dataBuffer; /* NOTE: Do not check the return value */ fwscanf(stdin, L"%99s\0", data); } } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fscanf_08.c:47
- 结论: 未检查fwscanf的返回值，可能导致当输入失败时dataBuffer内容未定义，但代码中无后续使用，实际影响有限，符合CWE-252模式。
- D验证: stage_c_preserved / ver_efd66545
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 249. hyp_path_6e3d5e93592a

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fscanf_11.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够通过标准输入提供输入。
- 触发路径: fwscanf(stdin, L"%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fscanf_11.c:34
- 结论: 未检查 fwscanf 的返回值，可能导致未初始化或部分读取的数据被使用。
- D验证: stage_c_preserved / ver_3108cbe4
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 250. hyp_path_1261f3beb3ea

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fwrite_08.c:42
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: None (no external input needed; the vulnerability is the missing check on fwrite's return value regardless of input)
- 触发路径: fwrite((wchar_t *)L"string", sizeof(wchar_t), wcslen(L"string"), stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fwrite_08.c:42
- 结论: CWE-252: Unchecked Return Value of fwrite
- D验证: stage_c_preserved / ver_14b69c9b
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 251. hyp_path_4df1b53ab330

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_fwrite_11.c:26
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部输入控制，但系统级错误（如stdout流错误）可能触发写入失败。
- 触发路径: fwrite((wchar_t *)L"string", sizeof(wchar_t), wcslen(L"string"), stdout); @ CWE252_Unchecked_Return_Value__wchar_t_fwrite_11.c:26
- 结论: 函数fwrite的返回值未被检查，可能导致未检测到的写入失败，属于CWE-252未检查返回值漏洞。
- D验证: stage_c_preserved / ver_00a5ea16
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 252. hyp_path_3c9a08fb8b66

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_putc_08.c:42
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 运行错误导致 putwc 失败（如 stdout 关闭或写入错误）的可能性。
- 触发路径: putwc((wchar_t)L'A', stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_putc_08.c:42
- 结论: 未检查 putwc 函数的返回值，可能导致输出错误未被发现。
- D验证: stage_c_preserved / ver_fd7704b8
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 253. hyp_path_736fc6f604ee

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_putc_11.c:26
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: No user-controlled input required; putwc may return WEOF on I/O error, and the unchecked return value leads to undetected errors or data loss.
- 触发路径: putwc((wchar_t)L'A', stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_putc_11.c:29
- 结论: CWE-252: Unchecked Return Value - putwc function call without checking return value
- D验证: stage_c_preserved / ver_628a0935
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 254. hyp_path_a8b873f395b6

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_putchar_08.c:39
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: No external input required; unconditional call
- 触发路径: putwchar((wchar_t)L'A'); @ 39
- 结论: Unchecked return value of putwchar
- D验证: stage_c_preserved / ver_6b2e072e
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 255. hyp_path_6e233f05fbf8

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_putchar_11.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无特定攻击者输入，代码本身存在未检查返回值的问题。
- 触发路径: putwchar((wchar_t)L'A'); @ L29
- 结论: 函数putwchar的返回值未被检查，可能忽略输出错误，导致程序状态不一致，但安全影响较低。
- D验证: stage_c_preserved / ver_14314f6c
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 256. hyp_path_445870c33f92

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_puts_08.c:45
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: PUTS(L"string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_puts_08.c:45
- 结论: CWE252_Unchecked_Return_Value: 函数PUTS的返回值未检查
- D验证: stage_c_preserved / ver_9398d309
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 257. hyp_path_4e7114c45607

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_puts_11.c:32
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无需外部输入，任何调用路径均触发此未检查返回值的操作。
- 触发路径: void CWE252_Unchecked_Return_Value__wchar_t_puts_11_case0() { @ 30; PUTS(L"string"); // 未检查返回值 @ 34
- 结论: 未检查_putws（PUTS）的返回值，可能导致程序忽略错误状态，符合CWE-252定义。
- D验证: stage_c_preserved / ver_6a154fdc
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 258. hyp_path_1e56481de0d3

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_remove_08.c:45
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 程序内部调用REMOVE删除固定文件，且开发者故意忽略返回值检查。
- 触发路径: void CWE252_Unchecked_Return_Value__wchar_t_remove_08_case0() { if(staticReturnsTrue()) { /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_remove_08.c:43-47; { /* NOTE: Do not check the return value */ REMOVE(L"removemecase0.txt"); } } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_remove_08.c:46-50
- 结论: 未检查REMOVE函数的返回值，可能导致删除操作失败不被发现，影响程序逻辑或数据完整性。
- D验证: stage_c_preserved / ver_c09c18c1
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 259. hyp_path_c708577fc7f4

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_remove_11.c:32
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够影响文件系统状态（如使得文件不可访问）或程序运行环境导致删除失败。
- 触发路径: void CWE252_Unchecked_Return_Value__wchar_t_remove_11_case0() { if(globalReturnsTrue()) { /* NOTE: Do not check the return value */ @ 30-34; { /* NOTE: Do not check the return value */ REMOVE(L"removemecase0.txt"); } @ 33-37
- 结论: 函数调用REMOVE(L"removemecase0.txt")未检查返回值，可能导致删除操作失败时程序未感知，引发后续逻辑错误或资源未释放（CWE-252未检查返回值）。
- D验证: stage_c_preserved / ver_016747f5
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 260. hyp_path_2b1325e6aa01

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_rename_08.c:51
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: The function staticReturnsTrue() always returns 1, ensuring the code path is reachable.
- 触发路径: RENAME(OLD_CASE0_FILE_NAME, L"newcase0filename.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_rename_08.c:51
- 结论: CWE252: Unchecked Return Value - rename function return value not checked
- D验证: stage_c_preserved / ver_4c6a3a03
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 261. hyp_path_286f26fdefd3

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_rename_11.c:38
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无特殊前提条件，代码直接执行
- 触发路径: RENAME(OLD_CASE0_FILE_NAME, L"newcase0filename.txt"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_rename_11.c:38
- 结论: 函数CWE252_Unchecked_Return_Value__wchar_t_rename_11_case0中调用RENAME（实际为wrename）未检查返回值，可能导致文件重命名失败而程序继续执行，引发逻辑错误或未定义行为。
- D验证: stage_c_preserved / ver_278436c2
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 262. hyp_path_26b83c535936

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_scanf_08.c:47
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够使得wscanf的输入失败（例如关闭标准输入或提供无效输入）
- 触发路径: wscanf(L"%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_scanf_08.c:47
- 结论: 未检查wscanf函数的返回值，可能导致在输入失败时data缓冲区未被正确写入，后续使用未初始化的数据，引发未定义行为。
- D验证: stage_c_preserved / ver_c1bc81ff
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 263. hyp_path_3fc4ea2b5e6a

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_scanf_11.c:26
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够提供导致wscanf失败的输入，如EOF或无效宽字符
- 触发路径: wscanf(L"%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_scanf_11.c:26
- 结论: 未检查wscanf的返回值，可能导致在输入失败时使用未初始化的数据或逻辑错误。
- D验证: stage_c_preserved / ver_e9806013
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 264. hyp_path_d9d407abb133

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_snprintf_08.c:55
- 漏洞类型: buffer_overflow
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够通过某种方式影响SRC的值（例如通过环境变量、配置文件或直接内存操作）
- 触发路径: if(staticReturnsTrue()) @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_snprintf_08.c:47; SNPRINTF(data,100-wcslen(SRC)-1, L"%s\n", SRC); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_snprintf_08.c:55
- 结论: 函数CWE252_Unchecked_Return_Value__wchar_t_snprintf_08_case0中调用SNPRINTF（实际为swprintf）未检查返回值，这可能导致缓冲区溢出或数据截断问题，但更直接的是未检查返回值本身属于CWE-252缺陷。假设攻击者能够控制输入字符串SRC或影响缓冲区大小，未检查返回值可能使程序忽略写入失败或截断，进而导致数据不一致或其他安全问题。
- D验证: stage_c_preserved / ver_117ae1e6
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 265. hyp_path_24658c2d5ca2

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_snprintf_11.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无特定外部输入控制，但函数调用本身不检查返回值
- 触发路径: void CWE252_Unchecked_Return_Value__wchar_t_snprintf_11_case0() @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_snprintf_11.c:32; SNPRINTF(data,100-wcslen(SRC)-1, L"%s\n", SRC); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_snprintf_11.c:34
- 结论: 未检查swprintf返回值导致CWE-252漏洞
- D验证: stage_c_preserved / ver_58fb7e76
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 266. hyp_path_3ab3e6341db8

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_sscanf_08.c:41
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制SRC输入（例如，通过外部输入或文件）
- 触发路径: swscanf(SRC, L"%99s\0", data); @ L41
- 结论: CWE252_Unchecked_Return_Value: swscanf返回值未检查，导致输入可能未写入dataBuffer
- D验证: stage_c_preserved / ver_a819b29d
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 267. hyp_path_80baa790db76

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_sscanf_11.c:28
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够控制提供给swscanf的源字符串SRC
- 触发路径: void CWE252_Unchecked_Return_Value__wchar_t_sscanf_11_case0() { if(globalReturnsTrue()) { { wchar_t * data = dataBuffer; swscanf(SRC, L"%99s\0", data); } } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_sscanf_11.c:26-28
- 结论: 未检查swscanf返回值，可能导致后续使用未初始化数据或错误处理遗漏，符合CWE-252未检查返回值漏洞。
- D验证: stage_c_preserved / ver_a3ef885b
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 268. hyp_path_5b1e5136373d

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_02.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: fprintf(stdout, "%s\n", "string"); @ 29
- 结论: 对fprintf的返回值未做检查，可能导致写入失败时无法感知。
- D验证: stage_c_preserved / ver_501809f3
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 269. hyp_path_9fe9d5cb47d2

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_01.c:27
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: fprintf(stdout, "%s\n", "string"); @ L27
- 结论: CWE-252: Unchecked Return Value
- D验证: stage_c_preserved / ver_d5b2e018
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 270. hyp_path_a6ac84094908

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_05.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 程序运行在stdout可能出错的环境中，如文件系统满或管道关闭。
- 触发路径: fprintf(stdout, "%s\n", "string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_05.c:35
- 结论: 程序中调用了fprintf，但未检查其返回值，可能导致未处理的写入错误。
- D验证: stage_c_preserved / ver_790f6e7e
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 271. hyp_path_002dc8363034

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_03.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: No external input required; the vulnerability is the failure to check the return value of fprintf, which is a programming error.
- 触发路径: fprintf(stdout, "%s\n", "string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_03.c:29
- 结论: CWE252: Unchecked Return Value - fprintf return value not checked
- D验证: stage_c_preserved / ver_c32af2c9
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 272. hyp_path_2b53acd377b8

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_04.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够使fprintf的写入操作失败（例如通过关闭标准输出文件描述符或影响文件系统状态）
- 触发路径: fprintf(stdout, "%s\n", "string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_04.c:35
- 结论: 在fprintf调用后未检查返回值，可能导致写入失败时未能发现错误，影响数据完整性或程序后续行为。
- D验证: stage_c_preserved / ver_28096479
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 273. hyp_path_7f9328fdcad1

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_09.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部输入要求，但返回值被忽略，可能导致部分写入或错误未检测
- 触发路径: /* NOTE: Do not check the return value */ fprintf(stdout, "%s\n", "string"); @ 28-30
- 结论: CWE252_Unchecked_Return_Value in fprintf call
- D验证: stage_c_preserved / ver_3f316ded
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 274. hyp_path_ce161ef3079e

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_10.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无需外部输入，函数调用本身返回值未检查
- 触发路径: fprintf(stdout, "%s\n", "string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_10.c:29
- 结论: 未检查fprintf的返回值，可能导致错误未处理
- D验证: stage_c_preserved / ver_aaba535b
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 275. hyp_path_3ff6e1430788

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_13.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: stdout写入可能因系统环境异常（如磁盘空间不足、文件描述符关闭）失败
- 触发路径: fprintf(stdout, "%s\n", "string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_13.c:29
- 结论: fprintf返回值未检查，可能导致未检测到的写入错误
- D验证: stage_c_preserved / ver_bd346d6d
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 276. hyp_path_93922f67965e

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_14.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: None (hardcoded input, but return value ignored)
- 触发路径: fprintf(stdout, "%s\n", "string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_14.c:29
- 结论: CWE252: Unchecked return value of fprintf, although the argument is a hardcoded string, the return value is not checked, which can lead to undetected write failures.
- D验证: stage_c_preserved / ver_733c8710
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 277. hyp_path_0c30e95011a7

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_15.c:30
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够影响stdout的可用性或写入状态（例如导致写入失败），但通常需要其他漏洞配合。
- 触发路径: case 6: /* NOTE: Do not check the return value */ fprintf(stdout, "%s\n", "string"); break; @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_15.c:30
- 结论: 调用fprintf未检查返回值，可能导致未处理错误或数据丢失，属于CWE-252未检查返回值漏洞。
- D验证: stage_c_preserved / ver_2ccaa9f5
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 278. hyp_path_54fc67373d69

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_16.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无特定输入控制，但任何可能使fprintf失败的环境因素（如磁盘满、权限不足）
- 触发路径: fprintf(stdout, "%s\n", "string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fprintf_16.c:29
- 结论: 未检查fprintf返回值，可能导致输出丢失或数据不一致，符合CWE-252
- D验证: stage_c_preserved / ver_c34b47e9
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 279. hyp_path_2fea50997045

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_05.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无特殊前提，fputc始终被调用
- 触发路径: 入口函数 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_05.c:30; fputc((int)'A', stdout); // 未检查返回值 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_05.c:35
- 结论: 未检查fputc返回值，可能导致输出错误或数据丢失
- D验证: stage_c_preserved / ver_21da03eb
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 280. hyp_path_5910bf4ebf26

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_04.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: fputc((int)'A', stdout); @ 35
- 结论: Unchecked return value of fputc
- D验证: stage_c_preserved / ver_8015774e
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 281. hyp_path_535149a62e41

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_02.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 无额外攻击前提，仅需代码执行到该位置。
- 触发路径: fputc((int)'A', stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_02.c:29
- 结论: fputc函数返回值未被检查，可能导致输出错误未被发现。
- D验证: stage_c_preserved / ver_6da5524b
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 282. hyp_path_b44e0bbce45e

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_06.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: No precondition required; the vulnerability lies in not checking the return value of fputc, which may indicate write failure.
- 触发路径: fputc((int)'A', stdout); @ L34
- 结论: Unchecked return value of fputc()
- D验证: stage_c_preserved / ver_78d3f855
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 283. hyp_path_bdea84529625

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_03.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 运行时环境异常（如磁盘满、管道关闭）导致 fputc 失败
- 触发路径: void CWE252_Unchecked_Return_Value__char_fputc_03_case0() @ L24; fputc((int)'A', stdout); /* NOTE: Do not check the return value */ @ L29
- 结论: fputc 返回值未检查，可能导致输出错误未被发现
- D验证: stage_c_preserved / ver_613891c2
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 284. hyp_path_8b85f8d18e5e

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_07.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部输入要求，仅因未检查返回值
- 触发路径: fputc((int)'A', stdout); // NOTE: Do not check the return value @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_07.c:34
- 结论: 未检查fputc返回值（CWE-252）
- D验证: stage_c_preserved / ver_5175861f
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 285. hyp_path_d53fce846fbf

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_10.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无特殊前提，函数调用返回值未检查
- 触发路径: CWE252_Unchecked_Return_Value__char_fputc_10_case0:24 @ L24; fputc((int)'A', stdout); @ L29
- 结论: 未检查fputc返回值，可能导致输出不完整或数据丢失，符合CWE-252
- D验证: stage_c_preserved / ver_78151765
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 286. hyp_path_340290c98ed3

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_09.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: stdout写入可能失败的环境条件，如stdout已关闭或发生I/O错误
- 触发路径: fputc((int)'A', stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_09.c:29
- 结论: fputc函数返回值未检查，若写入失败（如stdout关闭或出现写入错误），程序无法感知错误，可能导致数据丢失或程序行为异常。
- D验证: stage_c_preserved / ver_98cf965a
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 287. hyp_path_e718e0104583

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_13.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: fputc((int)'A', stdout); // NOTE: Do not check the return value @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_13.c:29
- 结论: Unchecked return value of fputc, leading to potential data loss or undetected write failure.
- D验证: stage_c_preserved / ver_b77d7215
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 288. hyp_path_39046b70375e

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_15.c:30
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部输入控制，但返回值未检查本身就是漏洞场景。
- 触发路径: fputc((int)'A', stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_15.c:30
- 结论: 函数fputc的返回值未被检查，可能遗漏错误处理，符合CWE-252漏洞。
- D验证: stage_c_preserved / ver_aa0e2820
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 289. hyp_path_3b9c5ebbbaad

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_16.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: No external control required, just the function call.
- 触发路径: fputc((int)'A', stdout); @ 29
- 结论: Unchecked return value of fputc, which may cause undetected write failure.
- D验证: stage_c_preserved / ver_20da1ba1
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 290. hyp_path_dc35a072c28d

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_14.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: fputc((int)'A', stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_14.c:29
- 结论: 在调用fputc时未检查返回值，可能导致未检测到的I/O错误，但该漏洞通常不会导致安全危害，仅需在严格可靠性要求下关注。
- D验证: stage_c_preserved / ver_bb318d3b
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 291. hyp_path_4ded8bd5ad51

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_01.c:27
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部输入控制，但函数返回值未检查
- 触发路径: fputs("string", stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_01.c:27
- 结论: CWE252: Unchecked Return Value - fputs return value not checked
- D验证: stage_c_preserved / ver_014bfecb
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 292. hyp_path_f85f614cd9ab

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_17.c:30
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者无法直接控制fputc的参数，但可能通过环境因素（如关闭标准输出）导致fputc失败，从而触发未检查返回值问题。
- 触发路径: fputc((int)'A', stdout); @ 30
- 结论: 调用fputc写入stdout时未检查返回值，可能导致输出不完整或写入失败未被感知，但此漏洞利用难度高，通常不会直接导致严重安全后果。
- D验证: stage_c_preserved / ver_e58ff8da
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 293. hyp_path_45a5102f55f7

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_18.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者需要能够影响stdout的写入状态（例如通过耗尽磁盘空间或关闭管道），但这通常不是直接可控的。
- 触发路径: fputc((int)'A', stdout); // 未检查返回值 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputc_18.c:29
- 结论: 未检查fputc的返回值，可能导致写入失败时未检测到错误，属于CWE252未检查返回值漏洞。
- D验证: stage_c_preserved / ver_c6acb588
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 294. hyp_path_50335d778b1f

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_02.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无特定攻击者控制条件，但依赖于程序运行时环境可能导致fputs失败（如stdout关闭或磁盘满）。
- 触发路径: fputs("string", stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_02.c:29
- 结论: 函数fputs的返回值未被检查，可能导致忽略写入错误，符合CWE-252（未检查返回值）漏洞模式。
- D验证: stage_c_preserved / ver_5e40d438
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 295. hyp_path_2e27847deab4

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_03.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Attacker must cause fputs to fail (e.g., by exhausting disk space if stdout is redirected to a file, or by closing stdout)
- 触发路径: fputs("string", stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_03.c:29
- 结论: Unchecked return value of fputs allows silent failure if the output operation fails
- D验证: stage_c_preserved / ver_a6257111
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 296. hyp_path_2b5c96b19d6f

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_05.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: fputs() may fail due to I/O errors (e.g., disk full, stdout closed)
- 触发路径: fputs("string", stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_05.c:35
- 结论: Unchecked return value of fputs()
- D验证: stage_c_preserved / ver_9c378b0b
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 297. hyp_path_5755bca185d4

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_04.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: fputs("string", stdout); @ L35
- 结论: CWE-252: Unchecked Return Value of fputs
- D验证: stage_c_preserved / ver_6039b3a9
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 298. hyp_path_e7b533398a4e

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_06.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够通过重定向stdout到错误目标、耗尽磁盘空间或关闭stdout等方式使fputs写入失败
- 触发路径: fputs("string", stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_06.c:34
- 结论: fputs() 的返回值未被检查，可能忽略写入错误，导致数据丢失或未完全写入，符合 CWE-252（未检查返回值）。
- D验证: stage_c_preserved / ver_efbc36bd
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 299. hyp_path_94ddb1358bda

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_07.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部输入控制；代码逻辑中明确忽略了返回值
- 触发路径: fputs("string", stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_07.c:34
- 结论: 函数fputs的返回值未被检查，可能导致部分写入或错误无法被及时发现，违反CWE-252。
- D验证: stage_c_preserved / ver_f3f906e1
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 300. hyp_path_73ff49e92e30

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_15.c:30
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部输入控制，但函数返回值被忽略
- 触发路径: case 6: /* NOTE: Do not check the return value */ fputs("string", stdout); break; @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_15.c:30
- 结论: CWE-252: Unchecked Return Value - fputs return value is not checked
- D验证: stage_c_preserved / ver_3a289cae
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 301. hyp_path_1b442d555a0c

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_16.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无额外条件，代码直接调用fputs并忽略返回值
- 触发路径: fputs("string", stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_16.c:29
- 结论: 未检查fputs的返回值，可能导致数据未完整写入，违反CWE-252
- D验证: stage_c_preserved / ver_63141f1c
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 302. hyp_path_359acb6f4197

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_13.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: fputs("string", stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_13.c:29
- 结论: CWE-252: Unchecked Return Value - fputs return value is not checked, leading to potential undetected errors.
- D验证: stage_c_preserved / ver_c3613af3
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 303. hyp_path_67c18765b8bb

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_18.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 无外部可控输入；stdout可能关闭或写入失败，但硬编码字符串降低可利用性
- 触发路径: /* NOTE: Do not check the return value */ fputs("string", stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_18.c:29
- 结论: 未检查fputs返回值，可能导致写入错误被忽略。虽然输入为硬编码字符串，但代码注释明确要求不检查返回值，违背安全编码实践。
- D验证: stage_c_preserved / ver_5195bb1a
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 304. hyp_path_d97525ba7f73

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fputs_17.c:30
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: fputs("string", stdout); // NOTE: Do not check the return value @ L30
- 结论: Unchecked return value of fputs; failure to check fputs return value may lead to undetected write failures, though exploitation likelihood is low due to hardcoded input.
- D验证: stage_c_preserved / ver_6daf2181
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 305. hyp_path_378087a9eafa

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_01.c:32
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够通过stdin提供输入，fscanf可能因EOF、格式不匹配等原因失败。
- 触发路径: fscanf(stdin, "%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_01.c:32
- 结论: 未检查fscanf返回值，可能导致后续使用未初始化的数据或未检测到输入错误。
- D验证: stage_c_preserved / ver_add36aa3
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 306. hyp_path_26092a3033ff

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_06.c:39
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够影响stdin输入，使其提前结束或为空
- 触发路径: fscanf(stdin, "%99s\0", data); @ 39
- 结论: 代码调用fscanf后未检查返回值，如果fscanf读取失败，data缓冲区内容可能未定义（未初始化或残留数据），可能导致后续使用未初始化数据或逻辑错误。
- D验证: stage_c_preserved / ver_5a35ff16
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 307. hyp_path_65e07751b138

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_05.c:40
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够通过控制stdin输入导致fscanf失败（如输入空白字符或提前结束）
- 触发路径: char * data = dataBuffer; /* NOTE: Do not check the return value */ fscanf(stdin, "%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_05.c:38-42
- 结论: fscanf的返回值未被检查，如果读入失败（如输入提前结束或格式不匹配），则data缓冲区可能包含未初始化的数据，导致后续使用该数据时产生未定义行为。
- D验证: stage_c_preserved / ver_418294b6
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 308. hyp_path_98e77e0c7b4a

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_03.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制stdin输入（如提供无效输入或提前EOF），导致fscanf失败。
- 触发路径: fscanf(stdin, "%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_03.c:34
- 结论: fscanf返回值未检查，可能导致在输入失败时使用未初始化的data变量，引发未定义行为或逻辑错误。
- D验证: stage_c_preserved / ver_82ab28b7
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 309. hyp_path_e254171486c7

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_02.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够控制或影响标准输入流（stdin）的内容或状态，使fscanf读取失败。
- 触发路径: fscanf(stdin, "%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_02.c:34
- 结论: 未检查fscanf返回值，可能导致在输入失败时使用未初始化的数据，造成信息泄露或程序行为异常。
- D验证: stage_c_preserved / ver_55344e1e
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 310. hyp_path_eb80438e8c96

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_04.c:40
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够提供导致fscanf失败的输入（如EOF或非字符串内容）
- 触发路径: fscanf(stdin, "%99s\0", data); @ L40
- 结论: 未检查fscanf返回值，可能导致使用未初始化或错误数据，属于CWE-252未检查返回值漏洞。
- D验证: stage_c_preserved / ver_636a12c3
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 311. hyp_path_424ee0da830b

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_10.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够影响stdin输入，使fscanf返回非1（读取失败或EOF）。
- 触发路径: fscanf(stdin, "%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_10.c:34
- 结论: 未检查fscanf返回值，可能导致程序在读取失败后使用未初始化的数据，引发意外行为或后续安全风险。
- D验证: stage_c_preserved / ver_126c112e
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 312. hyp_path_58ba88d758be

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_07.c:39
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够导致fscanf读取失败（如关闭stdin或提供非法输入）。
- 触发路径: fscanf(stdin, "%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_07.c:39
- 结论: 未检查fscanf的返回值，可能导致使用未初始化或错误的数据。
- D验证: stage_c_preserved / ver_9d744938
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 313. hyp_path_9ea785f51ca6

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_09.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够影响stdin的输入状态，导致读取失败
- 触发路径: fscanf(stdin, "%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_09.c:34
- 结论: 未检查fscanf的返回值，若读取失败，data可能保持未初始化状态，后续使用导致未定义行为
- D验证: stage_c_preserved / ver_ac3b40bd
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 314. hyp_path_bed577251105

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_13.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够使stdin读取操作失败（例如关闭标准输入或导致EOF）
- 触发路径: char * data = dataBuffer; @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_13.c:32; fscanf(stdin, "%99s\0", data); // 未检查返回值 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_13.c:34
- 结论: 未检查fscanf返回值，如果读取失败，后续使用未初始化的缓冲区数据可能导致未定义行为或信息泄露。
- D验证: stage_c_preserved / ver_c437b51b
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 315. hyp_path_d57c9dca30af

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_14.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够导致标准输入读取失败，如关闭输入流、提供无效输入或触发EOF。
- 触发路径: fscanf(stdin, "%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_14.c:34
- 结论: 函数未检查fscanf的返回值，如果fscanf读取失败（如EOF或无效输入），dataBuffer内容保持未定义，后续使用该缓冲区可能导致未初始化数据访问或逻辑错误，符合CWE-252。
- D验证: stage_c_preserved / ver_ba1c3190
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 316. hyp_path_32745fb623d7

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_16.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制stdin输入（例如，通过提供无效输入或关闭流）触发fscanf失败。
- 触发路径: fscanf(stdin, "%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_16.c:34
- 结论: 未检查fscanf的返回值，可能导致程序在输入失败时使用未初始化的数据或忽略错误状态。
- D验证: stage_c_preserved / ver_aa735f75
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 317. hyp_path_69a854d61220

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_15.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够通过stdin输入导致fscanf失败（如不提供输入或关闭stdin）。
- 触发路径: fscanf(stdin, "%99s\0", data); @ L35
- 结论: 函数fscanf的返回值未被检查，若读取失败（如输入无效或EOF），data可能包含未初始化的数据，导致后续使用不可预测。
- D验证: stage_c_preserved / ver_0769c1ab
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 318. hyp_path_1e977963099c

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_17.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够使stdin输入流出现错误或发送EOF，导致fscanf读取失败。
- 触发路径: fscanf(stdin, "%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_17.c:35
- 结论: 未检查fscanf返回值，可能导致在读取失败时使用未初始化的数据或旧数据，引发不可预测行为。
- D验证: stage_c_preserved / ver_9420ca6c
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 319. hyp_path_f034d5885ecc

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_16.c:66
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者通过stdin向程序提供输入，可能使得fscanf返回非EOF错误码
- 触发路径: static void case11() { while(1) { { char dataBuffer[100] = ""; char * data = dataBuffer; if (fscanf(stdin, "%99s\0", data) == EOF) { printLine("fscanf failed!"); } } break; } } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_16.c:45-62
- 结论: 函数case11中fscanf的返回值未完全检查，仅检查EOF错误，未检查其他读取失败情况（如格式匹配失败返回0），可能导致后续逻辑基于未初始化数据，但当前代码未使用读取结果，风险较低。
- D验证: stage_c_preserved / ver_be74fd9b
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 320. hyp_path_7a8c7685d5c5

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_18.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Attacker can provide input via stdin
- 触发路径: fscanf(stdin, "%99s\0", data); @ 34
- 结论: The return value of fscanf is not checked, leading to potential use of uninitialized or incomplete data, which may cause undefined behavior or security issues.
- D验证: stage_c_preserved / ver_41fcefc5
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 321. hyp_path_051f6d7eed6e

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_01.c:27
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无需要攻击者控制的输入；漏洞由编码时未检查返回值导致。
- 触发路径: fwrite((char *)"string", sizeof(char), strlen("string"), stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_01.c:27
- 结论: 函数fwrite的返回值未被检查，可能导致部分写入或写入失败未被察觉，违反CWE-252（未检查返回值）。
- D验证: stage_c_preserved / ver_5e069d84
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 322. hyp_path_b28c38fc5253

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_18.c:62
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Attacker can provide input via stdin
- 触发路径: if (fscanf(stdin, "%99s\0", data) == EOF) { @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fscanf_18.c:53
- 结论: CWE252: Unchecked Return Value - incomplete check of fscanf return value (only checks for EOF, not other failure conditions)
- D验证: stage_c_preserved / ver_e6289821
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 323. hyp_path_969b1b976983

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_03.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: stdout写入失败的情况（如磁盘满、权限不足，或stdout被重定向到文件且空间不足）
- 触发路径: fwrite((char *)"string", sizeof(char), strlen("string"), stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_03.c:29
- 结论: 调用fwrite时未检查返回值，可能导致未检测到的写入错误
- D验证: stage_c_preserved / ver_1342ba04
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 324. hyp_path_cc0d9d7e156b

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_04.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够影响stdout的可用性（如关闭标准输出流或重定向到受限文件），使fwrite失败。
- 触发路径: fwrite((char *)"string", sizeof(char), strlen("string"), stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_04.c:35
- 结论: 未检查fwrite返回值，可能导致数据未完全写入stdout，属于CWE-252未检查返回值漏洞。
- D验证: stage_c_preserved / ver_02f396fc
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 325. hyp_path_dfae1e0d11f5

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_05.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部输入，仅因编码习惯未检查返回值
- 触发路径: fwrite((char *)"string", sizeof(char), strlen("string"), stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_05.c:35
- 结论: 未检查fwrite返回值，可能导致写入操作失败时未处理错误，符合CWE-252定义
- D验证: stage_c_preserved / ver_3e988a92
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 326. hyp_path_3892cb70950a

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_07.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够使写入操作部分失败（例如磁盘空间耗尽）
- 触发路径: fwrite((char *)"string", sizeof(char), strlen("string"), stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_07.c:34
- 结论: CWE-252: Unchecked Return Value in fwrite call
- D验证: stage_c_preserved / ver_7d980dca
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 327. hyp_path_03ff594a8290

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_09.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: fwrite((char *)"string", sizeof(char), strlen("string"), stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_09.c:29
- 结论: 在fwrite调用后未检查返回值，可能导致部分写入或写入失败未被检测，违反CWE-252规范。
- D验证: stage_c_preserved / ver_e6887bb6
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 328. hyp_path_cd5adec6f60d

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_06.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无需用户输入，任何执行该路径的场景
- 触发路径: fwrite((char *)"string", sizeof(char), strlen("string"), stdout); @ 34
- 结论: 未检查fwrite返回值，可能导致部分写入或出错时数据丢失
- D验证: stage_c_preserved / ver_204518b6
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 329. hyp_path_be2e714cf8ff

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_10.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 函数fwrite返回值未被检查，但写入内容为固定字符串，风险较低
- 触发路径: fwrite((char *)"string", sizeof(char), strlen("string"), stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_10.c:29
- 结论: CWE252_Unchecked_Return_Value
- D验证: stage_c_preserved / ver_540c80f3
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 330. hyp_path_7dad93063e07

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_15.c:30
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者无法直接控制输入（写入内容为硬编码字符串），但运行环境可能异常（如stdout不可写）
- 触发路径: fwrite((char *)"string", sizeof(char), strlen("string"), stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_15.c:30
- 结论: 未检查fwrite返回值，可能导致数据写入失败或部分写入，影响数据完整性
- D验证: stage_c_preserved / ver_45b4d0bb
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 331. hyp_path_fc19c63613b0

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_16.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 该调用返回值未检查，但写入内容固定，目标为stdout，无外部输入控制
- 触发路径: fwrite((char *)"string", sizeof(char), strlen("string"), stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_16.c:29
- 结论: CWE-252: Unchecked return value of fwrite
- D验证: stage_c_preserved / ver_a4e15399
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 332. hyp_path_8ee331a2c157

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_17.c:30
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者无法直接控制写入数据，但可能通过改变标准输出状态（如关闭管道、填满磁盘）导致写入失败
- 触发路径: fwrite((char *)"string", sizeof(char), strlen("string"), stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_fwrite_17.c:30
- 结论: 未检查fwrite函数的返回值，可能导致数据写入不完整或错误未被发现，影响数据完整性
- D验证: stage_c_preserved / ver_f2802112
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 333. hyp_path_fdd51aff0d04

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_01.c:27
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: stdout write may fail (e.g., disk full, file system error)
- 触发路径: putc((int)'A', stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_01.c:27
- 结论: Unchecked return value of putc()
- D验证: stage_c_preserved / ver_4973c940
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 334. hyp_path_4686135ca04c

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_03.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 标准输出可能失败（如磁盘满、管道关闭等）
- 触发路径: putc((int)'A', stdout); @ L29
- 结论: putc的返回值未被检查，违反安全实践，可能导致数据丢失或程序行为异常
- D验证: stage_c_preserved / ver_1c436ee5
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 335. hyp_path_c48237f1d53c

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_05.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: stdout is closed or in error state
- 触发路径: putc((int)'A', stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_05.c:35
- 结论: The return value of putc() is not checked, which may cause undetected write errors to stdout.
- D验证: stage_c_preserved / ver_cb66a800
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 336. hyp_path_8dbb3108ab1c

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_02.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者可能通过影响stdout状态（如关闭文件描述符）使putc失败。
- 触发路径: putc((int)'A', stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_02.c:29
- 结论: 未检查putc()的返回值，可能导致写入错误未被检测到，从而引发未定义行为或数据丢失（CWE-252）。
- D验证: stage_c_preserved / ver_f53fe734
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 337. hyp_path_6c2cabb4fac1

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_04.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者可能通过耗尽磁盘空间、关闭管道或重定向stdout等方式使写入失败，但本场景中无直接攻击者输入，属于隐藏错误。
- 触发路径: putc((int)'A', stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_04.c:35
- 结论: 未检查putc函数的返回值，可能导致写错误未被发现。
- D验证: stage_c_preserved / ver_8937234a
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 338. hyp_path_9c2b0f3e0b66

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_07.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无，攻击者无需控制输入，但stdout可能因环境因素关闭或出错。
- 触发路径: putc((int)'A', stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_07.c:34
- 结论: 未检查putc函数的返回值，可能导致写入失败未被发现，属于CWE-252未检查返回值漏洞。
- D验证: stage_c_preserved / ver_cab7e559
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 339. hyp_path_acdec5a36316

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_06.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: putc((int)'A', stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_06.c:34
- 结论: 未检查 putc 返回值，可能导致数据写入错误被忽略
- D验证: stage_c_preserved / ver_05daaef7
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 340. hyp_path_44f93eb5efd3

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_09.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者可能通过使stdout写入失败（如磁盘满、输出重定向失败等）导致putc返回错误，而返回值未被检查
- 触发路径: putc((int)'A', stdout); @ L29
- 结论: VULNERABILITY: Unchecked return value of putc
- D验证: stage_c_preserved / ver_618ff545
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 341. hyp_path_db63a802641b

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_10.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无特定攻击者控制前提，但调用putc后未检查返回值
- 触发路径: putc((int)'A', stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_10.c:29
- 结论: 未检查putc返回值，可能导致写入失败未处理
- D验证: stage_c_preserved / ver_393c7959
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 342. hyp_path_8f4a463468a2

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_13.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无需外部输入，代码中固定字符'A'写至stdout
- 触发路径: putc((int)'A', stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_13.c:29
- 结论: 未检查putc返回值，如果写入失败则输出错误未被检测到
- D验证: stage_c_preserved / ver_a2d6d838
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 343. hyp_path_26ec330680f1

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_14.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部输入控制，但函数调用返回值未检查
- 触发路径: putc((int)'A', stdout); @ L29
- 结论: 未检查 putc 的返回值，导致潜在的未定义行为或数据丢失（CWE-252）
- D验证: stage_c_preserved / ver_af3f7010
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 344. hyp_path_27fc7195aef5

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_16.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 程序在具有潜在I/O错误的环境中运行
- 触发路径: putc((int)'A', stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_16.c:29
- 结论: 未检查putc函数的返回值，可能导致写入失败时程序未获知错误，造成数据丢失或状态不一致。
- D验证: stage_c_preserved / ver_147dc6e5
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 345. hyp_path_656e516bfc93

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_15.c:30
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: putc((int)'A', stdout); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_15.c:30
- 结论: Unchecked return value of putc() leads to potential data loss or silent failure (CWE-252)
- D验证: stage_c_preserved / ver_1c9d6755
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 346. hyp_path_6e2affe92140

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_17.c:30
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者无法控制输入，但漏洞在于未检查返回值
- 触发路径: putc((int)'A', stdout); @ CWE252_Unchecked_Return_Value__char_putc_17.c:30
- 结论: 在putc调用后未检查返回值，可能导致未检测到的写入错误
- D验证: stage_c_preserved / ver_6a185c43
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 347. hyp_path_79e887c061c0

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_18.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: putc((int)'A', stdout); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putc_18.c:29
- 结论: 函数 putc 的返回值未被检查，可能导致未检测到的写入错误，属于 CWE-252 未检查返回值漏洞。
- D验证: stage_c_preserved / ver_38611c94
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 348. hyp_path_8429caf4243a

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_02.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无需外部输入，代码直接调用putchar但忽略返回值
- 触发路径: putchar((int)'A'); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_02.c:29
- 结论: 未检查putchar的返回值，可能导致未检测到的I/O错误
- D验证: stage_c_preserved / ver_d30107dd
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 349. hyp_path_d8c0cb85307a

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_03.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部输入要求，仅需程序执行到该路径
- 触发路径: putchar((int)'A'); @ L29
- 结论: 未检查putchar返回值，可能忽略I/O错误
- D验证: stage_c_preserved / ver_46bb4130
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 350. hyp_path_a4402d67a096

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_05.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: putchar((int)'A'); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_05.c:35
- 结论: CWE252: Unchecked Return Value - call to putchar without checking return value
- D验证: stage_c_preserved / ver_3d412181
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 351. hyp_path_ab0042b28c3d

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_04.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无特殊前提条件，所有执行路径均触发。
- 触发路径: putchar((int)'A'); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_04.c:35
- 结论: CWE-252 未检查返回值：putchar 的返回值未被检查，可能导致写入错误未被处理。
- D验证: stage_c_preserved / ver_11326805
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 352. hyp_path_9cc9761e6cee

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_07.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 程序运行环境可能导致putchar失败（如文件系统错误、缓冲区满等）。
- 触发路径: putchar((int)'A'); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_07.c:34
- 结论: 调用putchar函数时未检查其返回值，可能导致输出错误未被发现。
- D验证: stage_c_preserved / ver_fd22ad2c
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 353. hyp_path_5e170fb4f1ad

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_06.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: 入口点 @ CWE252_Unchecked_Return_Value__char_putchar_06.c:29; putchar((int)'A'); /* NOTE: Do not check the return value */ @ CWE252_Unchecked_Return_Value__char_putchar_06.c:34
- 结论: 存在未检查返回值漏洞：putchar函数的返回值未被检查，可能导致字符输出失败而未被发现。
- D验证: stage_c_preserved / ver_3f3b93b1
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 354. hyp_path_dad2512bbed6

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_09.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: putchar((int)'A'); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_09.c:29
- 结论: 未检查putchar返回值，导致可能的输出错误被忽略
- D验证: stage_c_preserved / ver_882228da
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 355. hyp_path_36ed1fc1574d

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_10.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 代码被执行
- 触发路径: putchar((int)'A'); @ L29
- 结论: 未检查putchar返回值，可能导致调用失败时未被发现
- D验证: stage_c_preserved / ver_088e32c4
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 356. hyp_path_2feb1cae27a1

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_13.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 无特殊攻击前提，只要代码执行到此路径即可触发；但putchar失败通常不影响安全敏感操作。
- 触发路径: putchar((int)'A'); @ CWE252_Unchecked_Return_Value__char_putchar_13.c:29
- 结论: 未检查putchar函数的返回值，可能导致输出错误未被发现。虽然实际安全影响较低，但违反安全编码原则。
- D验证: stage_c_preserved / ver_2dc71761
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 357. hyp_path_f71f0255478e

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_14.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够影响程序的标准输出或文件描述符状态，例如通过关闭文件描述符或耗尽磁盘空间导致putchar失败。
- 触发路径: putchar((int)'A'); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_14.c:29
- 结论: 未检查putchar函数的返回值，可能导致程序忽略写入错误，在特定环境下（如输出到文件流时）可能造成数据丢失或未定义行为。
- D验证: stage_c_preserved / ver_46eff589
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 358. hyp_path_059d77bc0120

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_15.c:30
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 代码调用putchar后未检查其返回值
- 触发路径: putchar((int)'A'); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_15.c:30
- 结论: putchar返回值未检查，可能导致输出不完整或错误未被处理
- D验证: stage_c_preserved / ver_f63f99a1
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 359. hyp_path_903170da20be

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_16.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 无特定攻击者输入，但putchar可能因环境错误而失败。
- 触发路径: putchar((int)'A'); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_16.c:29
- 结论: 未检查putchar函数的返回值，可能导致输出错误未被检测，属于CWE-252不可信返回值使用。
- D验证: stage_c_preserved / ver_bcf3e11b
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 360. hyp_path_47e338b2fba9

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_17.c:30
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无攻击者可控输入，但putchar可能因系统资源不足等环境原因失败。
- 触发路径: CWE252_Unchecked_Return_Value__char_putchar_17_case0 @ 入口:24; putchar((int)'A'); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_17.c:30
- 结论: 未检查putchar返回值，可能导致未检测到的输出错误。
- D验证: stage_c_preserved / ver_51822e2e
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 361. hyp_path_a53a2189f0a6

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_18.c:29
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: putchar((int)'A'); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_putchar_18.c:29
- 结论: 未检查putchar返回值，可能导致忽略错误（CWE-252）
- D验证: stage_c_preserved / ver_22d482d1
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 362. hyp_path_c6077cd75b1c

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_01.c:33
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: No precondition required; the code path is static and always executes.
- 触发路径: PUTS("string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_01.c:33
- 结论: CWE252: Unchecked Return Value - puts function return value is not checked, leading to potential unnoticed errors.
- D验证: stage_c_preserved / ver_e1e9f6d7
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 363. hyp_path_b08b2346ea50

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_02.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: PUTS("string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_02.c:35
- 结论: CWE-252 未检查返回值漏洞：在 CWE252_Unchecked_Return_Value__char_puts_02.c 中调用 PUTS 函数但未检查其返回值，可能导致未处理的错误状态。
- D验证: stage_c_preserved / ver_3eaf556d
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 364. hyp_path_e030c32899df

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_03.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: PUTS("string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_03.c:35
- 结论: CWE252 Unchecked Return Value: puts() return value not checked
- D验证: stage_c_preserved / ver_fe8a38de
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 365. hyp_path_3b7ff66d2d9a

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_06.c:40
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无特殊前提条件，函数调用本身未检查返回值
- 触发路径: PUTS("string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_06.c:40
- 结论: CWE-252: Unchecked Return Value of puts()
- D验证: stage_c_preserved / ver_6494d09e
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 366. hyp_path_bfdb7fa76dda

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_10.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: No precondition required; the issue is the failure to check the return value of puts(), not input control.
- 触发路径: PUTS("string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_10.c:35
- 结论: CWE252: Unchecked return value of puts() function
- D验证: stage_c_preserved / ver_86f44d35
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 367. hyp_path_8c7192752442

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_14.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无外部输入控制，属于编程疏忽
- 触发路径: PUTS("string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_14.c:35
- 结论: 未检查puts函数的返回值
- D验证: stage_c_preserved / ver_7627c037
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 368. hyp_path_f24ceb8cebb7

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_15.c:36
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 程序执行流到达case 6分支。
- 触发路径: 入口进入路由 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_15.c:30; case 6: /* NOTE: Do not check the return value */ PUTS("string"); break; @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_15.c:36
- 结论: 在case 6分支中调用puts函数但未检查其返回值，可能导致未处理错误或资源问题，属于CWE-252未检查返回值漏洞。
- D验证: stage_c_preserved / ver_c4de08ac
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 369. hyp_path_3a2c20db7dd2

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_17.c:36
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: N/A
- 触发路径: PUTS("string"); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_puts_17.c:36
- 结论: 调用PUTS函数未检查返回值，可能导致错误未被发现，但当前代码仅输出固定字符串，影响极小。
- D验证: stage_c_preserved / ver_db001725
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 370. hyp_path_dd6053060954

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_01.c:32
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够通过标准输入提供数据，但scanf可能因各种原因失败
- 触发路径: scanf("%99s\0", data); @ 32
- 结论: 未检查scanf返回值，可能导致未初始化数据使用或忽略输入错误
- D验证: stage_c_preserved / ver_cce6ab43
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 371. hyp_path_e3d0a9023f3f

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_03.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制输入给scanf
- 触发路径: scanf("%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_03.c:34
- 结论: 未检查scanf返回值，可能导致未定义行为或安全漏洞
- D验证: stage_c_preserved / ver_62286482
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 372. hyp_path_c5f8117eba1c

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_05.c:40
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够影响程序的标准输入，例如通过提供空输入、EOF或不符合格式的字符串。
- 触发路径: scanf("%99s\0", data); // 未检查返回值 @ CWE252_Unchecked_Return_Value__char_scanf_05.c:40
- 结论: 未检查scanf函数的返回值，如果scanf执行失败（例如遇到EOF或格式不匹配），则dataBuffer的内容可能未初始化或保持之前的状态，导致后续使用时出现未定义行为，可能造成信息泄露或程序崩溃。
- D验证: stage_c_preserved / ver_09c7f463
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 373. hyp_path_66b88b747fc8

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_02.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够向程序的标准输入提供特殊输入（如EOF或触发读取失败的条件）。
- 触发路径: scanf("%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_02.c:34
- 结论: 调用了scanf但未检查返回值，可能导致在输入失败时使用未初始化的缓冲区数据，造成信息泄露或未定义行为。
- D验证: stage_c_preserved / ver_34115288
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 374. hyp_path_97b17a12e079

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_06.c:39
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够影响标准输入（如通过输入流控制）导致scanf失败
- 触发路径: scanf("%99s\0", data); @ CWE252_Unchecked_Return_Value__char_scanf_06.c:39
- 结论: 在scanf调用后未检查返回值，如果输入失败（如EOF或格式不匹配），data内容可能未更新，导致后续逻辑使用未定义数据，可能引发安全风险（如信息泄露或逻辑错误）。
- D验证: stage_c_preserved / ver_549f8f38
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 375. hyp_path_8c92ba56c2f5

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_09.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制标准输入，例如通过关闭输入流或提供无效输入使scanf失败。
- 触发路径: scanf("%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_09.c:34
- 结论: 程序未检查scanf函数的返回值，如果scanf读取失败（如遇到EOF），则data数组可能保持未初始化状态，后续使用该数据可能导致未定义行为或信息泄露。
- D验证: stage_c_preserved / ver_e5fce956
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 376. hyp_path_13256cc14c1a

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_07.c:39
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够控制输入导致scanf失败（如提供EOF或空输入）
- 触发路径: scanf("%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_07.c:39
- 结论: 调用scanf未检查返回值，如果后续操作依赖dataBuffer的内容，则可能因scanf失败导致使用未初始化或陈旧数据，但此处无后续sink，实际风险较低。
- D验证: stage_c_preserved / ver_5629db4a
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 377. hyp_path_6e0970a28a95

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_10.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够通过标准输入导致scanf返回非预期值（如EOF或0）
- 触发路径: scanf("%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_10.c:34
- 结论: 程序调用scanf时不检查返回值，可能导致在输入失败时数据未初始化或部分读取，造成未定义行为或逻辑错误
- D验证: stage_c_preserved / ver_6b88f2c7
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 378. hyp_path_76560663ada0

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_13.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够导致标准输入关闭或产生错误
- 触发路径: scanf("%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_13.c:34
- 结论: 未检查scanf函数的返回值，如果输入失败（如EOF），data可能包含未初始化数据，导致后续使用未定义行为。
- D验证: stage_c_preserved / ver_514fa030
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 379. hyp_path_1b4fbb3a2646

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_14.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: No specific precondition; the vulnerability is that the return value of scanf is ignored, which may leave data buffer uninitialized or partially filled if input fails.
- 触发路径: scanf("%99s\0", data); /* NOTE: Do not check the return value */ @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_14.c:34
- 结论: CWE-252: Unchecked Return Value - scanf return value not checked leading to potential use of uninitialized or incomplete data
- D验证: stage_c_preserved / ver_47e6bd80
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 380. hyp_path_0e7e685f56a3

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_15.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Input may fail (e.g., EOF or format mismatch)
- 触发路径: scanf("%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_15.c:35
- 结论: CWE-252: Unchecked Return Value - scanf() return value not checked, leading to potential use of uninitialized data
- D验证: stage_c_preserved / ver_30d24dfa
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 381. hyp_path_0e9ce52edcaf

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_16.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够提供无效输入（如EOF或格式不匹配）使scanf返回非1
- 触发路径: /* NOTE: Do not check the return value */ scanf("%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_16.c:34
- 结论: 未检查scanf函数的返回值，若输入失败（如EOF或格式不匹配），data变量将保持未初始化状态，可能导致未定义行为或信息泄露。
- D验证: stage_c_preserved / ver_e022a5a0
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 382. hyp_path_7c65ebea3caa

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_17.c:35
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者可以控制输入流，导致scanf失败（如提前关闭输入）。
- 触发路径: scanf("%99s\0", data); // 未检查返回值 @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_17.c:35
- 结论: 未检查scanf函数的返回值，可能导致后续使用未正确初始化的数据，引发不可预测行为或安全漏洞。
- D验证: stage_c_preserved / ver_bc90fd7f
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 383. hyp_path_8ba046244b1e

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_18.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Attacker provides input via stdin
- 触发路径: scanf("%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_18.c:34
- 结论: VULNERABILITY_FOUND: Unchecked return value of scanf leads to potential undefined behavior
- D验证: stage_c_preserved / ver_47fbd885
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 384. hyp_path_fac7e9c8d134

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_01.c:40
- 漏洞类型: buffer_overflow
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: SNPRINTF(data,100-strlen(SRC)-1, "%s\n", SRC); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_01.c:40
- 结论: CWE252_Unchecked_Return_Value：snprintf返回值未检查，可能导致数据截断或缓冲区溢出，但无外部可控输入
- D验证: stage_c_preserved / ver_5dee2253
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 385. hyp_path_b40ca53f3845

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_02.c:42
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: N/A
- 触发路径: SNPRINTF(data,100-strlen(SRC)-1, "%s\n", SRC); @ L42
- 结论: snprintf返回值未检查，可能导致截断等错误未处理
- D验证: stage_c_preserved / ver_376d6feb
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 386. hyp_path_bbe426f2b6f0

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_04.c:48
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 存在源字符串SRC，其长度可能超过目标缓冲区剩余空间
- 触发路径: SNPRINTF(data,100-strlen(SRC)-1, "%s\n", SRC); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_04.c:48
- 结论: 未检查snprintf返回值，可能导致缓冲区截断错误未被发现
- D验证: stage_c_preserved / ver_e9bd84c2
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 387. hyp_path_50f6736eede8

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_18.c:62
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够向程序标准输入提供数据
- 触发路径: static void case11() { goto sink; sink: { ... scanf("%99s\0", data); ... } } @ L? 或 case11函数入口; if (scanf("%99s\0", data) == EOF) { printLine("scanf failed!"); } @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_scanf_18.c:53
- 结论: 在函数case11中，scanf的返回值被检查是否为EOF，但未检查是否成功读取（返回1）。当输入仅包含空白字符时，scanf返回0，不会触发失败处理，但data内容未更新，仍为空字符串。这可能导致后续使用未正确初始化的数据，属于CWE-252未检查返回值漏洞。
- D验证: stage_c_preserved / ver_8c328b19
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 388. hyp_path_2c6fd9e6f957

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_03.c:42
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 调用 snprintf 后未检查返回值
- 触发路径: SNPRINTF(data,100-strlen(SRC)-1, "%s\n", SRC); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_03.c:42
- 结论: 未检查 snprintf 返回值可能导致缓冲区截断或数据丢失，符合 CWE-252
- D验证: stage_c_preserved / ver_0f1f0e68
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 389. hyp_path_ec63b57ca13b

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_06.c:47
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 函数调用后未检查返回值
- 触发路径: SNPRINTF(data,100-strlen(SRC)-1, "%s\n", SRC); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_06.c:47
- 结论: SNPRINTF返回值未被检查，可能导致数据截断或错误未被发现
- D验证: stage_c_preserved / ver_e61f6b56
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 390. hyp_path_51daa2844fc5

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_05.c:48
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够影响SRC的内容或长度，使得snprintf输出被截断
- 触发路径: SNPRINTF(data,100-strlen(SRC)-1, "%s\n", SRC); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_05.c:48
- 结论: snprintf返回值未检查，可能导致缓冲区截断但不报错，影响后续数据处理
- D验证: stage_c_preserved / ver_3b1a1492
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 391. hyp_path_433f520e76af

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_07.c:47
- 漏洞类型: integer_overflow
- CWE: CWE-190; CWE-120
- 风险等级: P2
- 触发条件: 攻击者能够控制SRC字符串的内容和长度。
- 触发路径: SNPRINTF(data,100-strlen(SRC)-1, "%s\n", SRC); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_07.c:45-49
- 结论: snprintf的size参数计算存在整数下溢，导致缓冲区溢出。当SRC长度大于99时，100-strlen(SRC)-1为负数，转换为无符号size_t后成为极大值，使得snprintf写入超出dataBuffer的100字节缓冲区。
- D验证: stage_c_preserved / ver_7b01c95a
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 392. hyp_path_1ed8a61a6b86

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_10.c:42
- 漏洞类型: integer_overflow
- CWE: CWE-190; CWE-120; CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够控制 SRC 的长度，使其足够长（>=100）。
- 触发路径: char * data = dataBuffer; @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_10.c:40; SNPRINTF(data,100-strlen(SRC)-1, "%s\n", SRC); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_10.c:42
- 结论: 代码中使用 snprintf 写入缓冲区，但计算缓冲区大小时使用了 `100-strlen(SRC)-1`，如果 SRC 长度大于等于 100，则结果为负数，作为 size_t 类型时变为极大值，导致 snprintf 写入超出缓冲区，造成缓冲区溢出。同时未检查 snprintf 返回值，可能忽略截断或错误。
- D验证: stage_c_preserved / ver_e3fc39db
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 393. hyp_path_eead73589b04

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_14.c:42
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制SRC的内容
- 触发路径: SNPRINTF(data,100-strlen(SRC)-1, "%s\n", SRC); @ L42
- 结论: snprintf返回值未检查，可能导致缓冲区截断或数据丢失
- D验证: stage_c_preserved / ver_02ff20c8
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 394. hyp_path_7fd9d28f788d

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_15.c:43
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 存在未检查返回值的snprintf调用
- 触发路径: SNPRINTF(data,100-strlen(SRC)-1, "%s\n", SRC); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_15.c:43
- 结论: snprintf返回值未检查，可能导致数据截断或写入错误
- D验证: stage_c_preserved / ver_4eb61c71
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 395. hyp_path_ffc3fbae9b97

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_17.c:43
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: SRC字符串长度可能超过目标缓冲区剩余空间，但即使无截断，未检查返回值本身即构成漏洞。
- 触发路径: SNPRINTF(data,100-strlen(SRC)-1, "%s\n", SRC); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_snprintf_17.c:43
- 结论: 代码未检查snprintf返回值，可能导致部分输出丢失或未检测到错误，属于CWE-252未检查返回值漏洞。
- D验证: stage_c_preserved / ver_a65bdf3a
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 396. hyp_path_79b7f49dab5e

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_02.c:36
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制SRC输入（如外部输入）
- 触发路径: sscanf(SRC, "%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_02.c:36
- 结论: sscanf返回值未检查，可能导致数据读取失败或未初始化数据使用
- D验证: stage_c_preserved / ver_d81f34bc
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 397. hyp_path_f29108f2ecec

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_06.c:41
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制SRC输入
- 触发路径: sscanf(SRC, "%99s\0", data); @ L41
- 结论: VULNERABILITY_FOUND: Unchecked return value of sscanf
- D验证: stage_c_preserved / ver_e1f7bb48
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 398. hyp_path_bd161eebb628

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_04.c:42
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 无，该漏洞静态存在，无需攻击者控制输入。
- 触发路径: sscanf(SRC, "%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_04.c:42
- 结论: 未检查sscanf函数的返回值，如果sscanf失败，dataBuffer可能未被正确初始化，后续使用未初始化的内存可能导致未定义行为或被攻击者利用。
- D验证: stage_c_preserved / ver_d5ffaeca
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 399. hyp_path_9da4ed9c0615

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_01.c:34
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: Attacker controls SRC (external input)
- 触发路径: sscanf(SRC, "%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_01.c:34
- 结论: Unchecked return value of sscanf leading to potential use of uninitialized or incomplete data
- D验证: stage_c_preserved / ver_dd1d814f
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 400. hyp_path_cc93aba7d4af

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_05.c:42
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P1
- 触发条件: 攻击者能够控制SRC输入，且sscanf可能失败（如空输入）
- 触发路径: sscanf(SRC, "%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_05.c:42
- 结论: sscanf函数返回值未检查，可能导致使用未初始化的dataBuffer，符合CWE-252
- D验证: stage_c_preserved / ver_18579a96
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 401. hyp_path_0bf538580d47

- 漏洞位置: juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_03.c:36
- 漏洞类型: CWE-252
- CWE: CWE-252
- 风险等级: P2
- 触发条件: 攻击者能够控制sscanf的输入参数SRC，使其解析失败或产生意外结果。
- 触发路径: sscanf(SRC, "%99s\0", data); @ juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_sscanf_03.c:36
- 结论: 在调用sscanf时未检查其返回值，可能导致后续处理使用未初始化的数据或状态，属于CWE-252未检查返回值漏洞。
- D验证: stage_c_preserved / ver_da1949cc
- 运行证据: unsupported oracle matched patterns: MAGUS_JULIET_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

## Unconfirmed / Failed Verification

These records are not reported as confirmed vulnerabilities. See `verification.failed.jsonl` for full failure details.

- hyp_path_1fb8039f2815 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_12.c:143 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_a070914d23ba | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_12.c:143 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_53d32bbd19bb | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_17.c:89 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_cc787f95545d | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_09.c:92 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_4a4c559c6649 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_10.c:92 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_671eb60a0884 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_07.c:97 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_db3cf150f568 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_14.c:92 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_f71ee1fe63a4 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_01.c:81 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_fd85602a481d | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_02.c:92 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_ccc2c336d730 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_02.c:125 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_8e50150437d2 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_06.c:97 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_452b92cfb670 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_09.c:125 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_9caf7e0a854c | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_07.c:130 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_3ca66e347ceb | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_06.c:130 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_6cb0ba3ebae8 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_16.c:88 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_c6e5a5b99719 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_15.c:133 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_aa7a665e5fd7 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_03.c:125 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_feb3fd9de3ca | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_02.c:92 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_60b802bbfeb4 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_05.c:131 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_0ce2f47ed91e | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_04.c:98 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_56ac85246b9b | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_06.c:97 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_8acf8dba59ed | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_09.c:125 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_9429047131b6 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_07.c:130 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_13a0e685802f | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_10.c:125 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_0afebb3a3325 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_14.c:125 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_a2f8e68bf4a5 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_16.c:88 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_07a95306a4bf | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_18.c:86 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_000abb664551 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/main.cpp:64 | ENV_MISSING | payload did not satisfy oracle
- hyp_path_a6acfadda16a | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateMutex_17.c:63 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_302414f1bde4 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateMutex_13.c:66 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_a32996b45326 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_05.c:139 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_473c6e6b0fe4 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__char_w32CreateNamedPipe_07.c:137 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_33b4a314e4f0 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_04.c:138 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_310fa9df8eba | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_05.c:139 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_5efa74b5ad71 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_03.c:133 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_7affe3c5fa79 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_08.c:146 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_5e674824ef35 | juliet-api-misuse/testcases/CWE252_Unchecked_Return_Value/CWE252_Unchecked_Return_Value__wchar_t_w32CreateNamedPipe_07.c:137 | NOT_ROUTE_BOUND | payload did not satisfy oracle
