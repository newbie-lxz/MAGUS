# MAGUS Final Vulnerability Report

- generated_at: 2026-05-22T15:22:18Z
- reportable_vulnerabilities: 36
- d_confirmed_vulnerabilities: 36
- stage_c_preserved_vulnerabilities: 0
- failed_verifications: 52
- source_confirmed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE273_Improper_Check_for_Dropped_Privileges/verification.jsonl
- source_failed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE273_Improper_Check_for_Dropped_Privileges/verification.failed.jsonl

## Confirmed Vulnerabilities

### 1. hyp_path_00ebdf18f647

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_12.c:48
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立命名管道连接，且能够使ImpersonateNamedPipeClient调用失败。
- 触发路径: if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) { CloseHandle(hPipe); exit(1); } @ 行44-48; ImpersonateNamedPipeClient(hPipe); @ 行50; printLine("Impersonated"); @ 行51; if (!RevertToSelf()) { exit(1); } @ 行52-54
- 结论: 在ImpersonateNamedPipeClient调用后未检查其返回值，如果模拟失败，程序可能错误地认为已获得特权，导致权限滥用。
- D验证: confirmed / ver_0445a279
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 2. hyp_path_bcf0fad02bac

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_08.c:61
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够连接到命名管道（作为客户端），且客户端上下文不具有模拟权限或模拟操作失败。
- 触发路径: if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) { CloseHandle(hPipe); exit(1); } @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_08.c:57-61; ImpersonateNamedPipeClient(hPipe); // 未检查返回值 @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_08.c:61; if (!RevertToSelf()) { exit(1); } // 仅检查还原是否成功，但无法确保模拟成功 @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_08.c:66-70
- 结论: 函数中调用了ImpersonateNamedPipeClient但未检查其返回值，之后调用RevertToSelf并检查其返回值，然而如果ImpersonateNamedPipeClient失败，RevertToSelf可能成功返回，导致程序错误地认为已经模拟了客户端权限，实际并未模拟，从而造成权限检查不恰当（CWE-273）。
- D验证: confirmed / ver_818dff66
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 3. hyp_path_18f2d275b87c

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_11.c:48
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 管道已成功创建并连接（或至少未导致提前退出），但ImpersonateNamedPipeClient可能因权限不足、句柄无效或其他原因失败，而返回值未被检查。
- 触发路径: hPipe = CreateNamedPipeA(...); @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_11.c:29-33; if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) { ... } @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_11.c:44-48; ImpersonateNamedPipeClient(hPipe); printLine("Impersonated"); @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_11.c:53-54; if (!RevertToSelf()) { exit(1); } @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_11.c:55-57
- 结论: 调用ImpersonateNamedPipeClient后未检查返回值，可能导致模拟客户端身份失败而不被察觉，从而未能正确撤销权限，违反CWE273对撤销权限的正确检查要求。
- D验证: confirmed / ver_b21c1c5e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 4. hyp_path_8528b019b911

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_17.c:49
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够连接命名管道并提供导致 ImpersonateNamedPipeClient 失败的客户端行为
- 触发路径: hPipe = CreateNamedPipeA(...) @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_17.c:30-34; if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) { CloseHandle(hPipe); exit(1); } @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_17.c:47-51; ImpersonateNamedPipeClient(hPipe); printLine("Impersonated"); if (!RevertToSelf()) { exit(1); } @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_17.c:56-58
- 结论: ImpersonateNamedPipeClient 的返回值未检查，如果失败，后续 RevertToSelf 可能导致特权未正确恢复，存在权限提升风险。
- D验证: confirmed / ver_c17d8613
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 5. hyp_path_548ba60605f6

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_01.c:46
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够连接到命名管道并使得ImpersonateNamedPipeClient失败（例如通过快速关闭连接或使管道处于无效状态）
- 触发路径: hPipe = CreateNamedPipeA("\\\\.\\pipe\\test_pipe", PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, ...); @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_01.c:30; if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) { CloseHandle(hPipe); exit(1); } @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_01.c:44; ImpersonateNamedPipeClient(hPipe); // 未检查返回值 @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_01.c:53; printLine("Impersonated"); // 错误地认为模拟成功 @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_01.c:54; if (!RevertToSelf()) { exit(1); } // 恢复自身，但模拟可能已失败 @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_01.c:55
- 结论: 未检查ImpersonateNamedPipeClient函数的返回值，如果模拟失败，后续代码仍认为已模拟客户端，可能导致未正确降低特权，存在权限提升风险。
- D验证: confirmed / ver_1890081a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 6. hyp_path_5de82a7b9295

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_03.c:48
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够连接到命名管道（即与服务器建立管道连接）
- 触发路径: ImpersonateNamedPipeClient(hPipe); printLine("Impersonated"); @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_03.c:53-54; if (!RevertToSelf()) @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_03.c:55-56
- 结论: 在ImpersonateNamedPipeClient调用后未检查其返回值，可能导致模拟失败时仍继续执行后续操作，违背了权限检查原则。
- D验证: confirmed / ver_4a0e5bae
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 7. hyp_path_4e3f6acf83db

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_02.c:48
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够通过命名管道连接服务端，并使得 ImpersonateNamedPipeClient 调用失败（例如模拟客户端失败）。
- 触发路径: hPipe = CreateNamedPipeA(...); @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_02.c:29-33; if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) { CloseHandle(hPipe); exit(1); } @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_02.c:44-48; ImpersonateNamedPipeClient(hPipe); printLine("Impersonated"); if (!RevertToSelf()) { exit(1); } @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_02.c:53-57
- 结论: ImpersonateNamedPipeClient 的返回值未检查，如果模拟失败，则后续权限操作可能基于错误的客户端标识，导致权限提升或降级漏洞。
- D验证: confirmed / ver_3fb25caa
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 8. hyp_path_2cc55af4d517

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_05.c:54
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够连接到命名管道
- 触发路径: ImpersonateNamedPipeClient(hPipe); printLine("Impersonated"); @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_05.c:59-60
- 结论: 代码未检查ImpersonateNamedPipeClient的返回值，如果模拟失败，后续操作将在错误的权限上下文中执行，可能导致权限提升或安全绕过。
- D验证: confirmed / ver_5046323c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 9. hyp_path_02b9c2c2288b

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_06.c:53
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够连接到命名管道 \\.\pipe\test_pipe
- 触发路径: hPipe = CreateNamedPipeA(...); @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_06.c:34-38; if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) { CloseHandle(hPipe); exit(1); } @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_06.c:49-53; ImpersonateNamedPipeClient(hPipe); // 未检查返回值 @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_06.c:58; if (!RevertToSelf()) { exit(1); } @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_06.c:60-62
- 结论: 未检查 ImpersonateNamedPipeClient 的返回值，如果模拟客户端失败，后续 RevertToSelf 可能导致权限错误，违反最小权限原则。
- D验证: confirmed / ver_3e5a017a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 10. hyp_path_9f8c44e9753a

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_04.c:54
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: A client connects to the named pipe before the server calls ImpersonateNamedPipeClient, and ImpersonateNamedPipeClient fails (e.g., if the client's security context is invalid or token cannot be duplicated).
- 触发路径: { HANDLE hPipe = INVALID_HANDLE_VALUE; hPipe = CreateNamedPipeA( ... ); @ 35-39; if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) { CloseHandle(hPipe); exit(1); } @ 50-54; ImpersonateNamedPipeClient(hPipe); // Return value not checked @ 61; if (!RevertToSelf()) { exit(1); } @ 63; CloseHandle(hPipe); @ 65
- 结论: CWE273: Improper Check for Dropped Privileges - ImpersonateNamedPipeClient return value not checked. The code calls ImpersonateNamedPipeClient but does not verify its return value, assuming impersonation succeeds. If impersonation fails, subsequent operations (like RevertToSelf) may execute with incorrect privileges.
- D验证: confirmed / ver_012048b6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 11. hyp_path_58a83061b608

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_07.c:53
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: Attacker connects to the named pipe before or during ConnectNamedPipe
- 触发路径: HANDLE hPipe = CreateNamedPipeA("\\\\.\\pipe\\test_pipe", PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, ...); @ L34-38; if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) { CloseHandle(hPipe); exit(1); } @ L49-53; ImpersonateNamedPipeClient(hPipe); printLine("Impersonated"); if (!RevertToSelf()) { exit(1); } @ L58-62
- 结论: Missing check of ImpersonateNamedPipeClient return value leads to improper privilege drop handling. If ImpersonateNamedPipeClient fails, the subsequent RevertToSelf may not properly restore original privileges, violating CWE-273.
- D验证: confirmed / ver_a047e54c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 12. hyp_path_3fd74218fd6f

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_10.c:48
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够连接到命名管道，但可能使ImpersonateNamedPipeClient失败（例如通过不正确的客户端模拟请求）
- 触发路径: ImpersonateNamedPipeClient(hPipe); @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_10.c:48
- 结论: 未检查ImpersonateNamedPipeClient函数的返回值，如果模拟客户端失败（例如客户端未正确连接或权限不足），则后续操作可能仍然以原始权限运行，导致权限检查不正确（CWE-273）。
- D验证: confirmed / ver_861c001e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 13. hyp_path_a5477dae1e63

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_13.c:48
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够连接到命名管道，但模拟客户端可能失败（例如权限不足）
- 触发路径: hPipe = CreateNamedPipeA( "\\.\pipe\test_pipe", PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, ...) @ L29-33; if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) { CloseHandle(hPipe); exit(1); } @ L44-46; ImpersonateNamedPipeClient(hPipe); // 未检查返回值 @ L48; printLine("Impersonated"); @ L49; if (!RevertToSelf()) { exit(1); } @ L50-52
- 结论: ImpersonateNamedPipeClient 的返回值未被检查，如果模拟客户端失败，后续操作可能仍以高权限运行，导致权限未正确丢弃。
- D验证: confirmed / ver_a4445861
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 14. hyp_path_398c8aa434f5

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_09.c:48
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够连接到命名管道，并导致ImpersonateNamedPipeClient失败（例如通过中断连接）。
- 触发路径: ImpersonateNamedPipeClient(hPipe); printLine("Impersonated"); @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_09.c:53-54; if (!RevertToSelf()) { exit(1); } @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_09.c:55-56
- 结论: 调用ImpersonateNamedPipeClient后未检查返回值，如果模拟客户端失败，程序仍会认为已模拟并继续执行，可能导致权限降级失败，存在权限提升风险。
- D验证: confirmed / ver_7e1cbd84
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 15. hyp_path_dae960725ebe

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_14.c:48
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够创建一个连接到命名管道的客户端，并且使 ImpersonateNamedPipeClient 失败（例如，管道权限设置不当）。
- 触发路径: hPipe = CreateNamedPipeA(...); @ 29-33; if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) { CloseHandle(hPipe); exit(1); } @ 46-48; ImpersonateNamedPipeClient(hPipe); printLine("Impersonated"); if (!RevertToSelf()) { exit(1); } @ 55-57
- 结论: 未检查 ImpersonateNamedPipeClient 的返回值，如果模拟失败，后续 RevertToSelf 可能无法正确恢复权限，导致权限提升或未授权访问。
- D验证: confirmed / ver_67092412
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 16. hyp_path_7457199604b9

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_18.c:48
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者可以通过命名管道连接，使服务器端模拟客户端身份，但若模拟失败（如权限不足），后续未检查模拟状态直接继续执行。
- 触发路径: ImpersonateNamedPipeClient(hPipe); @ L55; printLine("Impersonated"); @ L56; if (!RevertToSelf()) { exit(1); } @ L57
- 结论: 调用ImpersonateNamedPipeClient后未检查返回值，可能模拟失败但后续未正确处理，导致权限检查不恰当。
- D验证: confirmed / ver_46536a55
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 17. hyp_path_2b25d989db04

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_15.c:49
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够连接到命名管道，但模拟客户端操作可能因权限不足而失败。
- 触发路径: ImpersonateNamedPipeClient(hPipe); @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_15.c:49; if (!RevertToSelf()) { exit(1); } @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_15.c:54-58
- 结论: ImpersonateNamedPipeClient函数调用后未检查返回值，可能导致模拟客户端失败时仍继续执行，造成权限检查缺失漏洞。
- D验证: confirmed / ver_fe0fcdcc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 18. hyp_path_11469697cb66

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_16.c:48
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够连接到命名管道（即充当管道客户端），且ImpersonateNamedPipeClient调用可能失败（如权限不足或客户端断开）。
- 触发路径: hPipe = CreateNamedPipeA("\\\\.\\pipe\\test_pipe", PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, ...); @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_16.c:29-33; if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) { CloseHandle(hPipe); exit(1); } @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_16.c:44-48; ImpersonateNamedPipeClient(hPipe); // 未检查返回值 @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_16.c:55; printLine("Impersonated"); @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_16.c:56; if (!RevertToSelf()) { exit(1); } @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_16.c:57
- 结论: 未检查ImpersonateNamedPipeClient的返回值，如果模拟失败，则程序继续执行并打印"Impersonated"，误认为已模拟客户端权限，导致权限状态不一致。
- D验证: confirmed / ver_2b1b6523
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 19. hyp_path_5d08c4475420

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_12.c:37
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 程序运行时globalReturnsTrueOrFalse()返回true
- 触发路径: void CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_12_case0() { @ L25; if(globalReturnsTrueOrFalse()) { @ L27; RpcImpersonateClient(0); /* NOTE: Do not check if RpcImpersonateClient() fails */ @ L29
- 结论: 在函数globalReturnsTrueOrFalse()返回true的路径中，调用RpcImpersonateClient(0)后未检查返回值，如果模拟失败则权限未正确降低，可能导致权限提升漏洞。
- D验证: confirmed / ver_db07f99a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 20. hyp_path_9081badf038d

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_08.c:42
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够使RpcImpersonateClient调用失败（例如，提供无效的绑定句柄或处于异常网络条件）
- 触发路径: RpcImpersonateClient(0); /* NOTE: Do not check if RpcImpersonateClient() fails */ @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_08.c:42
- 结论: 调用RpcImpersonateClient(0)后未检查返回值，如果模拟失败，程序可能错误地认为已模拟客户端，导致权限检查缺失，后续操作可能以错误的安全上下文执行，造成特权提升或权限缺失。
- D验证: confirmed / ver_a77abccb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 21. hyp_path_456438fffb2f

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_11.c:29
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够作为RPC客户端连接并发送请求，触发服务端执行该函数。
- 触发路径: RpcImpersonateClient(0); /* NOTE: Do not check if RpcImpersonateClient() fails */ @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_11.c:29
- 结论: 未检查RpcImpersonateClient函数的返回值，如果函数失败，调用线程可能仍以较高权限运行，导致权限提升漏洞。
- D验证: confirmed / ver_2bd907a5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 22. hyp_path_9caecaa5b906

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_01.c:27
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够影响RPC调用上下文，使得RpcImpersonateClient调用失败，但代码未检测失败状态。
- 触发路径: RpcImpersonateClient(0); @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_01.c:27
- 结论: 函数调用RpcImpersonateClient(0)后未检查返回值，如果调用失败，将导致权限模拟未生效，可能使客户端获得过高权限或服务器权限未正确降低，构成CWE-273权限检查不恰当漏洞。
- D验证: confirmed / ver_f8956cdd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 23. hyp_path_74ad5c8d2f01

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_02.c:29
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够通过RPC调用触发该代码路径。
- 触发路径: if(1) { RpcImpersonateClient(0); /* NOTE: Do not check if RpcImpersonateClient() fails */ } @ 第27-31行
- 结论: 在RPC服务器实现中，调用RpcImpersonateClient(0)后未检查返回值。如果该函数失败，服务器将无法正确模拟客户端身份，导致权限检查缺失，可能允许攻击者以错误的权限执行操作。
- D验证: confirmed / ver_795b81bc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 24. hyp_path_8e443fda2a15

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_03.c:29
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够通过RPC连接触发该函数调用，且RpcImpersonateClient可能因权限不足或其他原因失败。
- 触发路径: RpcImpersonateClient(0); @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_03.c:29
- 结论: RpcImpersonateClient 的返回值未被检查，可能导致权限提升漏洞。
- D验证: confirmed / ver_d72133f3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 25. hyp_path_4aaa709f2e57

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_04.c:35
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够使RpcImpersonateClient调用失败（例如通过控制RPC绑定句柄），从而使得后续代码执行在非预期的权限上下文中。
- 触发路径: RpcImpersonateClient(0); /* NOTE: Do not check if RpcImpersonateClient() fails */ @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_04.c:35
- 结论: 函数RpcImpersonateClient(0)的返回值未被检查，若模拟失败则后续操作可能以错误的权限执行，导致权限提升或信息泄露。
- D验证: confirmed / ver_b8d74671
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 26. hyp_path_36eaa6f8ec61

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_05.c:35
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够触发RPC服务器端执行RpcImpersonateClient函数（例如，通过构造RPC请求）。
- 触发路径: RpcImpersonateClient(0); /* NOTE: Do not check if RpcImpersonateClient() fails */ @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_05.c:35
- 结论: 在不检查RpcImpersonateClient返回值的情况下进行模拟，可能导致权限处理错误（权限降低失败）。
- D验证: confirmed / ver_eb1a4fe5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 27. hyp_path_6bb44aedd06d

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_06.c:34
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: RPC服务端已连接客户端，且客户端可能提供无效或恶意请求导致RpcImpersonateClient失败
- 触发路径: RpcImpersonateClient(0); /* NOTE: Do not check if RpcImpersonateClient() fails */ @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_06.c:34
- 结论: 调用RpcImpersonateClient(0)后未检查返回值，如果函数失败则不会模拟客户端权限，但后续代码可能假定已模拟，导致权限提升漏洞。
- D验证: confirmed / ver_2781792d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 28. hyp_path_500909289912

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_07.c:34
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够向RPC服务发起调用，且能够导致RpcImpersonateClient失败
- 触发路径: RpcImpersonateClient(0); @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_07.c:34
- 结论: 在RpcImpersonateClient调用后未检查返回值，可能导致权限降级失败，攻击者可能利用此漏洞保持高权限。
- D验证: confirmed / ver_f640a5f5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 29. hyp_path_d792aa1e3a2e

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_09.c:29
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 触发该代码路径的函数被调用（例如作为RPC服务器处理程序），且RPC客户端连接存在，但RpcImpersonateClient可能失败（如无效句柄或RPC连接问题）。
- 触发路径: RpcImpersonateClient(0); /* NOTE: Do not check if RpcImpersonateClient() fails */ @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_09.c:29
- 结论: 代码中调用了RpcImpersonateClient(0)但没有检查其返回值，如果模拟客户端失败，当前线程可能保留过高特权，导致权限降级检查缺失。
- D验证: confirmed / ver_8fa894cd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 30. hyp_path_a70f9f38d692

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_10.c:29
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够触发当前RPC调用（作为客户端连接）
- 触发路径: RpcImpersonateClient(0); /* NOTE: Do not check if RpcImpersonateClient() fails */ @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_10.c:29
- 结论: 调用RpcImpersonateClient后未检查返回值，如果函数失败，则后续操作可能以错误的权限运行，导致权限提升或信息泄露。
- D验证: confirmed / ver_31a996f9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 31. hyp_path_308da104fafb

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_13.c:29
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 无需攻击者主动输入；只要RpcImpersonateClient执行失败即可触发漏洞。
- 触发路径: if(GLOBAL_CONST_FIVE==5) { @ L27; RpcImpersonateClient(0); // 未检查返回值 @ L29
- 结论: 在RPC模拟客户端后未检查RpcImpersonateClient的返回值，如果函数调用失败（例如客户端未正确验证），则当前线程的令牌可能不会被模拟，导致后续操作以原始特权执行，违反最小特权原则。
- D验证: confirmed / ver_26f0ffbe
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 32. hyp_path_32fda7af0bca

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_14.c:29
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 全局变量globalFive等于5，程序进入该条件分支。
- 触发路径: RpcImpersonateClient(0); /* NOTE: Do not check if RpcImpersonateClient() fails */ @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_14.c:29
- 结论: RpcImpersonateClient被调用后未检查返回值，可能导致权限模拟失败或意外提升，违反CWE-273。
- D验证: confirmed / ver_732e057f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 33. hyp_path_5d602cf2b632

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_15.c:30
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够向RPC服务发起调用，且服务端未检查RpcImpersonateClient的返回值。
- 触发路径: RpcImpersonateClient(0); /* NOTE: Do not check if RpcImpersonateClient() fails */ @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_15.c:30
- 结论: RpcImpersonateClient调用后未检查返回值，如果模拟失败，线程将保留原始权限，可能导致权限提升。
- D验证: confirmed / ver_2d2372c6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 34. hyp_path_97deaaac9076

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_16.c:29
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者可以控制RPC调用使得RpcImpersonateClient失败（例如提供无效的客户端句柄），且服务端在模拟失败后未降权继续执行后续高特权操作。
- 触发路径: while(1) { RpcImpersonateClient(0); /* NOTE: Do not check if RpcImpersonateClient() fails */ /* We'll leave out most of the implementation since it has nothing to do with the CWE */ @ 27-31
- 结论: 在while循环中调用RpcImpersonateClient(0)后未检查返回值，如果模拟失败，程序可能继续以更高权限执行，导致权限提升漏洞。
- D验证: confirmed / ver_fa0d4b04
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 35. hyp_path_17c2f9634084

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_17.c:30
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 无特定攻击者输入，但任何通过RPC调用此服务的客户端均可触发该路径。
- 触发路径: RpcImpersonateClient(0); /* NOTE: Do not check if RpcImpersonateClient() fails */ @ juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_17.c:30
- 结论: 调用RpcImpersonateClient后未检查返回值，可能导致权限提升或降权失败，违反最小权限原则。
- D验证: confirmed / ver_80379414
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

### 36. hyp_path_d9659bf31c08

- 漏洞位置: juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_18.c:29
- 漏洞类型: CWE-273
- CWE: CWE-273
- 风险等级: P0
- 触发条件: 攻击者能够影响RPC环境（如网络故障、服务端异常）导致RpcImpersonateClient失败
- 触发路径: RpcImpersonateClient(0); /* NOTE: Do not check if RpcImpersonateClient() fails */ @ L29
- 结论: 调用RpcImpersonateClient后未检查返回值，可能导致权限模拟失败但后续代码错误地认为已提升权限，属于CWE-273漏洞。
- D验证: confirmed / ver_c1ebce00
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED
- 保留原因: N/A

## Unconfirmed / Failed Verification

These records are not reported as confirmed vulnerabilities. See `verification.failed.jsonl` for full failure details.

- hyp_path_e40ce180646f | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_05.c:105 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_21e0a5bd93a5 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_08.c:157 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dace7cf1532e | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_11.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9ced9bd3ff8a | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_02.c:99 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_73a3816471ae | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_03.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4e0a5554f734 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_13.c:99 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1c7eccb36f3f | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_04.c:105 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0a94717a3abb | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_13.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2cf880fce3b2 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_09.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0312ef62ff07 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_10.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c31c3171326c | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_14.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7ab31de944bb | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_18.c:93 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0e22294d1650 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_16.c:95 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_65fa707ed7f8 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_15.c:152 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_722f0a4b4eb9 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_17.c:48 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_9194dd202a0f | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_08.c:64 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_01e1e93b5f6e | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_11.c:51 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_d41a8384b219 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_05.c:57 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_0c21e6c0c729 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_08.c:79 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_773989aa91f6 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_07.c:56 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_2ead117f09a2 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_12.c:66 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_25e171f323c9 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_10.c:51 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_21e978d5f480 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_11.c:66 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_5800278662aa | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_09.c:51 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_bcf107a70a01 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_01.c:40 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_f48198c3ec92 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_13.c:51 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_e8456f5d710a | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_14.c:51 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_d1c6fdf84d27 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_02.c:66 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_a81a43fb4892 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_02.c:51 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_0a9a53766c9e | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_03.c:51 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_206dfb55b48a | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_05.c:72 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_fa95f5651070 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_04.c:72 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_5c108da3f0eb | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_03.c:66 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_806e4a99c553 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_04.c:57 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_98eab72e7c34 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_09.c:66 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_49237f13b915 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_07.c:71 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_a12958442de7 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_06.c:71 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_44b6f66eb857 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_06.c:56 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_f144696f40a6 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_10.c:66 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_a83a2865e7f8 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_13.c:66 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_af84aae4a163 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_15.c:57 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_901f14ae67ab | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_14.c:66 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_9fbd7574f62b | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_15.c:74 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_358734462181 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_16.c:47 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_e2d7fdbd2cd7 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_18.c:45 | NOT_ROUTE_BOUND | payload did not satisfy oracle
- hyp_path_8a499ed4b292 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_02.c:167 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7809484c4979 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_06.c:172 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_160d1195e264 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_05.c:173 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0412342d46a2 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_10.c:167 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_23513d07c916 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_13.c:167 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e541f9c6c8bc | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_15.c:180 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0fe71b6229c0 | juliet-api-misuse/testcases/CWE273_Improper_Check_for_Dropped_Privileges/CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_14.c:77 | NOT_ROUTE_BOUND | payload did not satisfy oracle
