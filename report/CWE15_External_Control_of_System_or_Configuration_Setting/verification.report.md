# MAGUS Final Vulnerability Report

- generated_at: 2026-05-23T04:37:42Z
- reportable_vulnerabilities: 70
- d_confirmed_vulnerabilities: 51
- stage_c_preserved_vulnerabilities: 19
- failed_verifications: 37
- source_confirmed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE15_External_Control_of_System_or_Configuration_Setting/verification.jsonl
- source_failed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE15_External_Control_of_System_or_Configuration_Setting/verification.failed.jsonl

## Confirmed Vulnerabilities

### 1. hyp_path_8fb0e080cc8d

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73a.cpp:90
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P1
- 触发条件: 攻击者能够通过网络连接至监听端口，并发送数据。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ line 65; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ line 90; dataList.push_back(data); @ line 93; case0Sink(dataList); @ line 94
- 结论: 从网络套接字接收的数据被存储到列表中，随后传递给case0Sink函数，该函数可能将数据用于系统配置设置，导致攻击者控制的网络输入可篡改配置，构成CWE-15漏洞。
- D验证: stage_c_preserved / ver_1d565478
- 运行证据: unsupported oracle matched patterns: MAGUS_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 2. hyp_path_bfee1e414bf1

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_17.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够访问服务器的监听端口并发送TCP数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_17.c:85; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_17.c:93-97
- 结论: 程序通过网络socket接收外部输入，并直接将其作为参数传递给SetComputerNameA函数，攻击者可控制系统配置（计算机名）。
- D验证: confirmed / ver_f222e1ed
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 3. hyp_path_0b0c49ef539a

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74a.cpp:90
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P1
- 触发条件: 攻击者能够通过网络连接向监听socket发送数据，使recv接收到攻击者控制的内容。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74a.cpp:90; dataMap[0] = data; dataMap[1] = data; dataMap[2] = data; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74a.cpp:98-102; case0Sink(dataMap); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74a.cpp:??? (sink函数case0Sink)
- 结论: recv从网络接收的数据被存储并通过map传递给sink函数case0Sink，该sink可能使用外部数据执行系统配置更改（如设置环境变量或修改注册表），存在CWE15漏洞风险。
- D验证: stage_c_preserved / ver_3f98d0aa
- 运行证据: unsupported oracle matched patterns: MAGUS_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 4. hyp_path_940b4e857004

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:92
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够与应用程序的监听端口建立网络连接并发送任意数据
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:73-77; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:90-92; CWE15_External_Control_of_System_or_Configuration_Setting__w32_41_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:39; SetComputerNameA(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:31
- 结论: 攻击者通过网络连接发送数据，该数据被直接用作SetComputerNameA的参数，从而控制计算机名，导致系统或配置设置受外部控制。
- D验证: confirmed / ver_bfbe8a0d
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 5. hyp_path_1b647b79197e

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_12.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够访问监听端口并建立TCP连接; 攻击者可以发送包含任意字符串的网络数据; globalReturnsTrueOrFalse()返回真值以激活网络接收分支
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_12.c:59; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_12.c:84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_12.c:88（估计）
- 结论: 存在外部控制系统或配置设置的漏洞：从网络套接字接收到的数据未经验证直接用于设置计算机名称（SetComputerNameA），攻击者可以控制主机名，可能导致系统配置被恶意修改。漏洞路径受globalReturnsTrueOrFalse()条件约束。
- D验证: confirmed / ver_cf667ed7
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 6. hyp_path_3ac2b660d3ba

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52a.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P1
- 触发条件: 攻击者能够与服务器建立TCP连接并发送构造的payload。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52a.c:85; CWE15_External_Control_of_System_or_Configuration_Setting__w32_52b_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52a.c:96-97
- 结论: 外部控制系统或配置设置：通过网络socket接收的字符串未经验证就传递给配置设置操作，攻击者可以控制系统配置。
- D验证: stage_c_preserved / ver_6ccc0724
- 运行证据: unsupported oracle matched patterns: MAGUS_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 7. hyp_path_ac4ba2963d66

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_82a.cpp:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P1
- 触发条件: 攻击者能够通过网络访问监听端口; 服务处于运行状态并接受连接; 攻击者可以发送任意数据包; action函数实际执行系统配置修改操作
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == INVALID_SOCKET) { break; } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_82a.cpp:65-69; recvResult = recv(acceptSocket, data, 100 - 1, 0); if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_82a.cpp:82-86; baseObject->action(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_82a.cpp:84后调用（未直接展示）
- 结论: 程序从网络套接字接收数据，并通过基类虚函数action(data)处理，若action实际调用系统配置修改API（如SetComputerName），则攻击者可外部控制系统配置。当前关键sink代码未展示，证据链不完整。
- D验证: stage_c_preserved / ver_2535a1f3
- 运行证据: unsupported oracle matched patterns: MAGUS_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 8. hyp_path_dddf8e75d107

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51a.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务器上的监听端口; recv调用成功接收数据（非错误或0字节）
- 触发路径: listenSocket = socket(PF_INET, SOCK_STREAM, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51a.c:49-53; bind(listenSocket, (struct sockaddr*)&service, sizeof(service)); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51a.c:60; listen(listenSocket, LISTEN_BACKLOG); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51a.c:60; accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51a.c:60; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51a.c:85; CWE15_External_Control_of_System_or_Configuration_Setting__w32_51b_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51b.c
- 结论: 程序从网络socket接收数据并直接传递给外部系统或配置设置函数，攻击者可以控制数据内容，导致系统或配置被恶意修改。
- D验证: stage_c_preserved / ver_ac45473b
- 运行证据: unsupported oracle matched patterns: MAGUS_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 9. hyp_path_1ab694b7eca4

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53a.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P1
- 触发条件: 攻击者能够通过网络连接到监听套接字并发送恶意数据。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53a.c:85; CWE15_External_Control_of_System_or_Configuration_Setting__w32_53b_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53a.c:90
- 结论: 程序从网络套接字接收外部数据，并将其直接传递给sink函数，可能用于系统配置或命令执行，攻击者可以控制此数据导致外部控制系统或配置设置漏洞。
- D验证: stage_c_preserved / ver_2db1342f
- 运行证据: unsupported oracle matched patterns: MAGUS_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 10. hyp_path_624f30805d08

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54a.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P1
- 触发条件: 攻击者能够通过网络连接到目标服务器的监听端口。; 服务器在接受连接后，从套接字读取数据并传递给系统配置设置sink函数。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54a.c:60; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54a.c:85; CWE15_External_Control_of_System_or_Configuration_Setting__w32_54b_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54a.c:? (sink调用)
- 结论: 程序从网络套接字接收数据，并传递给系统配置设置sink函数，攻击者可通过发送恶意数据控制系统配置，导致外部控制系统或配置设置漏洞。
- D验证: stage_c_preserved / ver_72f1a8c2
- 运行证据: unsupported oracle matched patterns: MAGUS_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 11. hyp_path_21da82af0a43

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_08.c:98
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务的监听端口
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_08.c:96-100; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_08.c:106-110
- 结论: 通过recv从网络接收数据后直接作为SetComputerNameA的参数，攻击者可控制主机名设置，导致外部控制系统配置。
- D验证: confirmed / ver_5f28a436
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 12. hyp_path_941d10737f6b

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_63a.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P1
- 触发条件: 攻击者能够与目标程序建立网络连接并发送构造的数据包
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_63a.c:85; CWE15_External_Control_of_System_or_Configuration_Setting__w32_63b_case0Sink(&data); @ CWE15_External_Control_of_System_or_Configuration_Setting__w32_63a.c (sink call after recv)
- 结论: 程序通过recv从网络接收数据，并将该数据作为参数传递给sink函数，攻击者可以通过发送恶意网络数据来控制系统配置，存在CWE-15潜在漏洞。虽然sink函数内部实现未在代码中明确，但根据测试用例上下文和高风险sink标签，漏洞路径可达。
- D验证: stage_c_preserved / ver_231abdc1
- 运行证据: unsupported oracle matched patterns: MAGUS_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 13. hyp_path_fcafc75efa5c

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64a.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标主机的监听端口（LISTEN_PORT）; 发送的恶意数据能够影响系统配置设置
- 触发路径: listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64a.c:51; bind(listenSocket, (struct sockaddr*)&service, sizeof(service)); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64a.c:60; listen(listenSocket, LISTEN_BACKLOG); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64a.c:60; acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64a.c:66-68; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64a.c:85; CWE15_External_Control_of_System_or_Configuration_Setting__w32_64b_case0Sink(&data); // 调用sink函数 @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64a.c:97
- 结论: 程序从网络socket接收数据，并将接收到的数据作为参数传递给系统配置设置函数CWE15_External_Control_of_System_or_Configuration_Setting__w32_64b_case0Sink，攻击者可以通过控制网络输入来修改系统配置，存在外部控制系统或配置设置漏洞。
- D验证: stage_c_preserved / ver_b8583707
- 运行证据: unsupported oracle matched patterns: MAGUS_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 14. hyp_path_1d942f707016

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_11.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够访问程序监听的网络端口并发送特制的数据包
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_11.c:65-66; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_11.c:84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_11.c:88
- 结论: 从网络接收的数据直接用于设置计算机名，攻击者可通过控制网络输入来改变系统配置，存在外部控制系统配置漏洞。
- D验证: confirmed / ver_ebe5dd8c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 15. hyp_path_9af5470c0481

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_01.c:82
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标主机的监听端口 (LISTEN_PORT); 攻击者能够发送任意字符串作为主机名（长度不超过99字节）
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_01.c:57; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_01.c:82; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_01.c:90
- 结论: 外部控制的系统配置设置漏洞：程序通过 recv 从网络套接字接收主机名数据，未经任何输入验证直接传递给 SetComputerNameA，攻击者可通过发送任意字符串篡改系统计算机名。
- D验证: confirmed / ver_0f38d6d2
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 16. hyp_path_ee7c28da3796

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_04.c:91
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够与目标主机建立网络连接并发送控制数据，且目标主机监听在指定端口上
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_04.c:72; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_04.c:89; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_04.c:99
- 结论: 外部控制计算机名设置：程序通过网络接收用户输入，并直接用于SetComputerNameA函数设置计算机名，攻击者可以控制计算机名，导致系统配置被篡改。
- D验证: confirmed / ver_92aa889f
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 17. hyp_path_f0115f5031d0

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_02.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够访问目标主机的监听端口; 套接字接收的数据未经充分验证直接传入SetComputerNameA
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ 套接字监听和接受连接; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ 从套接字接收数据; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); } @ 使用接收的数据设置计算机名
- 结论: 外部可控数据通过SetComputerNameA设置系统主机名，导致系统配置被外部控制。
- D验证: confirmed / ver_b2777fa8
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 18. hyp_path_c1b58b470d5b

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_05.c:91
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务器的监听端口; 攻击者能够构造任意字符串作为计算机名发送到该端口
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == INVALID_SOCKET) { ... } @ CWE15_External_Control_of_System_or_Configuration_Setting__w32_05.c:72-76; recvResult = recv(acceptSocket, data, 100 - 1, 0); if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ CWE15_External_Control_of_System_or_Configuration_Setting__w32_05.c:89-93; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ CWE15_External_Control_of_System_or_Configuration_Setting__w32_05.c:99-103
- 结论: 程序通过recv从网络套接字接收数据，未经验证直接传递给SetComputerNameA函数设置计算机名，攻击者可通过控制网络输入更改系统配置，构成外部控制系统配置设置漏洞。
- D验证: confirmed / ver_580221fa
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 19. hyp_path_e0be488b7d84

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_03.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够访问服务器的监听端口并建立TCP连接; 数据经过recv后未进行充分验证直接用于配置设置
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_03.c:84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_03.c:? (SetComputerNameA调用所在行)
- 结论: 代码从网络套接字接收外部数据，并直接用于设置系统主机名（SetComputerNameA），攻击者可通过发送特制数据修改系统配置，导致CWE15外部控制配置设置漏洞。
- D验证: confirmed / ver_e5ebb946
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 20. hyp_path_fb3b81605899

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_13.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向目标服务发送任意字符串
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_13.c:84; if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_13.c:86; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); ... } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_13.c:92-96
- 结论: 程序从网络socket接收数据，然后直接用作SetComputerNameA的参数，导致外部控制系统配置设置，攻击者可设置任意计算机名。
- D验证: confirmed / ver_bde0dc31
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 21. hyp_path_3b5654ba5890

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_10.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到程序监听的TCP端口，并发送任意数据；recv成功接收至少1字节数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_10.c:84; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_10.c:92
- 结论: 外部可控制的系统配置设置：程序通过网络套接字接收数据，并将其直接用作SetComputerNameA的参数来设置计算机名。攻击者可以通过发送恶意数据，将系统主机名设置为任意值，可能导致系统配置受到外部控制。
- D验证: confirmed / ver_dc62a57a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 22. hyp_path_5ac355eeac4c

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_07.c:90
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过socket连接并发发送payload
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_07.c:90; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_07.c:98-102
- 结论: 外部控制配置设置：通过recv从网络接收数据，未充分验证即用于SetComputerNameA设置计算机名，攻击者可以控制计算机名。
- D验证: confirmed / ver_156896db
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 23. hyp_path_91a808f8e1fd

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_06.c:88
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务器的特定端口（LISTEN_PORT）。; 攻击者发送的数据长度不超过99字节且不包含空字符（因为data缓冲区为100字节，recv读取最多99字节）。; recv返回成功（recvResult > 0），且程序未因其他错误提前退出。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_06.c:63; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_06.c:88; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_06.c:94
- 结论: 存在外部控制系统或配置设置漏洞（CWE-15），攻击者可通过网络连接发送恶意输入，导致SetComputerNameA函数被调用时设置任意计算机名，可能造成系统配置被恶意篡改。
- D验证: confirmed / ver_80c0febd
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 24. hyp_path_4751ebf2c094

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_09.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络访问服务器监听的端口; 服务器使用默认或可预测的端口（LISTEN_PORT）; 攻击者发送的数据无需特殊权限
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_09.c:84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_09.c (SetComputerNameA调用处，约在recv之后，见代码片段)
- 结论: 外部控制的系统配置设置：程序从网络套接字接收数据，并将其作为参数传递给SetComputerNameA()，攻击者可以通过网络连接发送恶意数据来设置计算机名，可能导致系统配置被篡改或拒绝服务。
- D验证: confirmed / ver_ce594fec
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 25. hyp_path_b785c43f551b

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_14.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络访问目标主机的监听端口，并发送精心构造的数据作为新的主机名
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_14.c:59; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_14.c:84; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_14.c:92
- 结论: 外部可控的数据通过网络接收后，直接用于设置系统配置（计算机名），攻击者可以控制该配置，导致系统配置被篡改。
- D验证: confirmed / ver_43581d01
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 26. hyp_path_f35e5ff8eca5

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_15.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接目标主机的监听端口，并发送特制的字符串数据，长度不超过99字节
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_15.c:85; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_15.c:95附近（SetComputerNameA调用行）
- 结论: 从网络socket接收数据后，未经充分验证直接用于设置计算机名（SetComputerNameA），攻击者可控制计算机名，属于外部控制系统设置漏洞。
- D验证: confirmed / ver_a94fdb64
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 27. hyp_path_815010b21448

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_16.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够与目标主机建立TCP连接，并且目标主机在监听指定端口。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_16.c:84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_16.c:96
- 结论: 程序通过网络接收外部数据并将其作为参数传递给SetComputerNameA函数，攻击者可以控制传入的数据来设置任意计算机名，从而影响系统配置。
- D验证: confirmed / ver_de43974c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 28. hyp_path_6be28895b50c

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_18.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络访问目标机器的监听端口; 攻击者发送的字符串符合SetComputerNameA的格式要求
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_18.c:84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_18.c:96-100
- 结论: 外部控制的系统配置设置：从网络socket接收数据并将其作为参数传递给SetComputerNameA，攻击者可以通过控制网络输入来更改计算机名称，造成系统配置被篡改。
- D验证: confirmed / ver_7780431e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 29. hyp_path_b3ce3470f997

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_81a.cpp:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够访问服务器的监听端口; 服务器在该端口上监听连接; 攻击者能够发送超过0字节且不超过99字节的任意数据
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_81a.cpp:59; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_81a.cpp:84; baseObject.action(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_81a.cpp:97
- 结论: 存在外部控制系统配置的漏洞：攻击者可通过网络连接发送恶意数据，该数据被用于系统配置设置（如主机名），可能导致配置被篡改或拒绝服务。
- D验证: stage_c_preserved / ver_9570840d
- 运行证据: unsupported oracle matched patterns: MAGUS_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 30. hyp_path_0c19f67c03a0

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_32.c:52
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够访问服务器监听的端口并与服务器进行网络通信。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_32.c:67; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_32.c:84-86; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_32.c:92
- 结论: 程序从网络套接字接收数据后，未经充分验证即作为参数调用 SetComputerNameA，攻击者可控制计算机名设置，构成外部控制系统配置漏洞。
- D验证: confirmed / ver_43fb6812
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 31. hyp_path_d35498857816

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_31.c:82
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够访问服务器监听的端口并发送任意数据
- 触发路径: listenSocket = socket(PF_INET, SOCK_STREAM, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_31.c:48; acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_31.c:57; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_31.c:82; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_31.c:90-93
- 结论: 外部控制的系统配置设置漏洞：程序从网络套接字接收数据，直接将接收到的数据作为主机名传递给SetComputerNameA函数，攻击者可以通过发送恶意数据控制计算机名称，导致系统配置被篡改。
- D验证: confirmed / ver_ad9cccd0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 32. hyp_path_3f5e9e44c8f1

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_33.cpp:86
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够访问服务端的监听端口，并能发送特制数据包。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_33.cpp:86; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_33.cpp:88
- 结论: 通过recv从网络接收外部数据，未经验证直接传递给SetComputerNameA，导致外部控制系统或配置设置漏洞，攻击者可设置任意计算机名。
- D验证: confirmed / ver_66aadc9c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 33. hyp_path_fc5f482b1d26

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_34.c:89
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到程序监听的端口; 攻击者能够发送构造好的数据作为新的主机名
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_34.c:64; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_34.c:89; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_34.c:97
- 结论: 外部控制的系统或配置设置：程序从网络接收数据后直接调用SetComputerNameA设置计算机名，攻击者可通过控制网络输入修改系统配置。即使SetComputerNameA调用失败，外部数据已作为参数传入，漏洞仍然存在。
- D验证: confirmed / ver_efcb456b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 34. hyp_path_92b94c2ab608

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66a.c:52
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P1
- 触发条件: 攻击者能够与服务器建立TCP连接; 攻击者能够向服务器发送任意数据
- 触发路径: listenSocket = socket(PF_INET, SOCK_STREAM, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66a.c:52; acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66a.c:67; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66a.c:86; dataArray[2] = data; CWE15_External_Control_of_System_or_Configuration_Setting__w32_66b_case0Sink(dataArray); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66a.c:94
- 结论: 存在CWE-15（外部控制系统或配置设置）漏洞：程序从网络套接字接收数据并直接作为系统配置设置（如主机名）传递给sink函数，攻击者可以通过构造恶意网络输入来控制系统配置，可能导致任意代码执行或配置篡改。
- D验证: stage_c_preserved / ver_a48da21c
- 运行证据: unsupported oracle matched patterns: MAGUS_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 35. hyp_path_25dec91e033f

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:71
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到服务监听的端口; 攻击者发送的数据能够通过 recv 接收并存储到 data 缓冲区; 攻击者发送的数据长度不超过99字节（recv大小限制）
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:77-81; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:94-98; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:32-41
- 结论: 外部控制的系统或配置设置漏洞：程序从网络套接字接收数据后，直接调用 SetComputerNameA 设置计算机名，攻击者可以通过控制接收的数据来更改系统主机名，导致系统配置被外部控制。
- D验证: confirmed / ver_57049587
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 36. hyp_path_3839c3213121

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67a.c:66
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到程序监听的TCP端口并发送网络数据
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67a.c:72; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67a.c:89; myStruct.structFirst = data; CWE15_External_Control_of_System_or_Configuration_Setting__w32_67b_case0Sink(myStruct); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67a.c:102-103 (approx)
- 结论: 程序从网络socket接收数据，并将其直接传递给系统配置设置函数，攻击者可以通过发送恶意数据控制系统配置，导致外部控制系统或配置设置漏洞。
- D验证: stage_c_preserved / ver_92abfa04
- 运行证据: unsupported oracle matched patterns: MAGUS_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 37. hyp_path_658c77110f81

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68a.c:63
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够访问并连接目标机器的监听端口; 目标机器上的服务正在运行并接受连接
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68a.c:63; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68a.c:86-88; CWE15_External_Control_of_System_or_Configuration_Setting__w32_68_case0Data = data; CWE15_External_Control_of_System_or_Configuration_Setting__w32_68b_case0Sink(); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68a.c:91-92 (post recv)
- 结论: 从网络socket接收的数据被直接传递给系统配置设置函数，攻击者可以控制该数据，可能导致系统配置被恶意修改或执行任意命令。
- D验证: stage_c_preserved / ver_67e79161
- 运行证据: unsupported oracle matched patterns: MAGUS_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 38. hyp_path_6ab7f9b8f1c9

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62b.cpp:55
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P1
- 触发条件: 攻击者能够通过网络连接到监听端口并发送恶意数据。; 代码中后续存在未展示的系统配置操作（如设置主机名、修改注册表等），这些操作会使用data。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62b.cpp:78-80
- 结论: 从网络套接字接收的数据可能被用于系统配置设置，导致外部控制配置设置漏洞（CWE-15），但当前代码证据未完全展示sink操作。
- D验证: stage_c_preserved / ver_7d64ff4b
- 运行证据: unsupported oracle matched patterns: MAGUS_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 39. hyp_path_397d3388afb3

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_84_case0.cpp:57
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务的监听端口; 程序未对recv接收的数据进行充分验证和过滤
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_84_case0.cpp:63-67; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_84_case0.cpp:80-84; // 假设将data用于配置设置，如 SetComputerNameA(data); @ 假设后续代码（测试用例应包含类似SetComputerName等sink函数，但未在提供的代码片段中展示）
- 结论: 外部网络输入可能被用于系统或配置设置，导致攻击者可以控制主机名或其他配置，存在CWE-15漏洞。
- D验证: confirmed / ver_df5448d8
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 40. hyp_path_433e69fade88

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_43.cpp:82
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立网络连接并发送任意数据
- 触发路径: recv(acceptSocket, data, 100 - 1, 0); @ case0Source函数; SetComputerNameA(data); @ case函数
- 结论: 存在外部控制系统配置漏洞：攻击者可通过网络连接发送任意数据，该数据被直接传递给 SetComputerNameA 设置计算机名，无输入验证。
- D验证: confirmed / ver_cb3ff92b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 41. hyp_path_00201ab55fba

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_83_case0.cpp:57
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P1
- 触发条件: 攻击者能够与被攻击主机建立网络连接; 服务端监听指定端口并接受连接
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_83_case0.cpp:63-67; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_83_case0.cpp:80-84; 基于注释"read the new hostname from a network socket"，推测data被用于系统配置设置函数。具体代码行未在提供的代码片段中，但属CWE-15典型模式。 @ 后续未展示的配置设置调用（如SetComputerName等）
- 结论: 外部实体通过网络连接控制数据，进而控制系统或配置设置，可能导致未授权修改系统配置。
- D验证: stage_c_preserved / ver_54123531
- 运行证据: unsupported oracle matched patterns: MAGUS_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 42. hyp_path_2dc371166a8c

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_42.c:79
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标程序监听的socket并发送任意数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ case0Source函数内; data = case0Source(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_42.c:108-110; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_42.c:110
- 结论: 程序从网络socket接收数据并直接用于设置计算机名(SetComputerNameA)，攻击者可控制输入导致系统配置被外部控制。
- D验证: confirmed / ver_923f8b9c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 43. hyp_path_abdb28c94cff

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_21.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够与程序监听的网络套接字建立连接并发送数据
- 触发路径: recv(acceptSocket, data, 100 - 1, 0); @ case0Source function (line 32-107); data = case0Source(data); @ line 115-117; if (!SetComputerNameA(data)) @ line 117
- 结论: 程序从网络接收主机名并直接用于设置计算机名，攻击者可以控制网络输入，导致外部控制系统配置（CWE-15）。
- D验证: confirmed / ver_422027fe
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 44. hyp_path_b6a38a6e14b3

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74b.cpp:34
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制dataMap[2]的值，即能够向系统注入字符串数据。
- 触发路径: char * data = dataMap[2]; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74b.cpp:32; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74b.cpp:34
- 结论: 外部攻击者可能通过控制dataMap中的字符串来设置系统计算机名，从而控制系统配置，属于外部控制系统或配置设置漏洞。
- D验证: confirmed / ver_0711a2b0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 45. hyp_path_bb2877e43c88

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_22a.c:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_case0Source的返回值（函数名称和注释表明数据来自外部，但具体实现未展示）; 系统允许SetComputerNameA调用（通常需要管理员权限，假设攻击者已具备或通过其他漏洞提升）
- 触发路径: data = CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_case0Source(data); // NOTE: set the hostname to data obtained from a potentially external source @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_22a.c:34; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_22a.c:36
- 结论: 代码通过CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_case0Source从潜在外部源获取数据，并直接作为SetComputerNameA参数，攻击者可控制系统计算机名设置，导致外部控制系统配置。
- D验证: confirmed / ver_01f15292
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 46. hyp_path_6ff2e882995d

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_61a.c:39
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够影响CWE15_External_Control_of_System_or_Configuration_Setting__w32_61b_case0Source的返回值，该函数注释表明数据来自潜在外部源。
- 触发路径: data = CWE15_External_Control_of_System_or_Configuration_Setting__w32_61b_case0Source(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_61a.c:37; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_61a.c:39
- 结论: 外部数据通过CWE15_External_Control_of_System_or_Configuration_Setting__w32_61b_case0Source函数传递给SetComputerNameA，攻击者可能控制计算机名，导致系统配置被篡改（CWE-15）。
- D验证: confirmed / ver_bbd17da5
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 47. hyp_path_185875a9c9fa

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62a.cpp:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制case0Source的数据源（如环境变量、命令行参数等）
- 触发路径: char dataBuffer[100] = ""; data = dataBuffer; case0Source(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62a.cpp:32-34; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62a.cpp:36
- 结论: 外部控制导致系统配置被修改：程序通过case0Source获取外部数据并直接传递给SetComputerNameA设置主机名，攻击者可控制主机名，存在外部控制系统配置漏洞。
- D验证: confirmed / ver_825015b6
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 48. hyp_path_1e9a007d16d9

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_72b.cpp:32
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够向case0Sink函数传递被控的vector对象，且索引2处的字符串任意可控。
- 触发路径: char * data = dataVector[2]; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_72b.cpp:32; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_72b.cpp:34
- 结论: 在CWE15_External_Control_of_System_or_Configuration_Setting__w32_72b.cpp中，函数case0Sink从外部传入的vector中取出data元素，并直接作为参数调用SetComputerNameA设置计算机名。外部攻击者可以通过控制dataVector内容来任意修改系统主机名，属于外部控制系统配置漏洞。
- D验证: confirmed / ver_58ab7902
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 49. hyp_path_67f2b4e402bd

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73b.cpp:32
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制写入dataList的字符串内容
- 触发路径: case0Sink(list) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73b.cpp:29; char * data = dataList.back(); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73b.cpp:32; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73b.cpp:34
- 结论: 外部控制的系统设置：从dataList中获取的数据直接用于SetComputerNameA，如果数据来自外部可控源，攻击者可以设置任意计算机名，可能导致系统配置被篡改。但dataList的source在给定代码片段中未明确，证据不完整。
- D验证: confirmed / ver_5f58c708
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 50. hyp_path_27140c1b298e

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_83_case0.cpp:108
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制data参数的内容。
- 触发路径: if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_83_case0.cpp:108
- 结论: 外部可控数据用于设置系统配置（计算机名），可能导致拒绝服务或系统不稳定。
- D验证: confirmed / ver_a7e7c865
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 51. hyp_path_6064c8c40891

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:32
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制 data 变量的外部输入源（如命令行参数、环境变量等），但具体来源未在片段中体现。
- 触发路径: if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:32
- 结论: 外部控制可能导致系统配置被篡改：SetComputerNameA(data) 中的 data 可能来自外部源，但代码未显示具体赋值路径，存在潜在风险。
- D验证: confirmed / ver_a5247f09
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 52. hyp_path_0e404f093704

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_84_case0.cpp:108
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够向程序提供输入，从而控制`data`变量的内容。代码注释明确说明数据来自潜在外部源，但当前代码片段未展示source点。
- 触发路径: if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_84_case0.cpp:108
- 结论: 外部控制的系统或配置设置：攻击者通过外部输入控制`data`参数，并调用`SetComputerNameA`设置计算机名，可能导致系统配置被恶意修改。
- D验证: confirmed / ver_9b92cb91
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 53. hyp_path_0432e177ded0

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_44.c:32
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制或影响data变量的值，使其为任意字符串。
- 触发路径: if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); @ 30-34
- 结论: 外部控制的数据被用于设置系统配置（计算机名），可能导致安全配置被篡改。
- D验证: confirmed / ver_7202f806
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 54. hyp_path_9cbdd7fe5379

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制全局变量CWE15_External_Control_of_System_or_Configuration_Setting__w32_45_case0Data的值。
- 触发路径: char * data = CWE15_External_Control_of_System_or_Configuration_Setting__w32_45_case0Data; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:34; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:36
- 结论: 外部控制的系统或配置设置：攻击者可以通过控制全局变量CWE15_External_Control_of_System_or_Configuration_Setting__w32_45_case0Data来设置计算机名，从而影响系统配置。
- D验证: confirmed / ver_4bd8e5df
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 55. hyp_path_7d5b28c07ad9

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52c.c:34
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够提供任意字符串作为data参数的值，但data的来源未在代码片段中明确，需进一步验证。
- 触发路径: if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52c.c:34
- 结论: 外部数据可能用于SetComputerNameA函数设置主机名，但当前证据未显示data的具体来源，无法确认外部输入路径。
- D验证: confirmed / ver_92391236
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 56. hyp_path_7564cb3939a1

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51b.c:34
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制变量data的来源（如通过命令行参数、环境变量等），但代码片段未展示具体source
- 触发路径: if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51b.c:34
- 结论: 程序使用来自外部来源的数据直接调用SetComputerNameA设置系统主机名，攻击者可控制主机名，导致系统配置被篡改（CWE-15）。但缺少完整的source-sink证据链。
- D验证: confirmed / ver_37cb6057
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 57. hyp_path_78f336f8a5e1

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53d.c:34
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制data变量，但此前提缺乏代码证据支持。
- 触发路径: if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53d.c:34
- 结论: 函数SetComputerNameA接收潜在外部源数据，但代码证据未显示data的实际来源，无法确认外部可控性。
- D验证: confirmed / ver_c455c5f6
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 58. hyp_path_29fefba3bde0

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54e.c:34
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制或影响外部输入源，使得data参数包含恶意值。
- 触发路径: if (!SetComputerNameA(data)) { @ CWE15_External_Control_of_System_or_Configuration_Setting__w32_54e.c:34
- 结论: 外部可控制SetComputerNameA参数，攻击者可能修改系统主机名，属于外部控制系统配置漏洞。
- D验证: confirmed / ver_80584186
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 59. hyp_path_58cd230283dd

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_63b.c:33
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制dataPtr所指向的数据，即通过外部输入影响data的内容。
- 触发路径: char * data = *dataPtr; /* NOTE: set the hostname to data obtained from a potentially external source */ @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_63b.c:31; if (!SetComputerNameA(data)) { @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_63b.c:33
- 结论: 存在外部控制系统或配置设置漏洞，但source路径未闭合，需要更多证据确认数据是否真正外部可控。
- D验证: confirmed / ver_aaacefe0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 60. hyp_path_e6bac85f491c

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64b.c:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过某种方式（如网络输入、文件读取等）影响dataPtr所指向的内存区域，从而控制data的值。但当前代码证据未提供dataPtr的来源，该前提仅基于CWE15模式推测。
- 触发路径: char * data = (*dataPtr); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64b.c:34; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64b.c:36
- 结论: 外部控制计算机名设置：函数从外部来源获取数据并直接用作SetComputerNameA的参数，攻击者可设置任意计算机名，导致系统配置被外部控制。但source未闭合，路径不完整。
- D验证: confirmed / ver_a88f9e24
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 61. hyp_path_7a542cb8f496

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_65b.c:32
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制data的值
- 触发路径: if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_65b.c:32
- 结论: 代码中SetComputerNameA使用了外部数据（data）设置主机名，但未明确data的来源。如果data可由攻击者控制，则可能导致系统配置被外部控制，存在CWE-15漏洞。
- D验证: confirmed / ver_02cb5285
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 62. hyp_path_238699845ab6

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66b.c:34
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制或影响dataArray[2]的值; 进程以管理员权限运行
- 触发路径: char * data = dataArray[2]; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66b.c:32; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66b.c:34
- 结论: 存在外部控制系统配置设置漏洞，攻击者可能通过控制data参数修改计算机名称，影响系统安全。
- D验证: confirmed / ver_87bfcbdb
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 63. hyp_path_9c098d105ad6

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67b.c:38
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制structFirst字段的值，即能够提供任意字符串作为计算机名称。
- 触发路径: char * data = myStruct.structFirst; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67b.c:36; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67b.c:38
- 结论: 外部控制的系统或配置设置漏洞：data参数可能来源于外部，但source路径不明确，需要进一步确认外部可控性。
- D验证: confirmed / ver_aed09acc
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 64. hyp_path_13a4cc57db89

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_81_case0.cpp:29
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够将恶意数据注入到变量 data 中
- 触发路径: SetComputerNameA(data) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_81_case0.cpp:29
- 结论: 外部控制的系统或配置设置漏洞：SetComputerNameA 使用来自潜在外部源的数据设置主机名，未对输入进行验证或消毒，攻击者可通过控制 data 参数更改系统配置。
- D验证: confirmed / ver_73cec513
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 65. hyp_path_5df2232d3505

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68b.c:38
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制全局变量 CWE15_External_Control_of_System_or_Configuration_Setting__w32_68_case0Data 的内容，该内容可能来自外部输入（如命令行参数、网络数据等）。
- 触发路径: char * data = CWE15_External_Control_of_System_or_Configuration_Setting__w32_68_case0Data; @ CWE15_External_Control_of_System_or_Configuration_Setting__w32_68b.c:36; if (!SetComputerNameA(data)) @ CWE15_External_Control_of_System_or_Configuration_Setting__w32_68b.c:38
- 结论: 外部可控数据可能被用于设置计算机名，攻击者控制全局变量可导致系统配置被非授权修改，但源代码中全局变量赋值部分未提供，无法确认外部可控性。
- D验证: confirmed / ver_42ea23ba
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 66. hyp_path_76ddc67985b8

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_82_case0.cpp:29
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制变量data的内容（外部来源）
- 触发路径: if (!SetComputerNameA(data)) { @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_82_case0.cpp:29
- 结论: 外部输入的字符串可能被直接用于设置计算机名，但代码证据中缺少source路径，无法确认外部可控性，存在潜在漏洞假设。
- D验证: confirmed / ver_09d2aa61
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 67. hyp_path_ae22b6922f8b

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52b.c:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P1
- 触发条件: 攻击者能够控制传递给 sink 的 data 参数（例如通过环境变量或命令行参数）
- 触发路径: CWE15_External_Control_of_System_or_Configuration_Setting__w32_52c_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52b.c:36
- 结论: CWE15_External_Control_of_System_or_Configuration_Setting__w32_52b_case0Sink 是一个潜在的未受保护的sink，如果 data 来自外部可控源，则可能产生漏洞。需补充source路径以闭合证据。
- D验证: stage_c_preserved / ver_37e1e410
- 运行证据: unsupported oracle matched patterns: MAGUS_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 68. hyp_path_b65d76f6e3a1

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53c.c:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P1
- 触发条件: Attacker controls the 'data' parameter passed to the sink function.
- 触发路径: CWE15_External_Control_of_System_or_Configuration_Setting__w32_53d_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53c.c:36
- 结论: POTENTIAL_VULNERABILITY: External control of system or configuration setting possible if data originates from untrusted source, but source not provided in evidence.
- D验证: stage_c_preserved / ver_ae6f81a2
- 运行证据: unsupported oracle matched patterns: MAGUS_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 69. hyp_path_92d9cb69f2dc

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54b.c:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P1
- 触发条件: Data parameter 'data' is sourced from an external, attacker-controllable input (e.g., command line, environment, or user input).
- 触发路径: CWE15_External_Control_of_System_or_Configuration_Setting__w32_54c_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54b.c:36
- 结论: Potential vulnerability: External control of system or configuration setting via API misuse if data originates from untrusted source.
- D验证: stage_c_preserved / ver_2350863b
- 运行证据: unsupported oracle matched patterns: MAGUS_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

### 70. hyp_path_c25114b5c500

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54d.c:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P1
- 触发条件: 攻击者能够控制data变量（来自外部输入）
- 触发路径: CWE15_External_Control_of_System_or_Configuration_Setting__w32_54e_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54d.c:36
- 结论: 存在通过外部控制系统设置的潜在漏洞，若data来自外部输入且未被净化，则攻击者可通过外部控制修改系统或配置设置
- D验证: stage_c_preserved / ver_42aa256a
- 运行证据: unsupported oracle matched patterns: MAGUS_ORACLE_UNSUPPORTED
- 保留原因: UNSUPPORTED_ORACLE

## Unconfirmed / Failed Verification

These records are not reported as confirmed vulnerabilities. See `verification.failed.jsonl` for full failure details.

- hyp_path_91b6c678063e | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_65a.c:87 | UNSUPPORTED_ORACLE | Stage D oracle cannot prove or disprove this route, and Stage C priority P2 is not eligible for reportable preservation
- hyp_path_fa45cf1f9a43 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74b.cpp:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a972fe350c09 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_61a.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3975651f289c | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_22a.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_272274d19ac7 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_22a.c:62 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_95221accf7c0 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62a.cpp:57 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_97cfc96ee30e | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_15.c:159 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_566fa029149e | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_72b.cpp:48 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_45430962b7d6 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_32.c:135 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_374f509a4896 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73b.cpp:48 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0548e11301a6 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_84_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_16b13a451010 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_83_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7602ba3b97c2 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:123 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6b76a8c89622 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_44.c:127 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bacce1e579ab | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_164f4831ce44 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51b.c:49 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_22213965b83c | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52c.c:49 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b8344fe7fba4 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53d.c:49 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_56d2e4e59f89 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54e.c:49 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3ee462db32e4 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_63b.c:49 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1639a01efa2a | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64b.c:55 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a2cb1d743733 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_65b.c:47 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c1adf150f180 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66b.c:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_37ad3e4e23a1 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67b.c:54 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8ad993e8c5fa | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68b.c:54 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e53fe8ae6e50 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_81_case1V1.cpp:29 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_01f0be7cce8e | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_82_case1V1.cpp:29 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_10572e5e7dc0 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_21.c:191 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_28d875ae6020 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_22a.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7cc0bb7ca9cb | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_42.c:145 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_00a1c18c0f47 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_43.cpp:146 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ce7f0f05a1f0 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53b.c:49 | UNSUPPORTED_ORACLE | Stage D oracle cannot prove or disprove this route, and Stage C priority P2 is not eligible for reportable preservation
- hyp_path_78be93785822 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54c.c:49 | UNSUPPORTED_ORACLE | Stage D oracle cannot prove or disprove this route, and Stage C priority P2 is not eligible for reportable preservation
- hyp_path_95d1081188a7 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54d.c:49 | UNSUPPORTED_ORACLE | Stage D oracle cannot prove or disprove this route, and Stage C priority P2 is not eligible for reportable preservation
- hyp_path_91de31516608 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_61a.c:69 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b82ff82a3be4 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62a.cpp:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_03a314b94ac7 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/main.cpp:175 | ENV_MISSING | payload did not satisfy oracle
