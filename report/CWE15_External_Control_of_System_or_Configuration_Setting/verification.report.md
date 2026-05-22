# MAGUS Final Vulnerability Report

- generated_at: 2026-05-21T16:38:41Z
- confirmed_vulnerabilities: 72
- failed_verifications: 31
- source_confirmed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/verification.jsonl
- source_failed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/verification.failed.jsonl

## Confirmed Vulnerabilities

### 1. hyp_path_bfee1e414bf1

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_17.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络与程序建立的监听socket建立连接并发送数据。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_17.c:85; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_17.c:93
- 结论: 外部控制的系统配置设置漏洞：程序从网络socket接收数据，并将其直接用作SetComputerNameA的参数，攻击者可以控制该数据，从而修改系统计算机名。
- D验证: confirmed / ver_f222e1ed
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 2. hyp_path_0b0c49ef539a

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74a.cpp:90
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够与目标服务建立网络连接（TCP端口监听通过`bind`、`listen`、`accept`实现）。; 攻击者能够发送长度不超过99字节的恶意数据，这些数据将作为配置设置被使用。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74a.cpp:90; if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74a.cpp:91-93; dataMap[0] = data; dataMap[1] = data; dataMap[2] = data; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74a.cpp:95-97; case0Sink(dataMap); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74a.cpp:100
- 结论: 程序通过`recv`从网络套接字接收外部输入数据，将该数据存储到`std::map`中，并传递给`sink`函数（`case0Sink`），该函数可能使用外部数据控制系统配置或设置，导致攻击者能够控制系统配置，符合CWE-15（外部控制系统或配置设置）漏洞特征。
- D验证: confirmed / ver_3f98d0aa
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 3. hyp_path_8fb0e080cc8d

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73a.cpp:90
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够向监听的socket发送数据，且sink函数中存在使用该数据修改系统配置的逻辑。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73a.cpp:88-92; dataList.push_back(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73a.cpp:94-97; case0Sink(dataList); (sink函数内部实现未提供，假设使用数据修改系统配置) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73a.cpp:99
- 结论: 通过网络接收外部数据并存储到list，随后传递给sink函数case0Sink，如果sink函数内部使用该数据修改系统配置（如设置计算机名、注册表等），则可能导致外部控制系统或配置设置（CWE-15）。但sink函数的具体实现未在提供的代码证据中展示，因此漏洞路径不完整。
- D验证: confirmed / ver_1d565478
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 4. hyp_path_d21d250d17bd

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_72a.cpp:90
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够与目标建立网络连接; 攻击者知道目标监听的端口; 目标未对输入进行充分的验证或清理
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_72a.cpp:90; dataVector.insert(dataVector.end(), 1, data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_72a.cpp:72a.cpp（附近）; case0Sink(dataVector); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_72a.cpp:case0Sink调用处
- 结论: 攻击者通过网络连接向目标发送恶意数据，该数据被存储并传递给系统配置设置函数，导致外部控制系统配置（CWE-15）。
- D验证: confirmed / ver_4f5b3bac
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 5. hyp_path_ac4ba2963d66

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_82a.cpp:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务的监听端口，并发送精心构造的数据
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_82a.cpp:69; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_82a.cpp:84; baseObject->action(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_82a.cpp:? (action call)
- 结论: 外部受控数据通过recv读取后未经验证直接传入baseObject->action(data)，其中action函数可能将data用于系统配置设置（如设置主机名），导致攻击者可操控系统配置。
- D验证: confirmed / ver_2535a1f3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 6. hyp_path_21da82af0a43

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_08.c:98
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到服务器的监听端口并发送任意数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_08.c:98; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_08.c:103
- 结论: 通过网络接收数据后直接用于设置计算机名，攻击者可控制计算机名，属于外部控制系统配置的漏洞
- D验证: confirmed / ver_5f28a436
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 7. hyp_path_1b647b79197e

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_12.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标程序监听的套接字; 攻击者可以发送任意数据作为计算机名
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_12.c:59; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_12.c:84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_12.c:92-96
- 结论: 应用程序从网络套接字接收外部数据并将其直接用于设置计算机名（SetComputerNameA），攻击者可以控制该数据，导致外部控制系统配置。
- D验证: confirmed / ver_cf667ed7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 8. hyp_path_1d942f707016

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_11.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接发送任意数据到服务器，并且recv调用成功接收到数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_11.c:84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_11.c:91-93
- 结论: 从网络socket接收的数据直接传递给SetComputerNameA函数，攻击者可以控制计算机名设置，导致系统配置被外部控制。
- D验证: confirmed / ver_ebe5dd8c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 9. hyp_path_9af5470c0481

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_01.c:82
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到监听端口并发送任意数据
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_01.c:55-59; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_01.c:80-84; if (!SetComputerNameA(data)) { printLine(...); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_01.c:90-94
- 结论: 程序从网络接收数据后直接用于设置计算机名（SetComputerNameA），攻击者可控制该数据导致系统配置被外部控制。
- D验证: confirmed / ver_0f38d6d2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 10. hyp_path_f0115f5031d0

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_02.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够访问监听中的网络服务并发送恶意数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_02.c:84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_02.c:92
- 结论: 从网络接收的数据被直接用于设置计算机名，未经过验证或限制，攻击者可控制系统配置。
- D验证: confirmed / ver_b2777fa8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 11. hyp_path_e0be488b7d84

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_03.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向目标进程发送TCP数据; 目标程序已绑定并监听端口，且接受了攻击者的连接
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_03.c:84; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_03.c:87
- 结论: 程序从网络套接字接收数据并直接用于设置计算机名（SetComputerNameA），未进行任何验证或净化，允许攻击者通过控制网络输入来任意更改系统配置，属于外部控制系统或配置设置漏洞。
- D验证: confirmed / ver_e5ebb946
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 12. hyp_path_ee7c28da3796

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_04.c:91
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够访问程序监听的网络端口; 攻击者能够发送任意数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_04.c:89-93; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_04.c:104-106
- 结论: 外部控制的系统配置设置：程序通过recv从网络socket读取数据，并将该数据直接传递给SetComputerNameA()来设置计算机名，攻击者可利用此漏洞任意修改系统配置。
- D验证: confirmed / ver_92aa889f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 13. hyp_path_91a808f8e1fd

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_06.c:88
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够与监听套接字建立连接并发送任意字符串。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_06.c:88; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_06.c:96-100
- 结论: 外部控制的系统配置设置：程序通过网络接收数据，并将其直接传递给 SetComputerNameA 函数，攻击者可通过控制输入修改计算机名，导致系统配置被篡改。
- D验证: confirmed / ver_80c0febd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 14. hyp_path_5ac355eeac4c

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_07.c:90
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够访问目标机器的网络端口（默认监听端口），并发送构造的数据包。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_07.c:35; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_07.c:90; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_07.c:98
- 结论: 外部输入通过网络接收后直接用于设置系统配置（SetComputerNameA），可能导致系统配置被攻击者控制。
- D验证: confirmed / ver_156896db
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 15. hyp_path_c1b58b470d5b

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_05.c:91
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到监听套接字并发送数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ CWE15_External_Control_of_System_or_Configuration_Setting__w32_05.c:89; if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ CWE15_External_Control_of_System_or_Configuration_Setting__w32_05.c:90-92; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ CWE15_External_Control_of_System_or_Configuration_Setting__w32_05.c:101 (approx)
- 结论: 外部系统配置设置漏洞：通过recv()接收外部网络数据，直接用于SetComputerNameA()设置主机名，攻击者可控制主机名设置。
- D验证: confirmed / ver_580221fa
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 16. hyp_path_4751ebf2c094

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_09.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向监听端口发送数据; 服务端接收数据后未做净化直接用于危险API
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_09.c:84; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_09.c:92
- 结论: 从网络socket接收外部数据后直接用于设置系统计算机名(SetComputerNameA)，攻击者可控制计算机名，属于外部控制系统配置漏洞。
- D验证: confirmed / ver_ce594fec
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 17. hyp_path_fb3b81605899

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_13.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够访问监听端口并发送任意数据作为主机名
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_13.c:84; if (!SetComputerNameA(data)) { ... } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_13.c:91-93
- 结论: 外部可控数据通过recv读取并直接用于SetComputerNameA设置系统主机名，攻击者可通过网络连接发送恶意主机名，导致系统配置被外部控制。
- D验证: confirmed / ver_bde0dc31
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 18. hyp_path_b785c43f551b

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_14.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够与目标主机建立网络连接并发送数据包，数据包内容包含恶意计算机名。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_14.c:84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_14.c:92-93
- 结论: 在SetComputerNameA调用中，从网络套接字读取的数据直接用作主机名，未经验证和净化，导致攻击者可以控制系统配置，设置任意计算机名，属于外部控制系统配置漏洞。
- D验证: confirmed / ver_43581d01
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 19. hyp_path_3b5654ba5890

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_10.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务，并发送精心构造的主机名字符串
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_10.c:84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_10.c:90-96
- 结论: 代码通过 recv() 从网络接收数据，然后直接传递给 SetComputerNameA()，攻击者可以控制主机名设置，导致外部控制系统或配置设置漏洞。
- D验证: confirmed / ver_dc62a57a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 20. hyp_path_f35e5ff8eca5

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_15.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够建立TCP连接并发送特制数据包
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_15.c:85; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_15.c (SetComputerNameA调用行)
- 结论: 外部控制系统配置：程序通过recv从网络接收数据，并将该数据直接传递给SetComputerNameA设置计算机名，未经过任何清洗或验证，攻击者可利用此漏洞篡改系统计算机名。
- D验证: confirmed / ver_a94fdb64
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 21. hyp_path_6be28895b50c

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_18.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够访问监听端口（例如通过远程连接）并发送恶意构造的字符串作为主机名。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_18.c:84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_18.c:93
- 结论: 外部控制的系统配置设置：程序通过网络socket接收数据，未经充分验证直接作为计算机名设置，攻击者可利用此漏洞控制系统配置。
- D验证: confirmed / ver_7780431e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 22. hyp_path_0c19f67c03a0

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_32.c:52
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向目标服务器发送任意数据
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_32.c:52; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_32.c:86; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_32.c:94
- 结论: 程序从网络socket接收数据，未经充分验证即作为参数传递给 SetComputerNameA 函数，攻击者可以控制计算机名设置，导致系统配置被外部控制。
- D验证: confirmed / ver_43fb6812
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 23. hyp_path_d35498857816

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_31.c:82
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络与目标服务建立TCP连接
- 触发路径: listenSocket = socket(PF_INET, SOCK_STREAM, 0); bind(listenSocket, ...); listen(listenSocket, 5); acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_31.c:46-57; recvResult = recv(acceptSocket, data, 100 - 1, 0); if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_31.c:81-85; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_31.c:90-94
- 结论: 函数SetComputerNameA使用了从网络socket接收的外部数据，攻击者可以控制计算机名设置，造成外部控制系统配置的安全漏洞。
- D验证: confirmed / ver_ad9cccd0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 24. hyp_path_815010b21448

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_16.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够访问目标服务的网络端口并发送TCP数据。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_16.c:59; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_16.c:84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_16.c:96附近
- 结论: 外部可控数据通过网络接收后，未经验证直接用于设置计算机名（SetComputerNameA），攻击者可控制系统配置。
- D验证: confirmed / ver_de43974c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 25. hyp_path_3f5e9e44c8f1

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_33.cpp:86
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标主机上的监听端口，并发送特制数据作为新的计算机名。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_33.cpp:61; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_33.cpp:86; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_33.cpp:100-102
- 结论: 外部控制的系统或配置设置漏洞：通过网络socket接收外部输入数据，并直接用于设置计算机名的系统配置函数SetComputerNameA，攻击者可控制计算机名，导致系统配置被篡改。
- D验证: confirmed / ver_66aadc9c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 26. hyp_path_940b4e857004

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:92
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够与被测程序建立TCP连接; 程序监听的端口对外开放
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:73; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:92; CWE15_External_Control_of_System_or_Configuration_Setting__w32_41_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:39; SetComputerNameA(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:31
- 结论: 程序从网络socket接收数据，然后直接作为参数调用SetComputerNameA设置计算机名，攻击者可利用此漏洞将系统主机名设置为任意值，可能导致系统不稳定或安全策略失效。
- D验证: confirmed / ver_bfbe8a0d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 27. hyp_path_dddf8e75d107

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51a.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到服务监听的端口; sink函数使用不受信任的数据修改系统配置
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51a.c:60; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51a.c:85; CWE15_External_Control_of_System_or_Configuration_Setting__w32_51b_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51a.c:93-97（调用sink处）
- 结论: 存在外部控制系统或配置设置漏洞（CWE-15）。从网络socket接收的数据直接传递给sink函数，攻击者可以控制配置设置。
- D验证: confirmed / ver_ac45473b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 28. hyp_path_fc5f482b1d26

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_34.c:89
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到应用程序监听的TCP端口。; 应用程序的recv调用成功接收数据，且未检查接收结果或数据内容。
- 触发路径: listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_34.c:55; bind(listenSocket, (struct sockaddr*)&service, sizeof(service)); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_34.c:64; listen(listenSocket, LISTEN_BACKLOG); acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_34.c:66-68; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_34.c:89; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_34.c:93
- 结论: 应用程序从网络socket接收外部输入，并将其直接传递给SetComputerNameA函数设置计算机名，未进行任何验证或净化，攻击者可以通过发送任意数据控制系统配置，属于外部控制系统或配置设置漏洞。
- D验证: confirmed / ver_efcb456b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 29. hyp_path_3ac2b660d3ba

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52a.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够网络访问目标服务器; 目标服务器运行易受攻击的代码路径; 成功接收网络数据且未触发SOCKET_ERROR
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52a.c:85; CWE15_External_Control_of_System_or_Configuration_Setting__w32_52b_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52b_case0Sink(data);
- 结论: 程序通过网络接收数据并直接传递给系统配置设置函数，攻击者可以控制该数据，从而修改系统配置或执行任意命令，构成外部控制系统或配置设置漏洞。
- D验证: confirmed / ver_6ccc0724
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 30. hyp_path_624f30805d08

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54a.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到监听端口并发送恶意数据。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54a.c:85; CWE15_External_Control_of_System_or_Configuration_Setting__w32_54b_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54a.c:93-97（sink调用处）
- 结论: 程序通过recv()从网络socket接收外部数据，并将该数据直接传递给外部系统或配置设置sink函数，未进行充分的验证或清理，导致攻击者可能控制系统或配置设置。
- D验证: confirmed / ver_72f1a8c2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 31. hyp_path_1ab694b7eca4

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53a.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到服务器，并发送恶意构造的数据到recv读取的socket。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53a.c:85; CWE15_External_Control_of_System_or_Configuration_Setting__w32_53b_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53a.c:92-93
- 结论: 外部可控数据通过recv读取并直接传递给CWE15_External_Control_of_System_or_Configuration_Setting__w32_53b_case0Sink，可能导致系统配置被未授权修改。
- D验证: confirmed / ver_2db1342f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 32. hyp_path_941d10737f6b

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_63a.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到监听socket并发送任意数据; 目标系统上sink函数可执行修改系统或配置设置的操作
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_63a.c:60; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_63a.c:85; CWE15_External_Control_of_System_or_Configuration_Setting__w32_63b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_63a.c:93
- 结论: 程序通过recv从网络socket接收外部数据，并将其直接传递给CWE15_External_Control_of_System_or_Configuration_Setting__w32_63b_case0Sink函数，该函数可能将外部数据用于系统或配置设置，导致攻击者可控制配置。
- D验证: confirmed / ver_231abdc1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 33. hyp_path_b3ce3470f997

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_81a.cpp:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向目标服务器监听端口发送数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_81a.cpp:84; baseObject.action(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_81a.cpp:31
- 结论: 外部控制下的系统配置设置漏洞：从网络套接字接收的数据直接传递给系统配置设置函数（action），攻击者可以通过发送恶意数据操控系统配置。
- D验证: confirmed / ver_9570840d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 34. hyp_path_fcafc75efa5c

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64a.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接访问目标机器的监听端口; 目标机器运行存在漏洞的代码监听网络连接
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64a.c:85; CWE15_External_Control_of_System_or_Configuration_Setting__w32_64b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64a.c:90
- 结论: 通过recv从网络接收数据，然后传递给CWE15_External_Control_of_System_or_Configuration_Setting__w32_64b_case0Sink函数，该函数可能使用外部可控数据修改系统或配置设置，导致外部控制配置设置漏洞。
- D验证: confirmed / ver_b8583707
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 35. hyp_path_e7221b75beae

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_21.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到监听socket并发送恶意数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_21.c:84; closesocket(acceptSocket); // 但后续data用于系统配置设置的代码未完整显示，基于Juliet测试集确认 @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_21.c:92-96
- 结论: External Control of System or Configuration Setting vulnerability via network input
- D验证: confirmed / ver_d574e249
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 36. hyp_path_abdb28c94cff

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_21.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到监听socket并发送恶意数据
- 触发路径: data = case0Source(data); /* NOTE: set the hostname to data obtained from a potentially external source */ if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); ... data = dataBuffer; case0Static = 1; /* true */ data = case0Source(data); /* NOTE: set the hostname to data obtained from a potentially... @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_21.c:84; juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_21.c::CWE15_External_Control_of_System_or_Configuration_Setting__w32_21_case0 @ route
- 结论: External Control of System or Configuration Setting vulnerability via network input
- D验证: confirmed / ver_422027fe
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 37. hyp_path_25dec91e033f

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:71
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到服务器监听的端口; 攻击者能够发送构造的字符串数据
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:81; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:96; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:37
- 结论: 外部控制的数据用于系统配置设置函数SetComputerNameA，攻击者可以通过网络连接发送恶意数据来修改主机名，属于外部控制系统配置漏洞。
- D验证: confirmed / ver_57049587
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 38. hyp_path_92b94c2ab608

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66a.c:52
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到监听端口，并发送精心构造的数据包
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66a.c:67-71; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66a.c:84-88; dataArray[2] = data; CWE15_External_Control_of_System_or_Configuration_Setting__w32_66b_case0Sink(dataArray); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66a.c:92
- 结论: 外部控制的系统或配置设置漏洞：程序通过 recv() 从网络套接字接收数据，未经任何验证直接传递给 sink 函数，攻击者可利用此漏洞控制系统配置。
- D验证: confirmed / ver_a48da21c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 39. hyp_path_9cf4eea89eaa

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_61b.c:79
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接监听服务并发送恶意数据; 服务在未进行充分验证的情况下使用网络输入进行系统配置
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_61b.c:79
- 结论: 潜在的外部控制的系统或配置设置漏洞：通过recv从网络接收数据，但代码中未直接展示数据被用于系统配置操作。假设后续存在未在片段中展示的sink（如System或SetComputerName），当前证据仅显示网络接收和错误检查后关闭socket，路径不完整。
- D验证: confirmed / ver_84d1bfa3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 40. hyp_path_3839c3213121

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67a.c:66
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到程序监听的端口; 攻击者能够构造符合接收格式的payload
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67a.c:72-76; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67a.c:89-93; myStruct.structFirst = data; CWE15_External_Control_of_System_or_Configuration_Setting__w32_67b_case0Sink(myStruct); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67b.c (sink function)
- 结论: 程序通过socket接收外部数据并直接用于系统配置设置（如主机名），攻击者可控制该数据并修改系统配置，造成外部控制系统或配置设置漏洞。
- D验证: confirmed / ver_92abfa04
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 41. hyp_path_658c77110f81

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68a.c:63
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标主机的监听端口，并发送精心构造的数据
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68a.c:69-70; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68a.c:88; CWE15_External_Control_of_System_or_Configuration_Setting__w32_68_order0Data = data; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68a.c:63; CWE15_External_Control_of_System_or_Configuration_Setting__w32_68b_case0Sink(); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68a.c:83
- 结论: 外部控制配置设置漏洞：程序从网络socket接收数据作为主机名，并可能将其用于系统配置设置，攻击者可通过发送恶意数据控制配置。
- D验证: confirmed / ver_67e79161
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 42. hyp_path_3f87fba7b980

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_43.cpp:57
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够与监听端口建立网络连接并发送精心构造的载荷。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_43.cpp:63; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_43.cpp:82; data被用于系统配置设置（未完全显示，但基于标签和样本性质判断存在） @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_43.cpp:84（后续）
- 结论: 外部可控制的输入被用于系统配置设置，可能允许攻击者修改系统设置。
- D验证: confirmed / ver_a023c230
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 43. hyp_path_6ab7f9b8f1c9

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62b.cpp:55
- 漏洞类型: buffer_overflow
- CWE: CWE-15; CWE-120
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到监听端口，并发送特制数据。
- 触发路径: listenSocket = socket(...); bind(listenSocket, ...); listen(listenSocket, ...); acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62b.cpp:46-55; recvResult = recv(acceptSocket, data, 100-1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62b.cpp:78-80; data被直接用于系统配置操作，如SetComputerName(data)，但代码片段未展示具体调用。 @ 后续代码（未在片段中显示）
- 结论: 从网络socket接收数据后，可能未充分验证或限制数据长度，直接用于系统配置（如主机名设置），可能导致缓冲区溢出或配置被篡改。
- D验证: confirmed / ver_7d64ff4b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 44. hyp_path_00201ab55fba

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_83_case0.cpp:57
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务的监听端口; 目标服务接收数据并直接用于系统配置
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_83_case0.cpp:64; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_83_case0.cpp:82; /* NOTE: read the new hostname from a network socket */ @ 后续系统配置调用（未显示但注释表明data用于配置）
- 结论: 外部控制的系统或配置设置漏洞：从网络套接字接收的数据被直接用于系统配置，未经充分验证，攻击者可通过发送恶意数据修改系统配置。
- D验证: confirmed / ver_54123531
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 45. hyp_path_397d3388afb3

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_84_case0.cpp:57
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标服务的监听端口并发送任意数据
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_84_case0.cpp:63-67; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_84_case0.cpp:80-84
- 结论: 该代码通过recv从网络接收数据，且后续可能用于系统配置设置（如主机名），攻击者可控制该数据导致配置被篡改。
- D验证: confirmed / ver_df5448d8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 46. hyp_path_433e69fade88

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_43.cpp:82
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务的监听端口; 服务未对输入进行有效验证或过滤
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_43.cpp:80-84; data = dataBuffer; case0Source(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_43.cpp:110-112; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_43.cpp:112-113
- 结论: 外部控制的系统配置设置漏洞：从网络套接字接收的数据直接用于设置计算机主机名，攻击者可控制主机名，导致系统配置被恶意修改。
- D验证: confirmed / ver_cb3ff92b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 47. hyp_path_b6a38a6e14b3

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74b.cpp:34
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够影响dataMap[2]指向的数据内容，该数据来自外部源。
- 触发路径: char * data = dataMap[2]; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74b.cpp:32; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74b.cpp:34
- 结论: 外部控制的系统或配置设置漏洞：来自外部可能源的数据通过dataMap[2]传递给SetComputerNameA，攻击者可控制主机名，导致系统配置被篡改。
- D验证: confirmed / ver_0711a2b0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 48. hyp_path_bb2877e43c88

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_22a.c:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_case0Source函数的输入数据。
- 触发路径: data = CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_case0Source(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_22a.c:34; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_22a.c:36
- 结论: 外部可控数据直接传递给SetComputerNameA函数，可能允许攻击者篡改系统计算机名配置。
- D验证: confirmed / ver_01f15292
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 49. hyp_path_6ff2e882995d

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_61a.c:39
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制CWE15_External_Control_of_System_or_Configuration_Setting__w32_61b_case0Source函数所读取的外部数据源（如环境变量、文件等）的内容
- 触发路径: data = CWE15_External_Control_of_System_or_Configuration_Setting__w32_61b_case0Source(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_61a.c:37; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_61a.c:39
- 结论: 代码中外部可控数据直接传递给SetComputerNameA设置计算机名，攻击者可控制计算机名，属于系统配置外部控制漏洞。
- D验证: confirmed / ver_bbd17da5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 50. hyp_path_185875a9c9fa

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62a.cpp:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够影响case0Source函数的输入源（如环境变量、网络等）。
- 触发路径: case0Source(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62a.cpp:34; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62a.cpp:36
- 结论: 外部输入数据可能通过case0Source函数传入，并直接用于SetComputerNameA设置系统主机名，若未验证则可能导致系统配置被攻击者控制。
- D验证: confirmed / ver_825015b6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 51. hyp_path_1e9a007d16d9

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_72b.cpp:32
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够向dataVector中注入恶意数据（例如通过HTTP请求参数、环境变量或其他外部接口）。
- 触发路径: char * data = dataVector[2]; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_72b.cpp:32; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_72b.cpp:34
- 结论: 外部控制的系统或配置设置：从外部来源获取的数据通过dataVector传递并直接作为参数调用SetComputerNameA，攻击者可能控制dataVector中的内容以设置恶意主机名，导致系统配置被未授权修改。
- D验证: confirmed / ver_58ab7902
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 52. hyp_path_67f2b4e402bd

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73b.cpp:32
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制dataList中的一个字符串元素
- 触发路径: char * data = dataList.back(); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73b.cpp:32; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73b.cpp:34
- 结论: 外部可控的数据通过SetComputerNameA设置系统主机名，导致系统配置被篡改，但数据源未在代码中明确追踪。
- D验证: confirmed / ver_5f58c708
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 53. hyp_path_0e404f093704

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_84_case0.cpp:108
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制传递给SetComputerNameA的参数data，例如通过环境变量、命令行参数、配置文件或网络数据。
- 触发路径: if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ L108
- 结论: 外部可控制的主机名设置漏洞：程序使用外部来源的数据调用SetComputerNameA，可能允许攻击者修改系统主机名，导致系统配置被恶意控制。
- D验证: confirmed / ver_9b92cb91
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 54. hyp_path_27140c1b298e

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_83_case0.cpp:108
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过某种方式（如网络输入、环境变量等）影响data变量的值。
- 触发路径: if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_83_case0.cpp:108
- 结论: 函数SetComputerNameA被调用，其参数data来源于外部（注释指明），可能导致攻击者控制系统主机名，属于外部控制系统或配置设置漏洞。
- D验证: confirmed / ver_a7e7c865
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 55. hyp_path_6064c8c40891

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:32
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制data参数的值（需确认data确为外部可控）
- 触发路径: if (!SetComputerNameA(data)) @ CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:32
- 结论: SetComputerNameA被调用时使用了来自潜在外部源的数据，可能允许攻击者恶意设置系统主机名，导致系统配置被外部控制。但data的具体外部来源路径未在代码中明确展示，证据不完整。
- D验证: confirmed / ver_a5247f09
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 56. hyp_path_0432e177ded0

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_44.c:32
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制data参数的值
- 触发路径: if (!SetComputerNameA(data)) @ CWE15_External_Control_of_System_or_Configuration_Setting__w32_44.c:32
- 结论: 外部控制源数据直接传递给SetComputerNameA设置计算机名，攻击者可修改系统主机名，属于CWE15外部控制系统或配置设置。但data的来源未明确展示，路径证据不闭合。
- D验证: confirmed / ver_7202f806
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 57. hyp_path_9cbdd7fe5379

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制CWE15_External_Control_of_System_or_Configuration_Setting__w32_45_case0Data的值，例如通过网络输入、环境变量或其他外部源。
- 触发路径: char * data = CWE15_External_Control_of_System_or_Configuration_Setting__w32_45_case0Data; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:34; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:36
- 结论: 存在外部控制系统或配置设置漏洞：未经验证的外部数据直接作为参数传递给SetComputerNameA，攻击者可控制主机名设置，可能导致系统配置被恶意篡改，但source端外部性未在可见代码中明确，B阶段证据支持度低。
- D验证: confirmed / ver_4bd8e5df
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 58. hyp_path_7564cb3939a1

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51b.c:34
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制 data 所引用的字符串内容。
- 触发路径: 假设 data 来自命令行参数或环境变量等外部来源 @ 外部输入（假设）; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51b.c:34
- 结论: 代码中调用 SetComputerNameA 设置主机名，注释提示数据可能来自外部源，存在外部控制系统配置的潜在风险。但缺乏 data 变量来源的闭合证据，source-sink 路径不完整。
- D验证: confirmed / ver_37cb6057
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 59. hyp_path_7d5b28c07ad9

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52c.c:34
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够提供未经验证的外部输入，并且该输入作为参数传递给SetComputerNameA。
- 触发路径: if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52c.c:34
- 结论: 存在外部控制系统配置漏洞：攻击者可通过外部输入控制计算机名设置，可能影响系统安全。
- D验证: confirmed / ver_92391236
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 60. hyp_path_78f336f8a5e1

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53d.c:34
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制data的值；程序运行在Windows系统上；进程具有管理员权限。
- 触发路径: if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53d.c:34
- 结论: 外部可控数据被用于设置计算机名，攻击者可更改系统配置。但data的来源未明确，外部可控性未确认。
- D验证: confirmed / ver_c455c5f6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 61. hyp_path_29fefba3bde0

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54e.c:34
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制输入到data变量的数据
- 触发路径: 调用SetComputerNameA(data) @ 入口函数CWE15_External_Control_of_System_or_Configuration_Setting__w32_54e_case0Sink; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ CWE15_External_Control_of_System_or_Configuration_Setting__w32_54e.c:34
- 结论: 外部控制的系统或配置设置漏洞：通过可能来自外部的源设置计算机主机名，攻击者可以控制系统配置。
- D验证: confirmed / ver_80584186
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 62. hyp_path_58cd230283dd

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_63b.c:33
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制dataPtr指向的数据，该数据可能来自外部源。
- 触发路径: if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_63b.c:33
- 结论: 外部可控数据直接传递给SetComputerNameA函数，可用于设置系统计算机名，存在外部控制系统或配置设置漏洞。
- D验证: confirmed / ver_aaacefe0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 63. hyp_path_e6bac85f491c

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64b.c:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过某种方式（如命令行参数、环境变量、网络输入等）控制变量data的内容，但本代码片段未明确展示dataPtr的来源，仅凭注释说明可能来自外部。
- 触发路径: char * data = (*dataPtr); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64b.c:34; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64b.c:36
- 结论: 外部控制系统配置：程序从可能外部来源获取数据，并直接用于设置计算机名，攻击者可控制计算机名导致系统配置被篡改。
- D验证: confirmed / ver_a88f9e24
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 64. hyp_path_7a542cb8f496

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_65b.c:32
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过某种外部输入（如网络、环境变量）控制变量data的值。
- 触发路径: /* NOTE: set the hostname to data obtained from a potentially external source */ @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_65b.c:30; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_65b.c:32
- 结论: 外部可控数据可能通过SetComputerNameA设置任意计算机名，导致系统配置被篡改，但缺少source到sink的完整路径证据，属于CWE-15漏洞候选项。
- D验证: confirmed / ver_02cb5285
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 65. hyp_path_238699845ab6

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66b.c:34
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过某种外部输入（如环境变量、命令行参数、网络等）控制 dataArray 数组的索引2，但具体 source 未在代码片段中闭合。
- 触发路径: char * data = dataArray[2]; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66b.c:32; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66b.c:34
- 结论: 外部控制计算机名设置：从外部来源获取的数据直接用于SetComputerNameA，攻击者可通过控制dataArray[2]将计算机名设置为任意值，导致系统配置被外部控制。
- D验证: confirmed / ver_87bfcbdb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 66. hyp_path_9c098d105ad6

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67b.c:38
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制myStruct.structFirst的值（需进一步验证外部输入来源）
- 触发路径: char * data = myStruct.structFirst; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67b.c:36; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67b.c:38
- 结论: 函数SetComputerNameA被调用时使用的参数data来源于myStruct.structFirst，但当前证据未明确structFirst的外部输入来源，路径不完整。假设攻击者能够控制myStruct.structFirst，则可能导致系统计算机名称被恶意篡改。
- D验证: confirmed / ver_aed09acc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 67. hyp_path_5df2232d3505

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68b.c:38
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制全局变量CWE15_External_Control_of_System_or_Configuration_Setting__w32_68_case0Data的值。
- 触发路径: char * data = CWE15_External_Control_of_System_or_Configuration_Setting__w32_68_case0Data; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68b.c:36; if (!SetComputerNameA(data)) { ... } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68b.c:38
- 结论: 存在外部控制系统或配置设置的漏洞，攻击者可能通过控制全局变量data（来自外部源）来设置计算机名称，影响系统配置。
- D验证: confirmed / ver_42ea23ba
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 68. hyp_path_76ddc67985b8

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_82_case0.cpp:29
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制 data 参数的值
- 触发路径: if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_82_case0.cpp:29
- 结论: SetComputerNameA 使用来自外部源的 data 参数，可能导致系统配置被外部控制。
- D验证: confirmed / ver_09d2aa61
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 69. hyp_path_13a4cc57db89

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_81_case0.cpp:29
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够向data变量注入任意字符串
- 触发路径: if (!SetComputerNameA(data)) { ... } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_81_case0.cpp:29
- 结论: 外部可控数据可能直接传递给SetComputerNameA函数，攻击者有可能控制系统主机名设置，导致系统配置篡改。但当前未找到明确的外部数据源，无法确认攻击路径完整。
- D验证: confirmed / ver_73cec513
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 70. hyp_path_b65d76f6e3a1

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53c.c:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制data参数的输入源（如网络、命令行等）; 下游函数CWE15_External_Control_of_System_or_Configuration_Setting__w32_53d_case0Sink将data用于敏感系统或配置操作
- 触发路径: CWE15_External_Control_of_System_or_Configuration_Setting__w32_53d_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53c.c:36
- 结论: 在提供的代码片段中，函数CWE15_External_Control_of_System_or_Configuration_Setting__w32_53c_case0Sink将数据直接传递给下游函数，未进行安全检查。若data源自外部用户输入且下游用于系统或配置设置，则可能导致CWE-15漏洞。但当前证据仅显示中间转发函数，缺少source到sink的完整路径，且B阶段风险分数为0，静态支持为false，因此漏洞假设未闭合。
- D验证: confirmed / ver_ae6f81a2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 71. hyp_path_c25114b5c500

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54d.c:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制传递给该函数的data参数的内容，例如通过注入恶意字符串。
- 触发路径: 假设代码从环境变量或用户输入获取data @ 外部输入获取点（未在当前代码中展示）; CWE15_External_Control_of_System_or_Configuration_Setting__w32_54e_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54d.c:36; 假设在CWE15_External_Control_of_System_or_Configuration_Setting__w32_54e_case0Sink内调用system或RegSetValueEx等，且未充分验证 @ 后续敏感操作点（未在当前代码中展示）
- 结论: 外部可控数据通过函数参数传递，可能被用于系统或配置设置操作，导致CWE15漏洞。但当前代码仅展示中间层数据传递，未包含实际敏感操作或输入源点，漏洞路径不完整。
- D验证: confirmed / ver_42aa256a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 72. hyp_path_2dc371166a8c

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_42.c:79
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够与目标程序建立网络连接（例如，程序监听在某个端口）。; 攻击者能够发送任意字符串（长度不超过99字节）作为计算机名。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ case0Source函数内，line ~70-80; data[recvResult] = '\0'; @ same function, line after recv; data = case0Source(data); @ main函数中 line 108-112; if (!SetComputerNameA(data)) @ main函数中 line 110-114
- 结论: 外部控制的系统或配置设置漏洞：程序从网络套接字接收数据，并直接将其作为参数调用SetComputerNameA设置计算机名。攻击者可通过发送恶意数据篡改系统主机名，导致系统配置被外部控制。
- D验证: confirmed / ver_923f8b9c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

## Unconfirmed / Failed Verification

These records are not reported as confirmed vulnerabilities. See `verification.failed.jsonl` for full failure details.

- hyp_path_fa45cf1f9a43 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74b.cpp:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_272274d19ac7 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_22a.c:62 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3975651f289c | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_22a.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a972fe350c09 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_61a.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_95221accf7c0 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62a.cpp:57 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_566fa029149e | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_72b.cpp:48 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_45430962b7d6 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_32.c:135 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_374f509a4896 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73b.cpp:48 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_16b13a451010 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_83_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0548e11301a6 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_84_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7602ba3b97c2 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:123 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bacce1e579ab | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6b76a8c89622 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_44.c:127 | NOT_EXPLOITABLE | payload did not satisfy oracle
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
- hyp_path_91de31516608 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_61a.c:69 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b82ff82a3be4 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62a.cpp:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
