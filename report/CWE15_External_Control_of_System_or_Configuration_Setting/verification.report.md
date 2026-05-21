# MAGUS Final Vulnerability Report

- generated_at: 2026-05-21T12:42:41Z
- confirmed_vulnerabilities: 69
- failed_verifications: 33
- source_confirmed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/verification.jsonl
- source_failed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/verification.failed.jsonl

## Confirmed Vulnerabilities

### 1. hyp_path_433e69fade88

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_43.cpp:82
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够访问程序监听的网络端口并发送数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_43.cpp:80-84; data[recvResult] = '\0'; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_43.cpp:82; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_43.cpp:112
- 结论: 程序从网络接收数据后直接用作SetComputerNameA的参数，攻击者可通过网络连接发送恶意字符串，从而修改目标系统的计算机名，属于外部控制系统配置设置漏洞。
- D验证: confirmed / ver_cb3ff92b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 2. hyp_path_8fb0e080cc8d

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73a.cpp:90
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够与程序监听的网络端口进行通信并发送任意数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73a.cpp:90; dataList.push_back(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73a.cpp:97; case0Sink(dataList); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73a.cpp:99
- 结论: 外部控制系统或配置设置：程序从网络套接字接收数据，并将其直接传递给case0Sink函数，该函数可能基于外部输入修改系统配置，攻击者可以通过发送恶意数据控制系统配置。
- D验证: confirmed / ver_1d565478
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 3. hyp_path_abdb28c94cff

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_21.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到程序监听的端口，并发送任意字符串作为主机名。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_21.c:82-86; data = case0Source(data); if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_21.c:115-119
- 结论: 外部可控数据被用于设置系统主机名，攻击者可以通过网络发送恶意主机名，导致系统配置被篡改。
- D验证: confirmed / ver_422027fe
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 4. hyp_path_0b0c49ef539a

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74a.cpp:90
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务; 服务端正在监听并接受连接; 攻击者发送的数据在recv调用中被接收
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74a.cpp:65; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74a.cpp:90; dataMap[0] = data; dataMap[1] = data; dataMap[2] = data; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74a.cpp:103-105; case0Sink(dataMap); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74a.cpp:109
- 结论: 外部控制的系统配置设置漏洞：程序从网络socket接收数据，并将其存储在map中，随后调用sink函数处理该数据。攻击者可以通过发送恶意数据来控制系统配置设置。
- D验证: confirmed / ver_3f98d0aa
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 5. hyp_path_d21d250d17bd

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_72a.cpp:90
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到监听套接字并发送恶意数据。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_72a.cpp:88-92; dataVector.insert(dataVector.end(), 1, data); case0Sink(dataVector); @ same function, after recv success (around line 93-95)
- 结论: 程序从网络套接字接收数据并直接用于系统配置设置，攻击者可以通过发送恶意数据控制系统配置，导致外部控制系统或配置设置漏洞。
- D验证: confirmed / ver_4f5b3bac
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 6. hyp_path_2dc371166a8c

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_42.c:79
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标程序的监听socket并发送任意字符串
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_42.c:77-81; data[recvResult] = '\0'; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_42.c:79; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_42.c:110-111
- 结论: 外部控制系统配置设置：攻击者可通过网络socket向SetComputerNameA函数提供任意字符串，从而控制主机名设置，可能导致系统配置被篡改。
- D验证: confirmed / ver_923f8b9c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 7. hyp_path_1b647b79197e

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_12.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够与监听socket建立连接并发送数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_12.c:84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_12.c:86（推测）
- 结论: 外部控制的系统配置设置漏洞：程序通过socket接收外部输入的主机名数据，直接用于SetComputerNameA设置系统主机名，攻击者可以控制该输入从而修改系统配置。
- D验证: confirmed / ver_cf667ed7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 8. hyp_path_bfee1e414bf1

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_17.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接至目标程序监听的端口; 目标程序已启动并监听指定端口; 攻击者能够发送任意字符串作为计算机名称
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_17.c:83; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_17.c:93
- 结论: 外部控制的系统或配置设置：程序通过网络接收主机名数据，并将该数据直接用于设置计算机名称（SetComputerNameA），未进行充分验证或净化，攻击者可通过网络连接控制计算机名称设置，导致系统配置被外部控制。
- D验证: confirmed / ver_f222e1ed
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 9. hyp_path_dddf8e75d107

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51a.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接至监听套接字并发送任意数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51a.c:85; CWE15_External_Control_of_System_or_Configuration_Setting__w32_51b_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51a.c:93-97 (调用sink)
- 结论: 存在外部控制系统或配置设置漏洞，攻击者可通过网络连接发送恶意数据，该数据被用作系统或配置设置的输入，可能导致系统被篡改。
- D验证: confirmed / ver_ac45473b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 10. hyp_path_940b4e857004

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:92
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络访问目标服务的监听端口; 目标服务未对网络输入进行充分验证或过滤
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:67; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:92; CWE15_External_Control_of_System_or_Configuration_Setting__w32_41_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:39; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:31
- 结论: 外部可控数据通过 SetComputerNameA 设置系统配置，可能导致安全配置被篡改或拒绝服务。
- D验证: confirmed / ver_bfbe8a0d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 11. hyp_path_3ac2b660d3ba

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52a.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标主机的监听端口; 目标主机上的socket未设置严格的源IP限制或身份验证
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52a.c:60; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52a.c:85; CWE15_External_Control_of_System_or_Configuration_Setting__w32_52b_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52a.c:93（间接）
- 结论: 程序通过recv()从网络接收数据，并将该数据直接传递给CWE15_External_Control_of_System_or_Configuration_Setting__w32_52b_case0Sink()函数，该函数可能用于修改系统配置（如计算机名）。攻击者可以控制网络输入，从而实现对系统或配置设置的外部控制，导致安全配置被篡改。
- D验证: confirmed / ver_6ccc0724
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 12. hyp_path_1ab694b7eca4

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53a.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到服务器端口，并发送特制数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53a.c:85; CWE15_External_Control_of_System_or_Configuration_Setting__w32_53b_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53a.c:89 (sink调用行)
- 结论: 从网络接收数据后，未经充分验证直接用于系统配置设置，攻击者可通过网络发送恶意数据修改系统配置。
- D验证: confirmed / ver_2db1342f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 13. hyp_path_624f30805d08

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54a.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到监听套接字并发送特制数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54a.c:85; CWE15_External_Control_of_System_or_Configuration_Setting__w32_54b_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54a.c:93
- 结论: 网络接收的数据（data）直接传递到CWE15_External_Control_of_System_or_Configuration_Setting__w32_54b_case0Sink函数，该函数可能将该数据用于系统配置设置（如主机名），导致外部控制系统或配置设置漏洞。攻击者可以通过网络发送恶意数据，影响系统配置。
- D验证: confirmed / ver_72f1a8c2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 14. hyp_path_941d10737f6b

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_63a.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到服务端的监听socket，并发送特制的网络数据包
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_63a.c:85; CWE15_External_Control_of_System_or_Configuration_Setting__w32_63b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_63b_case0Sink 调用处
- 结论: 从网络socket接收的数据直接作为参数传递给系统或配置设置修改函数（sink），攻击者可通过发送恶意数据导致系统配置被外部控制，存在CWE-15漏洞。
- D验证: confirmed / ver_231abdc1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 15. hyp_path_21da82af0a43

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_08.c:98
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务; 目标服务监听并接受连接; recv函数成功接收数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_08.c:96-100; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_08.c:98-99
- 结论: 代码从网络socket接收数据，并直接将其设置为计算机名，未进行任何验证或净化，导致攻击者可以控制系统配置。
- D验证: confirmed / ver_5f28a436
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 16. hyp_path_fcafc75efa5c

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64a.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标程序的监听套接字
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64a.c:83; CWE15_External_Control_of_System_or_Configuration_Setting__w32_64b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64a.c:93
- 结论: 代码通过recv从网络接收数据，并将数据传递给外部控制系统或配置设置的sink函数，导致攻击者能够控制系统配置。
- D验证: confirmed / ver_b8583707
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 17. hyp_path_1d942f707016

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_11.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够访问监听端口（默认 LISTEN_PORT）并发送 TCP 数据
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_11.c:65-69; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_11.c:84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_11.c:92-96
- 结论: 外部控制系统设置：攻击者可以通过网络连接发送恶意数据，从而控制 SetComputerNameA 函数设置的主机名，导致系统配置被外部控制。
- D验证: confirmed / ver_ebe5dd8c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 18. hyp_path_f0115f5031d0

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_02.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络访问服务端监听端口，并发送任意载荷
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_02.c:84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_02.c:93
- 结论: 通过网络接收的数据用于调用SetComputerNameA设置计算机名，攻击者可以控制该数据，从而任意修改系统计算机名，属于外部控制系统配置设置漏洞。
- D验证: confirmed / ver_b2777fa8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 19. hyp_path_9af5470c0481

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_01.c:82
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能通过网络到达目标主机的监听端口; 攻击者能构造任意字符串数据
- 触发路径: listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); bind(listenSocket, ...); listen(listenSocket, LISTEN_BACKLOG); acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_01.c:48-57; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_01.c:82; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_01.c:90-94
- 结论: 程序通过recv从网络socket接收数据，未经任何过滤直接传递给SetComputerNameA()设置计算机名，攻击者可控制计算机名，导致外部控制系统配置漏洞。
- D验证: confirmed / ver_0f38d6d2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 20. hyp_path_ee7c28da3796

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_04.c:91
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够与目标服务建立TCP连接，并发送精心构造的数据。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == INVALID_SOCKET) { break; } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_04.c:72-76; recvResult = recv(acceptSocket, data, 100 - 1, 0); if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_04.c:89-93; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_04.c:99-103
- 结论: 网络接收的数据未经充分验证即用于设置系统配置（计算机名），存在外部控制配置设置漏洞。
- D验证: confirmed / ver_92aa889f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 21. hyp_path_e0be488b7d84

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_03.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到监听端口并发送恶意数据。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_03.c:84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_03.c:92-96 (approx)
- 结论: 外部控制的系统或配置设置漏洞：从网络接收的数据未经充分验证即用于设置计算机名（SetComputerNameA），攻击者可控制系统配置。
- D验证: confirmed / ver_e5ebb946
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 22. hyp_path_c1b58b470d5b

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_05.c:91
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到服务端监听的端口; 攻击者能够发送任意字符串作为主机名
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_05.c:89-93; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_05.c:99-103
- 结论: 外部输入通过网络接收后直接用于设置系统计算机名，可由攻击者控制系统配置，导致CWE-15漏洞。
- D验证: confirmed / ver_580221fa
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 23. hyp_path_91a808f8e1fd

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_06.c:88
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标主机的监听端口，并发送特制的数据作为主机名
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_06.c:86; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_06.c:92
- 结论: 程序从网络接收外部输入并直接作为参数调用SetComputerNameA设置计算机名，攻击者可控制传入的主机名，导致系统配置被外部控制。
- D验证: confirmed / ver_80c0febd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 24. hyp_path_5ac355eeac4c

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_07.c:90
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到程序的监听端口; 攻击者能够发送任意数据到该端口
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_07.c:90; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_07.c:98
- 结论: 程序通过recv从网络接收数据，然后直接调用SetComputerNameA设置计算机名，攻击者可以发送恶意数据更改系统配置，导致CWE15外部控制系统或配置设置漏洞。
- D验证: confirmed / ver_156896db
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 25. hyp_path_3b5654ba5890

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_10.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够访问目标主机的监听端口并发送数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_10.c:84; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_10.c:96
- 结论: 该测试用例存在外部控制系统或配置设置漏洞（CWE-15）。程序通过网络接收数据，并将其直接用于设置计算机名的系统配置函数SetComputerNameA，未进行充分验证或清理。攻击者可以控制网络输入，从而修改计算机名，可能导致系统配置被恶意篡改。
- D验证: confirmed / ver_dc62a57a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 26. hyp_path_b785c43f551b

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_14.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向目标主机的监听端口发送任意数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_14.c:82-84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_14.c:92-96
- 结论: 程序通过recv从网络接收数据，未充分验证数据内容，直接将其传递给SetComputerNameA函数设置计算机名，可能允许攻击者控制系统配置。
- D验证: confirmed / ver_43581d01
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 27. hyp_path_fb3b81605899

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_13.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够与目标程序建立网络连接并发送数据。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_13.c:84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_13.c:96
- 结论: 程序通过recv从网络socket接收数据，然后将数据直接传递给SetComputerNameA设置计算机名称。由于数据来自外部网络且未经验证，攻击者可以控制计算机名称，导致系统配置被外部控制。
- D验证: confirmed / ver_bde0dc31
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 28. hyp_path_4751ebf2c094

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_09.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标程序监听的socket并发送数据; recv()成功接收数据（返回正数）; 数据未被过滤或清理直接传递给SetComputerNameA
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_09.c:84; if (!SetComputerNameA(data)) { ... } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_09.c:88
- 结论: 程序从网络socket接收主机名数据，未经验证直接用于SetComputerNameA设置计算机名，攻击者可通过发送特制数据控制计算机名，构成外部控制系统/配置设置漏洞。
- D验证: confirmed / ver_ce594fec
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 29. hyp_path_f35e5ff8eca5

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_15.c:85
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过TCP连接向监听端口发送包含恶意主机名数据的网络包
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_15.c:60; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_15.c:85; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_15.c:93（近似）
- 结论: 程序通过recv从网络接收数据，并将该数据直接作为参数传递给SetComputerNameA函数，导致攻击者能够控制系统主机名，属于外部控制系统或配置设置漏洞。
- D验证: confirmed / ver_a94fdb64
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 30. hyp_path_815010b21448

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_16.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标主机上监听的端口。; 攻击者发送的数据能被recv成功接收并存储到data中。; 程序未对接收到的数据进行任何安全验证或过滤，直接用于SetComputerNameA。
- 触发路径: listenSocket = socket(PF_INET, SOCK_STREAM, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_16.c:50; bind(listenSocket, (struct sockaddr*)&service, sizeof(service)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_16.c:59; listen(listenSocket, LISTEN_BACKLOG); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_16.c:59; acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_16.c:59; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_16.c:84; if (recvResult != SOCKET_ERROR && recvResult != 0) { if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_16.c:92-96
- 结论: 远程攻击者可通过网络发送恶意数据，利用外部控制系统配置漏洞（CWE-15），调用SetComputerNameA设置任意计算机名，影响系统配置。
- D验证: confirmed / ver_de43974c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 31. hyp_path_6be28895b50c

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_18.c:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够网络连接至目标机器的监听端口; recv调用成功返回非错误值
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_18.c:59; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_18.c:84; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_18.c:87-92
- 结论: 外部可控数据通过socket接收后直接用于设置计算机名，存在外部控制系统或配置设置漏洞。攻击者可控制data字符串设置任意计算机名，可能导致系统配置被篡改。
- D验证: confirmed / ver_7780431e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 32. hyp_path_ac4ba2963d66

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_82a.cpp:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到服务端口并发送恶意负载; 服务未对输入进行充分的验证或净化
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_82a.cpp:84; baseObject->action(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_82a.cpp:89
- 结论: 外部控制的系统或配置设置：程序从网络socket接收数据，并直接将其传递给修改系统设置的操作，攻击者可以控制输入从而篡改系统配置。
- D验证: confirmed / ver_2535a1f3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 33. hyp_path_b3ce3470f997

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_81a.cpp:84
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到监听套接字并发送任意数据。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_81a.cpp:84; baseObject.action(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_81a.cpp:31
- 结论: 通过recv从网络接收外部数据，并传递到action函数，该函数可能将数据用于系统配置设置，导致外部控制配置设置漏洞。
- D验证: confirmed / ver_9570840d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 34. hyp_path_d35498857816

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_31.c:82
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到监听端口并发送长度不超过100字节的有效数据; recv成功且数据非空
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_31.c:82; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_31.c:95
- 结论: 从网络socket接收外部可控数据，未经验证直接用于SetComputerNameA设置系统主机名，可能导致系统配置被外部控制。
- D验证: confirmed / ver_ad9cccd0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 35. hyp_path_0c19f67c03a0

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_32.c:52
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务器; 攻击者可以发送任意数据
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_32.c:67; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_32.c:86; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_32.c:94
- 结论: 外部控制计算机名设置：程序从网络socket接收数据并直接用于SetComputerNameA，未经验证，攻击者可设置任意主机名。
- D验证: confirmed / ver_43fb6812
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 36. hyp_path_9cf4eea89eaa

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_61b.c:79
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标程序监听的端口并发送任意数据。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_61b.c:79; 假设将 data 用于系统配置 API，如 SetComputerName(data) 或类似操作。 @ 未知（后续调用位置）
- 结论: 外部控制的系统配置设置：程序从网络套接字接收数据，并可能将其用于系统配置，但未对输入进行验证，攻击者可以通过发送恶意数据操控系统配置。
- D验证: confirmed / ver_84d1bfa3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 37. hyp_path_fc5f482b1d26

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_34.c:89
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标主机的监听端口并发送任意数据。
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_34.c:89; if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_34.c:90-91; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); exit(1); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_34.c:97-98
- 结论: 程序通过recv从网络套接字读取主机名，并直接传递给SetComputerNameA设置计算机名，攻击者可以控制该输入，从而修改系统配置，违反了外部控制配置设置的安全约束。
- D验证: confirmed / ver_efcb456b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 38. hyp_path_3f5e9e44c8f1

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_33.cpp:86
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标服务器的监听端口，并发送任意数据。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_33.cpp:61; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_33.cpp:86; if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_33.cpp:94-98
- 结论: 外部控制系统或配置设置漏洞：通过网络socket接收外部可控数据，并直接用于设置计算机名（SetComputerNameA），攻击者可控制计算机名，导致系统配置被篡改。
- D验证: confirmed / ver_66aadc9c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 39. hyp_path_25dec91e033f

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:71
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立网络连接; 服务器运行在特权模式下以允许修改系统主机名
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:80; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:96; if (!SetComputerNameA(data)) { @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:38
- 结论: 从网络接收的数据未经验证直接用于设置系统主机名，攻击者可通过控制网络输入修改系统配置。
- D验证: confirmed / ver_57049587
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 40. hyp_path_92b94c2ab608

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66a.c:52
- 漏洞类型: CWE-15, CWE-20
- CWE: CWE-15; CWE-20
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标的监听端口（LISTEN_PORT）; 攻击者能够发送构造的恶意数据（如修改后的主机名字符串）
- 触发路径: listenSocket = socket(PF_INET, SOCK_STREAM, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66a.c:52; acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66a.c:67; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66a.c:86; dataArray[2] = data; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66a.c:88; CWE15_External_Control_of_System_or_Configuration_Setting__w32_66b_case0Sink(dataArray); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66a.c:89
- 结论: 存在外部控制系统或配置设置漏洞（CWE-15）：服务端从网络socket接收数据后，未经充分验证便将其用于系统配置设置，攻击者可通过发送恶意数据控制系统配置，例如修改主机名、服务设置等。
- D验证: confirmed / ver_a48da21c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 41. hyp_path_3839c3213121

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67a.c:66
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够向目标主机的监听端口建立网络连接并发送数据
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67a.c:72-73; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67a.c:91; myStruct.structFirst = data; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67a.c:96; CWE15_External_Control_of_System_or_Configuration_Setting__w32_67b_case0Sink(myStruct); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67a.c:97
- 结论: 外部攻击者通过网络发送恶意数据，该数据被接收并直接用于系统配置设置，可导致未经授权的配置更改。
- D验证: confirmed / ver_92abfa04
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 42. hyp_path_658c77110f81

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68a.c:63
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够发送网络数据到受监听端口; 系统未对输入进行充分验证或过滤
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68a.c:63; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68a.c:88; CWE15_External_Control_of_System_or_Configuration_Setting__w32_68_case0Data = data; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68a.c:93; CWE15_External_Control_of_System_or_Configuration_Setting__w32_68b_case0Sink(); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68a.c:95
- 结论: 存在外部控制系统或配置设置的漏洞，攻击者可通过网络连接发送恶意数据，导致系统配置被篡改或命令执行。
- D验证: confirmed / ver_67e79161
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 43. hyp_path_6ab7f9b8f1c9

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62b.cpp:55
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到监听端口并发送恶意数据
- 触发路径: recvResult = recv(acceptSocket, data, 100 - 1, 0); @ CWE15_External_Control_of_System_or_Configuration_Setting__w32_62b.cpp:78-80; 假设data被用于系统配置设置函数如SetComputerName(data); @ 后续代码（未展示）
- 结论: 存在外部控制系统或配置设置的漏洞：通过recv从网络套接字接收数据，数据可能用于设置系统主机名或其他配置，攻击者可控制输入导致配置被篡改。
- D验证: confirmed / ver_7d64ff4b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 44. hyp_path_3f87fba7b980

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_43.cpp:57
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立TCP连接; 服务器在监听端口上接受连接; 攻击者发送的载荷长度不超过99字节; 服务器未对接收数据进行充分的验证或过滤; 假设接收的数据被用于影响系统配置的API
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_43.cpp:63-67; recvResult = recv(acceptSocket, data, 100 - 1, 0); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_43.cpp:80-84; 假设使用data进行系统配置，如SetComputerNameEx等 @ 假设的后续系统配置调用
- 结论: 程序从网络socket接收数据，并将该数据存储在缓冲区'data'中，但未显示后续使用。如果该数据被用于系统配置设置（如修改主机名、路由表等），则攻击者可通过网络输入恶意数据，导致系统配置被外部控制，造成CWE15漏洞。
- D验证: confirmed / ver_a023c230
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 45. hyp_path_b6a38a6e14b3

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74b.cpp:34
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制dataMap中索引2的条目，例如通过函数参数传递恶意数据。
- 触发路径: char * data = dataMap[2]; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74b.cpp:32; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74b.cpp:34
- 结论: 外部输入控制系统设置：攻击者可能通过控制dataMap中索引2的数据，传递给SetComputerNameA API，从而修改系统主机名，造成配置篡改或潜在的安全风险。
- D验证: confirmed / ver_0711a2b0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 46. hyp_path_bb2877e43c88

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_22a.c:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够提供或影响外部输入数据，例如通过网络请求、环境变量或用户输入等。
- 触发路径: data = CWE15_External_Control_of_System_or_Configuration_Setting__w32_22_case0Source(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_22a.c:34; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_22a.c:36
- 结论: 外部控制下的系统配置设置漏洞：攻击者通过控制外部输入的字符串，可调用SetComputerNameA函数设置系统计算机名，导致系统配置被篡改。
- D验证: confirmed / ver_01f15292
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 47. hyp_path_6ff2e882995d

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_61a.c:39
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制CWE15_External_Control_of_System_or_Configuration_Setting__w32_61b_case0Source的输出（该函数通常从外部不可信源获取数据）。
- 触发路径: data = CWE15_External_Control_of_System_or_Configuration_Setting__w32_61b_case0Source(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_61a.c:37; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_61a.c:39
- 结论: 外部控制的系统或配置设置漏洞：攻击者可以通过控制CWE15_External_Control_of_System_or_Configuration_Setting__w32_61b_case0Source返回的数据来设置系统计算机名，可能导致系统行为异常或拒绝服务。
- D验证: confirmed / ver_bbd17da5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 48. hyp_path_185875a9c9fa

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62a.cpp:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制case0Source函数获取数据的外部源（如环境变量、注册表、文件或网络输入）。
- 触发路径: char dataBuffer[100] = ""; data = dataBuffer; case0Source(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62a.cpp:32-36; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62a.cpp:36
- 结论: 代码使用case0Source获取潜在外部可控数据，并直接调用SetComputerNameA设置计算机名，可能导致外部控制系统配置。但case0Source实现未知，且B阶段静态分析未通过，风险评分低。
- D验证: confirmed / ver_825015b6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 49. hyp_path_1e9a007d16d9

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_72b.cpp:32
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够影响或控制dataVector中索引2的元素内容
- 触发路径: char * data = dataVector[2]; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_72b.cpp:32; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_72b.cpp:34
- 结论: 外部控制的系统配置设置：从数据向量中获取外部可控的数据，直接用于设置计算机名称，未进行有效验证或限制，攻击者可能通过控制该数据修改系统主机名，影响系统安全或稳定性。
- D验证: confirmed / ver_58ab7902
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 50. hyp_path_67f2b4e402bd

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73b.cpp:32
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够向dataList中注入恶意的计算机名字符串
- 触发路径: char * data = dataList.back(); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73b.cpp:32; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73b.cpp:34
- 结论: 外部控制的系统或配置设置漏洞：攻击者可以通过控制dataList中的数据（来自外部来源）来设置计算机名，从而影响系统配置。
- D验证: confirmed / ver_5f58c708
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 51. hyp_path_27140c1b298e

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_83_case0.cpp:108
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制外部输入来影响data变量的值
- 触发路径: if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_83_case0.cpp:108
- 结论: 外部控制的系统配置设置漏洞：攻击者可通过控制data参数设置任意计算机名称，导致系统配置被篡改。
- D验证: confirmed / ver_a7e7c865
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 52. hyp_path_0e404f093704

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_84_case0.cpp:108
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制变量data的值，使其来自外部来源（如网络、用户输入等）。
- 触发路径: if (!SetComputerNameA(data)) @ CWE15_External_Control_of_System_or_Configuration_Setting__w32_84_case0.cpp:108
- 结论: 外部控制的输入可能用于设置系统主机名，存在配置篡改风险。
- D验证: confirmed / ver_9b92cb91
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 53. hyp_path_6064c8c40891

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:32
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制data的值，例如通过注入恶意字符串或从外部接口获取
- 触发路径: if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_41.c:32
- 结论: 函数SetComputerNameA接收来自外部源的数据并设置计算机名，攻击者可能通过控制该数据修改系统配置，造成系统不稳定或安全控制绕过。由于缺乏明确的source路径和静态证据支持，该假设证据不完整。
- D验证: confirmed / ver_a5247f09
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 54. hyp_path_0432e177ded0

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_44.c:32
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制data参数，该参数来自外部源（如网络、文件等）
- 触发路径: void case0Sink(char * data) @ 29; if (!SetComputerNameA(data)) @ 32
- 结论: 外部可控的系统配置设置：SetComputerNameA使用来自潜在外部源的数据设置主机名，导致系统配置被外部控制。
- D验证: confirmed / ver_7202f806
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 55. hyp_path_9cbdd7fe5379

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制全局变量CWE15_External_Control_of_System_or_Configuration_Setting__w32_45_case0Data的值
- 触发路径: char * data = CWE15_External_Control_of_System_or_Configuration_Setting__w32_45_case0Data; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:34; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_45.c:36
- 结论: 函数case0Sink从全局变量获取数据，并直接作为参数调用SetComputerNameA，可能导致系统配置被外部控制，但全局变量的外部来源未在本代码片段中直接证明。
- D验证: confirmed / ver_4bd8e5df
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 56. hyp_path_7564cb3939a1

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51b.c:34
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制data变量的内容（例如通过命令行参数、环境变量或网络输入）。
- 触发路径: if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_51b.c:34
- 结论: 外部可控数据被传递给SetComputerNameA函数，用于设置计算机名，可能导致攻击者控制系统配置。
- D验证: confirmed / ver_37cb6057
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 57. hyp_path_7d5b28c07ad9

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52c.c:34
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制传递给`SetComputerNameA`的`data`参数的值
- 触发路径: if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52c.c:34
- 结论: 外部控制系统设置：攻击者可通过控制`data`参数调用`SetComputerNameA`设置系统主机名，存在配置篡改风险。
- D验证: confirmed / ver_92391236
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 58. hyp_path_78f336f8a5e1

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53d.c:34
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够提供或影响变量 data 的值。
- 触发路径: if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53d.c:34
- 结论: 函数 SetComputerNameA 使用来自外部源的数据设置计算机名称，攻击者可能通过控制输入修改系统主机名，导致系统配置被篡改，影响系统安全。
- D验证: confirmed / ver_c455c5f6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 59. hyp_path_29fefba3bde0

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54e.c:34
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够向变量data注入任意字符串，例如通过命令行参数、配置文件或网络数据。
- 触发路径: if (!SetComputerNameA(data)) { @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54e.c:34
- 结论: 外部可控制的输入被直接传递给SetComputerNameA函数，可能导致系统配置被未授权修改（CWE-15）。
- D验证: confirmed / ver_80584186
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 60. hyp_path_58cd230283dd

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_63b.c:33
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制dataPtr指向的数据内容（外部输入）。
- 触发路径: char * data = *dataPtr; @ L29; if (!SetComputerNameA(data)) { ... } @ L33
- 结论: 代码中外部可控数据通过SetComputerNameA修改计算机名，存在CWE-15外部控制系统或配置设置漏洞。
- D验证: confirmed / ver_aaacefe0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 61. hyp_path_7a542cb8f496

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_65b.c:32
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制data的值，但当前代码未证明data来自外部输入。
- 触发路径: if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_65b.c:30-32
- 结论: 外部可控数据可能传递给SetComputerNameA函数，但证据不完整，需动态验证数据来源。
- D验证: confirmed / ver_02cb5285
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 62. hyp_path_e6bac85f491c

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64b.c:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制输入参数dataPtr指向的数据
- 触发路径: char * data = (*dataPtr); /* NOTE: set the hostname to data obtained from a potentially external source */ @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64b.c:34; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_64b.c:36
- 结论: 外部控制的系统配置设置：SetComputerNameA函数使用来自外部源的数据设置计算机名，可能导致系统配置被恶意篡改。
- D验证: confirmed / ver_a88f9e24
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 63. hyp_path_9c098d105ad6

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67b.c:38
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制输入到myStruct.structFirst的数据
- 触发路径: char * data = myStruct.structFirst; /* NOTE: set the hostname to data obtained from a potentially external source */ @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67b.c:36; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_67b.c:38
- 结论: 外部数据控制系统配置：SetComputerNameA函数使用来自外部源的数据，攻击者可设置任意主机名，导致系统配置被恶意控制。
- D验证: confirmed / ver_aed09acc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 64. hyp_path_238699845ab6

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66b.c:34
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制dataArray[2]的内容，例如通过网络输入或环境变量。
- 触发路径: char * data = dataArray[2]; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66b.c:32; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_66b.c:34
- 结论: 程序从外部源获取数据并直接用于设置系统主机名（SetComputerNameA），攻击者可控制该数据修改系统配置，导致外部控制系统设置漏洞。
- D验证: confirmed / ver_87bfcbdb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 65. hyp_path_5df2232d3505

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68b.c:38
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够直接或间接控制CWE15_External_Control_of_System_or_Configuration_Setting__w32_68_case0Data的值
- 触发路径: char * data = CWE15_External_Control_of_System_or_Configuration_Setting__w32_68_case0Data; @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68b.c:36; if (!SetComputerNameA(data)) @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_68b.c:38
- 结论: 外部可控的字符串直接传递给SetComputerNameA函数，可能导致攻击者控制系统配置（计算机名），但当前代码片段未展示data的来源，无法确认外部可控性。
- D验证: confirmed / ver_42ea23ba
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 66. hyp_path_13a4cc57db89

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_81_case0.cpp:29
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制data变量的来源，例如通过环境变量、命令行参数或网络输入。
- 触发路径: if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_81_case0.cpp:27-31
- 结论: 程序使用来自外部源的数据直接设置计算机名称（SetComputerNameA），而未进行充分验证，攻击者可能通过控制输入修改系统配置，导致安全风险。
- D验证: confirmed / ver_73cec513
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 67. hyp_path_76ddc67985b8

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_82_case0.cpp:29
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制`data`参数的值。; 程序进程具有管理员权限（否则SetComputerNameA失败）。
- 触发路径: /* NOTE: set the hostname to data obtained from a potentially external source */ if (!SetComputerNameA(data)) { printLine("Failure setting computer name"); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_82_case0.cpp:27-31
- 结论: 外部控制可导致系统配置被篡改，攻击者通过控制`data`参数可设置任意计算机名，可能引发命名冲突或服务依赖问题。
- D验证: confirmed / ver_09d2aa61
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 68. hyp_path_b65d76f6e3a1

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53c.c:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制char * data参数（但source端未提供，无法确认可控性）
- 触发路径: void CWE15_External_Control_of_System_or_Configuration_Setting__w32_53c_case0Sink(char * data) { CWE15_External_Control_of_System_or_Configuration_Setting__w32_53d_case0Sink(data); } @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_53c.c:34-38
- 结论: 可能存在外部控制系统或配置设置漏洞（CWE-15），但缺少source端代码，无法确认完整的攻击路径。
- D验证: confirmed / ver_ae6f81a2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 69. hyp_path_92d9cb69f2dc

- 漏洞位置: juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54b.c:36
- 漏洞类型: CWE-15
- CWE: CWE-15
- 风险等级: P0
- 触发条件: 攻击者能够控制data参数的内容
- 触发路径: CWE15_External_Control_of_System_or_Configuration_Setting__w32_54c_case0Sink(data); @ juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_54b.c:36
- 结论: 函数CWE15_External_Control_of_System_or_Configuration_Setting__w32_54b_case0Sink将外部数据data直接传递给后续函数，可能导致外部控制系统或配置设置（CWE-15），但当前代码片段仅展示中间转发，未包含数据来源（source）和最终配置操作（sink），路径不完整。
- D验证: confirmed / ver_2350863b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

## Unconfirmed / Failed Verification

These records are not reported as confirmed vulnerabilities. See `verification.failed.jsonl` for full failure details.

- hyp_path_fa45cf1f9a43 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_74b.cpp:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_54535d20636e | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_42.c:136 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3975651f289c | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_22a.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_272274d19ac7 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_22a.c:62 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a972fe350c09 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_61a.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_95221accf7c0 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62a.cpp:57 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_566fa029149e | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_72b.cpp:48 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_374f509a4896 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_73b.cpp:48 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_45430962b7d6 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_32.c:135 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_16b13a451010 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_83_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0548e11301a6 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_84_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
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
- hyp_path_2f1b4f1c6049 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_52b.c:49 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_91de31516608 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_61a.c:69 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b82ff82a3be4 | juliet-api-misuse/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__w32_62a.cpp:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
