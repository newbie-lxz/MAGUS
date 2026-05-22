# MAGUS Final Vulnerability Report

- generated_at: 2026-05-22T05:47:53Z
- confirmed_vulnerabilities: 18
- failed_verifications: 22
- source_confirmed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/verification.jsonl
- source_failed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/verification.failed.jsonl

## Confirmed Vulnerabilities

### 1. hyp_path_bca92ea16c82

- 漏洞位置: juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_08.c:69
- 漏洞类型: CWE-247
- CWE: CWE-247
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立网络连接; 攻击者能够控制反向DNS查询结果（例如通过DNS欺骗或篡改DNS记录）
- 触发路径: client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_08.c:69; hostInfo = gethostbyaddr((char*)&serviceClient.sin_addr, sizeof(serviceClient.sin_addr), AF_INET); // 根据API种子推测 @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_08.c:86-87（推测调用gethostbyaddr，但具体行号未在证据中明确显示）; if (strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) { printLine("Access granted."); } @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_08.c:86-87（strcmp使用hostInfo->h_name）
- 结论: 依赖DNS反向查找结果进行安全决策，存在DNS欺骗风险，攻击者可能通过控制DNS记录绕过授权检查。
- D验证: confirmed / ver_75595aaf
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 2. hyp_path_cc8b324e826b

- 漏洞位置: juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_12.c:56
- 漏洞类型: CWE-247
- CWE: CWE-247
- 风险等级: P0
- 触发条件: 攻击者能够使客户端IP地址的反向DNS解析指向一个他可以控制的主机名，该主机名与SECRET_HOSTNAME一致。; 攻击者能够通过网络连接到监听的服务端口。
- 触发路径: client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_12.c:63-67; hostInfo = gethostbyaddr((char*)&serviceClient.sin_addr, sizeof(serviceClient.sin_addr), AF_INET); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_12.c:75-76; if (strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) { printLine("Access granted."); // 后续操作 } @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_12.c:79-80
- 结论: 存在安全漏洞：程序使用gethostbyaddr()获取客户端反向DNS名称，并将其与硬编码的'SECRET_HOSTNAME'比较以决定是否授予访问权限。攻击者可以控制DNS响应，使解析出的主机名与预期值匹配，从而绕过认证。
- D验证: confirmed / ver_6c2506fb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 3. hyp_path_876b4ea55367

- 漏洞位置: juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_11.c:56
- 漏洞类型: CWE-247
- CWE: CWE-247
- 风险等级: P0
- 触发条件: 攻击者能够发起网络连接到服务器监听端口。; 攻击者可以控制其IP地址的反向DNS解析结果。
- 触发路径: client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_11.c:56; hostInfo = gethostbyaddr((char*)&serviceClient.sin_addr, sizeof(serviceClient.sin_addr), AF_INET); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_11.c:86; if (strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) { printLine("Access granted."); ... } @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_11.c:92
- 结论: 服务器通过反向DNS查找客户端主机名并与硬编码的SECRET_HOSTNAME比较来决定是否授予访问权限，攻击者可以控制DNS解析结果从而绕过安全检查。
- D验证: confirmed / ver_839c4be9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 4. hyp_path_f9cec004c26f

- 漏洞位置: juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_17.c:48
- 漏洞类型: CWE-247
- CWE: CWE-247
- 风险等级: P0
- 触发条件: 攻击者能够发起网络连接，并控制其IP地址或DNS响应，使得gethostbyaddr返回SECRET_HOSTNAME对应的主机名。
- 触发路径: serviceClientLen = sizeof(serviceClient); client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_17.c:65-67; /* NOTE: Using the reverse DNS of the client to determine whether to allow the connection */ hostInfo = gethostbyaddr((char*)&serviceClient.sin_addr, sizeof(serviceClient.sin_addr), AF_INET); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_17.c:48（注释附近，实际调用gethostbyaddr位置未精确给出但存在）; if (strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) { printLine("Access granted."); } @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_17.c:48（注释附近）
- 结论: 代码依赖DNS反向查找结果（hostInfo->h_name）与硬编码的SECRET_HOSTNAME比较，决定是否授予访问权限。攻击者可能通过DNS欺骗操纵反向查找结果，绕过访问控制。
- D验证: confirmed / ver_1a9f7cf8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 5. hyp_path_1c0fd2d2120a

- 漏洞位置: juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_02.c:56
- 漏洞类型: CWE-247
- CWE: CWE-247
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立网络连接（通过TCP连接）。; 攻击者能够控制或影响其IP地址的反向DNS解析结果。
- 触发路径: client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_02.c:56; hostInfo = gethostbyaddr((char*)&serviceClient.sin_addr.s_addr, sizeof(serviceClient.sin_addr.s_addr), AF_INET); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_02.c:63; if (strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) { printLine("Access granted."); } @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_02.c:67
- 结论: 应用程序依赖反向DNS查找（gethostbyaddr）来做安全决策，攻击者可能通过DNS欺骗绕过访问控制。
- D验证: confirmed / ver_3f57d2fe
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 6. hyp_path_b3c79792ab10

- 漏洞位置: juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_01.c:54
- 漏洞类型: CWE-247
- CWE: CWE-247
- 风险等级: P0
- 触发条件: 攻击者能够使反向DNS查询返回与SECRET_HOSTNAME匹配的主机名。; 攻击者能够连接至服务器监听的端口。
- 触发路径: client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_01.c:62; hostInfo = gethostbyaddr((char*)&serviceClient.sin_addr.s_addr, sizeof(serviceClient.sin_addr), AF_INET); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_01.c:71; if (strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) { printLine("Access granted."); } @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_01.c:86
- 结论: 服务器使用不可信的反向DNS查找结果进行安全决策，攻击者可通过控制DNS解析绕过授权。
- D验证: confirmed / ver_4316bbb2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 7. hyp_path_61d115a19560

- 漏洞位置: juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_03.c:56
- 漏洞类型: CWE-247
- CWE: CWE-247
- 风险等级: P0
- 触发条件: 攻击者能够发起网络连接，并控制其所用IP的反向DNS记录
- 触发路径: client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_03.c:56; hostInfo = gethostbyaddr((char*)&serviceClient.sin_addr.s_addr, sizeof(serviceClient.sin_addr.s_addr), AF_INET); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_03.c:92; if (strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) { printLine("Access granted."); } @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_03.c:100
- 结论: 依赖反向DNS查找进行安全决策，攻击者可通过DNS欺骗绕过授权检查
- D验证: confirmed / ver_412a61dc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 8. hyp_path_d1cfc7d55486

- 漏洞位置: juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_04.c:62
- 漏洞类型: CWE-247
- CWE: CWE-247
- 风险等级: P0
- 触发条件: 攻击者能够发起网络连接; 攻击者能够控制客户端IP的反向DNS解析结果
- 触发路径: client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_04.c:62; hostInfo = gethostbyaddr((char*)&(serviceClient.sin_addr), sizeof(serviceClient.sin_addr), AF_INET); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_04.c:69-73; if (strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) { printLine("Access granted."); } @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_04.c:98
- 结论: 代码依赖DNS反向查找结果进行安全授权决策，攻击者可欺骗DNS记录绕过访问控制，存在CWE-247漏洞。
- D验证: confirmed / ver_c997c482
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 9. hyp_path_be6c28935ce6

- 漏洞位置: juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_05.c:62
- 漏洞类型: CWE-247
- CWE: CWE-247
- 风险等级: P0
- 触发条件: 攻击者能够控制受害主机所依赖的DNS服务器或中间网络，使得对攻击者IP的反向DNS查询返回SECRET_HOSTNAME。; 攻击者能够与服务器建立TCP连接（服务器监听LISTEN_PORT）。
- 触发路径: client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_05.c:62; hostInfo = gethostbyaddr((char*)&serviceClient.sin_addr.s_addr, sizeof(serviceClient.sin_addr.s_addr), AF_INET); if (hostInfo == NULL) { ... } @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_05.c:88-94; if (strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) { printLine("Access granted."); } @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_05.c:98-102
- 结论: 存在安全漏洞：程序依赖于DNS反向查找结果进行安全决策（CWE-247）。攻击者可以通过欺骗DNS响应，使gethostbyaddr返回伪造的主机名，从而绕过访问控制，获得未授权访问。
- D验证: confirmed / ver_ce5e33be
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 10. hyp_path_960ac86069df

- 漏洞位置: juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_06.c:61
- 漏洞类型: CWE-247
- CWE: CWE-247
- 风险等级: P0
- 触发条件: 攻击者能够控制客户端IP地址的反向DNS记录; 攻击者可以连接到服务器的监听端口
- 触发路径: client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen); @ line 68-72; hostInfo = gethostbyaddr((char*)&serviceClient.sin_addr.s_addr, 4, AF_INET); @ line 85-87; if (strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) { printLine("Access granted."); } @ line 97-98
- 结论: 依赖DNS反向查询进行安全决策（CWE-247）：服务器使用gethostbyaddr()获取客户端主机名，并与硬编码的SECRET_HOSTNAME比较来决定是否授权访问。攻击者可以通过DNS欺骗或控制其DNS服务器，使反向DNS查询返回欺骗的主机名，从而绕过访问控制。
- D验证: confirmed / ver_5233ba50
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 11. hyp_path_0eec7db41d12

- 漏洞位置: juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_07.c:61
- 漏洞类型: CWE-247
- CWE: CWE-247
- 风险等级: P0
- 触发条件: 攻击者能够控制DNS反向查找结果; 攻击者能够发起网络连接到监听端口
- 触发路径: client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen); if (client == INVALID_SOCKET) { break; } @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_07.c:69-72; hostInfo = gethostbyaddr( ... ); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_07.c:80-81; if (strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) { printLine("Access granted."); } @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_07.c:97-101
- 结论: 依赖DNS反向查找进行安全决策，攻击者可以通过DNS欺骗绕过访问控制
- D验证: confirmed / ver_3bec7980
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 12. hyp_path_5955ece8f0c8

- 漏洞位置: juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_09.c:56
- 漏洞类型: CWE-247
- CWE: CWE-247
- 风险等级: P0
- 触发条件: 攻击者能够发起网络连接到服务器监听端口; 攻击者控制其IP地址的反向DNS记录，或能够进行DNS欺骗
- 触发路径: client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_09.c:56; hostInfo = gethostbyaddr((char*)&serviceClient.sin_addr, sizeof(serviceClient.sin_addr), AF_INET); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_09.c:84; if (strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) { printLine("Access granted."); } @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_09.c:88-90
- 结论: 服务器使用反向DNS查找（gethostbyaddr）获取客户端主机名，并与硬编码的SECRET_HOSTNAME比较以决定访问权限。攻击者可能通过DNS欺骗或控制反向DNS记录绕过认证，导致未经授权的访问。
- D验证: confirmed / ver_d3fd4e7d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 13. hyp_path_9273ef8b06b7

- 漏洞位置: juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_13.c:56
- 漏洞类型: CWE-247
- CWE: CWE-247
- 风险等级: P0
- 触发条件: 攻击者能够发起网络连接到目标监听端口; 攻击者能够控制客户端IP的反向DNS解析结果（例如通过DNS缓存投毒或控制反向DNS服务器）
- 触发路径: service.sin_addr.s_addr = INADDR_ANY; service.sin_port = htons(LISTEN_PORT); if (SOCKET_ERROR == bind(listenSocket, (struct sockaddr*)&service, sizeof(service))) { break; } @ L54-58; client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen); @ L63-67; hostInfo = gethostbyaddr((char*)&serviceClient.sin_addr, sizeof(serviceClient.sin_addr), AF_INET); @ L? (gethostbyaddr调用，推测在L70附近); if (strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) { printLine("Access granted."); } @ L? (strcmp比较，推测在L72附近)
- 结论: 该程序依赖反向DNS查询（gethostbyaddr）的结果来进行安全授权决策，攻击者可能通过DNS欺骗或控制DNS服务器使反向解析返回恶意主机名，从而绕过访问控制。
- D验证: confirmed / ver_e92c8793
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 14. hyp_path_b2f41606f926

- 漏洞位置: juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_10.c:56
- 漏洞类型: CWE-247
- CWE: CWE-247
- 风险等级: P0
- 触发条件: 攻击者能够发起网络连接，并能够控制该连接的反向DNS解析结果（例如通过DNS缓存投毒、操纵权威DNS服务器或本地hosts文件）。
- 触发路径: client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_10.c:56; hostInfo = gethostbyaddr((char*)&serviceClient.sin_addr, sizeof(serviceClient.sin_addr), AF_INET); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_10.c:约70-80行; if (strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) { printLine("Access granted."); } @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_10.c:约92行
- 结论: 依赖DNS查找进行安全决策，攻击者可能通过DNS欺骗（如修改DNS记录或中间人攻击）使反向DNS返回可控主机名，从而绕过访问控制。
- D验证: confirmed / ver_1bbe0cca
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 15. hyp_path_8000aae44b0d

- 漏洞位置: juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_15.c:57
- 漏洞类型: CWE-247
- CWE: CWE-247
- 风险等级: P0
- 触发条件: 攻击者能够使目标客户端IP的反向DNS记录被设置为与SECRET_HOSTNAME相同的主机名。; 服务器可被攻击者访问（即能够建立TCP连接）。
- 触发路径: client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen); @ CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_15.c:64; hostInfo = gethostbyaddr((const char*)&serviceClient.sin_addr.s_addr, sizeof(serviceClient.sin_addr.s_addr), AF_INET); @ CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_15.c:72; if (strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) { printLine("Access granted."); } @ CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_15.c:81
- 结论: 服务器通过反向DNS查找（gethostbyaddr）获取客户端主机名，并与硬编码的SECRET_HOSTNAME比较以决定是否授权访问。攻击者可以操纵DNS响应，使得反向查找返回任意主机名，从而绕过授权检查。
- D验证: confirmed / ver_8b05d305
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 16. hyp_path_115612e9492b

- 漏洞位置: juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_14.c:56
- 漏洞类型: CWE-247
- CWE: CWE-247
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立网络连接，即能够连接并触发accept。; 攻击者能够控制其IP地址的反向DNS解析结果，使其指向SECRET_HOSTNAME。通常需要DNS Poisoning或控制反向DNS区域。
- 触发路径: client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_14.c:63-67; hostInfo = gethostbyaddr((char*)&serviceClient.sin_addr, sizeof(serviceClient.sin_addr), AF_INET); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_14.c:84-86; if (strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) { printLine("Access granted."); } @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_14.c:92-93
- 结论: 该代码示例依赖反向DNS查找（gethostbyaddr）的结果进行安全决策，存在CWE-247漏洞。攻击者可以通过控制客户端IP的反向DNS记录或DNS欺骗，使hostInfo->h_name等于硬编码的SECRET_HOSTNAME，从而绕过访问控制，获得授权。
- D验证: confirmed / ver_75b640ee
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 17. hyp_path_6c2916aac64a

- 漏洞位置: juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_16.c:56
- 漏洞类型: CWE-247
- CWE: CWE-247
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接向服务器发起连接，并控制自身IP的反向DNS记录使其解析为预期的SECRET_HOSTNAME。
- 触发路径: client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_16.c:63-67; hostInfo = gethostbyaddr((char*)&serviceClient.sin_addr, 4, AF_INET); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_16.c:56 (附近); if (strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) { printLine("Access granted."); } @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_16.c:56 (附近)
- 结论: 使用反向DNS查询结果进行安全决策，攻击者可通过控制DNS反向解析记录绕过授权检查。
- D验证: confirmed / ver_8ff303d5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 18. hyp_path_8219a0b836e5

- 漏洞位置: juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_18.c:56
- 漏洞类型: CWE-247
- CWE: CWE-247
- 风险等级: P0
- 触发条件: 攻击者能够连接到服务器的监听端口，并能控制其IP地址的反向DNS记录，或进行DNS欺骗。
- 触发路径: client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_18.c:56; serviceClientLen = sizeof(serviceClient); client = accept(listenSocket, (struct sockaddr*)&serviceClient, &serviceClientLen); if (client == INVALID_SOCKET) { break;} @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_18.c:63-67; hostInfo = gethostbyaddr((char*)&serviceClient.sin_addr.s_addr, sizeof(serviceClient.sin_addr.s_addr), AF_INET); @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_18.c:86-92; if (strcmp(hostInfo->h_name, SECRET_HOSTNAME) == 0) { printLine("Access granted."); } @ juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_18.c:96-100
- 结论: 依赖DNS查找进行安全决策：服务器通过反向DNS查询客户端主机名并与硬编码的机密主机名比较来授权访问。攻击者可通过控制反向DNS记录或DNS欺骗绕过授权。
- D验证: confirmed / ver_306b939d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

## Unconfirmed / Failed Verification

These records are not reported as confirmed vulnerabilities. See `verification.failed.jsonl` for full failure details.

- hyp_path_baffad176b56 | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_08.c:242 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_65c5d6b408f2 | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_05.c:154 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fe3decb79db5 | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_06.c:153 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_804a8ef7ea52 | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_06.c:234 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_787c3590bd82 | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_02.c:281 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d5f4d644a901 | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_16.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9c25731502c9 | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_15.c:154 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_82334f587f34 | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_04.c:287 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_85ba74507490 | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_03.c:282 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_218dcdfd78ab | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_05.c:288 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_79799b588fc4 | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_09.c:281 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bb71cd312d0c | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_06.c:287 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8129275ff53d | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_10.c:281 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a83ad68b3ed9 | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_11.c:281 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2f8a51efa3e3 | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_14.c:281 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_86f5ec3b453f | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_13.c:282 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_150c95c0be9a | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_15.c:295 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_831f9f55b0e8 | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_16.c:197 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4aac7423591a | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_12.c:347 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8f17f0befab8 | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_01.c:188 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1de24ad255a9 | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_17.c:197 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e6be74b9098f | juliet-api-misuse/testcases/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision/CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_18.c:193 | NOT_EXPLOITABLE | payload did not satisfy oracle
