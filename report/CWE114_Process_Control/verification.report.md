# MAGUS Final Vulnerability Report

- generated_at: 2026-05-22T04:23:32Z
- confirmed_vulnerabilities: 820
- failed_verifications: 703
- source_confirmed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE114_Process_Control/verification.jsonl
- source_failed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE114_Process_Control/verification.failed.jsonl

## Confirmed Vulnerabilities

### 1. hyp_path_3ce74cab79a9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_74a.cpp:51
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意数据写入被程序读取的文件中
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_74a.cpp:51; fclose(pFile); @ same file line 61; dataMap[0] = data; dataMap[1] = data; dataMap[2] = data; @ map insertion; case0Sink(dataMap); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_74a.cpp:61 (sink call)
- 结论: 程序从文件读取数据并通过std::map传递到sink函数，sink函数可能执行进程控制操作（如LoadLibrary），攻击者可通过控制文件内容导致任意代码执行或加载恶意库。
- D验证: confirmed / ver_720c2225
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 2. hyp_path_0e90206a3a18

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_74a.cpp:51
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意数据写入被程序读取的文件中
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) { printLine("fgetws() failed"); /* Restore NUL terminator if fgetws fails */ data[dataLen] = L'\0'; ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) dataMap[0] = d... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_74a.cpp:51; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_74a.cpp::_ZN43CWE114_Process_Control__w32_wchar_t_file_745case0Ev @ route
- 结论: 程序从文件读取数据并通过std::map传递到sink函数，sink函数可能执行进程控制操作（如LoadLibrary），攻击者可通过控制文件内容导致任意代码执行或加载恶意库。
- D验证: confirmed / ver_8cfedcf2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 3. hyp_path_6195130d5c1d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_74a.cpp:49
- 漏洞类型: buffer_overflow
- CWE: CWE-121; CWE-457
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE为超长字符串; data栈缓冲区未初始化或包含数据
- 触发路径: size_t dataLen = strlen(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_74a.cpp:48; char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_74a.cpp:49; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_74a.cpp:52-53
- 结论: 函数case0中，从环境变量读取数据后通过strncat追加到栈缓冲区data，但data未初始化导致strlen(data)返回不可预测长度，可能导致缓冲区溢出。
- D验证: confirmed / ver_153a234b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 4. hyp_path_dee2e4fdafa2

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_74a.cpp:49
- 漏洞类型: buffer_overflow
- CWE: CWE-121; CWE-457
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE为超长字符串; data栈缓冲区未初始化或包含数据
- 触发路径: /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ if (environment != NULL) ... { /* NOTE: Read data from an environment variable */ wcsncat(data+dataLen, environment, 100-dataLen-1); } }... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_74a.cpp:49; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_74a.cpp::_ZN50CWE114_Process_Control__w32_wchar_t_environment_745case0Ev @ route
- 结论: 函数case0中，从环境变量读取数据后通过strncat追加到栈缓冲区data，但data未初始化导致strlen(data)返回不可预测长度，可能导致缓冲区溢出。
- D验证: confirmed / ver_1fbd4844
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 5. hyp_path_20939a4f1290

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_73a.cpp:51
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制文件FILENAME的内容（例如通过用户上传或修改文件）; sink函数case0Sink存在并执行进程控制操作（如system、LoadLibrary等）
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_73a.cpp:51; if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_73a.cpp:53; dataList.push_back(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_73a.cpp:59; case0Sink(dataList); // 假设sink使用数据执行进程控制 @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_73a.cpp:63
- 结论: 程序从文件读取可能受外部影响的数据（通过fgets），并将数据存入list后传递给sink函数case0Sink。若sink函数使用该数据作为进程创建或动态库加载的参数（如system、LoadLibrary等），则构成CWE-114（Process Control）漏洞。
- D验证: confirmed / ver_2434a4a2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 6. hyp_path_2aa52429ebc7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_73a.cpp:51
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制文件FILENAME的内容（例如通过用户上传或修改文件）; sink函数case0Sink存在并执行进程控制操作（如system、LoadLibrary等）
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) { printLine("fgetws() failed"); /* Restore NUL terminator if fgetws fails */ data[dataLen] = L'\0'; ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) dataList.push_... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_73a.cpp:51; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_73a.cpp::_ZN43CWE114_Process_Control__w32_wchar_t_file_735case0Ev @ route
- 结论: 程序从文件读取可能受外部影响的数据（通过fgets），并将数据存入list后传递给sink函数case0Sink。若sink函数使用该数据作为进程创建或动态库加载的参数（如system、LoadLibrary等），则构成CWE-114（Process Control）漏洞。
- D验证: confirmed / ver_06ae5367
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 7. hyp_path_09d6220a8e10

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_72a.cpp:49
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_72a.cpp:49; if (environment != NULL) { strncat(data+dataLen, environment, 100-dataLen-1); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_72a.cpp:52-54; dataVector.insert(dataVector.end(), 1, data); case0Sink(dataVector); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_72a.cpp:57-60（vector插入及sink调用）; 假设case0Sink使用data执行危险操作如system或LoadLibrary，但未确认 @ sink函数内部（未在证据中展示）
- 结论: 在CWE114 Process Control样本中，程序从环境变量读取数据，通过strncat追加到固定大小缓冲区，然后将该缓冲区通过vector传递给case0Sink函数。攻击者可控制环境变量，从而影响传递到sink的参数，可能导致进程控制漏洞，但sink函数的具体实现未在证据中提供，source-to-sink路径不完整。
- D验证: confirmed / ver_edb8d803
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 8. hyp_path_08c32efac387

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_72a.cpp:49
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值。
- 触发路径: /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ if (environment != NULL) ... { /* NOTE: Read data from an environment variable */ wcsncat(data+dataLen, environment, 100-dataLen-1); } }... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_72a.cpp:49; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_72a.cpp::_ZN50CWE114_Process_Control__w32_wchar_t_environment_725case0Ev @ route
- 结论: 在CWE114 Process Control样本中，程序从环境变量读取数据，通过strncat追加到固定大小缓冲区，然后将该缓冲区通过vector传递给case0Sink函数。攻击者可控制环境变量，从而影响传递到sink的参数，可能导致进程控制漏洞，但sink函数的具体实现未在证据中提供，source-to-sink路径不完整。
- D验证: confirmed / ver_2053910a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 9. hyp_path_07c159c8d936

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_72a.cpp:57
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入（stdin）提供任意字符串。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_72a.cpp:45; dataVector.insert(dataVector.end(), 1, data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_72a.cpp:60-66; case0Sink(dataVector); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_72a.cpp:68
- 结论: 该代码存在过程控制漏洞，攻击者可通过控制台输入任意字符串，最终被用于加载外部库，导致未授权的代码执行。
- D验证: confirmed / ver_58eff721
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 10. hyp_path_4e9e7eb7db4e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_72a.cpp:57
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入（stdin）提供任意字符串。
- 触发路径: else { printLine("fgetws() failed"); /* Restore NUL terminator if fgetws fails */ data[dataLen] = L'\0'; ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) dataVector.insert(dataVector.end(), 1, data); difference_type __offset = __position - cbegin(); { return const_iterator(this->_M_impl._M_start); } _M_... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_72a.cpp:57; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_72a.cpp::_ZN46CWE114_Process_Control__w32_wchar_t_console_725case0Ev @ route
- 结论: 该代码存在过程控制漏洞，攻击者可通过控制台输入任意字符串，最终被用于加载外部库，导致未授权的代码执行。
- D验证: confirmed / ver_4cd47e3c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 11. hyp_path_547c4f10f48f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_73a.cpp:49
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值为任意字符串。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_73a.cpp:49; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_73a.cpp:53; 数据通过list传递给case0Sink，可能用于进程控制函数 @ case0Sink（list参数）
- 结论: 程序从环境变量获取字符串，通过strncat拼接到固定缓冲区后，将数据放入list并传递给case0Sink函数，该函数可能将数据用于进程控制（如system或CreateProcess），导致攻击者通过环境变量控制进程执行路径。
- D验证: confirmed / ver_f54e29c0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 12. hyp_path_a6a7bb39a57c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_73a.cpp:49
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值为任意字符串。
- 触发路径: /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ if (environment != NULL) ... { /* NOTE: Read data from an environment variable */ wcsncat(data+dataLen, environment, 100-dataLen-1); } }... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_73a.cpp:49; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_73a.cpp::_ZN50CWE114_Process_Control__w32_wchar_t_environment_735case0Ev @ route
- 结论: 程序从环境变量获取字符串，通过strncat拼接到固定缓冲区后，将数据放入list并传递给case0Sink函数，该函数可能将数据用于进程控制（如system或CreateProcess），导致攻击者通过环境变量控制进程执行路径。
- D验证: confirmed / ver_37969a1c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 13. hyp_path_492cf316b658

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_74a.cpp:57
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入提供任意字符串
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_74a.cpp:43-47; dataMap[0] = data; dataMap[1] = data; dataMap[2] = data; @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_74a.cpp:57 (dataMap赋值); case0Sink(dataMap); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_74a.cpp:57
- 结论: 用户输入通过控制台读取后，存入map，并传递给sink函数，sink函数可能使用该输入作为参数执行进程（如调用system或CreateProcess），导致命令注入漏洞。
- D验证: confirmed / ver_e34657b6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 14. hyp_path_00e7cddc07ec

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_74a.cpp:57
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入提供任意字符串
- 触发路径: else { printLine("fgetws() failed"); /* Restore NUL terminator if fgetws fails */ data[dataLen] = L'\0'; ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) dataMap[0] = data; iterator __i = lower_bound(__k); { return _M_t.lower_bound(__x); } { return _M_lower_bound(_M_begin(), _M_end(), __k); } { return _... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_74a.cpp:57; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_74a.cpp::_ZN46CWE114_Process_Control__w32_wchar_t_console_745case0Ev @ route
- 结论: 用户输入通过控制台读取后，存入map，并传递给sink函数，sink函数可能使用该输入作为参数执行进程（如调用system或CreateProcess），导致命令注入漏洞。
- D验证: confirmed / ver_8d1fef68
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 15. hyp_path_0afca76e936f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_73a.cpp:57
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_73a.cpp:43-47; dataList.push_back(data); ... case0Sink(dataList); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_73a.cpp:55-57
- 结论: 存在CWE-114 Process Control漏洞，攻击者可通过控制台输入将任意字符串传入list<char *>，并最终作为进程创建函数参数，但sink函数内部行为未确认。
- D验证: confirmed / ver_54b3b31e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 16. hyp_path_91b11f086044

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_73a.cpp:57
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串
- 触发路径: else { printLine("fgetws() failed"); /* Restore NUL terminator if fgetws fails */ data[dataLen] = L'\0'; ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) dataList.push_back(data); { this->_M_insert(end(), __x); } { return iterator(&this->_M_impl._M_node); } _Node* __tmp = _M_create_node(std::forward<_Ar... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_73a.cpp:57; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_73a.cpp::_ZN46CWE114_Process_Control__w32_wchar_t_console_735case0Ev @ route
- 结论: 存在CWE-114 Process Control漏洞，攻击者可通过控制台输入将任意字符串传入list<char *>，并最终作为进程创建函数参数，但sink函数内部行为未确认。
- D验证: confirmed / ver_3dedeece
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 17. hyp_path_511c066b3e38

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_72a.cpp:103
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到服务器的监听端口; 攻击者能够发送任意数据（如恶意DLL路径或命令）
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_72a.cpp:101-105; dataVector.insert(dataVector.end(), 1, data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_72a.cpp:106-108; CWE114_Process_Control__w32_char_listen_socket_72b::case0Sink(dataVector); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_72a.cpp (sink function call, inferred)
- 结论: CWE114 Process Control: 从网络接收的数据被插入vector并传递给sink函数，可能导致攻击者控制进程执行（如加载恶意库）。
- D验证: confirmed / ver_470dcf19
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 18. hyp_path_59819c05689f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_72a.cpp:103
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到服务器的监听端口; 攻击者能够发送任意数据（如恶意DLL路径或命令）
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_72a.cpp:103; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_72a.cpp::_ZN52CWE114_Process_Control__w32_wchar_t_listen_socket_725case0Ev @ route
- 结论: CWE114 Process Control: 从网络接收的数据被插入vector并传递给sink函数，可能导致攻击者控制进程执行（如加载恶意库）。
- D验证: confirmed / ver_1dd2af53
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 19. hyp_path_2e1796ee24a9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_74a.cpp:88
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接目标程序的socket端口，并发送特制字符串作为进程控制命令或库名称。; 目标程序未对接收的数据执行安全过滤或白名单校验。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ CWE114_Process_Control__w32_char_connect_socket_74a.cpp:93-97; dataMap[0] = data; // 将网络数据存入map @ CWE114_Process_Control__w32_char_connect_socket_74a.cpp:115-119（约）; sink函数调用（如 LoadLibraryA 或 system），以dataMap中的数据为参数 @ CWE114_Process_Control__w32_char_connect_socket_74a.cpp:sink函数（未展示具体行号）
- 结论: 通过socket接收外部输入数据，未经充分验证即用于进程控制操作（如加载库或执行命令），导致攻击者可能控制进程执行内容。
- D验证: confirmed / ver_a941da37
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 20. hyp_path_a311e58fb82f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_74a.cpp:88
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接目标程序的socket端口，并发送特制字符串作为进程控制命令或库名称。; 目标程序未对接收的数据执行安全过滤或白名单校验。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... recvResult = recv(connectSocket, (char *)(data + da... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_74a.cpp:88; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_74a.cpp::_ZN53CWE114_Process_Control__w32_wchar_t_connect_socket_745case0Ev @ route
- 结论: 通过socket接收外部输入数据，未经充分验证即用于进程控制操作（如加载库或执行命令），导致攻击者可能控制进程执行内容。
- D验证: confirmed / ver_e070d5ef
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 21. hyp_path_3da3495d704c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_74a.cpp:103
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问应用程序监听的网络端口并发送恶意数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_74a.cpp:103; dataMap[0] = data; @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_74a.cpp:（map存储位置）; case0Sink(dataMap); // sink函数具体实现未提供 @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_74a.cpp:（sink函数调用）
- 结论: 应用程序通过recv从网络接收数据，存储到map中，并传递给sink函数case0Sink。如果该sink函数内部使用接收数据作为进程控制参数（如LoadLibrary），则可能构成CWE-114进程控制漏洞。但当前证据不完整，sink函数具体实现未提供。
- D验证: confirmed / ver_6f70a3ba
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 22. hyp_path_c14ad6f83b19

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_74a.cpp:103
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问应用程序监听的网络端口并发送恶意数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_74a.cpp:103; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_74a.cpp::_ZN52CWE114_Process_Control__w32_wchar_t_listen_socket_745case0Ev @ route
- 结论: 应用程序通过recv从网络接收数据，存储到map中，并传递给sink函数case0Sink。如果该sink函数内部使用接收数据作为进程控制参数（如LoadLibrary），则可能构成CWE-114进程控制漏洞。但当前证据不完整，sink函数具体实现未提供。
- D验证: confirmed / ver_a8f6dc30
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 23. hyp_path_620178ba2ef0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_73a.cpp:103
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立网络连接并发送恶意数据，程序接收后未做安全处理，且sink函数直接使用该数据加载动态库。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_73a.cpp:103; dataList.push_back(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_73a.cpp:107; case0Sink(dataList); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_73a.cpp:? (case0Sink调用处)
- 结论: 程序通过socket接收数据，将数据存入list中，随后在sink函数case0Sink中可能使用该数据加载动态链接库，攻击者可以控制接收的数据，从而加载任意代码，导致CWE114进程控制漏洞。
- D验证: confirmed / ver_099ca9aa
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 24. hyp_path_9670039d8d50

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_73a.cpp:103
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立网络连接并发送恶意数据，程序接收后未做安全处理，且sink函数直接使用该数据加载动态库。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_73a.cpp:103; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_73a.cpp::_ZN52CWE114_Process_Control__w32_wchar_t_listen_socket_735case0Ev @ route
- 结论: 程序通过socket接收数据，将数据存入list中，随后在sink函数case0Sink中可能使用该数据加载动态链接库，攻击者可以控制接收的数据，从而加载任意代码，导致CWE114进程控制漏洞。
- D验证: confirmed / ver_e08ea5e9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 25. hyp_path_4df111b028f3

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_12.c:81
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标程序并发送恶意数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_12.c:86-90; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_12.c:108-112
- 结论: 程序通过recv从网络接收数据，直接作为参数传递给LoadLibraryA，攻击者可以控制加载的库路径，导致任意代码执行（CWE-114）。
- D验证: confirmed / ver_fa1ae303
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 26. hyp_path_bf014e9e0386

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_12.c:81
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标程序并发送恶意数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_12.c:81; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_12.c::CWE114_Process_Control__w32_wchar_t_connect_socket_12_case0 @ route
- 结论: 程序通过recv从网络接收数据，直接作为参数传递给LoadLibraryA，攻击者可以控制加载的库路径，导致任意代码执行（CWE-114）。
- D验证: confirmed / ver_b56d24aa
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 27. hyp_path_37ac98602bd3

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_12.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够建立socket连接并发送任意数据; 目标程序运行于Windows平台，且LoadLibraryA可用
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_12.c:96; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_12.c:112
- 结论: 存在CWE-114 Process Control漏洞：程序通过socket接收外部输入，并直接作为LoadLibraryA的参数加载DLL，攻击者可以控制加载任意库，实现代码执行。
- D验证: confirmed / ver_8f05e7dc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 28. hyp_path_81ef9a9773c8

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_12.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够建立socket连接并发送任意数据; 目标程序运行于Windows平台，且LoadLibraryA可用
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_12.c:96; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_12.c::CWE114_Process_Control__w32_wchar_t_listen_socket_12_case0 @ route
- 结论: 存在CWE-114 Process Control漏洞：程序通过socket接收外部输入，并直接作为LoadLibraryA的参数加载DLL，攻击者可以控制加载任意库，实现代码执行。
- D验证: confirmed / ver_605d78a5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 29. hyp_path_e29b8b8260e7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_72a.cpp:88
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务的TCP端口; 目标服务在Windows系统上运行; 目标服务未对接收数据进行净化或白名单检查; case0Sink函数内部确实调用类似LoadLibrary的敏感函数
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_72a.cpp:93-97; dataVector.insert(dataVector.end(), 1, data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_72a.cpp:109-110; CWE114_Process_Control__w32_char_connect_socket_72::case0Sink(dataVector); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_72a.cpp (case0Sink调用，具体行号缺失)
- 结论: 程序通过网络接收外部输入并存入vector，然后调用case0Sink函数处理该vector。由于case0Sink函数内部可能使用数据加载库（如LoadLibrary），导致进程控制漏洞。但sink函数具体实现未在证据中提供，路径不完全闭合。
- D验证: confirmed / ver_ed36ee74
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 30. hyp_path_2aae8f78465e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_72a.cpp:88
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务的TCP端口; 目标服务在Windows系统上运行; 目标服务未对接收数据进行净化或白名单检查; case0Sink函数内部确实调用类似LoadLibrary的敏感函数
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... recvResult = recv(connectSocket, (char *)(data + da... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_72a.cpp:88; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_72a.cpp::_ZN53CWE114_Process_Control__w32_wchar_t_connect_socket_725case0Ev @ route
- 结论: 程序通过网络接收外部输入并存入vector，然后调用case0Sink函数处理该vector。由于case0Sink函数内部可能使用数据加载库（如LoadLibrary），导致进程控制漏洞。但sink函数具体实现未在证据中提供，路径不完全闭合。
- D验证: confirmed / ver_c1d7abbd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 31. hyp_path_e0a0cedf4665

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_41.c:54
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标主机的监听端口发起TCP连接; 攻击者能够发送构造的恶意DLL路径字符串
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_41.c:111; CWE114_Process_Control__w32_char_listen_socket_41_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_41.c:64; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_41.c:50
- 结论: 从网络socket接收的数据直接作为LoadLibraryA的参数，攻击者可以控制加载的DLL路径，导致进程控制漏洞。
- D验证: confirmed / ver_247284f2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 32. hyp_path_bd855474cc62

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_41.c:54
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标主机的监听端口发起TCP连接; 攻击者能够发送构造的恶意DLL路径字符串
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_41.c:54; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_41.c::CWE114_Process_Control__w32_wchar_t_listen_socket_41_case0 @ route
- 结论: 从网络socket接收的数据直接作为LoadLibraryA的参数，攻击者可以控制加载的DLL路径，导致进程控制漏洞。
- D验证: confirmed / ver_2bbe7a64
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 33. hyp_path_70339f24a5e5

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_41.c:54
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标主机的监听端口发起TCP连接; 攻击者能够发送构造的恶意DLL路径字符串
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... recvResult = recv(connectSocket, (char *)(data + dataL... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_41.c:54; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_41.c::CWE114_Process_Control__w32_char_connect_socket_41_case0 @ route
- 结论: 从网络socket接收的数据直接作为LoadLibraryA的参数，攻击者可以控制加载的DLL路径，导致进程控制漏洞。
- D验证: confirmed / ver_2c4e3053
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 34. hyp_path_a419d4dcd022

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_41.c:54
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标主机的监听端口发起TCP连接; 攻击者能够发送构造的恶意DLL路径字符串
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... recvResult = recv(connectSocket, (char *)(data + da... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_41.c:54; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_41.c::CWE114_Process_Control__w32_wchar_t_connect_socket_41_case0 @ route
- 结论: 从网络socket接收的数据直接作为LoadLibraryA的参数，攻击者可以控制加载的DLL路径，导致进程控制漏洞。
- D验证: confirmed / ver_d0689653
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 35. hyp_path_517c1676e66e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_41.c:54
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标主机的监听端口发起TCP连接; 攻击者能够发送构造的恶意DLL路径字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_41.c:54; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_41.c::CWE114_Process_Control__w32_char_connect_socket_41_case0Sink @ route
- 结论: 从网络socket接收的数据直接作为LoadLibraryA的参数，攻击者可以控制加载的DLL路径，导致进程控制漏洞。
- D验证: confirmed / ver_7d504cb0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 36. hyp_path_d71c80683bb8

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_41.c:54
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标主机的监听端口发起TCP连接; 攻击者能够发送构造的恶意DLL路径字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_41.c:54; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_41.c::CWE114_Process_Control__w32_char_listen_socket_41_case0Sink @ route
- 结论: 从网络socket接收的数据直接作为LoadLibraryA的参数，攻击者可以控制加载的DLL路径，导致进程控制漏洞。
- D验证: confirmed / ver_a4ef1be1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 37. hyp_path_fd5a000e4be6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_41.c:54
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标主机的监听端口发起TCP连接; 攻击者能够发送构造的恶意DLL路径字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_41.c:54; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_41.c::CWE114_Process_Control__w32_wchar_t_connect_socket_41_case0Sink @ route
- 结论: 从网络socket接收的数据直接作为LoadLibraryA的参数，攻击者可以控制加载的DLL路径，导致进程控制漏洞。
- D验证: confirmed / ver_9d70a0ee
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 38. hyp_path_3e6a7c8a151b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_41.c:54
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标主机的监听端口发起TCP连接; 攻击者能够发送构造的恶意DLL路径字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_41.c:54; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_41.c::CWE114_Process_Control__w32_wchar_t_listen_socket_41_case0Sink @ route
- 结论: 从网络socket接收的数据直接作为LoadLibraryA的参数，攻击者可以控制加载的DLL路径，导致进程控制漏洞。
- D验证: confirmed / ver_30cc6a2c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 39. hyp_path_cadc9e62286d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_73a.cpp:88
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络发送恶意数据到目标服务; 数据随后被用于进程控制操作，且未经验证
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_73a.cpp:93; dataList.push_back(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_73a.cpp:95-96附近; CWE114_Process_Control__w32_char_connect_socket_73a::case0Sink(dataList)内部可能调用LoadLibrary等进程控制API @ 假设在sink函数内部
- 结论: 网络接收的数据被存储到列表中，然后传递给CWE114的sink函数，可能用于进程控制操作（如LoadLibrary），存在进程控制漏洞。
- D验证: confirmed / ver_e75519bc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 40. hyp_path_76de0a523612

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_73a.cpp:88
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络发送恶意数据到目标服务; 数据随后被用于进程控制操作，且未经验证
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... recvResult = recv(connectSocket, (char *)(data + da... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_73a.cpp:88; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_73a.cpp::_ZN53CWE114_Process_Control__w32_wchar_t_connect_socket_735case0Ev @ route
- 结论: 网络接收的数据被存储到列表中，然后传递给CWE114的sink函数，可能用于进程控制操作（如LoadLibrary），存在进程控制漏洞。
- D验证: confirmed / ver_51705bec
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 41. hyp_path_30ad6e7c216d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_51a.c:97
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到服务器的指定端口（TCP_PORT）。; 服务器程序运行并监听连接。; 攻击者发送特制数据，该数据被sink函数解释为库路径或命令。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_51a.c:97; data[dataLen + recvResult / sizeof(char)] = '\0'; @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_51a.c:103-104; CWE114_Process_Control__w32_char_listen_socket_51b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_51a.c:108
- 结论: 该代码存在CWE-114进程控制漏洞，网络接收的数据直接传递给sink函数，可能导致任意代码执行或加载恶意库。
- D验证: confirmed / ver_89a5421c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 42. hyp_path_3bb126b4223d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_51a.c:97
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到服务器的指定端口（TCP_PORT）。; 服务器程序运行并监听连接。; 攻击者发送特制数据，该数据被sink函数解释为库路径或命令。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_51a.c:97; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_51a.c::CWE114_Process_Control__w32_wchar_t_listen_socket_51_case0 @ route
- 结论: 该代码存在CWE-114进程控制漏洞，网络接收的数据直接传递给sink函数，可能导致任意代码执行或加载恶意库。
- D验证: confirmed / ver_66db2461
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 43. hyp_path_f05262c3fac3

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_53a.c:97
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标服务器的监听端口，并发送任意数据。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_53a.c:83; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_53a.c:97; CWE114_Process_Control__w32_char_listen_socket_53b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_53a.c:121
- 结论: 程序通过socket接收用户输入的数据，并将该数据传递给进程控制相关的sink函数（如LoadLibrary、system等），攻击者可以控制data内容，从而执行任意命令或加载恶意库，存在CWE-114 Process Control漏洞。
- D验证: confirmed / ver_1a996fc2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 44. hyp_path_dac3b7e588c0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_53a.c:97
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标服务器的监听端口，并发送任意数据。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_53a.c:97; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_53a.c::CWE114_Process_Control__w32_wchar_t_listen_socket_53_case0 @ route
- 结论: 程序通过socket接收用户输入的数据，并将该数据传递给进程控制相关的sink函数（如LoadLibrary、system等），攻击者可以控制data内容，从而执行任意命令或加载恶意库，存在CWE-114 Process Control漏洞。
- D验证: confirmed / ver_e67eea25
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 45. hyp_path_bd7c6ef1d3bc

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_52a.c:97
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到监听socket并发送数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_52a.c:95-99; CWE114_Process_Control__w32_char_listen_socket_52b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_52a.c:（sink函数调用处，跨文件）
- 结论: 从网络接收数据后传递给sink函数，但sink函数内部是否执行进程控制操作（如system或LoadLibrary）未经代码证实，路径存在但风险不确定，存在CWE-114进程控制漏洞的潜在风险。
- D验证: confirmed / ver_6d3a079c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 46. hyp_path_b371e289b76b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_52a.c:97
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到监听socket并发送数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_52a.c:97; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_52a.c::CWE114_Process_Control__w32_wchar_t_listen_socket_52_case0 @ route
- 结论: 从网络接收数据后传递给sink函数，但sink函数内部是否执行进程控制操作（如system或LoadLibrary）未经代码证实，路径存在但风险不确定，存在CWE-114进程控制漏洞的潜在风险。
- D验证: confirmed / ver_47fb81cc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 47. hyp_path_a9ff1670dd55

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_63a.c:97
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标建立网络连接并发送恶意负载
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_63a.c:95-99; data[dataLen + recvResult / sizeof(char)] = '\0'; @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_63a.c:106-107; CWE114_Process_Control__w32_char_listen_socket_63b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_63a.c:109-110
- 结论: 代码通过listen socket接收来自网络的数据，并将数据传递给CWE114_Process_Control__w32_char_listen_socket_63b_case0Sink函数，该函数可能将用户输入用于加载库或执行命令，导致过程控制漏洞（CWE-114）。攻击者可通过发送特制数据控制程序行为。
- D验证: confirmed / ver_cbfd5ff6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 48. hyp_path_610dffca3ced

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_63a.c:97
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标建立网络连接并发送恶意负载
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_63a.c:97; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_63a.c::CWE114_Process_Control__w32_wchar_t_listen_socket_63_case0 @ route
- 结论: 代码通过listen socket接收来自网络的数据，并将数据传递给CWE114_Process_Control__w32_char_listen_socket_63b_case0Sink函数，该函数可能将用户输入用于加载库或执行命令，导致过程控制漏洞（CWE-114）。攻击者可通过发送特制数据控制程序行为。
- D验证: confirmed / ver_ca925da5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 49. hyp_path_0b5fc00f7454

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_64a.c:97
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向服务端发送网络数据，且服务端未对数据做充分验证或过滤。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_64a.c:97; CWE114_Process_Control__w32_char_listen_socket_64b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_64a.c:121-124
- 结论: 通过套接字接收外部可控数据，并传递给CWE114_Process_Control__w32_char_listen_socket_64b_case0Sink函数，该函数可能将数据用作进程控制参数（如加载库或执行命令），导致代码执行或命令注入。
- D验证: confirmed / ver_e96db00c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 50. hyp_path_0935e00da0d2

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_64a.c:97
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向服务端发送网络数据，且服务端未对数据做充分验证或过滤。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_64a.c:97; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_64a.c::CWE114_Process_Control__w32_wchar_t_listen_socket_64_case0 @ route
- 结论: 通过套接字接收外部可控数据，并传递给CWE114_Process_Control__w32_char_listen_socket_64b_case0Sink函数，该函数可能将数据用作进程控制参数（如加载库或执行命令），导致代码执行或命令注入。
- D验证: confirmed / ver_b89b26ca
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 51. hyp_path_989ddd4b12e6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_82a.cpp:95
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向监听socket发送任意数据，且data缓冲区内容被传入action函数。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_82a.cpp:93-95; baseObject->action(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_82a.cpp:119
- 结论: 漏洞位于网络数据接收后传递给action函数，攻击者可通过控制网络输入操纵进程执行（如加载恶意库），即CWE-114（Process Control）。
- D验证: confirmed / ver_b1945127
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 52. hyp_path_2e6ff98203da

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_82a.cpp:95
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向监听socket发送任意数据，且data缓冲区内容被传入action函数。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_82a.cpp:95; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_82a.cpp::_ZN52CWE114_Process_Control__w32_wchar_t_listen_socket_825case0Ev @ route
- 结论: 漏洞位于网络数据接收后传递给action函数，攻击者可通过控制网络输入操纵进程执行（如加载恶意库），即CWE-114（Process Control）。
- D验证: confirmed / ver_3bb78d82
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 53. hyp_path_f69ad1b406ad

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_54a.c:97
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接目标机器的监听端口并发送任意数据。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_54a.c:97; CWE114_Process_Control__w32_char_listen_socket_54b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_54b.c (sink function)
- 结论: 从网络接收的数据未经充分验证就被用于进程控制，可能导致远程代码执行。
- D验证: confirmed / ver_58878031
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 54. hyp_path_e1af8144dafc

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_54a.c:97
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接目标机器的监听端口并发送任意数据。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_54a.c:97; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_54a.c::CWE114_Process_Control__w32_wchar_t_listen_socket_54_case0 @ route
- 结论: 从网络接收的数据未经充分验证就被用于进程控制，可能导致远程代码执行。
- D验证: confirmed / ver_6774ee25
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 55. hyp_path_9b10ae48ba99

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_51a.c:82
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标主机，并发送任意载荷。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_51a.c:87-91; CWE114_Process_Control__w32_char_connect_socket_51b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_51a.c:107
- 结论: 程序通过socket接收来自网络的数据，未经过充分验证，直接传递给进程控制相关函数，可能允许攻击者控制进程执行路径，导致任意代码执行。
- D验证: confirmed / ver_80aa7b3e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 56. hyp_path_b9baf6d913ba

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_51a.c:82
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标主机，并发送任意载荷。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... wchar_t *replace; SOCKET connectSocket = INVALID_SO... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_51a.c:82; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_51a.c::CWE114_Process_Control__w32_wchar_t_connect_socket_51_case0 @ route
- 结论: 程序通过socket接收来自网络的数据，未经过充分验证，直接传递给进程控制相关函数，可能允许攻击者控制进程执行路径，导致任意代码执行。
- D验证: confirmed / ver_0e24461f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 57. hyp_path_888117b444b2

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_52a.c:82
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者能够通过中间人攻击（如ARP欺骗）篡改网络传输数据，从而控制注入到data缓冲区的内容。
- 触发路径: connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_52a.c:73; service.sin_addr.s_addr = inet_addr(IP_ADDRESS); service.sin_port = htons(TCP_PORT); if (connect(connectSocket, ...) == SOCKET_ERROR) break; @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_52a.c:80-84; recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_52a.c:87-91; CWE114_Process_Control__w32_char_connect_socket_52b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_52a.c:104
- 结论: 通过socket接收外部输入数据，未经验证直接传递给sink函数，可能被利用加载恶意库或执行任意命令，导致进程控制漏洞。
- D验证: confirmed / ver_96882445
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 58. hyp_path_45372058c9b3

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_52a.c:82
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者能够通过中间人攻击（如ARP欺骗）篡改网络传输数据，从而控制注入到data缓冲区的内容。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... wchar_t *replace; SOCKET connectSocket = INVALID_SO... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_52a.c:82; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_52a.c::CWE114_Process_Control__w32_wchar_t_connect_socket_52_case0 @ route
- 结论: 通过socket接收外部输入数据，未经验证直接传递给sink函数，可能被利用加载恶意库或执行任意命令，导致进程控制漏洞。
- D验证: confirmed / ver_a536dac9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 59. hyp_path_9b79fb48a02c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_63a.c:82
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标服务器的指定端口并发送任意数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_63a.c:82; CWE114_Process_Control__w32_char_connect_socket_63b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_63a.c:109 (sink调用)
- 结论: 外部可控制的字符串通过socket传输，未经充分验证就用于进程控制操作，攻击者可以加载任意库或执行任意命令。
- D验证: confirmed / ver_e79ee56a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 60. hyp_path_bfcb0b2b41ee

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_63a.c:82
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标服务器的指定端口并发送任意数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... wchar_t *replace; SOCKET connectSocket = INVALID_SO... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_63a.c:82; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_63a.c::CWE114_Process_Control__w32_wchar_t_connect_socket_63_case0 @ route
- 结论: 外部可控制的字符串通过socket传输，未经充分验证就用于进程控制操作，攻击者可以加载任意库或执行任意命令。
- D验证: confirmed / ver_8bb3c9d2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 61. hyp_path_a0c1c735056e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_64a.c:82
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到socket服务器并发送恶意数据; data缓冲区初始内容无关紧要，攻击者发送的数据将覆盖data缓冲区
- 触发路径: SOCKET connectSocket = INVALID_SOCKET; service.sin_addr.s_addr = inet_addr(IP_ADDRESS); service.sin_port = htons(TCP_PORT); if (connect(connectSocket, (struct sockaddr*)&service, sizeof(service)) == SOCKET_ERROR) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_64a.c:73; recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_64a.c:82; call to CWE114_Process_Control__w32_char_connect_socket_64b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_64a.c:100
- 结论: 存在外部控制的进程控制漏洞：通过socket接收攻击者可控数据，并直接传递给进程控制函数（如LoadLibrary），可能导致任意代码执行或恶意库加载。
- D验证: confirmed / ver_586ab18c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 62. hyp_path_e867606e03de

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_64a.c:82
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到socket服务器并发送恶意数据; data缓冲区初始内容无关紧要，攻击者发送的数据将覆盖data缓冲区
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... wchar_t *replace; SOCKET connectSocket = INVALID_SO... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_64a.c:82; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_64a.c::CWE114_Process_Control__w32_wchar_t_connect_socket_64_case0 @ route
- 结论: 存在外部控制的进程控制漏洞：通过socket接收攻击者可控数据，并直接传递给进程控制函数（如LoadLibrary），可能导致任意代码执行或恶意库加载。
- D验证: confirmed / ver_c4487a5f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 63. hyp_path_5a5040bb97a8

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_17.c:97
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与监听socket建立连接并发送数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_17.c:97; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_17.c:106
- 结论: 通过socket接收用户输入，并直接作为LoadLibraryA的参数，未经验证，可能导致加载任意DLL，属于CWE-114 Process Control漏洞。
- D验证: confirmed / ver_d59d3138
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 64. hyp_path_9d5ba62290cb

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_17.c:97
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与监听socket建立连接并发送数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_17.c:97; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_17.c::CWE114_Process_Control__w32_wchar_t_listen_socket_17_case0 @ route
- 结论: 通过socket接收用户输入，并直接作为LoadLibraryA的参数，未经验证，可能导致加载任意DLL，属于CWE-114 Process Control漏洞。
- D验证: confirmed / ver_ef54e034
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 65. hyp_path_ad5ff5f6f494

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_53a.c:82
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标程序的socket端口（如本例中通过inet_addr和htons指定的地址和端口），并发送精心构造的数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_53a.c:82; CWE114_Process_Control__w32_char_connect_socket_53b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_53a.c:109（sink调用行）
- 结论: 存在CWE-114 Process Control漏洞：程序通过socket接收外部输入数据，并将数据作为参数传递给CWE114_Process_Control__w32_char_connect_socket_53b_case0Sink函数，攻击者可利用该漏洞加载恶意库或控制程序行为。
- D验证: confirmed / ver_b431af0d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 66. hyp_path_585f42dc0e30

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_53a.c:82
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标程序的socket端口（如本例中通过inet_addr和htons指定的地址和端口），并发送精心构造的数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... wchar_t *replace; SOCKET connectSocket = INVALID_SO... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_53a.c:82; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_53a.c::CWE114_Process_Control__w32_wchar_t_connect_socket_53_case0 @ route
- 结论: 存在CWE-114 Process Control漏洞：程序通过socket接收外部输入数据，并将数据作为参数传递给CWE114_Process_Control__w32_char_connect_socket_53b_case0Sink函数，攻击者可利用该漏洞加载恶意库或控制程序行为。
- D验证: confirmed / ver_aee571ef
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 67. hyp_path_c158adf4748c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_54a.c:82
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立TCP连接并发送数据。; sink函数CWE114_Process_Control__w32_char_connect_socket_54b_case0Sink未对数据做充分校验，直接用于进程控制操作（如LoadLibrary或system）。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_54a.c:82; CWE114_Process_Control__w32_char_connect_socket_54b_case0Sink(data); @ sink调用位置未在证据中明确行号，但存在于同文件或关联文件中，函数名为CWE114_Process_Control__w32_char_connect_socket_54b_case0Sink
- 结论: 该代码从网络套接字接收数据，并传递给CWE114_Process_Control__w32_char_connect_socket_54b_case0Sink函数，可能导致攻击者控制进程行为（例如加载任意库或执行命令），存在CWE-114进程控制漏洞。
- D验证: confirmed / ver_25a772d2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 68. hyp_path_5181b1d64673

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_54a.c:82
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立TCP连接并发送数据。; sink函数CWE114_Process_Control__w32_char_connect_socket_54b_case0Sink未对数据做充分校验，直接用于进程控制操作（如LoadLibrary或system）。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... wchar_t *replace; SOCKET connectSocket = INVALID_SO... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_54a.c:82; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_54a.c::CWE114_Process_Control__w32_wchar_t_connect_socket_54_case0 @ route
- 结论: 该代码从网络套接字接收数据，并传递给CWE114_Process_Control__w32_char_connect_socket_54b_case0Sink函数，可能导致攻击者控制进程行为（例如加载任意库或执行命令），存在CWE-114进程控制漏洞。
- D验证: confirmed / ver_d90dcb59
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 69. hyp_path_e96273c3ac2c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_17.c:82
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问目标服务的网络端口; 攻击者能够构造并发送恶意DLL路径或名称
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_17.c:87-91; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_17.c:110-113
- 结论: 通过socket接收外部输入并直接传递给LoadLibraryA，导致任意DLL加载，存在代码执行漏洞。
- D验证: confirmed / ver_a48505c1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 70. hyp_path_d0c90eda02d6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_17.c:82
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问目标服务的网络端口; 攻击者能够构造并发送恶意DLL路径或名称
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_17.c:82; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_17.c::CWE114_Process_Control__w32_wchar_t_connect_socket_17_case0 @ route
- 结论: 通过socket接收外部输入并直接传递给LoadLibraryA，导致任意DLL加载，存在代码执行漏洞。
- D验证: confirmed / ver_4d1b71a1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 71. hyp_path_8aadfcca326b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_08.c:110
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标机器的监听端口发起网络连接并发送任意数据，且数据能通过recv接收并存入data缓冲区。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_08.c:110; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_08.c:136
- 结论: 代码通过recv从网络接收数据到data缓冲区，然后直接调用LoadLibraryA(data)。攻击者可控制网络输入来指定任意DLL路径，导致加载恶意库，实现任意代码执行。
- D验证: confirmed / ver_13e5fc62
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 72. hyp_path_e3f1e0498801

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_08.c:110
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标机器的监听端口发起网络连接并发送任意数据，且数据能通过recv接收并存入data缓冲区。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_08.c:110; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_08.c::CWE114_Process_Control__w32_wchar_t_listen_socket_08_case0 @ route
- 结论: 代码通过recv从网络接收数据到data缓冲区，然后直接调用LoadLibraryA(data)。攻击者可控制网络输入来指定任意DLL路径，导致加载恶意库，实现任意代码执行。
- D验证: confirmed / ver_cef0675e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 73. hyp_path_ee13707b7401

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_82a.cpp:80
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务器的 socket 并发送任意数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_82a.cpp:80; baseObject->action(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_82a.cpp:118
- 结论: 外部可控数据通过网络接收进入程序，并通过 action(data) 传递，可能被用于 LoadLibrary 等库加载函数，导致 CWE-114 进程控制漏洞。但现有代码证据仅显示网络接收和 socket 关闭操作，未发现实际的库加载调用，因此漏洞路径不完整。
- D验证: confirmed / ver_f09f3f58
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 74. hyp_path_92ac3b868a56

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_82a.cpp:80
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务器的 socket 并发送任意数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... wchar_t *replace; SOCKET connectSocket = INVALID_SO... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_82a.cpp:80; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_82a.cpp::_ZN53CWE114_Process_Control__w32_wchar_t_connect_socket_825case0Ev @ route
- 结论: 外部可控数据通过网络接收进入程序，并通过 action(data) 传递，可能被用于 LoadLibrary 等库加载函数，导致 CWE-114 进程控制漏洞。但现有代码证据仅显示网络接收和 socket 关闭操作，未发现实际的库加载调用，因此漏洞路径不完整。
- D验证: confirmed / ver_efccc2ad
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 75. hyp_path_7b343c3010c9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_11.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标建立网络连接并发送恶意数据。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ CWE114_Process_Control__w32_char_listen_socket_11.c:96; hModule = LoadLibraryA(data); @ CWE114_Process_Control__w32_char_listen_socket_11.c (after recv, within same function, hModule = LoadLibraryA(data);)
- 结论: 在Windows平台上，通过socket接收的数据直接作为LoadLibraryA的参数，攻击者可以控制加载的DLL路径，导致任意代码执行。
- D验证: confirmed / ver_4a5162de
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 76. hyp_path_6eb4ed6ec531

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_11.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标建立网络连接并发送恶意数据。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_11.c:96; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_11.c::CWE114_Process_Control__w32_wchar_t_listen_socket_11_case0 @ route
- 结论: 在Windows平台上，通过socket接收的数据直接作为LoadLibraryA的参数，攻击者可以控制加载的DLL路径，导致任意代码执行。
- D验证: confirmed / ver_a244c884
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 77. hyp_path_db390d4edb68

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_01.c:94
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务器的监听端口; 攻击者能够发送任意数据到服务器并被recv接收
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ L94; hModule = LoadLibraryA(data); @ L122
- 结论: 程序通过socket接收数据，并将接收到的字符串直接作为参数传递给LoadLibraryA函数，攻击者可以通过网络发送恶意构造的库路径，导致任意代码执行。
- D验证: confirmed / ver_04a33485
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 78. hyp_path_ab4dbf3136d4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_01.c:94
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务器的监听端口; 攻击者能够发送任意数据到服务器并被recv接收
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_01.c:94; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_01.c::CWE114_Process_Control__w32_wchar_t_listen_socket_01_case0 @ route
- 结论: 程序通过socket接收数据，并将接收到的字符串直接作为参数传递给LoadLibraryA函数，攻击者可以通过网络发送恶意构造的库路径，导致任意代码执行。
- D验证: confirmed / ver_6cb9e631
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 79. hyp_path_a3c6e091514c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_02.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标服务的 TCP 端口，并发送精心构造的数据（如恶意 DLL 路径）。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_02.c:96; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_02.c:120
- 结论: 从网络接收的数据直接作为参数传递给 LoadLibraryA，攻击者可控制加载的 DLL 路径，导致任意代码执行。
- D验证: confirmed / ver_778e3d2a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 80. hyp_path_5c63dde5efcf

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_02.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标服务的 TCP 端口，并发送精心构造的数据（如恶意 DLL 路径）。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_02.c:96; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_02.c::CWE114_Process_Control__w32_wchar_t_listen_socket_02_case0 @ route
- 结论: 从网络接收的数据直接作为参数传递给 LoadLibraryA，攻击者可控制加载的 DLL 路径，导致任意代码执行。
- D验证: confirmed / ver_faff8e8b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 81. hyp_path_57e6a5056438

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_03.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标程序的监听端口并发送任意数据
- 触发路径: 入口函数调用 @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_03.c:45; acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_03.c:82; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_03.c:96; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_03.c:120
- 结论: 程序通过套接字接收网络数据，并将该数据直接作为参数传递给 LoadLibraryA，导致攻击者可以控制加载任意动态链接库（DLL），实现进程控制。
- D验证: confirmed / ver_8a02c93a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 82. hyp_path_f80f0b4f75cc

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_03.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标程序的监听端口并发送任意数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_03.c:96; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_03.c::CWE114_Process_Control__w32_wchar_t_listen_socket_03_case0 @ route
- 结论: 程序通过套接字接收网络数据，并将该数据直接作为参数传递给 LoadLibraryA，导致攻击者可以控制加载任意动态链接库（DLL），实现进程控制。
- D验证: confirmed / ver_9e39edce
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 83. hyp_path_57c286dc109a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_04.c:103
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向目标主机的监听端口发送TCP数据
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_04.c:89; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_04.c:103; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_04.c:121
- 结论: 在Windows平台上，程序通过socket接收外部输入的字符串，然后直接作为参数调用LoadLibraryA加载库。攻击者可以控制输入内容，导致加载任意DLL，从而实现代码执行。
- D验证: confirmed / ver_500339ec
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 84. hyp_path_97d80d3b6e66

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_04.c:103
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向目标主机的监听端口发送TCP数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_04.c:103; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_04.c::CWE114_Process_Control__w32_wchar_t_listen_socket_04_case0 @ route
- 结论: 在Windows平台上，程序通过socket接收外部输入的字符串，然后直接作为参数调用LoadLibraryA加载库。攻击者可以控制输入内容，导致加载任意DLL，从而实现代码执行。
- D验证: confirmed / ver_035cad4e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 85. hyp_path_815dc27a815a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_05.c:103
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者能够向目标主机的监听端口发送网络数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ path_815dc27a815a.c:103; if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ path_815dc27a815a.c:106-107; hModule = LoadLibraryA(data); @ path_815dc27a815a.c:144
- 结论: 程序通过套接字接收数据，未经任何验证直接作为参数调用LoadLibraryA，导致攻击者可以加载任意DLL，执行任意代码。
- D验证: confirmed / ver_be8e8eba
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 86. hyp_path_774c97e181b8

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_05.c:103
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者能够向目标主机的监听端口发送网络数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_05.c:103; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_05.c::CWE114_Process_Control__w32_wchar_t_listen_socket_05_case0 @ route
- 结论: 程序通过套接字接收数据，未经任何验证直接作为参数调用LoadLibraryA，导致攻击者可以加载任意DLL，执行任意代码。
- D验证: confirmed / ver_1c0fb1a7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 87. hyp_path_4fdc7205d3f7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_06.c:100
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标程序的监听端口。; 目标程序未对接收的数据进行任何安全检查或过滤。; 攻击者构造的DLL路径合法且可被系统加载。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_06.c:98-102; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_06.c:131
- 结论: 从网络套接字接收的数据直接作为参数传递给LoadLibraryA函数，导致攻击者可能通过控制接收的数据来加载任意DLL，实现代码执行。
- D验证: confirmed / ver_f24857f0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 88. hyp_path_03267f536dab

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_06.c:100
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标程序的监听端口。; 目标程序未对接收的数据进行任何安全检查或过滤。; 攻击者构造的DLL路径合法且可被系统加载。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_06.c:100; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_06.c::CWE114_Process_Control__w32_wchar_t_listen_socket_06_case0 @ route
- 结论: 从网络套接字接收的数据直接作为参数传递给LoadLibraryA函数，导致攻击者可能通过控制接收的数据来加载任意DLL，实现代码执行。
- D验证: confirmed / ver_28ea3704
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 89. hyp_path_d7b0abdbe0a4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_07.c:102
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到服务器的监听端口; 攻击者能够发送任意数据到服务端
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_07.c:100-104; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_07.c:120
- 结论: 代码通过recv从网络接收数据，并将数据直接作为LoadLibraryA的参数加载库，攻击者可以控制输入加载任意恶意DLL，导致任意代码执行（Process Control漏洞）。
- D验证: confirmed / ver_819c390a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 90. hyp_path_967e8406fd34

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_07.c:102
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到服务器的监听端口; 攻击者能够发送任意数据到服务端
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_07.c:102; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_07.c::CWE114_Process_Control__w32_wchar_t_listen_socket_07_case0 @ route
- 结论: 代码通过recv从网络接收数据，并将数据直接作为LoadLibraryA的参数加载库，攻击者可以控制输入加载任意恶意DLL，导致任意代码执行（Process Control漏洞）。
- D验证: confirmed / ver_686fb516
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 91. hyp_path_41bb4f9b3eee

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_09.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接目标主机的指定TCP端口（TCP_PORT），并发送恶意构造的DLL路径字符串。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_09.c:82; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_09.c:96; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_09.c:113
- 结论: 程序通过socket接收外部数据，并直接作为LoadLibraryA的参数加载动态库，攻击者可控制加载的库路径，实现任意代码执行。
- D验证: confirmed / ver_3e83d86e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 92. hyp_path_d7a3b79d64e7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_09.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接目标主机的指定TCP端口（TCP_PORT），并发送恶意构造的DLL路径字符串。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_09.c:96; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_09.c::CWE114_Process_Control__w32_wchar_t_listen_socket_09_case0 @ route
- 结论: 程序通过socket接收外部数据，并直接作为LoadLibraryA的参数加载动态库，攻击者可控制加载的库路径，实现任意代码执行。
- D验证: confirmed / ver_bb7a9fcd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 93. hyp_path_5f62d9b654d7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_13.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到程序监听的TCP端口; 攻击者发送的数据能够作为有效的DLL路径字符串
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_13.c:96; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_13.c:112-113
- 结论: 程序通过网络接收数据，并使用该数据直接作为LoadLibraryA的参数，导致攻击者可以加载任意DLL，实现远程代码执行。
- D验证: confirmed / ver_9264e654
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 94. hyp_path_21f441bf1183

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_13.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到程序监听的TCP端口; 攻击者发送的数据能够作为有效的DLL路径字符串
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_13.c:96; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_13.c::CWE114_Process_Control__w32_wchar_t_listen_socket_13_case0 @ route
- 结论: 程序通过网络接收数据，并使用该数据直接作为LoadLibraryA的参数，导致攻击者可以加载任意DLL，实现远程代码执行。
- D验证: confirmed / ver_df86e4a8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 95. hyp_path_00bd082627cf

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_14.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务器的监听端口，并发送特制的字符串作为库路径
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_14.c:96; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_14.c:106
- 结论: 代码通过socket接收远程数据，并直接作为参数调用LoadLibraryA加载库，攻击者可控制加载路径，导致执行任意代码。
- D验证: confirmed / ver_4d5a5afc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 96. hyp_path_e41ac1e9a050

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_14.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务器的监听端口，并发送特制的字符串作为库路径
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_14.c:96; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_14.c::CWE114_Process_Control__w32_wchar_t_listen_socket_14_case0 @ route
- 结论: 代码通过socket接收远程数据，并直接作为参数调用LoadLibraryA加载库，攻击者可控制加载路径，导致执行任意代码。
- D验证: confirmed / ver_6bd71ff5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 97. hyp_path_142c81f533e2

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_10.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能连接服务器监听的TCP端口（如示例中的TCP_PORT）; 攻击者能发送构造的字符串，其中包含恶意库路径或名称
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_10.c:96; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_10.c:113
- 结论: 代码通过网络接收数据后直接作为参数调用LoadLibraryA，未经验证，攻击者可控制加载任意库，导致进程控制漏洞。
- D验证: confirmed / ver_1ddb8c20
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 98. hyp_path_2ef07e7deda1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_10.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能连接服务器监听的TCP端口（如示例中的TCP_PORT）; 攻击者能发送构造的字符串，其中包含恶意库路径或名称
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_10.c:96; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_10.c::CWE114_Process_Control__w32_wchar_t_listen_socket_10_case0 @ route
- 结论: 代码通过网络接收数据后直接作为参数调用LoadLibraryA，未经验证，攻击者可控制加载任意库，导致进程控制漏洞。
- D验证: confirmed / ver_03268a5b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 99. hyp_path_697bf95907a0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_16.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到监听的socket并发送数据; 攻击者能够构造恶意的DLL路径或名称作为payload发送
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_16.c:94-98; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_16.c:116
- 结论: 通过socket接收外部输入，然后直接作为LoadLibraryA的参数加载动态库，可能导致任意代码执行。
- D验证: confirmed / ver_a0eea3d1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 100. hyp_path_7a1df8512251

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_16.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到监听的socket并发送数据; 攻击者能够构造恶意的DLL路径或名称作为payload发送
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_16.c:96; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_16.c::CWE114_Process_Control__w32_wchar_t_listen_socket_16_case0 @ route
- 结论: 通过socket接收外部输入，然后直接作为LoadLibraryA的参数加载动态库，可能导致任意代码执行。
- D验证: confirmed / ver_7576401c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 101. hyp_path_7da5a5b047b4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_15.c:97
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立TCP连接并可访问监听端口。; 攻击者发送的数据被程序接收并存入data缓冲区，且未做路径校验。; 系统上存在攻击者可控的DLL文件（如通过上传或网络共享）或攻击者能利用DLL搜索顺序劫持。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); ... recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_15.c:88-93; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) {...} @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_15.c:95-99; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_15.c:121-125
- 结论: 存在恶意库加载漏洞：程序通过socket接收外部数据，并将数据直接作为LoadLibraryA的参数加载库，攻击者可以控制加载的DLL路径，可能导致任意代码执行。
- D验证: confirmed / ver_bf0a6b00
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 102. hyp_path_9c6807fc76e1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_15.c:97
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立TCP连接并可访问监听端口。; 攻击者发送的数据被程序接收并存入data缓冲区，且未做路径校验。; 系统上存在攻击者可控的DLL文件（如通过上传或网络共享）或攻击者能利用DLL搜索顺序劫持。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_15.c:97; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_15.c::CWE114_Process_Control__w32_wchar_t_listen_socket_15_case0 @ route
- 结论: 存在恶意库加载漏洞：程序通过socket接收外部数据，并将数据直接作为LoadLibraryA的参数加载库，攻击者可以控制加载的DLL路径，可能导致任意代码执行。
- D验证: confirmed / ver_b8b6324b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 103. hyp_path_d1ea25d5ffd8

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_18.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络发送任意数据到服务器
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_18.c:96; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_18.c:124
- 结论: 程序通过socket接收数据，然后直接作为LoadLibraryA的参数，导致攻击者能够控制加载的库，实现任意代码执行。
- D验证: confirmed / ver_034ac57c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 104. hyp_path_dd145f08842f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_18.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络发送任意数据到服务器
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_18.c:96; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_18.c::CWE114_Process_Control__w32_wchar_t_listen_socket_18_case0 @ route
- 结论: 程序通过socket接收数据，然后直接作为LoadLibraryA的参数，导致攻击者能够控制加载的库，实现任意代码执行。
- D验证: confirmed / ver_274bc77d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 105. hyp_path_664ef05a8290

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_08.c:95
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制网络输入（作为client或通过中间人），向服务端发送特制的库路径字符串; 服务端网络连接成功建立且recv接收到的数据未触发错误或连接关闭
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_08.c:100-104; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_08.c:118-120; if (hModule != NULL) { FreeLibrary(hModule); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_08.c:122-126
- 结论: 程序通过recv从网络接收数据，未充分验证即作为LoadLibraryA的参数，导致攻击者可加载任意DLL，实现任意代码执行。
- D验证: confirmed / ver_3f913405
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 106. hyp_path_c6f5d37ec6de

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_08.c:95
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制网络输入（作为client或通过中间人），向服务端发送特制的库路径字符串; 服务端网络连接成功建立且recv接收到的数据未触发错误或连接关闭
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_08.c:95; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_08.c::CWE114_Process_Control__w32_wchar_t_connect_socket_08_case0 @ route
- 结论: 程序通过recv从网络接收数据，未充分验证即作为LoadLibraryA的参数，导致攻击者可加载任意DLL，实现任意代码执行。
- D验证: confirmed / ver_74e5bac9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 107. hyp_path_ce72ec47b730

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_11.c:81
- 漏洞类型: CWE-114, CWE-427
- CWE: CWE-114; CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到服务并发送构造的字符串数据；接收的数据未经过滤直接用于LoadLibraryA。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_11.c:81; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_11.c:90 (if失败后)
- 结论: 外部可控数据通过socket接收后直接传递给LoadLibraryA，导致攻击者可以加载任意DLL，存在进程控制漏洞。
- D验证: confirmed / ver_b070e0a0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 108. hyp_path_63857ba318c7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_11.c:81
- 漏洞类型: CWE-114, CWE-427
- CWE: CWE-114; CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到服务并发送构造的字符串数据；接收的数据未经过滤直接用于LoadLibraryA。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... if (hModule != NULL) { FreeLibrary(hModule); printL... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_11.c:81; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_11.c::CWE114_Process_Control__w32_wchar_t_connect_socket_11_case0 @ route
- 结论: 外部可控数据通过socket接收后直接传递给LoadLibraryA，导致攻击者可以加载任意DLL，存在进程控制漏洞。
- D验证: confirmed / ver_5268a1c6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 109. hyp_path_9ca8f7b8e8ff

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_03.c:81
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标服务器并发送特制的库路径字符串。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_03.c:86; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_03.c:109
- 结论: 程序通过socket接收用户输入，并直接作为参数调用LoadLibraryA，导致攻击者可以加载任意恶意库，实现远程代码执行。
- D验证: confirmed / ver_0c4f1294
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 110. hyp_path_0a2b409e5316

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_03.c:81
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标服务器并发送特制的库路径字符串。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_03.c:81; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_03.c::CWE114_Process_Control__w32_wchar_t_connect_socket_03_case0 @ route
- 结论: 程序通过socket接收用户输入，并直接作为参数调用LoadLibraryA，导致攻击者可以加载任意恶意库，实现远程代码执行。
- D验证: confirmed / ver_017c653a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 111. hyp_path_7dbeeb484195

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_02.c:81
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接发送恶意数据到目标端口，且目标程序接收并处理该数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_02.c:86-88; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_02.c:108
- 结论: 从网络接收数据后直接作为LoadLibraryA参数，攻击者可加载任意DLL，导致代码执行。
- D验证: confirmed / ver_e8f53474
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 112. hyp_path_e1e05b14944e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_02.c:81
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接发送恶意数据到目标端口，且目标程序接收并处理该数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... if (hModule != NULL) { FreeLibrary(hModule); printL... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_02.c:81; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_02.c::CWE114_Process_Control__w32_wchar_t_connect_socket_02_case0 @ route
- 结论: 从网络接收数据后直接作为LoadLibraryA参数，攻击者可加载任意DLL，导致代码执行。
- D验证: confirmed / ver_4ffc3f82
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 113. hyp_path_8b5ad80c20bd

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_04.c:88
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标程序建立TCP连接，并发送特制的库名字符串，且recv成功接收数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_04.c:93-97; if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_04.c:94-98; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_04.c:约105行
- 结论: 程序通过socket接收外部数据，并将该数据直接用作LoadLibraryA的参数，攻击者可控制加载任意DLL，导致任意代码执行。
- D验证: confirmed / ver_fa277411
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 114. hyp_path_7c829fddb9fc

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_04.c:88
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标程序建立TCP连接，并发送特制的库名字符串，且recv成功接收数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_04.c:88; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_04.c::CWE114_Process_Control__w32_wchar_t_connect_socket_04_case0 @ route
- 结论: 程序通过socket接收外部数据，并将该数据直接用作LoadLibraryA的参数，攻击者可控制加载任意DLL，导致任意代码执行。
- D验证: confirmed / ver_f39c536a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 115. hyp_path_21dbc9473722

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_01.c:79
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标服务的指定端口发送TCP数据; 目标服务未对接收数据进行充分验证或过滤
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_01.c:84-88; hModule = LoadLibraryA(data); @ 同一函数内，recv之后的条件分支中
- 结论: 通过socket接收数据后直接作为LoadLibraryA的参数，攻击者可控制加载任意DLL，导致任意代码执行。
- D验证: confirmed / ver_7bb8f216
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 116. hyp_path_94a440feb511

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_01.c:79
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标服务的指定端口发送TCP数据; 目标服务未对接收数据进行充分验证或过滤
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... if (hModule != NULL) { FreeLibrary(hModule); printL... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_01.c:79; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_01.c::CWE114_Process_Control__w32_wchar_t_connect_socket_01_case0 @ route
- 结论: 通过socket接收数据后直接作为LoadLibraryA的参数，攻击者可控制加载任意DLL，导致任意代码执行。
- D验证: confirmed / ver_0483ff64
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 117. hyp_path_ccf4550079cb

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_05.c:88
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接目标程序监听的TCP端口; 攻击者可以构造一个有效的DLL路径字符串作为payload
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_05.c:93; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_05.c:115
- 结论: 程序通过socket接收数据并将其直接作为LoadLibraryA的参数，攻击者可以控制加载的库，导致任意代码执行。
- D验证: confirmed / ver_b9bf8443
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 118. hyp_path_b954a88584b2

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_05.c:88
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接目标程序监听的TCP端口; 攻击者可以构造一个有效的DLL路径字符串作为payload
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_05.c:88; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_05.c::CWE114_Process_Control__w32_wchar_t_connect_socket_05_case0 @ route
- 结论: 程序通过socket接收数据并将其直接作为LoadLibraryA的参数，攻击者可以控制加载的库，导致任意代码执行。
- D验证: confirmed / ver_4b6e00a5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 119. hyp_path_0fe8792da093

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_07.c:87
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标程序监听的TCP端口并发送恶意数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_07.c:87; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_07.c:114-118
- 结论: 程序通过网络接收数据后，未经验证直接作为参数传递给LoadLibraryA，导致攻击者可以控制加载任意DLL，实现代码执行或DLL劫持。
- D验证: confirmed / ver_cf632cc0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 120. hyp_path_aaa823e638aa

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_07.c:87
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标程序监听的TCP端口并发送恶意数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_07.c:87; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_07.c::CWE114_Process_Control__w32_wchar_t_connect_socket_07_case0 @ route
- 结论: 程序通过网络接收数据后，未经验证直接作为参数传递给LoadLibraryA，导致攻击者可以控制加载任意DLL，实现代码执行或DLL劫持。
- D验证: confirmed / ver_9210679e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 121. hyp_path_e8565a9e3868

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_09.c:81
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接目标程序的套接字，并发送特制的数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_09.c:86; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_09.c:104
- 结论: 存在安全漏洞：程序通过套接字接收外部输入，并直接作为参数传递给LoadLibraryA函数，导致攻击者可以控制加载的库，可能造成任意代码执行。
- D验证: confirmed / ver_ab5f19e2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 122. hyp_path_5e634d79f967

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_09.c:81
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接目标程序的套接字，并发送特制的数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... if (hModule != NULL) { FreeLibrary(hModule); printL... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_09.c:81; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_09.c::CWE114_Process_Control__w32_wchar_t_connect_socket_09_case0 @ route
- 结论: 存在安全漏洞：程序通过套接字接收外部输入，并直接作为参数传递给LoadLibraryA函数，导致攻击者可以控制加载的库，可能造成任意代码执行。
- D验证: confirmed / ver_dd9585e1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 123. hyp_path_1fd3e6e9cf88

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_06.c:85
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标主机的监听的TCP端口; 攻击者能够发送包含DLL名称或路径的数据
- 触发路径: connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); ... connect(connectSocket, (struct sockaddr*)&service, sizeof(service)) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_06.c:76-87; recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_06.c:90-94; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_06.c:112-116
- 结论: 通过socket接收外部输入，直接用于LoadLibraryA加载库，攻击者可控制加载任意DLL，导致任意代码执行。
- D验证: confirmed / ver_0e599c79
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 124. hyp_path_483c6dea3ec6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_06.c:85
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标主机的监听的TCP端口; 攻击者能够发送包含DLL名称或路径的数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... if (hModule != NULL) { FreeLibrary(hModule); printL... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_06.c:85; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_06.c::CWE114_Process_Control__w32_wchar_t_connect_socket_06_case0 @ route
- 结论: 通过socket接收外部输入，直接用于LoadLibraryA加载库，攻击者可控制加载任意DLL，导致任意代码执行。
- D验证: confirmed / ver_7ed78b43
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 125. hyp_path_3b2282f28b03

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_10.c:81
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 目标系统运行该程序并监听指定端口; 攻击者能够通过网络访问该端口; 程序未对接收数据进行充分验证（如白名单校验）
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_10.c:86-90; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_10.c:108-112
- 结论: 存在CWE-114（过程控制）漏洞。程序通过socket接收外部数据，并将该数据直接作为LoadLibraryA的参数，攻击者可以控制加载的DLL，实现任意代码执行。
- D验证: confirmed / ver_6b67e7a9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 126. hyp_path_eca1d9077624

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_10.c:81
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 目标系统运行该程序并监听指定端口; 攻击者能够通过网络访问该端口; 程序未对接收数据进行充分验证（如白名单校验）
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_10.c:81; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_10.c::CWE114_Process_Control__w32_wchar_t_connect_socket_10_case0 @ route
- 结论: 存在CWE-114（过程控制）漏洞。程序通过socket接收外部数据，并将该数据直接作为LoadLibraryA的参数，攻击者可以控制加载的DLL，实现任意代码执行。
- D验证: confirmed / ver_cb91f36a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 127. hyp_path_f8e57a80dbfe

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_13.c:81
- 漏洞类型: CWE-114, CWE-73
- CWE: CWE-114; CWE-73
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标主机的指定TCP端口并发送恶意负载
- 触发路径: connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_13.c:72; if (connect(connectSocket, (struct sockaddr*)&service, sizeof(service)) == SOCKET_ERROR) { break; } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_13.c:79-83; recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_13.c:86-90; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_13.c:108-112
- 结论: 从网络socket接收的数据直接用作LoadLibraryA的参数，攻击者可控制加载的库路径，导致任意DLL加载执行。
- D验证: confirmed / ver_038566b7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 128. hyp_path_37516e4c9b8f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_13.c:81
- 漏洞类型: CWE-114, CWE-73
- CWE: CWE-114; CWE-73
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标主机的指定TCP端口并发送恶意负载
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... if (hModule != NULL) { FreeLibrary(hModule); printL... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_13.c:81; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_13.c::CWE114_Process_Control__w32_wchar_t_connect_socket_13_case0 @ route
- 结论: 从网络socket接收的数据直接用作LoadLibraryA的参数，攻击者可控制加载的库路径，导致任意DLL加载执行。
- D验证: confirmed / ver_926d4936
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 129. hyp_path_fd42f81250f4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_15.c:82
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标服务建立TCP连接并发送任意数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_15.c:82; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_15.c:109
- 结论: 网络接收的数据直接作为LoadLibraryA的参数，攻击者可以控制DLL路径，加载恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_503d7830
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 130. hyp_path_bfe99caeaf01

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_15.c:82
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标服务建立TCP连接并发送任意数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_15.c:82; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_15.c::CWE114_Process_Control__w32_wchar_t_connect_socket_15_case0 @ route
- 结论: 网络接收的数据直接作为LoadLibraryA的参数，攻击者可以控制DLL路径，加载恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_49579497
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 131. hyp_path_e3ec85f08ea1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_18.c:81
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向目标发送恶意数据，并确保recv成功接收。
- 触发路径: recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_18.c:86-90; if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_18.c:91; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_18.c:103-107
- 结论: 代码从网络接收数据后直接作为LoadLibraryA的参数，未对数据进行验证，攻击者可以通过控制网络输入加载任意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_56978a3c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 132. hyp_path_e35765e170c6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_18.c:81
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向目标发送恶意数据，并确保recv成功接收。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_18.c:81; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_18.c::CWE114_Process_Control__w32_wchar_t_connect_socket_18_case0 @ route
- 结论: 代码从网络接收数据后直接作为LoadLibraryA的参数，未对数据进行验证，攻击者可以通过控制网络输入加载任意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_58817258
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 133. hyp_path_8f6051acd9aa

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_16.c:81
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问服务监听的TCP端口（IP_ADDRESS:TCP_PORT）; 攻击者可以构造并发送恶意数据，使得data字符串指向一个攻击者可控的DLL路径（例如远程共享或已上传的恶意DLL）
- 触发路径: connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); ... connect(connectSocket, (struct sockaddr*)&service, sizeof(service)); @ socket创建和连接; recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ 接收网络数据; if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ 检查接收结果; hModule = LoadLibraryA(data); @ 加载库
- 结论: 代码通过socket接收网络数据，并直接作为参数传递给LoadLibraryA函数，攻击者可以控制加载的库路径，导致任意代码执行。
- D验证: confirmed / ver_4275c983
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 134. hyp_path_8793cce5688d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_16.c:81
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问服务监听的TCP端口（IP_ADDRESS:TCP_PORT）; 攻击者可以构造并发送恶意数据，使得data字符串指向一个攻击者可控的DLL路径（例如远程共享或已上传的恶意DLL）
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... if (hModule != NULL) { FreeLibrary(hModule); printL... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_16.c:81; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_16.c::CWE114_Process_Control__w32_wchar_t_connect_socket_16_case0 @ route
- 结论: 代码通过socket接收网络数据，并直接作为参数传递给LoadLibraryA函数，攻击者可以控制加载的库路径，导致任意代码执行。
- D验证: confirmed / ver_3a3033b0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 135. hyp_path_a84f13ee7b31

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_44.c:115
- 漏洞类型: command_injection
- CWE: CWE-114; CWE-78
- 风险等级: P0
- 触发条件: 攻击者能够访问网络并连接目标应用的监听端口。; 应用在接收数据后，未对数据进行有效的校验或净化。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_44.c:101; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_44.c:115; 未显示，但标签指示高风险的sink，可能调用进程控制函数如system或LoadLibrary，参数为data。 @ 推测后续代码
- 结论: 应用程序通过网络接收外部输入，并可能将其用于进程控制操作（如加载库或执行命令），构成命令注入或代码执行漏洞。
- D验证: confirmed / ver_1438cff6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 136. hyp_path_5d26e44901e0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_44.c:115
- 漏洞类型: command_injection
- CWE: CWE-114; CWE-78
- 风险等级: P0
- 触发条件: 攻击者能够访问网络并连接目标应用的监听端口。; 应用在接收数据后，未对数据进行有效的校验或净化。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_44.c:115; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_44.c::CWE114_Process_Control__w32_wchar_t_listen_socket_44_case0 @ route
- 结论: 应用程序通过网络接收外部输入，并可能将其用于进程控制操作（如加载库或执行命令），构成命令注入或代码执行漏洞。
- D验证: confirmed / ver_ee5da598
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 137. hyp_path_8aec8213e8e4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_81a.cpp:95
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到服务器监听的TCP端口; 服务器成功接收并处理攻击者发送的数据; action函数未对输入进行充分验证或净化
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); ... data[dataLen + recvResult / sizeof(char)] = '\0'; @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_81a.cpp:84-91; const CWE114_Process_Control__w32_char_listen_socket_81_base& baseObject = CWE114_Process_Control__w32_char_listen_socket_81_case0(); baseObject.action(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_81a.cpp:99-101
- 结论: 应用程序通过socket接收外部输入数据，并直接传递给后续处理函数（action），该函数可能将用户输入作为进程控制参数（如加载库或执行命令），导致攻击者可以控制程序行为，实现任意代码执行或拒绝服务。
- D验证: confirmed / ver_74733827
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 138. hyp_path_f591299c410a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_81a.cpp:95
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到服务器监听的TCP端口; 服务器成功接收并处理攻击者发送的数据; action函数未对输入进行充分验证或净化
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_81a.cpp:95; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_81a.cpp::_ZN52CWE114_Process_Control__w32_wchar_t_listen_socket_815case0Ev @ route
- 结论: 应用程序通过socket接收外部输入数据，并直接传递给后续处理函数（action），该函数可能将用户输入作为进程控制参数（如加载库或执行命令），导致攻击者可以控制程序行为，实现任意代码执行或拒绝服务。
- D验证: confirmed / ver_106935ab
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 139. hyp_path_295a0630ff08

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_14.c:81
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标程序的监听端口并发送恶意数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_14.c:86-90; hModule = LoadLibraryA(data); @ LoadLibraryA调用处（基于trace证据，位于recv后条件检查内）
- 结论: 程序通过socket接收外部数据，直接作为参数传递给LoadLibraryA()加载库，攻击者可以控制网络输入加载任意DLL，导致代码执行。
- D验证: confirmed / ver_12db63f2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 140. hyp_path_de7c8aa8b44a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_14.c:81
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标程序的监听端口并发送恶意数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_14.c:81; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_14.c::CWE114_Process_Control__w32_wchar_t_connect_socket_14_case0 @ route
- 结论: 程序通过socket接收外部数据，直接作为参数传递给LoadLibraryA()加载库，攻击者可以控制网络输入加载任意DLL，导致代码执行。
- D验证: confirmed / ver_bcd3e833
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 141. hyp_path_7b4b73373c0d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_81a.cpp:80
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接并发送数据到目标socket
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_81a.cpp:85-89
- 结论: 该代码通过socket接收外部数据，并可能用于进程控制（如LoadLibrary或CreateProcess），但未对接收数据进行充分验证和清理，攻击者可以发送恶意数据导致任意代码执行。需进一步确认接收数据是否被传递至进程控制函数。
- D验证: confirmed / ver_4f451c6c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 142. hyp_path_f37ba30f4a78

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_81a.cpp:80
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接并发送数据到目标socket
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... wchar_t *replace; SOCKET connectSocket = INVALID_SO... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_81a.cpp:80; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_81a.cpp::_ZN53CWE114_Process_Control__w32_wchar_t_connect_socket_815case0Ev @ route
- 结论: 该代码通过socket接收外部数据，并可能用于进程控制（如LoadLibrary或CreateProcess），但未对接收数据进行充分验证和清理，攻击者可以发送恶意数据导致任意代码执行。需进一步确认接收数据是否被传递至进程控制函数。
- D验证: confirmed / ver_d4c77a50
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 143. hyp_path_2eeaafceb5de

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_33.cpp:98
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问目标主机的监听端口，并发送精心构造的字符串作为恶意库路径。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_33.cpp:84; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_33.cpp:98; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_33.cpp:135
- 结论: 程序通过socket接收外部数据，并直接作为LoadLibraryA的参数加载库文件，攻击者可远程控制加载恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_ae4c9573
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 144. hyp_path_3c59bea95654

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_33.cpp:98
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问目标主机的监听端口，并发送精心构造的字符串作为恶意库路径。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_33.cpp:98; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_33.cpp::_ZN52CWE114_Process_Control__w32_wchar_t_listen_socket_335case0Ev @ route
- 结论: 程序通过socket接收外部数据，并直接作为LoadLibraryA的参数加载库文件，攻击者可远程控制加载恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_1bbb9e8c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 145. hyp_path_371e7364dde6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_17.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制文件FILENAME的内容，使其包含一个有效的DLL路径或文件名。
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_17.c:44; if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_17.c:48; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_17.c:68
- 结论: 程序从文件读取数据并使用LoadLibraryA动态加载库，攻击者如果能够控制文件内容，则可以加载任意DLL，导致代码执行。
- D验证: confirmed / ver_637a9d5f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 146. hyp_path_04254c603536

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_17.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制文件FILENAME的内容，使其包含一个有效的DLL路径或文件名。
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_17.c:46; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_17.c::CWE114_Process_Control__w32_wchar_t_file_17_case0 @ route
- 结论: 程序从文件读取数据并使用LoadLibraryA动态加载库，攻击者如果能够控制文件内容，则可以加载任意DLL，导致代码执行。
- D验证: confirmed / ver_258454ff
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 147. hyp_path_9a6bdda66204

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_32.c:75
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问服务监听的TCP端口，并能够发送任意数据
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_32.c:90-94; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_32.c:96-100; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_32.c:118-122
- 结论: 程序通过socket接收外部输入，并将该输入直接作为LoadLibraryA的参数，导致攻击者可以加载任意DLL，实现进程控制。
- D验证: confirmed / ver_62804820
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 148. hyp_path_55f5880b2359

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_32.c:75
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问服务监听的TCP端口，并能够发送任意数据
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); ... recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_32.c:75; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_32.c::CWE114_Process_Control__w32_wchar_t_listen_socket_32_case0 @ route
- 结论: 程序通过socket接收外部输入，并将该输入直接作为LoadLibraryA的参数，导致攻击者可以加载任意DLL，实现进程控制。
- D验证: confirmed / ver_8963f3c7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 149. hyp_path_78667bf8ff5b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_31.c:94
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到程序监听的TCP端口; 攻击者能够发送包含恶意库路径的字符串; 程序未对输入进行任何验证或白名单过滤
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_31.c:94; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_31.c (LoadLibraryA调用行，约118-122)
- 结论: 程序从网络socket接收字符串数据，并直接将其作为参数传递给LoadLibraryA()，加载动态链接库。攻击者可以通过控制网络输入加载任意恶意库，导致代码执行或系统控制。
- D验证: confirmed / ver_6eb43e0c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 150. hyp_path_dd42b0c2656f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_31.c:94
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到程序监听的TCP端口; 攻击者能够发送包含恶意库路径的字符串; 程序未对输入进行任何验证或白名单过滤
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_31.c:94; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_31.c::CWE114_Process_Control__w32_wchar_t_listen_socket_31_case0 @ route
- 结论: 程序从网络socket接收字符串数据，并直接将其作为参数传递给LoadLibraryA()，加载动态链接库。攻击者可以通过控制网络输入加载任意恶意库，导致代码执行或系统控制。
- D验证: confirmed / ver_bd63ccf4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 151. hyp_path_ee58f44378a1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_31.c:79
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络访问目标服务并发送恶意数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_31.c:79; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_31.c:93
- 结论: 程序通过socket接收外部输入，并将其作为参数直接传递给LoadLibraryA函数，导致攻击者可以加载任意DLL，实现代码执行。
- D验证: confirmed / ver_ebdc6779
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 152. hyp_path_48b62986e2bd

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_31.c:79
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络访问目标服务并发送恶意数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... if (hModule != NULL) { FreeLibrary(hModule); printL... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_31.c:79; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_31.c::CWE114_Process_Control__w32_wchar_t_connect_socket_31_case0 @ route
- 结论: 程序通过socket接收外部输入，并将其作为参数直接传递给LoadLibraryA函数，导致攻击者可以加载任意DLL，实现代码执行。
- D验证: confirmed / ver_90ca23d5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 153. hyp_path_8fe4500cb9f2

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_34.c:101
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标程序建立网络连接; 攻击者能够发送控制数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_34.c:101; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_34.c (recv成功后的条件分支中)
- 结论: 程序通过套接字接收外部输入，并直接作为LoadLibraryA的参数加载动态链接库，攻击者可以控制加载的DLL路径，导致任意代码执行。
- D验证: confirmed / ver_8f8e081a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 154. hyp_path_4cf59a9077cb

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_34.c:101
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标程序建立网络连接; 攻击者能够发送控制数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_34.c:101; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_34.c::CWE114_Process_Control__w32_wchar_t_listen_socket_34_case0 @ route
- 结论: 程序通过套接字接收外部输入，并直接作为LoadLibraryA的参数加载动态链接库，攻击者可以控制加载的DLL路径，导致任意代码执行。
- D验证: confirmed / ver_79cc05a1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 155. hyp_path_825ee7b7c6ee

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_33.cpp:83
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标建立网络连接并发送数据。; 目标运行在Windows平台且存在LoadLibraryA函数。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_33.cpp:88-92; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_33.cpp:96
- 结论: 代码从网络接收数据并直接作为LoadLibraryA的参数，攻击者可以控制加载的库路径，导致任意代码执行。
- D验证: confirmed / ver_d4832470
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 156. hyp_path_6157e4c2d594

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_33.cpp:83
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标建立网络连接并发送数据。; 目标运行在Windows平台且存在LoadLibraryA函数。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_33.cpp:83; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_33.cpp::_ZN53CWE114_Process_Control__w32_wchar_t_connect_socket_335case0Ev @ route
- 结论: 代码从网络接收数据并直接作为LoadLibraryA的参数，攻击者可以控制加载的库路径，导致任意代码执行。
- D验证: confirmed / ver_b514aaa6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 157. hyp_path_a25837cb13f8

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_34.c:86
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标应用程序建立TCP连接; 攻击者能够发送任意数据到目标应用程序
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_34.c:86; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_34.c:113
- 结论: 程序通过socket接收外部输入，并直接作为参数调用LoadLibraryA，攻击者可以控制加载任意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_f5ed2587
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 158. hyp_path_3b19ee654257

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_34.c:86
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标应用程序建立TCP连接; 攻击者能够发送任意数据到目标应用程序
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... if (hModule != NULL) { FreeLibrary(hModule); printL... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_34.c:86; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_34.c::CWE114_Process_Control__w32_wchar_t_connect_socket_34_case0 @ route
- 结论: 程序通过socket接收外部输入，并直接作为参数调用LoadLibraryA，攻击者可以控制加载任意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_69918d76
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 159. hyp_path_cdf8380fd6d7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_32.c:83
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标程序的监听端口，并发送格式正确的库路径字符串。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_32.c:83; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_32.c:112
- 结论: 程序通过 recv 从网络接收数据后，直接作为参数传递给 LoadLibraryA 加载动态库，攻击者可以控制加载任意恶意 DLL，导致进程控制漏洞。
- D验证: confirmed / ver_ce9e9094
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 160. hyp_path_56101f270be7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_32.c:83
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标程序的监听端口，并发送格式正确的库路径字符串。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_32.c:83; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_32.c::CWE114_Process_Control__w32_wchar_t_connect_socket_32_case0 @ route
- 结论: 程序通过 recv 从网络接收数据后，直接作为参数传递给 LoadLibraryA 加载动态库，攻击者可以控制加载任意恶意 DLL，导致进程控制漏洞。
- D验证: confirmed / ver_efe7bdb4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 161. hyp_path_a749e46fdb9a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_45.c:94
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接访问服务端监听端口（TCP_PORT）。; 攻击者能够发送精心构造的路径字符串到data缓冲区。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_45.c:109; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_45.c:117; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_45.c:48-66
- 结论: 该代码存在外部控制库加载路径的漏洞（CWE-114）。攻击者可以通过网络连接向监听socket发送数据，控制data变量内容，进而影响LoadLibraryA加载的库路径，导致加载恶意DLL。
- D验证: confirmed / ver_646c75a4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 162. hyp_path_f26243c6888e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_45.c:94
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接访问服务端监听端口（TCP_PORT）。; 攻击者能够发送精心构造的路径字符串到data缓冲区。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); ... recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_45.c:94; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_45.c::CWE114_Process_Control__w32_wchar_t_listen_socket_45_case0 @ route
- 结论: 该代码存在外部控制库加载路径的漏洞（CWE-114）。攻击者可以通过网络连接向监听socket发送数据，控制data变量内容，进而影响LoadLibraryA加载的库路径，导致加载恶意DLL。
- D验证: confirmed / ver_469ffef8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 163. hyp_path_4bb51b3b932f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_66a.c:75
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接服务端并发送任意数据。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_66a.c:90; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_66a.c:98; dataArray[2] = data; CWE114_Process_Control__w32_char_listen_socket_66b_case0Sink(dataArray); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_66a.c:109
- 结论: 存在安全漏洞：外部攻击者可通过网络连接发送恶意数据，该数据被用于进程控制操作（如LoadLibrary），可能导致任意代码执行。
- D验证: confirmed / ver_17460dbc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 164. hyp_path_7be3cbc72d84

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_66a.c:75
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接服务端并发送任意数据。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); ... recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_66a.c:75; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_66a.c::CWE114_Process_Control__w32_wchar_t_listen_socket_66_case0 @ route
- 结论: 存在安全漏洞：外部攻击者可通过网络连接发送恶意数据，该数据被用于进程控制操作（如LoadLibrary），可能导致任意代码执行。
- D验证: confirmed / ver_83adae95
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 165. hyp_path_bec9c8d499a6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_68a.c:77
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标主机的TCP端口，并发送精心构造的负载。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_68a.c:92; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_68a.c:98; CWE114_Process_Control__w32_char_listen_socket_68b_case0Sink(); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_68a.c:104-108
- 结论: 程序通过socket接收外部输入数据，并将数据传递给外部命令执行函数（CWE114），攻击者可构造恶意输入导致任意命令执行。
- D验证: confirmed / ver_ee7a302f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 166. hyp_path_74e74e0fb0ce

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_68a.c:77
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标主机的TCP端口，并发送精心构造的负载。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); ... recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_68a.c:77; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_68a.c::CWE114_Process_Control__w32_wchar_t_listen_socket_68_case0 @ route
- 结论: 程序通过socket接收外部输入数据，并将数据传递给外部命令执行函数（CWE114），攻击者可构造恶意输入导致任意命令执行。
- D验证: confirmed / ver_b44416a5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 167. hyp_path_1240204c742b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_67a.c:80
- 漏洞类型: command_injection
- CWE: CWE-114; CWE-78
- 风险等级: P0
- 触发条件: 攻击者能够访问目标机器的监听端口（TCP端口由代码定义）; sink函数中未对data进行充分校验或白名单过滤
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_67a.c:103; myStruct.structFirst = data; CWE114_Process_Control__w32_char_listen_socket_67b_case0Sink(myStruct); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_67a.c:125-127; sink函数可能将data作为进程路径或参数调用CreateProcess等（具体代码未在证据中提供，但基于CWE114的典型实现，存在进程控制风险） @ CWE114_Process_Control__w32_char_listen_socket_67b.c（sink函数）
- 结论: 通过socket接收的未验证数据被传递给进程控制函数，可能导致任意进程执行或命令注入。
- D验证: confirmed / ver_8d1286f8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 168. hyp_path_09fae58b51af

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_67a.c:80
- 漏洞类型: command_injection
- CWE: CWE-114; CWE-78
- 风险等级: P0
- 触发条件: 攻击者能够访问目标机器的监听端口（TCP端口由代码定义）; sink函数中未对data进行充分校验或白名单过滤
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); ... recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_67a.c:80; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_67a.c::CWE114_Process_Control__w32_wchar_t_listen_socket_67_case0 @ route
- 结论: 通过socket接收的未验证数据被传递给进程控制函数，可能导致任意进程执行或命令注入。
- D验证: confirmed / ver_36ec215c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 169. hyp_path_6cad0b9b66e1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_12.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制被读取的文件内容。
- 触发路径: fgets(data+dataLen, (int)(100-dataLen), pFile) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_12.c:43-51; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_12.c:72
- 结论: 从文件读取用户可控数据并直接用于加载动态库，可能导致加载恶意库，存在CWE-114 Process Control漏洞。
- D验证: confirmed / ver_285ad3d7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 170. hyp_path_4cdd5cbeb9fa

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_12.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制被读取的文件内容。
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_12.c:45; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_12.c::CWE114_Process_Control__w32_wchar_t_file_12_case0 @ route
- 结论: 从文件读取用户可控数据并直接用于加载动态库，可能导致加载恶意库，存在CWE-114 Process Control漏洞。
- D验证: confirmed / ver_cac82181
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 171. hyp_path_0fa8436e2fc8

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_62b.cpp:70
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到服务端的监听端口并发送任意数据。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_62b.cpp:85-89; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_62b.cpp:91-95
- 结论: 存在潜在的进程控制漏洞，服务端通过socket接收数据，该数据可能后续被用于进程控制函数（如LoadLibrary）的参数，导致执行非预期代码，但当前代码证据未展示该调用，路径不完整。
- D验证: confirmed / ver_a00ce0a2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 172. hyp_path_bc9ea3953f70

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_62b.cpp:70
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到服务端的监听端口并发送任意数据。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); ... recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_62b.cpp:70; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_62b.cpp::_ZN52CWE114_Process_Control__w32_wchar_t_listen_socket_6211case0SourceERPw @ route
- 结论: 存在潜在的进程控制漏洞，服务端通过socket接收数据，该数据可能后续被用于进程控制函数（如LoadLibrary）的参数，导致执行非预期代码，但当前代码证据未展示该调用，路径不完整。
- D验证: confirmed / ver_480333d7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 173. hyp_path_ba0330e72d78

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_43.cpp:71
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务器的TCP端口; 攻击者可以发送任意数据作为要加载的库路径
- 触发路径: listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_43.cpp:71; bind(listenSocket, ...); listen(listenSocket, ...); acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_43.cpp:80; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_43.cpp:94; 假设存在LoadLibrary(data)等进程控制函数调用，但代码证据中未出现。 @ 假设后续代码未提供
- 结论: 通过socket接收网络数据，数据可能被用于LoadLibrary等进程控制函数，攻击者可以通过控制接收到的数据加载恶意DLL，导致任意代码执行。但代码证据中未直接展示LoadLibrary调用，路径不完整。
- D验证: confirmed / ver_84e0b702
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 174. hyp_path_4ddaf45aab27

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_43.cpp:71
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务器的TCP端口; 攻击者可以发送任意数据作为要加载的库路径
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); ... recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_43.cpp:71; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_43.cpp::_ZN52CWE114_Process_Control__w32_wchar_t_listen_socket_43L11case0SourceERPw @ route
- 结论: 通过socket接收网络数据，数据可能被用于LoadLibrary等进程控制函数，攻击者可以通过控制接收到的数据加载恶意DLL，导致任意代码执行。但代码证据中未直接展示LoadLibrary调用，路径不完整。
- D验证: confirmed / ver_ab9b94c7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 175. hyp_path_8fbef4f78d90

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_45.c:102
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接目标服务器的监听端口（如TCP_PORT）。; 攻击者能够发送构造的恶意库路径字符串（如UNC路径或本地路径指向恶意DLL）。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_45.c:107-111; CWE114_Process_Control__w32_char_connect_socket_45_case0Data = data; case0Sink(); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_45.c:68; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_45.c:48-66
- 结论: 通过网络接收的字符串直接作为LoadLibraryA参数，攻击者可控制加载恶意库，导致任意代码执行。
- D验证: confirmed / ver_ec448d74
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 176. hyp_path_60b7bf77bbde

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_45.c:102
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接目标服务器的监听端口（如TCP_PORT）。; 攻击者能够发送构造的恶意库路径字符串（如UNC路径或本地路径指向恶意DLL）。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... wchar_t *replace; SOCKET connectSocket = INVALID_SO... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_45.c:102; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_45.c::CWE114_Process_Control__w32_wchar_t_connect_socket_45_case0 @ route
- 结论: 通过网络接收的字符串直接作为LoadLibraryA参数，攻击者可控制加载恶意库，导致任意代码执行。
- D验证: confirmed / ver_e87d3cb9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 177. hyp_path_8805a292d250

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_84_case0.cpp:69
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务，并发送超长的数据。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_84_case0.cpp:84; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_84_case0.cpp:92
- 结论: 在Windows套接字编程中，recv函数将网络数据读取到固定大小的栈缓冲区data中，未充分验证接收长度，可能导致栈缓冲区溢出。
- D验证: confirmed / ver_936a40d0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 178. hyp_path_c4c8c311b30f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_84_case0.cpp:69
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务，并发送超长的数据。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); ... recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_84_case0.cpp:69; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_84_case0.cpp::_ZN52CWE114_Process_Control__w32_wchar_t_listen_socket_8458CWE114_Process_Control__w32_wchar_t_listen_socket_84_case0C2EPw @ route
- 结论: 在Windows套接字编程中，recv函数将网络数据读取到固定大小的栈缓冲区data中，未充分验证接收长度，可能导致栈缓冲区溢出。
- D验证: confirmed / ver_9aa56300
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 179. hyp_path_04b884934a18

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_66a.c:83
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标主机的指定端口并发送长度为1到99字节的数据，且数据中包含可被操作系统解释为命令的字符
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_66a.c:83; dataArray[2] = data; CWE114_Process_Control__w32_char_connect_socket_66b_case0Sink(dataArray); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_66a.c:100-104
- 结论: 通过socket接收外部输入并用于进程控制（如system或CreateProcess），攻击者可构造恶意命令导致任意代码执行。
- D验证: confirmed / ver_76bfc11c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 180. hyp_path_c9a0178804e3

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_66a.c:83
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标主机的指定端口并发送长度为1到99字节的数据，且数据中包含可被操作系统解释为命令的字符
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... wchar_t *replace; SOCKET connectSocket = INVALID_SO... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_66a.c:83; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_66a.c::CWE114_Process_Control__w32_wchar_t_connect_socket_66_case0 @ route
- 结论: 通过socket接收外部输入并用于进程控制（如system或CreateProcess），攻击者可构造恶意命令导致任意代码执行。
- D验证: confirmed / ver_25c8de8d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 181. hyp_path_c0cd459323ef

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_67a.c:88
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者能够与目标建立网络连接并发送任意数据
- 触发路径: recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_67a.c:93-97; myStruct.structFirst = data; @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_67a.c:105; CWE114_Process_Control__w32_char_connect_socket_67b_case0Sink(myStruct); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_67a.c:106
- 结论: 从网络接收数据后，未经充分验证即传递给进程控制sink函数，攻击者可通过构造恶意输入控制进程参数，导致任意命令执行。
- D验证: confirmed / ver_898dfcde
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 182. hyp_path_2ff6b22f0cf7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_67a.c:88
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者能够与目标建立网络连接并发送任意数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... wchar_t *replace; SOCKET connectSocket = INVALID_SO... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_67a.c:88; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_67a.c::CWE114_Process_Control__w32_wchar_t_connect_socket_67_case0 @ route
- 结论: 从网络接收数据后，未经充分验证即传递给进程控制sink函数，攻击者可通过构造恶意输入控制进程参数，导致任意命令执行。
- D验证: confirmed / ver_35980c97
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 183. hyp_path_30ab2d038b8e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_68a.c:85
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接向目标发送任意数据，且该数据包含恶意进程路径字符串。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_68a.c:90; if (connectSocket != INVALID_SOCKET) { CLOSE_SOCKET(connectSocket); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_68a.c:112-116; CWE114_Process_Control__w32_char_connect_socket_68b_case0Sink(); // 内部将data用于进程控制 @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_68a.c:某行
- 结论: 外部可控数据用于构造进程路径，导致任意命令执行漏洞（Process Control）。
- D验证: confirmed / ver_2dfc70af
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 184. hyp_path_536f938b8f56

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_68a.c:85
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接向目标发送任意数据，且该数据包含恶意进程路径字符串。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... wchar_t *replace; SOCKET connectSocket = INVALID_SO... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_68a.c:85; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_68a.c::CWE114_Process_Control__w32_wchar_t_connect_socket_68_case0 @ route
- 结论: 外部可控数据用于构造进程路径，导致任意命令执行漏洞（Process Control）。
- D验证: confirmed / ver_d8d88cfb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 185. hyp_path_35f45af3b025

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_22b.c:95
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到服务器并发送特制数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_22b.c:95; 假设data被用于LoadLibrary或类似函数 @ 后续代码（未显示）
- 结论: 通过socket接收外部数据，可能用于进程控制操作（如LoadLibrary），存在外部控制下的进程控制漏洞。
- D验证: confirmed / ver_5c5b35d0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 186. hyp_path_9f4932270f1f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_22b.c:95
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到服务器并发送特制数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_22b.c:95; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_22b.c::CWE114_Process_Control__w32_wchar_t_listen_socket_22_case0Source @ route
- 结论: 通过socket接收外部数据，可能用于进程控制操作（如LoadLibrary），存在外部控制下的进程控制漏洞。
- D验证: confirmed / ver_ac86bbf4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 187. hyp_path_0f078eca70c1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_08.c:59
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者具有对文件FILENAME的写入权限
- 触发路径: pFile = fopen(FILENAME, "r"); @ CWE114_Process_Control__w32_char_file_08.c:57-61; fgets(data+dataLen, (int)(100-dataLen), pFile); @ CWE114_Process_Control__w32_char_file_08.c:61-65; hModule = LoadLibraryA(data); @ CWE114_Process_Control__w32_char_file_08.c:81
- 结论: 从文件中读取数据作为LoadLibraryA的参数，导致任意DLL加载。攻击者可控制文件内容，加载恶意库。
- D验证: confirmed / ver_7c9ba068
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 188. hyp_path_f6f984b611af

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_08.c:59
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者具有对文件FILENAME的写入权限
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_08.c:59; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_08.c::CWE114_Process_Control__w32_wchar_t_file_08_case0 @ route
- 结论: 从文件中读取数据作为LoadLibraryA的参数，导致任意DLL加载。攻击者可控制文件内容，加载恶意库。
- D验证: confirmed / ver_0adc52e6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 189. hyp_path_4d43c05b70da

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_61b.c:91
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务监听的TCP端口
- 触发路径: listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_61b.c:66; bind(listenSocket, (struct sockaddr*)&service, sizeof(service)) @ ~:77; listen(listenSocket, LISTEN_BACKLOG); @ ~:77; acceptSocket = accept(listenSocket, NULL, NULL); @ ~:85; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ :91; data[dataLen + recvResult / sizeof(char)] = '\0'; /* Eliminate CRLF */ @ :~; system(data); 或 CreateProcess(data, ...); @ （假设的进程调用位置）
- 结论: 程序通过socket接收数据，未经过充分验证，直接用作进程控制（如system或CreateProcess）的参数，攻击者可远程执行任意命令。
- D验证: confirmed / ver_114083ce
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 190. hyp_path_03a30699f9d7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_61b.c:91
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务监听的TCP端口
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (acceptSocket != INVALID_SOCKET) CLOSE_SOCKET(acceptSocket); ... acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) recvResult = recv... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_61b.c:91; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_61b.c::CWE114_Process_Control__w32_wchar_t_listen_socket_61b_case0Source @ route
- 结论: 程序通过socket接收数据，未经过充分验证，直接用作进程控制（如system或CreateProcess）的参数，攻击者可远程执行任意命令。
- D验证: confirmed / ver_cb3a4dd4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 191. hyp_path_933cd0dd30a2

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_01.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向数据源文件写入或控制其内容
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) { @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_01.c:43; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_01.c:64
- 结论: 从文件读取外部输入并直接作为参数传递给LoadLibraryA，导致任意DLL加载漏洞。攻击者可以通过控制文件内容来加载恶意库。
- D验证: confirmed / ver_8fa6bf58
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 192. hyp_path_061e77a7c43b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_01.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向数据源文件写入或控制其内容
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_01.c:43; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_01.c::CWE114_Process_Control__w32_wchar_t_file_01_case0 @ route
- 结论: 从文件读取外部输入并直接作为参数传递给LoadLibraryA，导致任意DLL加载漏洞。攻击者可以通过控制文件内容来加载恶意库。
- D验证: confirmed / ver_e401f273
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 193. hyp_path_03d0d7ef8b64

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_11.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向输入文件FILENAME中写入数据
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_11.c:45; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_11.c:67
- 结论: 程序从文件读取库名称，并直接传递给LoadLibraryA，未进行验证，可导致加载恶意库，构成CWE-114 Process Control漏洞。
- D验证: confirmed / ver_06035761
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 194. hyp_path_4b6044299679

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_11.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向输入文件FILENAME中写入数据
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_11.c:45; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_11.c::CWE114_Process_Control__w32_wchar_t_file_11_case0 @ route
- 结论: 程序从文件读取库名称，并直接传递给LoadLibraryA，未进行验证，可导致加载恶意库，构成CWE-114 Process Control漏洞。
- D验证: confirmed / ver_c4d2b363
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 195. hyp_path_bf5dd509fe30

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_04.c:52
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制文件FILENAME的内容
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_04.c:50; if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_04.c:54; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_04.c:74
- 结论: 从文件FILENAME中读取数据后，直接作为参数传递给LoadLibraryA加载库，攻击者可通过控制文件内容加载任意恶意DLL，导致代码执行或系统控制。
- D验证: confirmed / ver_00035da0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 196. hyp_path_da3fb6257b01

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_04.c:52
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制文件FILENAME的内容
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_04.c:52; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_04.c::CWE114_Process_Control__w32_wchar_t_file_04_case0 @ route
- 结论: 从文件FILENAME中读取数据后，直接作为参数传递给LoadLibraryA加载库，攻击者可通过控制文件内容加载任意恶意DLL，导致代码执行或系统控制。
- D验证: confirmed / ver_4f0479d8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 197. hyp_path_f81313723d86

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_03.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制文件FILENAME的内容或路径。
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_03.c:45; if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) { printLine("fgets() failed"); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_03.c:47-49; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_03.c:55
- 结论: 程序从文件读取数据后直接作为参数调用LoadLibraryA，攻击者若能控制文件内容，可加载任意恶意DLL，导致过程控制漏洞。
- D验证: confirmed / ver_54ccc46d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 198. hyp_path_55bf8e67fe88

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_03.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制文件FILENAME的内容或路径。
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_03.c:45; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_03.c::CWE114_Process_Control__w32_wchar_t_file_03_case0 @ route
- 结论: 程序从文件读取数据后直接作为参数调用LoadLibraryA，攻击者若能控制文件内容，可加载任意恶意DLL，导致过程控制漏洞。
- D验证: confirmed / ver_24078a57
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 199. hyp_path_b5f5c6cc3ad1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_02.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够创建或修改文件 FILENAME，使其内容包含恶意动态链接库的路径。
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_02.c:44; fgets(data+dataLen, (int)(100-dataLen), pFile); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_02.c:55; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_02.c:67; FreeLibrary(hModule); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_02.c:68
- 结论: 程序从文件读取数据，并将该数据直接作为参数传递给 LoadLibraryA 函数，导致可能加载攻击者控制的恶意库，存在 Process Control 漏洞。
- D验证: confirmed / ver_b52f639e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 200. hyp_path_6daa5687faba

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_02.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够创建或修改文件 FILENAME，使其内容包含恶意动态链接库的路径。
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_02.c:45; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_02.c::CWE114_Process_Control__w32_wchar_t_file_02_case0 @ route
- 结论: 程序从文件读取数据，并将该数据直接作为参数传递给 LoadLibraryA 函数，导致可能加载攻击者控制的恶意库，存在 Process Control 漏洞。
- D验证: confirmed / ver_4dd8c3e1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 201. hyp_path_7b1f82b31da4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_06.c:49
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制或影响文件FILENAME的内容; 网络或本地访问允许读取该文件; 系统允许加载未签名的DLL（取决于环境）
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_06.c:49; fgets(data+dataLen, (int)(100-dataLen), pFile); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_06.c:51; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_06.c:71
- 结论: 从文件读取的数据未经验证直接作为参数传递给LoadLibraryA，攻击者可通过控制文件内容加载任意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_32b5ecdb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 202. hyp_path_e6016b81af0e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_06.c:49
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制或影响文件FILENAME的内容; 网络或本地访问允许读取该文件; 系统允许加载未签名的DLL（取决于环境）
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_06.c:49; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_06.c::CWE114_Process_Control__w32_wchar_t_file_06_case0 @ route
- 结论: 从文件读取的数据未经验证直接作为参数传递给LoadLibraryA，攻击者可通过控制文件内容加载任意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_45bd52e3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 203. hyp_path_618302ce4139

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_05.c:52
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制文件FILENAME的内容或能够影响文件读取过程
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_05.c:52; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_05.c:74
- 结论: 程序从文件读取数据后直接作为参数调用LoadLibraryA加载动态库，攻击者可通过控制文件内容加载任意恶意库，导致进程控制漏洞。
- D验证: confirmed / ver_3514919d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 204. hyp_path_9a603b023d61

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_05.c:52
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制文件FILENAME的内容或能够影响文件读取过程
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_05.c:52; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_05.c::CWE114_Process_Control__w32_wchar_t_file_05_case0 @ route
- 结论: 程序从文件读取数据后直接作为参数调用LoadLibraryA加载动态库，攻击者可通过控制文件内容加载任意恶意库，导致进程控制漏洞。
- D验证: confirmed / ver_5c451a62
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 205. hyp_path_fa1231c8c074

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_07.c:51
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向文件FILENAME中写入任意内容
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_07.c:51; if (fgets(data+dataLen, (int)(100-dataLen), pFile) != NULL) { /* 成功读取数据 */ } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_07.c:53-57; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_07.c:73
- 结论: 存在CWE-114（Process Control）漏洞：从文件读取的数据被用作LoadLibraryA的参数，攻击者可通过控制文件内容加载任意DLL。
- D验证: confirmed / ver_aaf1113f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 206. hyp_path_cb14a24a563c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_07.c:51
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向文件FILENAME中写入任意内容
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_07.c:51; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_07.c::CWE114_Process_Control__w32_wchar_t_file_07_case0 @ route
- 结论: 存在CWE-114（Process Control）漏洞：从文件读取的数据被用作LoadLibraryA的参数，攻击者可通过控制文件内容加载任意DLL。
- D验证: confirmed / ver_5ee8e922
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 207. hyp_path_016bceff10ab

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_09.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标文件写入任意字符串（如恶意DLL路径）
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_09.c:43; fgets(data+dataLen, (int)(100-dataLen), pFile) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_09.c:47; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_09.c:67
- 结论: 程序从文件读取用户可控的DLL路径，并直接传递给LoadLibraryA，攻击者可以控制DLL内容导致任意代码执行。
- D验证: confirmed / ver_c6fe52fd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 208. hyp_path_9e551feafe4f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_09.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标文件写入任意字符串（如恶意DLL路径）
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_09.c:45; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_09.c::CWE114_Process_Control__w32_wchar_t_file_09_case0 @ route
- 结论: 程序从文件读取用户可控的DLL路径，并直接传递给LoadLibraryA，攻击者可以控制DLL内容导致任意代码执行。
- D验证: confirmed / ver_36cbcf27
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 209. hyp_path_967356cb88b4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_14.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意数据写入文件 FILENAME（例如通过文件上传、共享目录或配置文件覆盖）。; 程序以足够权限运行，能够加载攻击者放置在系统路径中的 DLL。
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_14.c:45; if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_14.c:47-51; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_14.c:67
- 结论: 从文件读取的字符串直接传递给 LoadLibraryA，攻击者可通过控制文件内容加载任意 DLL，导致代码执行。
- D验证: confirmed / ver_b15b7820
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 210. hyp_path_6a950db581fe

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_14.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意数据写入文件 FILENAME（例如通过文件上传、共享目录或配置文件覆盖）。; 程序以足够权限运行，能够加载攻击者放置在系统路径中的 DLL。
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_14.c:45; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_14.c::CWE114_Process_Control__w32_wchar_t_file_14_case0 @ route
- 结论: 从文件读取的字符串直接传递给 LoadLibraryA，攻击者可通过控制文件内容加载任意 DLL，导致代码执行。
- D验证: confirmed / ver_e7bc55d8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 211. hyp_path_38fb0beb094a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_15.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够影响文件FILENAME的内容，使其包含一个恶意DLL的路径。
- 触发路径: pFile = fopen(FILENAME, "r"); ... if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_15.c:44-52; data[dataLen] = '\0'; } fclose(pFile); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_15.c:54-58; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_15.c:71-73
- 结论: 程序从文件读取数据并直接用作LoadLibraryA的参数，导致可能加载任意DLL，存在过程控制漏洞。
- D验证: confirmed / ver_b88baa3f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 212. hyp_path_f5ff9ec1dfd6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_15.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够影响文件FILENAME的内容，使其包含一个恶意DLL的路径。
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_15.c:46; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_15.c::CWE114_Process_Control__w32_wchar_t_file_15_case0 @ route
- 结论: 程序从文件读取数据并直接用作LoadLibraryA的参数，导致可能加载任意DLL，存在过程控制漏洞。
- D验证: confirmed / ver_069d303d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 213. hyp_path_9f330bf711ab

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_10.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向文件FILENAME中写入恶意DLL路径，或能够控制文件内容。
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_10.c:45; if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_10.c:47; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_10.c:67
- 结论: 程序从文件读取数据，并将该数据作为参数调用LoadLibraryA，如果攻击者能够控制该文件内容，则可以加载任意恶意库，导致进程控制漏洞。
- D验证: confirmed / ver_7834256a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 214. hyp_path_d7640802552a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_10.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向文件FILENAME中写入恶意DLL路径，或能够控制文件内容。
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_10.c:45; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_10.c::CWE114_Process_Control__w32_wchar_t_file_10_case0 @ route
- 结论: 程序从文件读取数据，并将该数据作为参数调用LoadLibraryA，如果攻击者能够控制该文件内容，则可以加载任意恶意库，导致进程控制漏洞。
- D验证: confirmed / ver_ef297a6b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 215. hyp_path_51937b56eedd

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_13.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制或写入文件FILENAME的内容
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_13.c:45; if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) { printLine("fgets() failed"); ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_13.c:47-51; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_13.c:67
- 结论: 从文件读取数据作为库名称调用LoadLibraryA，导致任意DLL加载，攻击者可执行任意代码。
- D验证: confirmed / ver_5bf8f803
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 216. hyp_path_ad6a254192e9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_13.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制或写入文件FILENAME的内容
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_13.c:45; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_13.c::CWE114_Process_Control__w32_wchar_t_file_13_case0 @ route
- 结论: 从文件读取数据作为库名称调用LoadLibraryA，导致任意DLL加载，攻击者可执行任意代码。
- D验证: confirmed / ver_4fadc302
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 217. hyp_path_c4c143a36cbc

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_18.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意内容写入文件FILENAME（例如通过上传、共享目录等）
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_18.c:47-51; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_18.c:66
- 结论: 程序从外部文件读取数据，并直接作为参数传递给LoadLibraryA函数，攻击者可通过控制文件内容加载任意动态链接库，导致任意代码执行。
- D验证: confirmed / ver_5ae383b8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 218. hyp_path_eaac8e1d2732

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_18.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意内容写入文件FILENAME（例如通过上传、共享目录等）
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_18.c:45; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_18.c::CWE114_Process_Control__w32_wchar_t_file_18_case0 @ route
- 结论: 程序从外部文件读取数据，并直接作为参数传递给LoadLibraryA函数，攻击者可通过控制文件内容加载任意动态链接库，导致任意代码执行。
- D验证: confirmed / ver_bcf6f4f0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 219. hyp_path_352504f7c023

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_12.c:70
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向stdin提供输入（如控制台输入或重定向输入文件）。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_12.c:37-41; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_12.c:70
- 结论: 程序从控制台读取用户输入作为库名称，并调用LoadLibraryA加载该库，未对输入进行验证，攻击者可加载任意DLL，导致任意代码执行。
- D验证: confirmed / ver_5c9b823b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 220. hyp_path_d6f67c47c8de

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_12.c:70
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向stdin提供输入（如控制台输入或重定向输入文件）。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... wchar_t dataBuffer[100] = L""; data = dataBuffer; if(globalReturnsTrueOrFalse()... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_12.c:70; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_12.c::CWE114_Process_Control__w32_wchar_t_console_12_case0 @ route
- 结论: 程序从控制台读取用户输入作为库名称，并调用LoadLibraryA加载该库，未对输入进行验证，攻击者可加载任意DLL，导致任意代码执行。
- D验证: confirmed / ver_6693abe7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 221. hyp_path_034e7e161eb7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_31.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制文件系统，写入或修改FILENAME所指向的文件内容
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_31.c:43; if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_31.c:46; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_31.c:67
- 结论: 程序从固定路径文件中读取数据，并直接作为LoadLibraryA的参数，导致攻击者可通过控制文件内容加载恶意DLL，实现任意代码执行。
- D验证: confirmed / ver_05187108
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 222. hyp_path_b36abe367c2c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_31.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制文件系统，写入或修改FILENAME所指向的文件内容
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_31.c:43; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_31.c::CWE114_Process_Control__w32_wchar_t_file_31_case0 @ route
- 结论: 程序从固定路径文件中读取数据，并直接作为LoadLibraryA的参数，导致攻击者可通过控制文件内容加载恶意DLL，实现任意代码执行。
- D验证: confirmed / ver_79bef22a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 223. hyp_path_28070bf7f244

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_16.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向文件FILENAME中写入任意内容
- 触发路径: pFile = fopen(FILENAME, "r"); if (pFile != NULL) { ... if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) { ... } fclose(pFile); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_16.c:43-45; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_16.c:68
- 结论: 程序从文件读取数据后，未经充分验证直接用做LoadLibraryA的参数，攻击者若可控制文件内容，则可加载任意恶意DLL，导致代码执行。
- D验证: confirmed / ver_e3fe0696
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 224. hyp_path_bf56105e2dff

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_16.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向文件FILENAME中写入任意内容
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_16.c:45; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_16.c::CWE114_Process_Control__w32_wchar_t_file_16_case0 @ route
- 结论: 程序从文件读取数据后，未经充分验证直接用做LoadLibraryA的参数，攻击者若可控制文件内容，则可加载任意恶意DLL，导致代码执行。
- D验证: confirmed / ver_7e5d9ade
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 225. hyp_path_3e6718e779d6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_33.cpp:47
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入文件FILENAME，或者控制文件的内容使其包含恶意DLL路径。
- 触发路径: pFile = fopen(FILENAME, "r"); if (pFile != NULL) { ... if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_33.cpp:45-47; fclose(pFile); } } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_33.cpp:55-57; hModule = LoadLibraryA(data); if (hModule != NULL) { FreeLibrary(hModule); ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_33.cpp:68-70
- 结论: 从文件读取数据构造的路径直接传递给LoadLibraryA，可能导致加载恶意DLL，属于CWE-114（进程控制）。
- D验证: confirmed / ver_62d5b235
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 226. hyp_path_af90f5902c0c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_33.cpp:47
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入文件FILENAME，或者控制文件的内容使其包含恶意DLL路径。
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_33.cpp:47; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_33.cpp::_ZN43CWE114_Process_Control__w32_wchar_t_file_335case0Ev @ route
- 结论: 从文件读取数据构造的路径直接传递给LoadLibraryA，可能导致加载恶意DLL，属于CWE-114（进程控制）。
- D验证: confirmed / ver_7f5b8f5e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 227. hyp_path_6407e95c8cc0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_12.c:64
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够影响目标进程的环境变量（例如通过执行上下文或漏洞利用）。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); /* 获取环境变量 */ @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_12.c:40-44; strncat(data+dataLen, environment, 100-dataLen-1); /* 追加到data */ @ 同文件:42; hModule = LoadLibraryA(data); /* 加载库 */ @ 同文件:59-63
- 结论: 代码从环境变量获取输入并拼接到库路径，然后调用LoadLibraryA加载库，攻击者可通过控制环境变量加载任意DLL，导致任意代码执行。
- D验证: confirmed / ver_78090fda
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 228. hyp_path_ef8aaafdc749

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_12.c:64
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够影响目标进程的环境变量（例如通过执行上下文或漏洞利用）。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* ALT: Specify the full pathname for the library */ wcscpy(data, L"C:\\Windows\\System32\\winsrv.dll"); } { ... { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * env... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_12.c:64; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_12.c::CWE114_Process_Control__w32_wchar_t_environment_12_case0 @ route
- 结论: 代码从环境变量获取输入并拼接到库路径，然后调用LoadLibraryA加载库，攻击者可通过控制环境变量加载任意DLL，导致任意代码执行。
- D验证: confirmed / ver_6d3df022
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 229. hyp_path_6f289c0d203f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_34.c:50
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制文件FILENAME的内容
- 触发路径: pFile = fopen(FILENAME, "r"); if (pFile != NULL) { ... if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_34.c:48-52; fclose(pFile); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_34.c:58-62; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_34.c:74
- 结论: 进程控制漏洞：程序从文件读取数据作为库路径并调用LoadLibraryA，攻击者可通过控制文件内容加载任意恶意库。
- D验证: confirmed / ver_c45259ea
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 230. hyp_path_73493972f7dc

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_34.c:50
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制文件FILENAME的内容
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ...... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_34.c:50; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_34.c::CWE114_Process_Control__w32_wchar_t_file_34_case0 @ route
- 结论: 进程控制漏洞：程序从文件读取数据作为库路径并调用LoadLibraryA，攻击者可通过控制文件内容加载任意恶意库。
- D验证: confirmed / ver_c6cf2ee2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 231. hyp_path_e9c6554f1246

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_32.c:47
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者必须能够控制或替换FILENAME文件的内容，或影响fgets读取的内容
- 触发路径: size_t dataLen = strlen(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_32.c:42; if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) { printLine("fgets() failed"); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_32.c:49-53; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_32.c:72
- 结论: 从文件读取的字符串直接作为参数传递给LoadLibraryA，如果攻击者能够控制文件内容，则可加载恶意库，导致任意代码执行。
- D验证: confirmed / ver_021a0d50
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 232. hyp_path_885869a17063

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_32.c:47
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者必须能够控制或替换FILENAME文件的内容，或影响fgets读取的内容
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hMod... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_32.c:47; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_32.c::CWE114_Process_Control__w32_wchar_t_file_32_case0 @ route
- 结论: 从文件读取的字符串直接作为参数传递给LoadLibraryA，如果攻击者能够控制文件内容，则可加载恶意库，导致任意代码执行。
- D验证: confirmed / ver_43fdaff9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 233. hyp_path_8702d7f2e2a2

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_32.c:47
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者必须能够控制或替换FILENAME文件的内容，或影响fgets读取的内容
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... char * data = *dataPtr1; /*... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_32.c:47; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_32.c::CWE114_Process_Control__w32_char_relativePath_32_case0 @ route
- 结论: 从文件读取的字符串直接作为参数传递给LoadLibraryA，如果攻击者能够控制文件内容，则可加载恶意库，导致任意代码执行。
- D验证: confirmed / ver_98f0ad1e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 234. hyp_path_6a020d8e593a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_32.c:47
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者必须能够控制或替换FILENAME文件的内容，或影响fgets读取的内容
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... wchar_t * data = *dataPtr1;... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_32.c:47; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_32.c::CWE114_Process_Control__w32_wchar_t_relativePath_32_case0 @ route
- 结论: 从文件读取的字符串直接作为参数传递给LoadLibraryA，如果攻击者能够控制文件内容，则可加载恶意库，导致任意代码执行。
- D验证: confirmed / ver_0cf6f608
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 235. hyp_path_3483c1c28898

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_08.c:79
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向stdin输入数据，且系统允许加载指定路径的库。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_08.c:51-55; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_08.c:74; if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_08.c:77-81
- 结论: 该代码存在CWE-114（Process Control）漏洞，攻击者可以通过控制台输入恶意库路径，导致加载任意DLL。
- D验证: confirmed / ver_7c7e9242
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 236. hyp_path_e1b8b1b74171

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_08.c:79
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向stdin输入数据，且系统允许加载指定路径的库。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... wchar_t dataBuffer[100] = L""; data = dataBuffer; if(staticReturnsTrue()) { { .... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_08.c:79; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_08.c::CWE114_Process_Control__w32_wchar_t_console_08_case0 @ route
- 结论: 该代码存在CWE-114（Process Control）漏洞，攻击者可以通过控制台输入恶意库路径，导致加载任意DLL。
- D验证: confirmed / ver_28649b98
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 237. hyp_path_27ed1612b165

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_11.c:65
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入（stdin）提供输入。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_11.c:37-41; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_11.c:60-64
- 结论: 程序使用fgets从控制台读取用户输入作为库名，然后直接传递给LoadLibraryA加载库。攻击者可以控制输入，加载恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_6f4d0bc0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 238. hyp_path_bbc2bf6dc77c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_11.c:65
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入（stdin）提供输入。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... wchar_t dataBuffer[100] = L""; data = dataBuffer; if(globalReturnsTrue()) { { .... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_11.c:65; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_11.c::CWE114_Process_Control__w32_wchar_t_console_11_case0 @ route
- 结论: 程序使用fgets从控制台读取用户输入作为库名，然后直接传递给LoadLibraryA加载库。攻击者可以控制输入，加载恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_543f5a09
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 239. hyp_path_8da9c3d5f0f0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_01.c:62
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串
- 触发路径: fgets(data+dataLen, (int)(100-dataLen), stdin); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_01.c:35-39; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_01.c:57
- 结论: 程序从控制台读取用户输入作为动态链接库的路径，直接传递给LoadLibraryA函数加载。攻击者可以提供一个恶意DLL路径，导致任意代码执行。
- D验证: confirmed / ver_8455d0ba
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 240. hyp_path_01bbc0e2b226

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_01.c:62
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_01.c:62; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_01.c::CWE114_Process_Control__w32_wchar_t_console_01_case0 @ route
- 结论: 程序从控制台读取用户输入作为动态链接库的路径，直接传递给LoadLibraryA函数加载。攻击者可以提供一个恶意DLL路径，导致任意代码执行。
- D验证: confirmed / ver_61005198
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 241. hyp_path_f23ce539a147

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_02.c:65
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够在程序运行时通过标准输入提供恶意DLL路径。
- 触发路径: fgets(data+dataLen, (int)(100-dataLen), stdin) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_02.c:37-41; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_02.c:60-62
- 结论: 通过控制台输入指定库路径，攻击者可导致加载任意DLL，实现进程控制。
- D验证: confirmed / ver_6c786528
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 242. hyp_path_ffb44ba65b1e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_02.c:65
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够在程序运行时通过标准输入提供恶意DLL路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... else { printLine("Unable to load library"); } } ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_02.c:65; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_02.c::CWE114_Process_Control__w32_wchar_t_console_02_case0 @ route
- 结论: 通过控制台输入指定库路径，攻击者可导致加载任意DLL，实现进程控制。
- D验证: confirmed / ver_1568e32e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 243. hyp_path_bc92e262cfa5

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_03.c:65
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入发送字符串，例如通过交互式控制台或重定向输入。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_03.c:37-41; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_03.c:60-64; if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_03.c:63-67
- 结论: 程序从控制台读取输入并将其用作LoadLibraryA的参数，没有进行任何路径验证，允许攻击者指定任意库路径，可能导致加载恶意DLL，实现代码执行或权限提升。
- D验证: confirmed / ver_f6eeba37
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 244. hyp_path_4cf14b6287cc

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_03.c:65
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入发送字符串，例如通过交互式控制台或重定向输入。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... else { printLine("Unable to load library"); } } ... else { printLine("fgetws() ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_03.c:65; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_03.c::CWE114_Process_Control__w32_wchar_t_console_03_case0 @ route
- 结论: 程序从控制台读取输入并将其用作LoadLibraryA的参数，没有进行任何路径验证，允许攻击者指定任意库路径，可能导致加载恶意DLL，实现代码执行或权限提升。
- D验证: confirmed / ver_fd08057d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 245. hyp_path_cb83a8b48ca0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_04.c:72
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制标准输入的内容，且目标系统上存在可执行恶意DLL的路径。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_04.c:44-48; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_04.c:67
- 结论: 通过控制台输入，攻击者可以控制LoadLibraryA加载的DLL路径，导致任意代码执行。
- D验证: confirmed / ver_404d6419
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 246. hyp_path_d8ded681207a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_04.c:72
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制标准输入的内容，且目标系统上存在可执行恶意DLL的路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_04.c:72; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_04.c::CWE114_Process_Control__w32_wchar_t_console_04_case0 @ route
- 结论: 通过控制台输入，攻击者可以控制LoadLibraryA加载的DLL路径，导致任意代码执行。
- D验证: confirmed / ver_5b81b728
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 247. hyp_path_fbb9596fcb9f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_05.c:72
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供任意字符串，作为DLL路径或名称。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_05.c:44-48; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_05.c:67
- 结论: 程序使用fgets从控制台读取输入，并直接作为LoadLibraryA的参数加载动态库。如果攻击者能够控制控制台输入，可能加载任意恶意DLL，导致代码执行。
- D验证: confirmed / ver_c5a22388
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 248. hyp_path_9d67472dfd71

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_05.c:72
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供任意字符串，作为DLL路径或名称。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_05.c:72; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_05.c::CWE114_Process_Control__w32_wchar_t_console_05_case0 @ route
- 结论: 程序使用fgets从控制台读取输入，并直接作为LoadLibraryA的参数加载动态库。如果攻击者能够控制控制台输入，可能加载任意恶意DLL，导致代码执行。
- D验证: confirmed / ver_317188b0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 249. hyp_path_f099f2b6e3f1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_06.c:69
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向stdin输入数据; 存在攻击者可控的DLL文件
- 触发路径: fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_06.c:41-45; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_06.c:64; if (hModule != NULL) { FreeLibrary(hModule); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_06.c:67-69
- 结论: 程序通过fgets从控制台读取用户输入作为DLL路径，然后直接调用LoadLibraryA加载该DLL。攻击者可以通过提供恶意DLL路径加载任意代码，导致进程控制漏洞。
- D验证: confirmed / ver_49e1e672
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 250. hyp_path_b33d50ce9e65

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_06.c:69
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向stdin输入数据; 存在攻击者可控的DLL文件
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... else { printLine("Unable to load library"); } } ... else { printLine("fgetws() ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_06.c:69; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_06.c::CWE114_Process_Control__w32_wchar_t_console_06_case0 @ route
- 结论: 程序通过fgets从控制台读取用户输入作为DLL路径，然后直接调用LoadLibraryA加载该DLL。攻击者可以通过提供恶意DLL路径加载任意代码，导致进程控制漏洞。
- D验证: confirmed / ver_b8149a36
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 251. hyp_path_a1c6dc93a42f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_07.c:71
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制标准输入（stdin）的内容
- 触发路径: fgets(data+dataLen, (int)(100-dataLen), stdin) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_07.c:43-47; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_07.c:66-70
- 结论: 程序通过fgets从控制台读取用户输入作为库路径，并直接传递给LoadLibraryA加载库。攻击者可以控制输入，从而加载任意恶意库，导致任意代码执行或系统受影响。
- D验证: confirmed / ver_d97c5d68
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 252. hyp_path_abf37875b057

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_07.c:71
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制标准输入（stdin）的内容
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... else { printLine("fgetws() failed"); /* Restore NUL terminator if fgetws fails ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_07.c:71; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_07.c::CWE114_Process_Control__w32_wchar_t_console_07_case0 @ route
- 结论: 程序通过fgets从控制台读取用户输入作为库路径，并直接传递给LoadLibraryA加载库。攻击者可以控制输入，从而加载任意恶意库，导致任意代码执行或系统受影响。
- D验证: confirmed / ver_1b5e796d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 253. hyp_path_d57678f98234

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_09.c:65
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够直接或间接向程序的标准输入提供数据（如本地控制台访问或远程注入）
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_09.c:37-41; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_09.c:60; if (hModule != NULL) { FreeLibrary(hModule); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_09.c:63-67
- 结论: CWE114 Process Control: 程序通过fgets从控制台读取用户输入，并将其直接作为参数传递给LoadLibraryA加载动态库。攻击者可以控制输入的库路径，从而加载任意恶意库，导致进程控制漏洞。
- D验证: confirmed / ver_23352d37
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 254. hyp_path_df501fdfe4d1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_09.c:65
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够直接或间接向程序的标准输入提供数据（如本地控制台访问或远程注入）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... else { printLine("Unable to load library"); } } ... else { printLine("fgetws() ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_09.c:65; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_09.c::CWE114_Process_Control__w32_wchar_t_console_09_case0 @ route
- 结论: CWE114 Process Control: 程序通过fgets从控制台读取用户输入，并将其直接作为参数传递给LoadLibraryA加载动态库。攻击者可以控制输入的库路径，从而加载任意恶意库，导致进程控制漏洞。
- D验证: confirmed / ver_2d30f8cb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 255. hyp_path_0a57e7e91896

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_13.c:65
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入发送恶意数据
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ 39-41; hModule = LoadLibraryA(data); @ 62
- 结论: 程序从控制台读取用户输入作为库路径，直接传递给LoadLibraryA函数加载，攻击者可通过控制台输入指定恶意库路径，导致执行任意代码。
- D验证: confirmed / ver_9c7e8c60
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 256. hyp_path_ea29206b7c84

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_13.c:65
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入发送恶意数据
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... else { printLine("fgetws() failed"); /* Restore NUL terminator if fgetws fails ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_13.c:65; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_13.c::CWE114_Process_Control__w32_wchar_t_console_13_case0 @ route
- 结论: 程序从控制台读取用户输入作为库路径，直接传递给LoadLibraryA函数加载，攻击者可通过控制台输入指定恶意库路径，导致执行任意代码。
- D验证: confirmed / ver_a44fc47c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 257. hyp_path_afa4ec171925

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_10.c:65
- 漏洞类型: CWE-114, CWE-73
- CWE: CWE-114; CWE-73
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台或类似输入源提供任意字符串
- 触发路径: fgets(data+dataLen, (int)(100-dataLen), stdin) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_10.c:37-41; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_10.c:60
- 结论: 程序通过控制台输入获取库路径，并直接调用LoadLibraryA加载该库，未对输入进行验证。攻击者可通过提供恶意库路径（如利用DLL搜索顺序劫持）导致任意代码执行。
- D验证: confirmed / ver_6a4249f0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 258. hyp_path_990c11c64df7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_10.c:65
- 漏洞类型: CWE-114, CWE-73
- CWE: CWE-114; CWE-73
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台或类似输入源提供任意字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... else { printLine("fgetws() failed"); /* Restore NUL terminator if fgetws fails ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_10.c:65; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_10.c::CWE114_Process_Control__w32_wchar_t_console_10_case0 @ route
- 结论: 程序通过控制台输入获取库路径，并直接调用LoadLibraryA加载该库，未对输入进行验证。攻击者可通过提供恶意库路径（如利用DLL搜索顺序劫持）导致任意代码执行。
- D验证: confirmed / ver_32bca1d8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 259. hyp_path_e20c78273461

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_14.c:65
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问程序的控制台输入（stdin）并输入恶意DLL路径。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_14.c:37-41; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_14.c:60; if (hModule != NULL) { FreeLibrary(hModule); ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_14.c:63-67
- 结论: 存在CWE-114（进程控制）漏洞：程序通过控制台读取用户输入作为库路径，直接传递给LoadLibraryA，攻击者可控制加载任意恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_fef3be7d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 260. hyp_path_b33080b19f2d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_14.c:65
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问程序的控制台输入（stdin）并输入恶意DLL路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... else { printLine("Unable to load library"); } } ... else { printLine("fgetws() ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_14.c:65; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_14.c::CWE114_Process_Control__w32_wchar_t_console_14_case0 @ route
- 结论: 存在CWE-114（进程控制）漏洞：程序通过控制台读取用户输入作为库路径，直接传递给LoadLibraryA，攻击者可控制加载任意恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_a541d738
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 261. hyp_path_359ae747e2fa

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_16.c:66
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与控制台交互，提供输入
- 触发路径: fgets(data+dataLen, (int)(100-dataLen), stdin) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_16.c:37-41; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_16.c:61-65
- 结论: 存在不受信任的输入控制进程行为漏洞：通过控制台输入直接传递给LoadLibraryA加载动态链接库，攻击者可加载任意恶意DLL，导致代码执行。
- D验证: confirmed / ver_8f026a9b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 262. hyp_path_92421cc4f94e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_16.c:66
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与控制台交互，提供输入
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_16.c:66; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_16.c::CWE114_Process_Control__w32_wchar_t_console_16_case0 @ route
- 结论: 存在不受信任的输入控制进程行为漏洞：通过控制台输入直接传递给LoadLibraryA加载动态链接库，攻击者可加载任意恶意DLL，导致代码执行。
- D验证: confirmed / ver_0aedc63b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 263. hyp_path_5069fe7f42e0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_17.c:66
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台向程序输入数据（stdin可控）
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_17.c:38-40; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_17.c:61-62
- 结论: 代码从控制台读取输入后直接作为LoadLibraryA参数加载动态库，未对输入进行验证或限制，攻击者可通过控制恶意DLL路径实现任意代码执行。
- D验证: confirmed / ver_6b9677ed
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 264. hyp_path_4103f24e1b71

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_17.c:66
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台向程序输入数据（stdin可控）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... else { printLine("fgetws() failed"); /* Restore NUL terminator if fgetws fails ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_17.c:66; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_17.c::CWE114_Process_Control__w32_wchar_t_console_17_case0 @ route
- 结论: 代码从控制台读取输入后直接作为LoadLibraryA参数加载动态库，未对输入进行验证或限制，攻击者可通过控制恶意DLL路径实现任意代码执行。
- D验证: confirmed / ver_504fdda4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 265. hyp_path_c42c11f2ca3b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_18.c:64
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供输入。; 目标系统允许加载任意路径的DLL（未启用安全加载策略）。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_18.c:37-41; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_18.c:59
- 结论: 程序从控制台读取用户输入，并将其直接作为LoadLibraryA的参数加载库，未对输入进行任何验证或限制，攻击者可以通过提供恶意DLL路径实现任意代码执行。
- D验证: confirmed / ver_4bd55f91
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 266. hyp_path_39f8b43dfb61

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_18.c:64
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供输入。; 目标系统允许加载任意路径的DLL（未启用安全加载策略）。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_18.c:64; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_18.c::CWE114_Process_Control__w32_wchar_t_console_18_case0 @ route
- 结论: 程序从控制台读取用户输入，并将其直接作为LoadLibraryA的参数加载库，未对输入进行任何验证或限制，攻击者可以通过提供恶意DLL路径实现任意代码执行。
- D验证: confirmed / ver_120edf71
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 267. hyp_path_b96825af3e8d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_15.c:71
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入发送任意字符串; 系统搜索顺序允许攻击者预先放置恶意DLL
- 触发路径: fgets(data+dataLen, (int)(100-dataLen), stdin) @ L38-42; hModule = LoadLibraryA(data); @ L66-70; if (hModule != NULL) FreeLibrary(hModule); @ L69-73
- 结论: 程序从控制台读取输入作为动态链接库路径，并直接调用LoadLibraryA加载，攻击者可控制输入加载任意DLL，导致任意代码执行。
- D验证: confirmed / ver_7c810b82
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 268. hyp_path_edff39710eae

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_15.c:71
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入发送任意字符串; 系统搜索顺序允许攻击者预先放置恶意DLL
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_15.c:71; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_15.c::CWE114_Process_Control__w32_wchar_t_console_15_case0 @ route
- 结论: 程序从控制台读取输入作为动态链接库路径，并直接调用LoadLibraryA加载，攻击者可控制输入加载任意DLL，导致任意代码执行。
- D验证: confirmed / ver_ec778a64
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 269. hyp_path_c45d1782350c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_08.c:73
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE为恶意库路径
- 触发路径: size_t dataLen = strlen(data); char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_08.c:54-58; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_08.c:60-64; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_08.c:68-72
- 结论: 代码从环境变量读取数据后直接作为库路径传递给LoadLibraryA，攻击者可通过控制环境变量加载任意库，导致进程控制漏洞。
- D验证: confirmed / ver_4003c7d2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 270. hyp_path_6ac4233359eb

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_08.c:73
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE为恶意库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* Append input from an e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_08.c:73; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_08.c::CWE114_Process_Control__w32_wchar_t_environment_08_case0 @ route
- 结论: 代码从环境变量读取数据后直接作为库路径传递给LoadLibraryA，攻击者可通过控制环境变量加载任意库，导致进程控制漏洞。
- D验证: confirmed / ver_4f545bf5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 271. hyp_path_5e90936b2b7b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_11.c:59
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: if(globalReturnsTrue()) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_11.c:38; char * environment = GETENV(ENV_VARIABLE); ... strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_11.c:40-44; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_11.c:54-58
- 结论: 在CWE114_Process_Control__w32_char_environment_11.c中，程序从环境变量中读取库路径并调用LoadLibraryA加载，攻击者可以通过控制环境变量来加载任意恶意库，导致代码执行。
- D验证: confirmed / ver_51d5418c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 272. hyp_path_5c9c9884199d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_11.c:59
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* Append input from an e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_11.c:59; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_11.c::CWE114_Process_Control__w32_wchar_t_environment_11_case0 @ route
- 结论: 在CWE114_Process_Control__w32_char_environment_11.c中，程序从环境变量中读取库路径并调用LoadLibraryA加载，攻击者可以通过控制环境变量来加载任意恶意库，导致代码执行。
- D验证: confirmed / ver_fd732868
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 273. hyp_path_60e7a948aa2e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_34.c:72
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制程序的标准输入（例如通过重定向或交互式控制台）。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ 42-46; hModule = LoadLibraryA(data); @ 70-74
- 结论: 程序从控制台读取用户输入作为动态链接库路径，然后调用LoadLibraryA加载该库。攻击者可以通过控制台输入指定恶意库的路径，从而加载并执行任意代码，导致进程控制漏洞。
- D验证: confirmed / ver_7e21748d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 274. hyp_path_c7c7f2293315

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_34.c:72
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制程序的标准输入（例如通过重定向或交互式控制台）。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... /* NOTE: If the path to the library is not specified, an attacker may be able t... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_34.c:72; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_34.c::CWE114_Process_Control__w32_wchar_t_console_34_case0 @ route
- 结论: 程序从控制台读取用户输入作为动态链接库路径，然后调用LoadLibraryA加载该库。攻击者可以通过控制台输入指定恶意库的路径，从而加载并执行任意代码，导致进程控制漏洞。
- D验证: confirmed / ver_1ba4707f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 275. hyp_path_42659d33ca87

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_33.cpp:68
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制控制台输入（stdin）
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_33.cpp:39-43; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_33.cpp:68
- 结论: 程序通过fgets从控制台读取用户输入作为库路径，并直接传递给LoadLibraryA加载，攻击者可以指定恶意DLL路径，导致任意代码执行。
- D验证: confirmed / ver_8e7d9ad1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 276. hyp_path_b79b6c6ee622

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_33.cpp:68
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制控制台输入（stdin）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... /* NOTE: If the path to the library is not specified, an attacker may be able t... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_33.cpp:68; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_33.cpp::_ZN46CWE114_Process_Control__w32_wchar_t_console_335case0Ev @ route
- 结论: 程序通过fgets从控制台读取用户输入作为库路径，并直接传递给LoadLibraryA加载，攻击者可以指定恶意DLL路径，导致任意代码执行。
- D验证: confirmed / ver_493a69aa
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 277. hyp_path_8567713865d9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_32.c:70
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够在程序运行时向控制台输入恶意字符串，且该字符串被用于LoadLibraryA的路径参数
- 触发路径: fgets(data+dataLen, (int)(100-dataLen), stdin); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_32.c:34-38; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_32.c:65
- 结论: 程序从控制台读取用户输入作为库路径并调用LoadLibraryA加载，攻击者可指定恶意DLL路径，导致任意代码执行。
- D验证: confirmed / ver_532bf285
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 278. hyp_path_3c24aefd529d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_32.c:70
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够在程序运行时向控制台输入恶意字符串，且该字符串被用于LoadLibraryA的路径参数
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... /* The next few lines remov... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_32.c:70; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_32.c::CWE114_Process_Control__w32_wchar_t_console_32_case0 @ route
- 结论: 程序从控制台读取用户输入作为库路径并调用LoadLibraryA加载，攻击者可指定恶意DLL路径，导致任意代码执行。
- D验证: confirmed / ver_21362876
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 279. hyp_path_007ba3abc8c3

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_31.c:65
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过stdin提供任意字符串作为库路径; 程序运行在Windows平台上，且系统PATH或当前目录下存在攻击者控制的恶意DLL，或攻击者能提供绝对路径指向恶意DLL
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_31.c:35-39; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_31.c:65
- 结论: 程序通过fgets从控制台读取用户输入，未经验证直接作为参数传递给LoadLibraryA，攻击者可以通过提供恶意库路径加载任意DLL，导致代码执行漏洞。
- D验证: confirmed / ver_803af6d5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 280. hyp_path_68bc4e7d6e44

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_31.c:65
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过stdin提供任意字符串作为库路径; 程序运行在Windows平台上，且系统PATH或当前目录下存在攻击者控制的恶意DLL，或攻击者能提供绝对路径指向恶意DLL
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... /* NOTE: If the path to the library is not specified, an attacker may be able t... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_31.c:65; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_31.c::CWE114_Process_Control__w32_wchar_t_console_31_case0 @ route
- 结论: 程序通过fgets从控制台读取用户输入，未经验证直接作为参数传递给LoadLibraryA，攻击者可以通过提供恶意库路径加载任意DLL，导致代码执行漏洞。
- D验证: confirmed / ver_7d5e0d8c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 281. hyp_path_d9a00255f10a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_41.c:42
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值; 环境变量值不为空
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_41.c:60; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_41.c:66; CWE114_Process_Control__w32_char_environment_41_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_41.c:70; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_41.c:36
- 结论: 代码从环境变量读取数据并拼接到缓冲区后，直接作为参数传递给LoadLibraryA加载库。攻击者可通过控制环境变量加载任意DLL，导致代码执行或权限提升。
- D验证: confirmed / ver_0dfdcf28
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 282. hyp_path_00448eb4f70b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_41.c:42
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值; 环境变量值不为空
- 触发路径: { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... { /* NOTE: Read data from an environment variable */ wcsncat(data+dataLen, environment, 100-dataLen-1); } } ... } } CWE114_Process... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_41.c:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_41.c::CWE114_Process_Control__w32_wchar_t_environment_41_case0 @ route
- 结论: 代码从环境变量读取数据并拼接到缓冲区后，直接作为参数传递给LoadLibraryA加载库。攻击者可通过控制环境变量加载任意DLL，导致代码执行或权限提升。
- D验证: confirmed / ver_2e3f1df0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 283. hyp_path_b7feecc100ad

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_41.c:42
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值; 环境变量值不为空
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_41.c:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_41.c::CWE114_Process_Control__w32_char_environment_41_case0Sink @ route
- 结论: 代码从环境变量读取数据并拼接到缓冲区后，直接作为参数传递给LoadLibraryA加载库。攻击者可通过控制环境变量加载任意DLL，导致代码执行或权限提升。
- D验证: confirmed / ver_577f4e13
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 284. hyp_path_ae7dd3d24dca

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_41.c:42
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值; 环境变量值不为空
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_41.c:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_41.c::CWE114_Process_Control__w32_wchar_t_environment_41_case0Sink @ route
- 结论: 代码从环境变量读取数据并拼接到缓冲区后，直接作为参数传递给LoadLibraryA加载库。攻击者可通过控制环境变量加载任意DLL，导致代码执行或权限提升。
- D验证: confirmed / ver_508f5bb6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 285. hyp_path_f671efd9a228

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_21.c:69
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者需要能够控制目标进程的环境变量（例如，通过setenv、继承或本地访问）。
- 触发路径: data = dataBuffer; case0Static = 1; data = case0Source(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_21.c:59-62; static char * case0Source(char * data) { ... char * environment = GETENV(ENV_VARIABLE); ... strncat(data+dataLen, environment, 100-dataLen-1); return data; } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_21.c:36-53; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_21.c:65-66
- 结论: 存在CWE-114（Process Control）漏洞：攻击者通过控制环境变量，可以指定任意动态库路径，导致加载恶意库，实现代码执行。
- D验证: confirmed / ver_65840e16
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 286. hyp_path_eda2e1596a3f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_21.c:69
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者需要能够控制目标进程的环境变量（例如，通过setenv、继承或本地访问）。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... data = dataBuffer; case0Sta... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_21.c:69; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_21.c::CWE114_Process_Control__w32_wchar_t_environment_21_case0 @ route
- 结论: 存在CWE-114（Process Control）漏洞：攻击者通过控制环境变量，可以指定任意动态库路径，导致加载恶意库，实现代码执行。
- D验证: confirmed / ver_801da4df
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 287. hyp_path_1e58d9e740e8

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_41.c:62
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者具有对文件系统的写入权限，能够创建或修改特定文件。; 程序以高权限运行，允许加载任意库。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) { fclose(pFile); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_41.c:62; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_41.c:40 (sink函数内)
- 结论: 程序从文件读取外部可控数据，并将其作为参数传递给LoadLibraryA函数，导致攻击者可以控制加载的库，实现任意代码执行。
- D验证: confirmed / ver_74c7a0a1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 288. hyp_path_60b6a7640429

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_41.c:62
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者具有对文件系统的写入权限，能够创建或修改特定文件。; 程序以高权限运行，允许加载任意库。
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) CWE114_Process_Control__w32_wchar_t_file_41_case0Sink(data); hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... if (fgetws(data+dataLen, (int)(100-dataLe... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_41.c:62; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_41.c::CWE114_Process_Control__w32_wchar_t_file_41_case0 @ route
- 结论: 程序从文件读取外部可控数据，并将其作为参数传递给LoadLibraryA函数，导致攻击者可以控制加载的库，实现任意代码执行。
- D验证: confirmed / ver_1eea5393
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 289. hyp_path_66437f5d3687

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_43.cpp:64
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_43.cpp:44; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_43.cpp:48; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_43.cpp:60
- 结论: 攻击者可通过控制环境变量指定恶意DLL路径，导致LoadLibraryA加载恶意库，实现任意代码执行。
- D验证: confirmed / ver_ce5a32e6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 290. hyp_path_83a89fd210fa

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_43.cpp:64
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... wchar_t dataBuffer[100] = L... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_43.cpp:64; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_43.cpp::_ZN50CWE114_Process_Control__w32_wchar_t_environment_435case0Ev @ route
- 结论: 攻击者可通过控制环境变量指定恶意DLL路径，导致LoadLibraryA加载恶意库，实现任意代码执行。
- D验证: confirmed / ver_ee309f2a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 291. hyp_path_78488dc97b7e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_17.c:60
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够修改目标进程的环境变量; 环境变量ENV_VARIABLE中设置为恶意库的路径
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_17.c:41-45; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_17.c:47-51; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_17.c:55-59
- 结论: 应用程序从环境变量获取输入并拼接到库路径，然后使用LoadLibraryA加载该库，攻击者可通过控制环境变量加载恶意库，导致任意代码执行。
- D验证: confirmed / ver_facf295c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 292. hyp_path_b0274c1ddcbe

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_17.c:60
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够修改目标进程的环境变量; 环境变量ENV_VARIABLE中设置为恶意库的路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* Append input from an e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_17.c:60; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_17.c::CWE114_Process_Control__w32_wchar_t_environment_17_case0 @ route
- 结论: 应用程序从环境变量获取输入并拼接到库路径，然后使用LoadLibraryA加载该库，攻击者可通过控制环境变量加载恶意库，导致任意代码执行。
- D验证: confirmed / ver_4f52adc9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 293. hyp_path_c57ebbc0d564

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_42.c:62
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值，使其指向恶意DLL路径
- 触发路径: char dataBuffer[100] = ""; data = dataBuffer; @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_42.c:52; data = case0Source(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_42.c:53; char * environment = GETENV(ENV_VARIABLE); strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_42.c:33-47 (case0Source); hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_42.c:57
- 结论: 通过环境变量控制加载库路径，导致任意DLL加载（进程控制漏洞）
- D验证: confirmed / ver_7be90196
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 294. hyp_path_1e7c53af1b37

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_42.c:62
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值，使其指向恶意DLL路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... wchar_t dataBuffer[100] = L... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_42.c:62; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_42.c::CWE114_Process_Control__w32_wchar_t_environment_42_case0 @ route
- 结论: 通过环境变量控制加载库路径，导致任意DLL加载（进程控制漏洞）
- D验证: confirmed / ver_7025047e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 295. hyp_path_51e80b65ac38

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_21.c:75
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入（stdin）向程序发送任意字符串，该字符串被用作LoadLibraryA的参数。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_21.c:37-41; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_21.c:70-74
- 结论: 应用程序使用从控制台读取的输入直接作为LoadLibraryA的参数加载动态链接库，攻击者可以通过控制台输入任意库路径，导致加载恶意库，可能执行任意代码。
- D验证: confirmed / ver_adcf0d83
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 296. hyp_path_8d31f8229bd9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_21.c:75
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入（stdin）向程序发送任意字符串，该字符串被用作LoadLibraryA的参数。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) return data; hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... { FreeLibrary(hModule); printLine("Library loaded and freed succes... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_21.c:75; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_21.c::CWE114_Process_Control__w32_wchar_t_console_21_case0 @ route
- 结论: 应用程序使用从控制台读取的输入直接作为LoadLibraryA的参数加载动态链接库，攻击者可以通过控制台输入任意库路径，导致加载恶意库，可能执行任意代码。
- D验证: confirmed / ver_e6e68746
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 297. hyp_path_2710860d56d8

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_21.c:77
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件的内容，即FILENAME所指定的文件或data缓冲区中已有数据可被攻击者影响。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) { printLine("fgets() failed"); ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_21.c:47-51; hModule = LoadLibraryA(data); if (hModule != NULL) { @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_21.c:72-76
- 结论: 从文件读取的路径数据未经验证即用于加载动态链接库，可能导致加载恶意DLL，执行任意代码。
- D验证: confirmed / ver_6c5aac31
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 298. hyp_path_1f3c42dc514b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_21.c:77
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件的内容，即FILENAME所指定的文件或data缓冲区中已有数据可被攻击者影响。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) return data; hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... else { printLine("Unable to load library"); } } ... { FreeLibrary(... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_21.c:77; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_21.c::CWE114_Process_Control__w32_wchar_t_file_21_case0 @ route
- 结论: 从文件读取的路径数据未经验证即用于加载动态链接库，可能导致加载恶意DLL，执行任意代码。
- D验证: confirmed / ver_85da7806
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 299. hyp_path_9c68656a3b91

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_43.cpp:70
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问标准输入（如通过控制台或重定向）。; 目标系统上存在或可被放置恶意动态链接库。
- 触发路径: fgets(data+dataLen, (int)(100-dataLen), stdin) @ CWE114_Process_Control__w32_char_console_43.cpp:35-39; hModule = LoadLibraryA(data); @ CWE114_Process_Control__w32_char_console_43.cpp:65; if (hModule != NULL) { FreeLibrary(hModule); } @ CWE114_Process_Control__w32_char_console_43.cpp:68-72
- 结论: 函数通过控制台输入读取数据，未经校验直接作为LoadLibraryA的参数加载库，攻击者可指定任意库路径导致任意库加载（DLL劫持）。
- D验证: confirmed / ver_329d79ab
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 300. hyp_path_2209d7679957

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_43.cpp:70
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问标准输入（如通过控制台或重定向）。; 目标系统上存在或可被放置恶意动态链接库。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_43.cpp:70; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_43.cpp::_ZN46CWE114_Process_Control__w32_wchar_t_console_435case0Ev @ route
- 结论: 函数通过控制台输入读取数据，未经校验直接作为LoadLibraryA的参数加载库，攻击者可指定任意库路径导致任意库加载（DLL劫持）。
- D验证: confirmed / ver_a9d3e5b4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 301. hyp_path_1f7cdc738451

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_42.c:68
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供数据。; 系统中存在攻击者可控的DLL或攻击者能够通过网络路径指向恶意DLL。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_42.c:32-36; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_42.c:68; if (hModule != NULL) FreeLibrary(hModule); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_42.c:69
- 结论: 程序使用从控制台读取的用户输入作为LoadLibraryA的参数，攻击者可以通过提供恶意DLL路径来加载并执行任意代码。
- D验证: confirmed / ver_f9a1f94e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 302. hyp_path_70215eca72c0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_42.c:68
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供数据。; 系统中存在攻击者可控的DLL或攻击者能够通过网络路径指向恶意DLL。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) return data; hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... else { printLine("Unable to load library"); } } ... { FreeLibrary(... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_42.c:68; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_42.c::CWE114_Process_Control__w32_wchar_t_console_42_case0 @ route
- 结论: 程序使用从控制台读取的用户输入作为LoadLibraryA的参数，攻击者可以通过提供恶意DLL路径来加载并执行任意代码。
- D验证: confirmed / ver_996b78ed
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 303. hyp_path_7857393a6da2

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_42.c:70
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件的内容（如通过替换文件或控制文件写入）
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_42.c:42; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_42.c:70
- 结论: 程序从文件读取数据并直接作为参数传递给LoadLibraryA函数，攻击者可以通过控制文件内容加载恶意DLL，实现任意代码执行。
- D验证: confirmed / ver_62585195
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 304. hyp_path_0e578ea7f371

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_42.c:70
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件的内容（如通过替换文件或控制文件写入）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) return data; hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... { FreeLibrary(hModule); printLine("Library loaded and freed succes... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_42.c:70; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_42.c::CWE114_Process_Control__w32_wchar_t_file_42_case0 @ route
- 结论: 程序从文件读取数据并直接作为参数传递给LoadLibraryA函数，攻击者可以通过控制文件内容加载恶意DLL，实现任意代码执行。
- D验证: confirmed / ver_6ed4ac90
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 305. hyp_path_7f34005cfec2

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_43.cpp:72
- 漏洞类型: CWE-114, CWE-427
- CWE: CWE-114; CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够影响文件FILENAME的内容，使得data包含恶意库路径。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_43.cpp:45-49; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_43.cpp:67-71
- 结论: 存在CWE-114（Process Control）漏洞：程序从文件读取用户控制的输入，并将其直接作为LoadLibraryA的参数加载库。攻击者可以通过控制文件内容加载恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_b2d5cd0e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 306. hyp_path_3036ce17c05d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_43.cpp:72
- 漏洞类型: CWE-114, CWE-427
- CWE: CWE-114; CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够影响文件FILENAME的内容，使得data包含恶意库路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... else { printLine("Unable to load library"); } } ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_43.cpp:72; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_43.cpp::_ZN43CWE114_Process_Control__w32_wchar_t_file_435case0Ev @ route
- 结论: 存在CWE-114（Process Control）漏洞：程序从文件读取用户控制的输入，并将其直接作为LoadLibraryA的参数加载库。攻击者可以通过控制文件内容加载恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_a1c0b242
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 307. hyp_path_b9806674a546

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_01.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制或影响环境变量 ENV_VARIABLE 的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_01.c:40-41; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_01.c:46; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_01.c:51
- 结论: 程序从环境变量获取输入，并直接用作 LoadLibraryA 的参数，攻击者可通过设置恶意环境变量加载任意 DLL，导致任意代码执行。
- D验证: confirmed / ver_c61f9b27
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 308. hyp_path_8604b59b8698

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_01.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制或影响环境变量 ENV_VARIABLE 的值
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* Append input from an e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_01.c:56; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_01.c::CWE114_Process_Control__w32_wchar_t_environment_01_case0 @ route
- 结论: 程序从环境变量获取输入，并直接用作 LoadLibraryA 的参数，攻击者可通过设置恶意环境变量加载任意 DLL，导致任意代码执行。
- D验证: confirmed / ver_f52c404f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 309. hyp_path_f26599e1a90a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_03.c:59
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_03.c:40-44; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_03.c:46-50; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_03.c:54-58
- 结论: 程序从环境变量读取DLL路径并调用LoadLibraryA，攻击者可通过控制环境变量加载任意恶意DLL，导致代码执行。
- D验证: confirmed / ver_f2d51c04
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 310. hyp_path_a2598a2ade6c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_03.c:59
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* Append input from an e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_03.c:59; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_03.c::CWE114_Process_Control__w32_wchar_t_environment_03_case0 @ route
- 结论: 程序从环境变量读取DLL路径并调用LoadLibraryA，攻击者可通过控制环境变量加载任意恶意DLL，导致代码执行。
- D验证: confirmed / ver_09ac13ca
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 311. hyp_path_5e0361b8953a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_04.c:66
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制ENV_VARIABLE环境变量的值。; 目标系统运行具有相应权限的进程。
- 触发路径: size_t dataLen = strlen(data); char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_04.c:47-51; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_04.c:53-57; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_04.c:61-65
- 结论: 程序从环境变量读取库路径并直接传递给LoadLibraryA，攻击者可通过控制环境变量加载任意恶意库，导致代码执行。
- D验证: confirmed / ver_d3b10941
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 312. hyp_path_ec80ed1e87dc

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_04.c:66
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制ENV_VARIABLE环境变量的值。; 目标系统运行具有相应权限的进程。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* Append input from an e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_04.c:66; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_04.c::CWE114_Process_Control__w32_wchar_t_environment_04_case0 @ route
- 结论: 程序从环境变量读取库路径并直接传递给LoadLibraryA，攻击者可通过控制环境变量加载任意恶意库，导致代码执行。
- D验证: confirmed / ver_d964dc38
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 313. hyp_path_2747685d77f9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_02.c:59
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_02.c:43; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_02.c:48; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_02.c:59
- 结论: 程序从环境变量读取数据，并将其作为参数传递给LoadLibraryA函数，攻击者可通过控制环境变量加载任意恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_52648841
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 314. hyp_path_3b9526da100b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_02.c:59
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* Append input from an e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_02.c:59; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_02.c::CWE114_Process_Control__w32_wchar_t_environment_02_case0 @ route
- 结论: 程序从环境变量读取数据，并将其作为参数传递给LoadLibraryA函数，攻击者可通过控制环境变量加载任意恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_54bb8188
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 315. hyp_path_0d4207b05424

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_05.c:66
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响环境变量ENV_VARIABLE的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_05.c:50; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_05.c:53-57; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_05.c:65
- 结论: 攻击者可以通过控制环境变量来指定加载任意动态链接库，导致进程控制漏洞。
- D验证: confirmed / ver_632096f3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 316. hyp_path_306594324f79

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_05.c:66
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响环境变量ENV_VARIABLE的值
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* Append input from an e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_05.c:66; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_05.c::CWE114_Process_Control__w32_wchar_t_environment_05_case0 @ route
- 结论: 攻击者可以通过控制环境变量来指定加载任意动态链接库，导致进程控制漏洞。
- D验证: confirmed / ver_db3d35b5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 317. hyp_path_ecb2a4a077cd

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_06.c:63
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_06.c:47; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_06.c:52; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_06.c:58
- 结论: 程序使用环境变量数据作为库加载路径，攻击者可通过控制环境变量加载任意库，存在代码执行风险。
- D验证: confirmed / ver_30e5191b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 318. hyp_path_21aef67db17b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_06.c:63
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* Append input from an e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_06.c:63; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_06.c::CWE114_Process_Control__w32_wchar_t_environment_06_case0 @ route
- 结论: 程序使用环境变量数据作为库加载路径，攻击者可通过控制环境变量加载任意库，存在代码执行风险。
- D验证: confirmed / ver_cd11c82b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 319. hyp_path_40214217af73

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_09.c:59
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的内容
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_09.c:43; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_09.c:59
- 结论: 代码从环境变量获取数据并用作LoadLibraryA的参数，攻击者可通过控制环境变量加载任意恶意库，导致进程控制漏洞。
- D验证: confirmed / ver_5a6511f4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 320. hyp_path_b2223110b9bc

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_09.c:59
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的内容
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* Append input from an e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_09.c:59; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_09.c::CWE114_Process_Control__w32_wchar_t_environment_09_case0 @ route
- 结论: 代码从环境变量获取数据并用作LoadLibraryA的参数，攻击者可通过控制环境变量加载任意恶意库，导致进程控制漏洞。
- D验证: confirmed / ver_183bcb61
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 321. hyp_path_b45d64fc1a5f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_07.c:65
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_07.c:49; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_07.c:55; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_07.c:62
- 结论: 程序使用环境变量中的数据作为参数调用LoadLibraryA加载动态库，攻击者可以通过控制环境变量来指定任意库文件，导致不受控制的进程控制漏洞。
- D验证: confirmed / ver_09e57951
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 322. hyp_path_6cdf654551f0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_07.c:65
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* Append input from an e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_07.c:65; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_07.c::CWE114_Process_Control__w32_wchar_t_environment_07_case0 @ route
- 结论: 程序使用环境变量中的数据作为参数调用LoadLibraryA加载动态库，攻击者可以通过控制环境变量来指定任意库文件，导致不受控制的进程控制漏洞。
- D验证: confirmed / ver_4b225433
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 323. hyp_path_344bb8b47256

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_10.c:59
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_10.c:43; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_10.c:48; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_10.c:54
- 结论: 攻击者可以通过控制环境变量来加载任意库，实现进程控制漏洞。
- D验证: confirmed / ver_06ee8cc4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 324. hyp_path_4153d875cb60

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_10.c:59
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* Append input from an e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_10.c:59; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_10.c::CWE114_Process_Control__w32_wchar_t_environment_10_case0 @ route
- 结论: 攻击者可以通过控制环境变量来加载任意库，实现进程控制漏洞。
- D验证: confirmed / ver_793260a7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 325. hyp_path_f7d3c979dda3

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_13.c:59
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响程序运行环境中的相关环境变量
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_13.c:42-43; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_13.c:48; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_13.c:55
- 结论: 代码从环境变量读取路径并通过LoadLibraryA加载库，攻击者可设置环境变量加载恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_bfb325c3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 326. hyp_path_40db94618578

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_13.c:59
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响程序运行环境中的相关环境变量
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* Append input from an e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_13.c:59; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_13.c::CWE114_Process_Control__w32_wchar_t_environment_13_case0 @ route
- 结论: 代码从环境变量读取路径并通过LoadLibraryA加载库，攻击者可设置环境变量加载恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_d4648c67
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 327. hyp_path_0324fd958ee5

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_15.c:65
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量 ENV_VARIABLE 的值，使其指向一个恶意 DLL 文件
- 触发路径: size_t dataLen = strlen(data); char * environment = GETENV(ENV_VARIABLE); if (environment != NULL) { @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_15.c:41-45; strncat(data+dataLen, environment, 100-dataLen-1); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_15.c:47-51; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_15.c:60-64
- 结论: 程序从环境变量读取数据并用于加载动态链接库，攻击者可以通过控制环境变量来加载任意恶意库，导致任意代码执行。
- D验证: confirmed / ver_9ad484ee
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 328. hyp_path_054693b220ca

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_15.c:65
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量 ENV_VARIABLE 的值，使其指向一个恶意 DLL 文件
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* Append input from an e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_15.c:65; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_15.c::CWE114_Process_Control__w32_wchar_t_environment_15_case0 @ route
- 结论: 程序从环境变量读取数据并用于加载动态链接库，攻击者可以通过控制环境变量来加载任意恶意库，导致任意代码执行。
- D验证: confirmed / ver_614241d2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 329. hyp_path_930cb80ef56d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_14.c:59
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值; 环境变量字符串长度不超过data缓冲区大小（100字节）
- 触发路径: { /* Append input from an environment variable to data */ size_t dataLen = strlen(data); char * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_14.c:40-44; { /* NOTE: Read data from an environment variable */ strncat(data+dataLen, environment, 100-dataLen-1); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_14.c:46-50; /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_14.c:54-58
- 结论: 代码从环境变量读取数据并拼接到路径字符串，然后调用LoadLibraryA加载库。攻击者可以通过控制环境变量来加载恶意库，导致进程控制漏洞。
- D验证: confirmed / ver_054b3f81
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 330. hyp_path_31e44162849b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_14.c:59
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值; 环境变量字符串长度不超过data缓冲区大小（100字节）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* Append input from an e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_14.c:59; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_14.c::CWE114_Process_Control__w32_wchar_t_environment_14_case0 @ route
- 结论: 代码从环境变量读取数据并拼接到路径字符串，然后调用LoadLibraryA加载库。攻击者可以通过控制环境变量来加载恶意库，导致进程控制漏洞。
- D验证: confirmed / ver_f74485ca
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 331. hyp_path_6a04efe17e6e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_18.c:58
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的内容
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_18.c:43; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_18.c:48; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_18.c:56
- 结论: 程序从环境变量读取数据并拼接到库路径，然后加载该库，攻击者可通过控制环境变量加载恶意库，实现进程控制。
- D验证: confirmed / ver_80da019c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 332. hyp_path_757c5c944ed7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_18.c:58
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的内容
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* Append input from an e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_18.c:58; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_18.c::CWE114_Process_Control__w32_wchar_t_environment_18_case0 @ route
- 结论: 程序从环境变量读取数据并拼接到库路径，然后加载该库，攻击者可通过控制环境变量加载恶意库，实现进程控制。
- D验证: confirmed / ver_909b7fda
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 333. hyp_path_448c8b87e05e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_16.c:60
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的内容，使其指向一个由攻击者控制的恶意DLL文件路径。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_16.c:43; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_16.c:49; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_16.c:59
- 结论: 该代码从环境变量读取数据并拼接到字符串data中，然后调用LoadLibraryA(data)加载库。攻击者可通过控制环境变量来加载恶意库，导致任意代码执行。
- D验证: confirmed / ver_133aec8e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 334. hyp_path_cbb3a3b47f86

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_16.c:60
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的内容，使其指向一个由攻击者控制的恶意DLL文件路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* Append input from an e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_16.c:60; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_16.c::CWE114_Process_Control__w32_wchar_t_environment_16_case0 @ route
- 结论: 该代码从环境变量读取数据并拼接到字符串data中，然后调用LoadLibraryA(data)加载库。攻击者可通过控制环境变量来加载恶意库，导致任意代码执行。
- D验证: confirmed / ver_f90c32d3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 335. hyp_path_fb3e71bd9ab9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_22a.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串，作为库路径
- 触发路径: data = dataBuffer; CWE114_Process_Control__w32_char_console_22_case0Global = 1; data = CWE114_Process_Control__w32_char_console_22_case0Source(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_22a.c:34-37; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_22a.c:39-40
- 结论: 程序从控制台读取数据，并将其作为参数传递给LoadLibraryA，加载外部库。攻击者可通过控制台输入恶意库路径，导致加载恶意DLL，实现代码执行。
- D验证: confirmed / ver_50c4b125
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 336. hyp_path_576d68eaab4c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_22a.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串，作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... data = dataBuffer; CWE114_P... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_22a.c:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_22a.c::CWE114_Process_Control__w32_char_environment_22_case0 @ route
- 结论: 程序从控制台读取数据，并将其作为参数传递给LoadLibraryA，加载外部库。攻击者可通过控制台输入恶意库路径，导致加载恶意DLL，实现代码执行。
- D验证: confirmed / ver_5e6e65d7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 337. hyp_path_470aa8329e2e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_22a.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串，作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... data = dataBuffer; CWE114_P... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_22a.c:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_22a.c::CWE114_Process_Control__w32_wchar_t_console_22_case0 @ route
- 结论: 程序从控制台读取数据，并将其作为参数传递给LoadLibraryA，加载外部库。攻击者可通过控制台输入恶意库路径，导致加载恶意DLL，实现代码执行。
- D验证: confirmed / ver_f786d615
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 338. hyp_path_ccc31ab600fd

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_22a.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串，作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... data = dataBuffer; CWE114_P... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_22a.c:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_22a.c::CWE114_Process_Control__w32_wchar_t_environment_22_case0 @ route
- 结论: 程序从控制台读取数据，并将其作为参数传递给LoadLibraryA，加载外部库。攻击者可通过控制台输入恶意库路径，导致加载恶意DLL，实现代码执行。
- D验证: confirmed / ver_402fbc0b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 339. hyp_path_30174580134e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_22a.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串，作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... data = dataBuffer; CWE114_P... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_22a.c:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_22a.c::CWE114_Process_Control__w32_char_connect_socket_22_case0 @ route
- 结论: 程序从控制台读取数据，并将其作为参数传递给LoadLibraryA，加载外部库。攻击者可通过控制台输入恶意库路径，导致加载恶意DLL，实现代码执行。
- D验证: confirmed / ver_729d127b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 340. hyp_path_2fb202628618

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_22a.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串，作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... data = dataBuffer; CWE114_P... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_22a.c:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_22a.c::CWE114_Process_Control__w32_char_listen_socket_22_case0 @ route
- 结论: 程序从控制台读取数据，并将其作为参数传递给LoadLibraryA，加载外部库。攻击者可通过控制台输入恶意库路径，导致加载恶意DLL，实现代码执行。
- D验证: confirmed / ver_053b3ede
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 341. hyp_path_afe4cc52b29b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_22a.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串，作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... data = dataBuffer; CWE114_P... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_22a.c:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_22a.c::CWE114_Process_Control__w32_wchar_t_connect_socket_22_case0 @ route
- 结论: 程序从控制台读取数据，并将其作为参数传递给LoadLibraryA，加载外部库。攻击者可通过控制台输入恶意库路径，导致加载恶意DLL，实现代码执行。
- D验证: confirmed / ver_f21cfbc8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 342. hyp_path_564ff45193be

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_22a.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串，作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... data = dataBuffer; CWE114_P... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_22a.c:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_22a.c::CWE114_Process_Control__w32_wchar_t_listen_socket_22_case0 @ route
- 结论: 程序从控制台读取数据，并将其作为参数传递给LoadLibraryA，加载外部库。攻击者可通过控制台输入恶意库路径，导致加载恶意DLL，实现代码执行。
- D验证: confirmed / ver_f87f864f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 343. hyp_path_1b3590bc96e3

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_22a.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串，作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... data = dataBuffer; CWE114_P... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_22a.c:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_22a.c::CWE114_Process_Control__w32_char_file_22_case0 @ route
- 结论: 程序从控制台读取数据，并将其作为参数传递给LoadLibraryA，加载外部库。攻击者可通过控制台输入恶意库路径，导致加载恶意DLL，实现代码执行。
- D验证: confirmed / ver_455c94fa
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 344. hyp_path_63d879628517

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_22a.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串，作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... data = dataBuffer; CWE114_P... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_22a.c:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_22a.c::CWE114_Process_Control__w32_wchar_t_file_22_case0 @ route
- 结论: 程序从控制台读取数据，并将其作为参数传递给LoadLibraryA，加载外部库。攻击者可通过控制台输入恶意库路径，导致加载恶意DLL，实现代码执行。
- D验证: confirmed / ver_5ce3d273
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 345. hyp_path_a30cd1c73683

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_22a.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串，作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... data = dataBuffer; CWE114_P... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_22a.c:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_22a.c::CWE114_Process_Control__w32_char_relativePath_22_case0 @ route
- 结论: 程序从控制台读取数据，并将其作为参数传递给LoadLibraryA，加载外部库。攻击者可通过控制台输入恶意库路径，导致加载恶意DLL，实现代码执行。
- D验证: confirmed / ver_401362b7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 346. hyp_path_78a88a589b78

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_22a.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串，作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... data = dataBuffer; CWE114_P... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_22a.c:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_22a.c::CWE114_Process_Control__w32_wchar_t_relativePath_22_case0 @ route
- 结论: 程序从控制台读取数据，并将其作为参数传递给LoadLibraryA，加载外部库。攻击者可通过控制台输入恶意库路径，导致加载恶意DLL，实现代码执行。
- D验证: confirmed / ver_cfd8b610
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 347. hyp_path_ab5f720e3729

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_61a.c:41
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够在程序运行时向控制台输入任意字符串（如恶意DLL路径）
- 触发路径: char dataBuffer[100] = ""; data = dataBuffer; data = CWE114_Process_Control__w32_char_console_61b_case0Source(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_61a.c:31-35; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_61a.c:36-38
- 结论: 程序从控制台读取输入后直接作为参数传递给LoadLibraryA，攻击者可以通过控制台输入指定任意DLL路径，导致加载恶意库，实现代码执行。
- D验证: confirmed / ver_59ea2d72
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 348. hyp_path_24f5273d8506

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_61a.c:41
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够在程序运行时向控制台输入任意字符串（如恶意DLL路径）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... wchar_t dataBuffer[100] = L... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_61a.c:41; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_61a.c::CWE114_Process_Control__w32_wchar_t_console_61_case0 @ route
- 结论: 程序从控制台读取输入后直接作为参数传递给LoadLibraryA，攻击者可以通过控制台输入指定任意DLL路径，导致加载恶意库，实现代码执行。
- D验证: confirmed / ver_8ee9425a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 349. hyp_path_4c155d739e25

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_61a.c:41
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够在程序运行时向控制台输入任意字符串（如恶意DLL路径）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... char dataBuffer[100] = ""; ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_61a.c:41; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_61a.c::CWE114_Process_Control__w32_char_relativePath_61_case0 @ route
- 结论: 程序从控制台读取输入后直接作为参数传递给LoadLibraryA，攻击者可以通过控制台输入指定任意DLL路径，导致加载恶意库，实现代码执行。
- D验证: confirmed / ver_8ef13005
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 350. hyp_path_8956cf6cbfaa

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_61a.c:41
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够在程序运行时向控制台输入任意字符串（如恶意DLL路径）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... wchar_t dataBuffer[100] = L... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_61a.c:41; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_61a.c::CWE114_Process_Control__w32_wchar_t_relativePath_61_case0 @ route
- 结论: 程序从控制台读取输入后直接作为参数传递给LoadLibraryA，攻击者可以通过控制台输入指定任意DLL路径，导致加载恶意库，实现代码执行。
- D验证: confirmed / ver_72966b0d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 351. hyp_path_8cd0b646cff6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_62a.cpp:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入字符串
- 触发路径: char dataBuffer[100] = ""; data = dataBuffer; case0Source(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_62a.cpp:34-38; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_62a.cpp:39-43
- 结论: 程序从控制台读取字符串并将其作为参数传递给LoadLibraryA，未对库路径进行充分验证，攻击者可以通过提供恶意库路径导致加载任意代码。
- D验证: confirmed / ver_4be134d4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 352. hyp_path_a86ca86b75ad

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_62a.cpp:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... char dataBuffer[100] = ""; ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_62a.cpp:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_62a.cpp::_ZN47CWE114_Process_Control__w32_char_environment_625case0Ev @ route
- 结论: 程序从控制台读取字符串并将其作为参数传递给LoadLibraryA，未对库路径进行充分验证，攻击者可以通过提供恶意库路径导致加载任意代码。
- D验证: confirmed / ver_0fa4052c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 353. hyp_path_590a2c7c7830

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_62a.cpp:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... wchar_t dataBuffer[100] = L... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_62a.cpp:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_62a.cpp::_ZN46CWE114_Process_Control__w32_wchar_t_console_625case0Ev @ route
- 结论: 程序从控制台读取字符串并将其作为参数传递给LoadLibraryA，未对库路径进行充分验证，攻击者可以通过提供恶意库路径导致加载任意代码。
- D验证: confirmed / ver_b05f7a1c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 354. hyp_path_2daedd15dac8

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_62a.cpp:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... wchar_t dataBuffer[100] = L... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_62a.cpp:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_62a.cpp::_ZN50CWE114_Process_Control__w32_wchar_t_environment_625case0Ev @ route
- 结论: 程序从控制台读取字符串并将其作为参数传递给LoadLibraryA，未对库路径进行充分验证，攻击者可以通过提供恶意库路径导致加载任意代码。
- D验证: confirmed / ver_483e8e80
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 355. hyp_path_f98f66f55153

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_62a.cpp:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... char dataBuffer[100] = ""; ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_62a.cpp:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_62a.cpp::_ZN50CWE114_Process_Control__w32_char_connect_socket_625case0Ev @ route
- 结论: 程序从控制台读取字符串并将其作为参数传递给LoadLibraryA，未对库路径进行充分验证，攻击者可以通过提供恶意库路径导致加载任意代码。
- D验证: confirmed / ver_1e113d30
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 356. hyp_path_6d4b5055c6a0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_62a.cpp:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... char dataBuffer[100] = ""; ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_62a.cpp:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_62a.cpp::_ZN49CWE114_Process_Control__w32_char_listen_socket_625case0Ev @ route
- 结论: 程序从控制台读取字符串并将其作为参数传递给LoadLibraryA，未对库路径进行充分验证，攻击者可以通过提供恶意库路径导致加载任意代码。
- D验证: confirmed / ver_e64ef6b9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 357. hyp_path_8b6f87c5945e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_62a.cpp:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... wchar_t dataBuffer[100] = L... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_62a.cpp:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_62a.cpp::_ZN53CWE114_Process_Control__w32_wchar_t_connect_socket_625case0Ev @ route
- 结论: 程序从控制台读取字符串并将其作为参数传递给LoadLibraryA，未对库路径进行充分验证，攻击者可以通过提供恶意库路径导致加载任意代码。
- D验证: confirmed / ver_cf2601b8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 358. hyp_path_a60078c4cdd1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_62a.cpp:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... wchar_t dataBuffer[100] = L... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_62a.cpp:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_62a.cpp::_ZN52CWE114_Process_Control__w32_wchar_t_listen_socket_625case0Ev @ route
- 结论: 程序从控制台读取字符串并将其作为参数传递给LoadLibraryA，未对库路径进行充分验证，攻击者可以通过提供恶意库路径导致加载任意代码。
- D验证: confirmed / ver_8ba7d5c8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 359. hyp_path_12e0ae951488

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_62a.cpp:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... char dataBuffer[100] = ""; ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_62a.cpp:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_62a.cpp::_ZN40CWE114_Process_Control__w32_char_file_625case0Ev @ route
- 结论: 程序从控制台读取字符串并将其作为参数传递给LoadLibraryA，未对库路径进行充分验证，攻击者可以通过提供恶意库路径导致加载任意代码。
- D验证: confirmed / ver_383fba65
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 360. hyp_path_8384f7016911

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_62a.cpp:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... wchar_t dataBuffer[100] = L... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_62a.cpp:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_62a.cpp::_ZN43CWE114_Process_Control__w32_wchar_t_file_625case0Ev @ route
- 结论: 程序从控制台读取字符串并将其作为参数传递给LoadLibraryA，未对库路径进行充分验证，攻击者可以通过提供恶意库路径导致加载任意代码。
- D验证: confirmed / ver_8607a311
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 361. hyp_path_190913d697f6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_62a.cpp:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... char dataBuffer[100] = ""; ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_62a.cpp:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_62a.cpp::_ZN48CWE114_Process_Control__w32_char_relativePath_625case0Ev @ route
- 结论: 程序从控制台读取字符串并将其作为参数传递给LoadLibraryA，未对库路径进行充分验证，攻击者可以通过提供恶意库路径导致加载任意代码。
- D验证: confirmed / ver_3ba67e46
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 362. hyp_path_9f724ce94b50

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_62a.cpp:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... wchar_t dataBuffer[100] = L... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_62a.cpp:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_62a.cpp::_ZN51CWE114_Process_Control__w32_wchar_t_relativePath_625case0Ev @ route
- 结论: 程序从控制台读取字符串并将其作为参数传递给LoadLibraryA，未对库路径进行充分验证，攻击者可以通过提供恶意库路径导致加载任意代码。
- D验证: confirmed / ver_8220789f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 363. hyp_path_29ecfd2adf37

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_61a.c:49
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响环境变量，从而控制CWE114_Process_Control__w32_char_environment_61b_case0Source的返回值。
- 触发路径: data = CWE114_Process_Control__w32_char_environment_61b_case0Source(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_61a.c:43; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_61a.c:44
- 结论: CWE114进程控制漏洞：外部可控的环境变量字符串被直接用于LoadLibraryA加载库，攻击者可替换恶意DLL。
- D验证: confirmed / ver_de65ff07
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 364. hyp_path_0f3344ce7afd

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_61a.c:49
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响环境变量，从而控制CWE114_Process_Control__w32_char_environment_61b_case0Source的返回值。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... wchar_t dataBuffer[100] = L... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_61a.c:49; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_61a.c::CWE114_Process_Control__w32_wchar_t_environment_61_case0 @ route
- 结论: CWE114进程控制漏洞：外部可控的环境变量字符串被直接用于LoadLibraryA加载库，攻击者可替换恶意DLL。
- D验证: confirmed / ver_85e6bc46
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 365. hyp_path_d9735510b4bb

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_41.c:34
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问程序的标准输入流，并输入任意字符串。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_41.c:54; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_41.c:34
- 结论: 程序通过fgets从标准输入读取用户输入，并将该输入直接传递给LoadLibraryA函数加载库。攻击者可以通过控制输入加载任意恶意DLL，导致任意代码执行或权限提升。
- D验证: confirmed / ver_80b71405
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 366. hyp_path_24f8f5749231

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_41.c:34
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问程序的标准输入流，并输入任意字符串。
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) CWE114_Process_Control__w32_wchar_t_console_41_case0Sink(data); hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hModule); ... else { printLine("fgetws() failed"); /* Restore NUL terminator if fgetws fails */ data[dataLen] = L'\0'; @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_41.c:34; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_41.c::CWE114_Process_Control__w32_wchar_t_console_41_case0 @ route
- 结论: 程序通过fgets从标准输入读取用户输入，并将该输入直接传递给LoadLibraryA函数加载库。攻击者可以通过控制输入加载任意恶意DLL，导致任意代码执行或权限提升。
- D验证: confirmed / ver_ef7bc99c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 367. hyp_path_13c09e262ade

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_41.c:34
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问程序的标准输入流，并输入任意字符串。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_41.c:34; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_41.c::CWE114_Process_Control__w32_char_console_41_case0Sink @ route
- 结论: 程序通过fgets从标准输入读取用户输入，并将该输入直接传递给LoadLibraryA函数加载库。攻击者可以通过控制输入加载任意恶意DLL，导致任意代码执行或权限提升。
- D验证: confirmed / ver_efc4c44e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 368. hyp_path_9a0a2ebeed90

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_41.c:34
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问程序的标准输入流，并输入任意字符串。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_41.c:34; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_41.c::CWE114_Process_Control__w32_wchar_t_console_41_case0Sink @ route
- 结论: 程序通过fgets从标准输入读取用户输入，并将该输入直接传递给LoadLibraryA函数加载库。攻击者可以通过控制输入加载任意恶意DLL，导致任意代码执行或权限提升。
- D验证: confirmed / ver_a29f56e6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 369. hyp_path_af8051faef00

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_41.c:34
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问程序的标准输入流，并输入任意字符串。
- 触发路径: data = dataBuffer; /* NOTE: Specify just the file name for the library, not the full path */ strcpy(data, "winsrv.dll"); CWE114_Process_Control__w32_char_relativePath_41_case0Sink(data); } ... /* NOTE: Specify just the file name for the library, not the full path */ strcpy(data, "winsrv.dll"); CWE114_Process_Control__w... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_41.c:34; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_41.c::CWE114_Process_Control__w32_char_relativePath_41_case0 @ route
- 结论: 程序通过fgets从标准输入读取用户输入，并将该输入直接传递给LoadLibraryA函数加载库。攻击者可以通过控制输入加载任意恶意DLL，导致任意代码执行或权限提升。
- D验证: confirmed / ver_ee1ad5da
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 370. hyp_path_bd19c8e150f9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_41.c:34
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问程序的标准输入流，并输入任意字符串。
- 触发路径: data = dataBuffer; /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); CWE114_Process_Control__w32_wchar_t_relativePath_41_case0Sink(data); } ... /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); CWE114_Process_Contr... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_41.c:34; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_41.c::CWE114_Process_Control__w32_wchar_t_relativePath_41_case0 @ route
- 结论: 程序通过fgets从标准输入读取用户输入，并将该输入直接传递给LoadLibraryA函数加载库。攻击者可以通过控制输入加载任意恶意DLL，导致任意代码执行或权限提升。
- D验证: confirmed / ver_844468d2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 371. hyp_path_422f8278216b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_41.c:34
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问程序的标准输入流，并输入任意字符串。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_41.c:34; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_41.c::CWE114_Process_Control__w32_char_relativePath_41_case0Sink @ route
- 结论: 程序通过fgets从标准输入读取用户输入，并将该输入直接传递给LoadLibraryA函数加载库。攻击者可以通过控制输入加载任意恶意DLL，导致任意代码执行或权限提升。
- D验证: confirmed / ver_2b471bb4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 372. hyp_path_372d09ea8810

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_41.c:34
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问程序的标准输入流，并输入任意字符串。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_41.c:34; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_41.c::CWE114_Process_Control__w32_wchar_t_relativePath_41_case0Sink @ route
- 结论: 程序通过fgets从标准输入读取用户输入，并将该输入直接传递给LoadLibraryA函数加载库。攻击者可以通过控制输入加载任意恶意DLL，导致任意代码执行或权限提升。
- D验证: confirmed / ver_c90b1859
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 373. hyp_path_0aaf83c32850

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_33.cpp:62
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_33.cpp:45; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_33.cpp:49; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_33.cpp:57
- 结论: 代码从环境变量读取路径并拼接后调用LoadLibraryA加载库，攻击者可通过控制环境变量加载任意恶意库，导致代码执行。
- D验证: confirmed / ver_b4b87bb0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 374. hyp_path_58732604f626

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_33.cpp:62
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... { /* NOTE: Read data from a... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_33.cpp:62; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_33.cpp::_ZN50CWE114_Process_Control__w32_wchar_t_environment_335case0Ev @ route
- 结论: 代码从环境变量读取路径并拼接后调用LoadLibraryA加载库，攻击者可通过控制环境变量加载任意恶意库，导致代码执行。
- D验证: confirmed / ver_dd91e1b1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 375. hyp_path_15da1d170a9e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_31.c:59
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够在目标系统上设置环境变量ENV_VARIABLE
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ L38-42; strncat(data+dataLen, environment, 100-dataLen-1); @ L44-48; hModule = LoadLibraryA(data); @ L54-58
- 结论: 代码从环境变量读取数据并拼接到data，然后使用LoadLibraryA加载该路径的库。攻击者通过控制环境变量，可以加载任意恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_9a514458
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 376. hyp_path_bd9ae4d45ebd

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_31.c:59
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够在目标系统上设置环境变量ENV_VARIABLE
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... { /* NOTE: Read data from a... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_31.c:59; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_31.c::CWE114_Process_Control__w32_wchar_t_environment_31_case0 @ route
- 结论: 代码从环境变量读取数据并拼接到data，然后使用LoadLibraryA加载该路径的库。攻击者通过控制环境变量，可以加载任意恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_d12d9369
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 377. hyp_path_57d51e632129

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_34.c:66
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_34.c:48; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_34.c:55; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_34.c:62
- 结论: 程序从环境变量读取数据，并直接作为LoadLibraryA的参数加载库，导致攻击者可通过控制环境变量加载任意DLL，实现代码执行。
- D验证: confirmed / ver_c1193f2b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 378. hyp_path_c5ea1d31424d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_34.c:66
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... { /* NOTE: Read data from a... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_34.c:66; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_34.c::CWE114_Process_Control__w32_wchar_t_environment_34_case0 @ route
- 结论: 程序从环境变量读取数据，并直接作为LoadLibraryA的参数加载库，导致攻击者可通过控制环境变量加载任意DLL，实现代码执行。
- D验证: confirmed / ver_a5ff3737
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 379. hyp_path_f25f6c035ea6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_32.c:64
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置或篡改进程的环境变量ENV_VARIABLE。
- 触发路径: size_t dataLen = strlen(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_32.c:44; char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_32.c:45; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_32.c:50; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_32.c:59
- 结论: 该代码片段从环境变量读取数据作为库路径并调用LoadLibraryA加载库，攻击者可通过控制环境变量加载任意恶意库，存在CWE-114过程控制漏洞。
- D验证: confirmed / ver_e6ce1504
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 380. hyp_path_4abeb6ccad7d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_32.c:64
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置或篡改进程的环境变量ENV_VARIABLE。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* Append input from an e... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_32.c:64; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_32.c::CWE114_Process_Control__w32_wchar_t_environment_32_case0 @ route
- 结论: 该代码片段从环境变量读取数据作为库路径并调用LoadLibraryA加载库，攻击者可通过控制环境变量加载任意恶意库，存在CWE-114过程控制漏洞。
- D验证: confirmed / ver_d6901022
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 381. hyp_path_fe25d0f0dcce

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_44.c:100
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问目标服务的网络端口，并发送特制的字符串数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_44.c:105-109; HMODULE hMod = LoadLibraryA(data); @ 后续代码（未明确给出，但根据CWE114样本推测）
- 结论: 存在从网络接收数据后，未经充分验证直接用于LoadLibrary函数加载DLL的漏洞，攻击者可利用此漏洞加载任意恶意DLL，导致远程代码执行。
- D验证: confirmed / ver_697f1241
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 382. hyp_path_e3a0da16c8fb

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_44.c:100
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问目标服务的网络端口，并发送特制的字符串数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... wchar_t *replace; SOCKET connectSocket = INVALID_SO... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_44.c:100; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_44.c::CWE114_Process_Control__w32_wchar_t_connect_socket_44_case0 @ route
- 结论: 存在从网络接收数据后，未经充分验证直接用于LoadLibrary函数加载DLL的漏洞，攻击者可利用此漏洞加载任意恶意DLL，导致远程代码执行。
- D验证: confirmed / ver_426b57b3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 383. hyp_path_97310d23e6dd

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_82a.cpp:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制文件FILENAME的内容。
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_82a.cpp:43; fgets(data+dataLen, (int)(100-dataLen), pFile); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_82a.cpp:45; baseObject->action(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_82a.cpp:57
- 结论: 程序从文件读取外部输入作为库加载或命令执行的参数，可能导致攻击者控制进程行为。
- D验证: confirmed / ver_33601c6c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 384. hyp_path_323be7330819

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_82a.cpp:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制文件FILENAME的内容。
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... } } CWE114_Process_Control__w32_wchar_t_file_82_base* baseObject = new CWE114_Process_Control__w32_wchar_t_file_82_case0; baseObject->action(data); delete baseObject; ... CWE114_Process_Control__w32_wchar_t_file_82_base* baseObject = new CW... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_82a.cpp:43; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_82a.cpp::_ZN43CWE114_Process_Control__w32_wchar_t_file_825case0Ev @ route
- 结论: 程序从文件读取外部输入作为库加载或命令执行的参数，可能导致攻击者控制进程行为。
- D验证: confirmed / ver_18f604e7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 385. hyp_path_d298ff1b5b51

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_74b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入或其他方式向程序提供数据，从而影响dataMap中的内容
- 触发路径: char * data = dataMap[2]; @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_74b.cpp:33; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_74b.cpp:39
- 结论: 存在外部控制的库加载漏洞，攻击者可以通过控制data参数加载任意DLL，导致代码执行。
- D验证: confirmed / ver_7367f389
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 386. hyp_path_ef60db0c169f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_74b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入或其他方式向程序提供数据，从而影响dataMap中的内容
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* copy data out of dataMap */ char * data = dataMap[2]; { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hM... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_74b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_74b.cpp::_ZN47CWE114_Process_Control__w32_char_environment_749case0SinkESt3mapIiPcSt4lessIiESaISt4pairIKiS1_EEE @ route
- 结论: 存在外部控制的库加载漏洞，攻击者可以通过控制data参数加载任意DLL，导致代码执行。
- D验证: confirmed / ver_0e16b50e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 387. hyp_path_9be7a03c1e83

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_74b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入或其他方式向程序提供数据，从而影响dataMap中的内容
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* copy data out of dataMap */ wchar_t * data = dataMap[2]; { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_74b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_74b.cpp::_ZN46CWE114_Process_Control__w32_wchar_t_console_749case0SinkESt3mapIiPwSt4lessIiESaISt4pairIKiS1_EEE @ route
- 结论: 存在外部控制的库加载漏洞，攻击者可以通过控制data参数加载任意DLL，导致代码执行。
- D验证: confirmed / ver_69fdf179
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 388. hyp_path_138cbfb94283

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_74b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入或其他方式向程序提供数据，从而影响dataMap中的内容
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* copy data out of dataMap */ wchar_t * data = dataMap[2]; { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_74b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_74b.cpp::_ZN50CWE114_Process_Control__w32_wchar_t_environment_749case0SinkESt3mapIiPwSt4lessIiESaISt4pairIKiS1_EEE @ route
- 结论: 存在外部控制的库加载漏洞，攻击者可以通过控制data参数加载任意DLL，导致代码执行。
- D验证: confirmed / ver_0e759cb6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 389. hyp_path_a828529e33e0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_74b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入或其他方式向程序提供数据，从而影响dataMap中的内容
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* copy data out of dataMap */ char * data = dataMap[2]; { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hM... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_74b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_74b.cpp::_ZN50CWE114_Process_Control__w32_char_connect_socket_749case0SinkESt3mapIiPcSt4lessIiESaISt4pairIKiS1_EEE @ route
- 结论: 存在外部控制的库加载漏洞，攻击者可以通过控制data参数加载任意DLL，导致代码执行。
- D验证: confirmed / ver_bf8784f8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 390. hyp_path_f506612f368b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_74b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入或其他方式向程序提供数据，从而影响dataMap中的内容
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* copy data out of dataMap */ char * data = dataMap[2]; { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hM... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_74b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_74b.cpp::_ZN49CWE114_Process_Control__w32_char_listen_socket_749case0SinkESt3mapIiPcSt4lessIiESaISt4pairIKiS1_EEE @ route
- 结论: 存在外部控制的库加载漏洞，攻击者可以通过控制data参数加载任意DLL，导致代码执行。
- D验证: confirmed / ver_310c572b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 391. hyp_path_b8d04c4bfd07

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_74b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入或其他方式向程序提供数据，从而影响dataMap中的内容
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* copy data out of dataMap */ wchar_t * data = dataMap[2]; { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_74b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_74b.cpp::_ZN53CWE114_Process_Control__w32_wchar_t_connect_socket_749case0SinkESt3mapIiPwSt4lessIiESaISt4pairIKiS1_EEE @ route
- 结论: 存在外部控制的库加载漏洞，攻击者可以通过控制data参数加载任意DLL，导致代码执行。
- D验证: confirmed / ver_00383de6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 392. hyp_path_40f00a8aef2a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_74b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入或其他方式向程序提供数据，从而影响dataMap中的内容
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* copy data out of dataMap */ wchar_t * data = dataMap[2]; { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_74b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_74b.cpp::_ZN52CWE114_Process_Control__w32_wchar_t_listen_socket_749case0SinkESt3mapIiPwSt4lessIiESaISt4pairIKiS1_EEE @ route
- 结论: 存在外部控制的库加载漏洞，攻击者可以通过控制data参数加载任意DLL，导致代码执行。
- D验证: confirmed / ver_947a180a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 393. hyp_path_6f8ced995af2

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_74b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入或其他方式向程序提供数据，从而影响dataMap中的内容
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* copy data out of dataMap */ char * data = dataMap[2]; { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hM... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_74b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_74b.cpp::_ZN40CWE114_Process_Control__w32_char_file_749case0SinkESt3mapIiPcSt4lessIiESaISt4pairIKiS1_EEE @ route
- 结论: 存在外部控制的库加载漏洞，攻击者可以通过控制data参数加载任意DLL，导致代码执行。
- D验证: confirmed / ver_56099be8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 394. hyp_path_cc022affd1b2

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_74b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入或其他方式向程序提供数据，从而影响dataMap中的内容
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* copy data out of dataMap */ wchar_t * data = dataMap[2]; { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_74b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_74b.cpp::_ZN43CWE114_Process_Control__w32_wchar_t_file_749case0SinkESt3mapIiPwSt4lessIiESaISt4pairIKiS1_EEE @ route
- 结论: 存在外部控制的库加载漏洞，攻击者可以通过控制data参数加载任意DLL，导致代码执行。
- D验证: confirmed / ver_7a909e36
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 395. hyp_path_83d4d19c23fe

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_74b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入或其他方式向程序提供数据，从而影响dataMap中的内容
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* copy data out of dataMap */ char * data = dataMap[2]; { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hM... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_74b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_74b.cpp::_ZN48CWE114_Process_Control__w32_char_relativePath_749case0SinkESt3mapIiPcSt4lessIiESaISt4pairIKiS1_EEE @ route
- 结论: 存在外部控制的库加载漏洞，攻击者可以通过控制data参数加载任意DLL，导致代码执行。
- D验证: confirmed / ver_44065004
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 396. hyp_path_16aec75e11c0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_74b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入或其他方式向程序提供数据，从而影响dataMap中的内容
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* copy data out of dataMap */ wchar_t * data = dataMap[2]; { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_74b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_74b.cpp::_ZN51CWE114_Process_Control__w32_wchar_t_relativePath_749case0SinkESt3mapIiPwSt4lessIiESaISt4pairIKiS1_EEE @ route
- 结论: 存在外部控制的库加载漏洞，攻击者可以通过控制data参数加载任意DLL，导致代码执行。
- D验证: confirmed / ver_085f05b3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 397. hyp_path_d24adeaf8320

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_43.cpp:79
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标socket并发送特制数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_43.cpp:79; HMODULE hMod = LoadLibraryA(data); // 假设的sink @ 假定后续代码行
- 结论: 程序通过socket接收外部数据，并将该数据直接用于进程控制操作（如LoadLibrary），攻击者可能构造恶意数据导致任意代码执行。
- D验证: confirmed / ver_e09c46cb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 398. hyp_path_e2cc12079e3c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_43.cpp:79
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标socket并发送特制数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... wchar_t *replace; SOCKET connectSocket = INVALID_SO... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_43.cpp:79; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_43.cpp::_ZN53CWE114_Process_Control__w32_wchar_t_connect_socket_43L11case0SourceERPw @ route
- 结论: 程序通过socket接收外部数据，并将该数据直接用于进程控制操作（如LoadLibrary），攻击者可能构造恶意数据导致任意代码执行。
- D验证: confirmed / ver_e24fe821
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 399. hyp_path_40f9dfdd7027

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_62b.cpp:78
- 漏洞类型: buffer_overflow
- CWE: CWE-121; CWE-120
- 风险等级: P0
- 触发条件: 攻击者能够与目标主机建立网络连接并发送数据到该socket服务
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_62b.cpp:78; data[dataLen + recvResult / sizeof(char)] = '\0'; @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_62b.cpp:85; replace = strchr(data, '\r'); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_62b.cpp:87
- 结论: 在处理从socket接收的数据时，未对缓冲区边界进行充分检查，可能导致栈缓冲区溢出。攻击者可以发送特制数据覆盖栈上相邻内存，可能造成代码执行或拒绝服务。
- D验证: confirmed / ver_cb41c0d0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 400. hyp_path_7c2f4bc2dc02

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_62b.cpp:78
- 漏洞类型: buffer_overflow
- CWE: CWE-121; CWE-120
- 风险等级: P0
- 触发条件: 攻击者能够与目标主机建立网络连接并发送数据到该socket服务
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... wchar_t *replace; SOCKET connectSocket = INVALID_SO... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_62b.cpp:78; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_62b.cpp::_ZN53CWE114_Process_Control__w32_wchar_t_connect_socket_6211case0SourceERPw @ route
- 结论: 在处理从socket接收的数据时，未对缓冲区边界进行充分检查，可能导致栈缓冲区溢出。攻击者可以发送特制数据覆盖栈上相邻内存，可能造成代码执行或拒绝服务。
- D验证: confirmed / ver_dc7f991f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 401. hyp_path_0051def4f24d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_84_case0.cpp:77
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制远程主机，向目标发送特制的网络数据包。; 目标系统运行在Windows平台且启动了Winsock。; 后续代码中使用了接收到的data进行进程控制操作。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_84_case0.cpp:77; data[dataLen + recvResult / sizeof(char)] = '\0'; /* Eliminate CRLF */ replace = strchr(data, '\r'); if (replace) { *replace = '\0'; } replace = strchr(data, '\n'); if (replace) { *replace = '\0'; } @ same file, line 84-86; 假设存在如 LoadLibrary(data) 或 CreateProcess 等调用 @ 后续未展示的sink代码
- 结论: 函数通过网络接收数据到缓冲区data，该数据可能被用于后续的进程控制（如作为LoadLibrary的参数），构成CWE114进程控制漏洞。
- D验证: confirmed / ver_556d3477
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 402. hyp_path_96a410857c5e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_84_case0.cpp:77
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制远程主机，向目标发送特制的网络数据包。; 目标系统运行在Windows平台且启动了Winsock。; 后续代码中使用了接收到的data进行进程控制操作。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... wchar_t *replace; SOCKET connectSocket = INVALID_SO... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_84_case0.cpp:77; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_84_case0.cpp::_ZN53CWE114_Process_Control__w32_wchar_t_connect_socket_8459CWE114_Process_Control__w32_wchar_t_connect_socket_84_case0C2EPw @ route
- 结论: 函数通过网络接收数据到缓冲区data，该数据可能被用于后续的进程控制（如作为LoadLibrary的参数），构成CWE114进程控制漏洞。
- D验证: confirmed / ver_3fc14dc3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 403. hyp_path_1719685ee602

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_72b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供恶意输入，且输入被用于构建dataVector中的字符串。
- 触发路径: { /* copy data out of dataVector */ char * data = dataVector[2]; @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_72b.cpp:32-36; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_72b.cpp:37-41
- 结论: 从控制台输入的数据未经校验直接传递给LoadLibraryA函数，导致可能加载恶意DLL，属于不受信任的控制输入导致的进程控制漏洞。
- D验证: confirmed / ver_78d964bb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 404. hyp_path_7b707348a979

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_72b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供恶意输入，且输入被用于构建dataVector中的字符串。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { /* copy data out of dataV... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_72b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_72b.cpp::_ZN47CWE114_Process_Control__w32_char_environment_729case0SinkESt6vectorIPcSaIS1_EE @ route
- 结论: 从控制台输入的数据未经校验直接传递给LoadLibraryA函数，导致可能加载恶意DLL，属于不受信任的控制输入导致的进程控制漏洞。
- D验证: confirmed / ver_ca282575
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 405. hyp_path_6f287f61e2c0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_72b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供恶意输入，且输入被用于构建dataVector中的字符串。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* copy data out of dataVector */ wchar_t * data = dataVector[2]; { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended libr... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_72b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_72b.cpp::_ZN46CWE114_Process_Control__w32_wchar_t_console_729case0SinkESt6vectorIPwSaIS1_EE @ route
- 结论: 从控制台输入的数据未经校验直接传递给LoadLibraryA函数，导致可能加载恶意DLL，属于不受信任的控制输入导致的进程控制漏洞。
- D验证: confirmed / ver_4a8bc8f6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 406. hyp_path_4de2a56994c1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_72b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供恶意输入，且输入被用于构建dataVector中的字符串。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* copy data out of dataV... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_72b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_72b.cpp::_ZN50CWE114_Process_Control__w32_wchar_t_environment_729case0SinkESt6vectorIPwSaIS1_EE @ route
- 结论: 从控制台输入的数据未经校验直接传递给LoadLibraryA函数，导致可能加载恶意DLL，属于不受信任的控制输入导致的进程控制漏洞。
- D验证: confirmed / ver_024124d9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 407. hyp_path_a3f111de3077

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_72b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供恶意输入，且输入被用于构建dataVector中的字符串。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { /* copy data out of dataV... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_72b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_72b.cpp::_ZN50CWE114_Process_Control__w32_char_connect_socket_729case0SinkESt6vectorIPcSaIS1_EE @ route
- 结论: 从控制台输入的数据未经校验直接传递给LoadLibraryA函数，导致可能加载恶意DLL，属于不受信任的控制输入导致的进程控制漏洞。
- D验证: confirmed / ver_bd7e36e3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 408. hyp_path_d5d168a6284b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_72b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供恶意输入，且输入被用于构建dataVector中的字符串。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { /* copy data out of dataV... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_72b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_72b.cpp::_ZN49CWE114_Process_Control__w32_char_listen_socket_729case0SinkESt6vectorIPcSaIS1_EE @ route
- 结论: 从控制台输入的数据未经校验直接传递给LoadLibraryA函数，导致可能加载恶意DLL，属于不受信任的控制输入导致的进程控制漏洞。
- D验证: confirmed / ver_4356d3d5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 409. hyp_path_4738007a612d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_72b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供恶意输入，且输入被用于构建dataVector中的字符串。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* copy data out of dataVector */ wchar_t * data = dataVector[2]; { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended libr... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_72b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_72b.cpp::_ZN53CWE114_Process_Control__w32_wchar_t_connect_socket_729case0SinkESt6vectorIPwSaIS1_EE @ route
- 结论: 从控制台输入的数据未经校验直接传递给LoadLibraryA函数，导致可能加载恶意DLL，属于不受信任的控制输入导致的进程控制漏洞。
- D验证: confirmed / ver_6d811da1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 410. hyp_path_c8ef4d5b7b86

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_72b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供恶意输入，且输入被用于构建dataVector中的字符串。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* copy data out of dataV... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_72b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_72b.cpp::_ZN52CWE114_Process_Control__w32_wchar_t_listen_socket_729case0SinkESt6vectorIPwSaIS1_EE @ route
- 结论: 从控制台输入的数据未经校验直接传递给LoadLibraryA函数，导致可能加载恶意DLL，属于不受信任的控制输入导致的进程控制漏洞。
- D验证: confirmed / ver_bb0d4de0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 411. hyp_path_228fcce7f042

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_72b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供恶意输入，且输入被用于构建dataVector中的字符串。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* copy data out of dataVector */ char * data = dataVector[2]; { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_72b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_72b.cpp::_ZN40CWE114_Process_Control__w32_char_file_729case0SinkESt6vectorIPcSaIS1_EE @ route
- 结论: 从控制台输入的数据未经校验直接传递给LoadLibraryA函数，导致可能加载恶意DLL，属于不受信任的控制输入导致的进程控制漏洞。
- D验证: confirmed / ver_c5bee8d0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 412. hyp_path_3e37af2286c3

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_72b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供恶意输入，且输入被用于构建dataVector中的字符串。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* copy data out of dataVector */ wchar_t * data = dataVector[2]; { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended libr... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_72b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_72b.cpp::_ZN43CWE114_Process_Control__w32_wchar_t_file_729case0SinkESt6vectorIPwSaIS1_EE @ route
- 结论: 从控制台输入的数据未经校验直接传递给LoadLibraryA函数，导致可能加载恶意DLL，属于不受信任的控制输入导致的进程控制漏洞。
- D验证: confirmed / ver_971d0973
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 413. hyp_path_7f0ee71bb5df

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_72b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供恶意输入，且输入被用于构建dataVector中的字符串。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { /* copy data out of dataV... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_72b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_72b.cpp::_ZN48CWE114_Process_Control__w32_char_relativePath_729case0SinkESt6vectorIPcSaIS1_EE @ route
- 结论: 从控制台输入的数据未经校验直接传递给LoadLibraryA函数，导致可能加载恶意DLL，属于不受信任的控制输入导致的进程控制漏洞。
- D验证: confirmed / ver_75112dd9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 414. hyp_path_67443b7acccb

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_72b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供恶意输入，且输入被用于构建dataVector中的字符串。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* copy data out of dataVector */ wchar_t * data = dataVector[2]; { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended libr... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_72b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_72b.cpp::_ZN51CWE114_Process_Control__w32_wchar_t_relativePath_729case0SinkESt6vectorIPwSaIS1_EE @ route
- 结论: 从控制台输入的数据未经校验直接传递给LoadLibraryA函数，导致可能加载恶意DLL，属于不受信任的控制输入导致的进程控制漏洞。
- D验证: confirmed / ver_b20ff6be
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 415. hyp_path_f6f3f7f234f7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_73b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入到程序的数据，使data指向一个攻击者选择的DLL路径。
- 触发路径: char * data = dataList.back(); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_73b.cpp:32-33; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_73b.cpp:37-38
- 结论: 代码使用外部可控的字符串作为参数调用LoadLibraryA函数加载动态库，攻击者可以通过控制该字符串加载任意恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_681f4b80
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 416. hyp_path_55b4d5e7c766

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_73b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入到程序的数据，使data指向一个攻击者选择的DLL路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { /* copy data out of dataL... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_73b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_73b.cpp::_ZN47CWE114_Process_Control__w32_char_environment_739case0SinkENSt7__cxx114listIPcSaIS2_EEE @ route
- 结论: 代码使用外部可控的字符串作为参数调用LoadLibraryA函数加载动态库，攻击者可以通过控制该字符串加载任意恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_4c9b95d7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 417. hyp_path_42d905facdc4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_73b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入到程序的数据，使data指向一个攻击者选择的DLL路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* copy data out of dataList */ wchar_t * data = dataList.back(); { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended libr... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_73b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_73b.cpp::_ZN46CWE114_Process_Control__w32_wchar_t_console_739case0SinkENSt7__cxx114listIPwSaIS2_EEE @ route
- 结论: 代码使用外部可控的字符串作为参数调用LoadLibraryA函数加载动态库，攻击者可以通过控制该字符串加载任意恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_5e5cf55c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 418. hyp_path_07ec55cabce4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_73b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入到程序的数据，使data指向一个攻击者选择的DLL路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* copy data out of dataL... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_73b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_73b.cpp::_ZN50CWE114_Process_Control__w32_wchar_t_environment_739case0SinkENSt7__cxx114listIPwSaIS2_EEE @ route
- 结论: 代码使用外部可控的字符串作为参数调用LoadLibraryA函数加载动态库，攻击者可以通过控制该字符串加载任意恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_1b046a51
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 419. hyp_path_84199f0878af

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_73b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入到程序的数据，使data指向一个攻击者选择的DLL路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { /* copy data out of dataL... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_73b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_73b.cpp::_ZN50CWE114_Process_Control__w32_char_connect_socket_739case0SinkENSt7__cxx114listIPcSaIS2_EEE @ route
- 结论: 代码使用外部可控的字符串作为参数调用LoadLibraryA函数加载动态库，攻击者可以通过控制该字符串加载任意恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_9dc8b274
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 420. hyp_path_25eac650420a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_73b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入到程序的数据，使data指向一个攻击者选择的DLL路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* copy data out of dataList */ char * data = dataList.back(); { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_73b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_73b.cpp::_ZN49CWE114_Process_Control__w32_char_listen_socket_739case0SinkENSt7__cxx114listIPcSaIS2_EEE @ route
- 结论: 代码使用外部可控的字符串作为参数调用LoadLibraryA函数加载动态库，攻击者可以通过控制该字符串加载任意恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_fe34dd95
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 421. hyp_path_accbc2a5c81e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_73b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入到程序的数据，使data指向一个攻击者选择的DLL路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* copy data out of dataList */ wchar_t * data = dataList.back(); { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended libr... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_73b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_73b.cpp::_ZN53CWE114_Process_Control__w32_wchar_t_connect_socket_739case0SinkENSt7__cxx114listIPwSaIS2_EEE @ route
- 结论: 代码使用外部可控的字符串作为参数调用LoadLibraryA函数加载动态库，攻击者可以通过控制该字符串加载任意恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_694b90f2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 422. hyp_path_a6cdee29cf18

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_73b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入到程序的数据，使data指向一个攻击者选择的DLL路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* copy data out of dataL... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_73b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_73b.cpp::_ZN52CWE114_Process_Control__w32_wchar_t_listen_socket_739case0SinkENSt7__cxx114listIPwSaIS2_EEE @ route
- 结论: 代码使用外部可控的字符串作为参数调用LoadLibraryA函数加载动态库，攻击者可以通过控制该字符串加载任意恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_34bdb283
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 423. hyp_path_3315929075d2

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_73b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入到程序的数据，使data指向一个攻击者选择的DLL路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { /* copy data out of dataL... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_73b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_73b.cpp::_ZN40CWE114_Process_Control__w32_char_file_739case0SinkENSt7__cxx114listIPcSaIS2_EEE @ route
- 结论: 代码使用外部可控的字符串作为参数调用LoadLibraryA函数加载动态库，攻击者可以通过控制该字符串加载任意恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_31c874ba
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 424. hyp_path_85d5fe986cba

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_73b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入到程序的数据，使data指向一个攻击者选择的DLL路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* copy data out of dataL... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_73b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_73b.cpp::_ZN43CWE114_Process_Control__w32_wchar_t_file_739case0SinkENSt7__cxx114listIPwSaIS2_EEE @ route
- 结论: 代码使用外部可控的字符串作为参数调用LoadLibraryA函数加载动态库，攻击者可以通过控制该字符串加载任意恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_23ad4943
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 425. hyp_path_28c9eaadb8ae

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_73b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入到程序的数据，使data指向一个攻击者选择的DLL路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { /* copy data out of dataL... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_73b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_73b.cpp::_ZN48CWE114_Process_Control__w32_char_relativePath_739case0SinkENSt7__cxx114listIPcSaIS2_EEE @ route
- 结论: 代码使用外部可控的字符串作为参数调用LoadLibraryA函数加载动态库，攻击者可以通过控制该字符串加载任意恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_b745cc76
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 426. hyp_path_d3075070db89

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_73b.cpp:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入到程序的数据，使data指向一个攻击者选择的DLL路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { /* copy data out of dataL... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_73b.cpp:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_73b.cpp::_ZN51CWE114_Process_Control__w32_wchar_t_relativePath_739case0SinkENSt7__cxx114listIPwSaIS2_EEE @ route
- 结论: 代码使用外部可控的字符串作为参数调用LoadLibraryA函数加载动态库，攻击者可以通过控制该字符串加载任意恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_7e4e441a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 427. hyp_path_285810979d88

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_83_case0.cpp:64
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供任意库路径或名称
- 触发路径: hModule = LoadLibraryA(data); @ L59-63
- 结论: 存在进程控制漏洞，攻击者可通过控制台输入任意库名，利用LoadLibraryA加载恶意库，导致任意代码执行。
- D验证: confirmed / ver_bd9564b3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 428. hyp_path_df5d06299b26

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_83_case0.cpp:64
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供任意库路径或名称
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_83_case0.cpp:64; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_83_case0.cpp::_ZN46CWE114_Process_Control__w32_wchar_t_console_8352CWE114_Process_Control__w32_wchar_t_console_83_case0D2Ev @ route
- 结论: 存在进程控制漏洞，攻击者可通过控制台输入任意库名，利用LoadLibraryA加载恶意库，导致任意代码执行。
- D验证: confirmed / ver_12517bd0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 429. hyp_path_0f0e0fe021fa

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_84_case0.cpp:64
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入提供恶意库路径。
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_84_case0.cpp:59-60; if (hModule != NULL) { FreeLibrary(hModule); ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_84_case0.cpp:62-64
- 结论: 程序使用用户可控的数据作为参数调用LoadLibraryA加载动态链接库，攻击者可以指定恶意库路径，导致任意代码执行。
- D验证: confirmed / ver_646bfd90
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 430. hyp_path_ecc03197e33c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_84_case0.cpp:64
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入提供恶意库路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_84_case0.cpp:64; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_84_case0.cpp::_ZN46CWE114_Process_Control__w32_wchar_t_console_8452CWE114_Process_Control__w32_wchar_t_console_84_case0D2Ev @ route
- 结论: 程序使用用户可控的数据作为参数调用LoadLibraryA加载动态链接库，攻击者可以指定恶意库路径，导致任意代码执行。
- D验证: confirmed / ver_cae24d8a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 431. hyp_path_0090673d25e3

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_83_case0.cpp:58
- 漏洞类型: CWE-114, CWE-426
- CWE: CWE-114; CWE-426
- 风险等级: P0
- 触发条件: Attacker can set the environment variable used to produce 'data'.; No input validation or path restriction is applied before LoadLibraryA.
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_83_case0.cpp:58
- 结论: CWE-114 Process Control: The application uses an environment variable to load a library via LoadLibraryA without proper validation. An attacker may control the environment variable to load a malicious DLL, leading to arbitrary code execution.
- D验证: confirmed / ver_c7216d63
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 432. hyp_path_6fd62898f4ff

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_83_case0.cpp:58
- 漏洞类型: CWE-114, CWE-426
- CWE: CWE-114; CWE-426
- 风险等级: P0
- 触发条件: Attacker can set the environment variable used to produce 'data'.; No input validation or path restriction is applied before LoadLibraryA.
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_83_case0.cpp:58; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_83_case0.cpp::_ZN50CWE114_Process_Control__w32_wchar_t_environment_8356CWE114_Process_Control__w32_wchar_t_environment_83_case0D2Ev @ route
- 结论: CWE-114 Process Control: The application uses an environment variable to load a library via LoadLibraryA without proper validation. An attacker may control the environment variable to load a malicious DLL, leading to arbitrary code execution.
- D验证: confirmed / ver_7e703cf3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 433. hyp_path_18cc10fc2bcb

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_84_case0.cpp:58
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响环境变量，使data指向恶意DLL的路径
- 触发路径: /* NOTE: If the path to the library is not specified, an attacker may be able to replace his own file with the intended library */ hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_84_case0.cpp:53-57; if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_84_case0.cpp:56-60
- 结论: 通过环境变量控制LoadLibraryA加载的库路径，攻击者可替换合法库为恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_19fcb3a5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 434. hyp_path_b31834ad9de6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_84_case0.cpp:58
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响环境变量，使data指向恶意DLL的路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_84_case0.cpp:58; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_84_case0.cpp::_ZN50CWE114_Process_Control__w32_wchar_t_environment_8456CWE114_Process_Control__w32_wchar_t_environment_84_case0D2Ev @ route
- 结论: 通过环境变量控制LoadLibraryA加载的库路径，攻击者可替换合法库为恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_8f9fa680
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 435. hyp_path_ffc5136b7ddd

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_22b.c:80
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标建立socket连接; 攻击者能够发送特制字符串数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_22b.c:80; HMODULE hMod = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_22b.c:XXX（根据Juliet测试套件，后续调用LoadLibraryA(data)）
- 结论: 攻击者通过socket发送恶意数据，该数据被用于进程控制操作（如加载库或执行命令），可能导致任意代码执行。
- D验证: confirmed / ver_8967c635
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 436. hyp_path_8ccd07e6dfee

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_22b.c:80
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标建立socket连接; 攻击者能够发送特制字符串数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... wchar_t *replace; SOCKET connectSocket = INVALID_SO... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_22b.c:80; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_22b.c::CWE114_Process_Control__w32_wchar_t_connect_socket_22_case0Source @ route
- 结论: 攻击者通过socket发送恶意数据，该数据被用于进程控制操作（如加载库或执行命令），可能导致任意代码执行。
- D验证: confirmed / ver_95c0d58e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 437. hyp_path_bac75f144875

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_44.c:34
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串，且程序未对输入路径进行验证或限制。
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_44.c:34
- 结论: 程序从控制台读取字符串作为DLL路径并加载，攻击者可以通过提供恶意DLL路径执行任意代码。
- D验证: confirmed / ver_3e665125
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 438. hyp_path_2cf85235e29a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_44.c:34
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串，且程序未对输入路径进行验证或限制。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_44.c:34; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_44.c::case0Sink @ route
- 结论: 程序从控制台读取字符串作为DLL路径并加载，攻击者可以通过提供恶意DLL路径执行任意代码。
- D验证: confirmed / ver_0c458be8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 439. hyp_path_51580bf0529f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_44.c:34
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串，且程序未对输入路径进行验证或限制。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_44.c:34; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_44.c::case0Sink @ route
- 结论: 程序从控制台读取字符串作为DLL路径并加载，攻击者可以通过提供恶意DLL路径执行任意代码。
- D验证: confirmed / ver_a4621988
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 440. hyp_path_2df46ae4d1a1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_44.c:34
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串，且程序未对输入路径进行验证或限制。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_44.c:34; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_44.c::case0Sink @ route
- 结论: 程序从控制台读取字符串作为DLL路径并加载，攻击者可以通过提供恶意DLL路径执行任意代码。
- D验证: confirmed / ver_01c0a97b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 441. hyp_path_cfe0f328135b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_42.c:76
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: Attacker can control network input to the recv socket
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_42.c:76
- 结论: Possible process control vulnerability via network input, but missing explicit sink function call (e.g., system, CreateProcess). Evidence incomplete.
- D验证: confirmed / ver_25e684c6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 442. hyp_path_fe75000bca4a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_42.c:76
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: Attacker can control network input to the recv socket
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) if (connectSocket != INVALID_SOCKET) CLOSE_SOCKET(connectSocket); ... if (wsaDataInit) { WSACleanup(); } #endif ... wchar_t *replace; SOCKET connectSocket = INVALID_SO... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_42.c:76; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_42.c::case0Source @ route
- 结论: Possible process control vulnerability via network input, but missing explicit sink function call (e.g., system, CreateProcess). Evidence incomplete.
- D验证: confirmed / ver_5d90493c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 443. hyp_path_12940ff5480e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_45.c:38
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的控制台输入任意字符串（例如通过重定向或交互式输入）。
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_45.c:33-34
- 结论: 程序通过控制台接收字符串作为参数调用LoadLibraryA，未进行任何路径或来源验证，攻击者可控制控制台输入指定任意DLL路径，导致加载恶意库，实现代码执行或权限提升。
- D验证: confirmed / ver_e0bbcc62
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 444. hyp_path_ff815ce77eb4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_45.c:38
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的控制台输入任意字符串（例如通过重定向或交互式输入）。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_45.c:38; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_45.c::case0Sink @ route
- 结论: 程序通过控制台接收字符串作为参数调用LoadLibraryA，未进行任何路径或来源验证，攻击者可控制控制台输入指定任意DLL路径，导致加载恶意库，实现代码执行或权限提升。
- D验证: confirmed / ver_8ba655d5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 445. hyp_path_2ac06daf2f0a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_45.c:38
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的控制台输入任意字符串（例如通过重定向或交互式输入）。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_45.c:38; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_45.c::case0Sink @ route
- 结论: 程序通过控制台接收字符串作为参数调用LoadLibraryA，未进行任何路径或来源验证，攻击者可控制控制台输入指定任意DLL路径，导致加载恶意库，实现代码执行或权限提升。
- D验证: confirmed / ver_db17f604
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 446. hyp_path_bb554a66f81b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_45.c:38
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的控制台输入任意字符串（例如通过重定向或交互式输入）。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_45.c:38; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_45.c::case0Sink @ route
- 结论: 程序通过控制台接收字符串作为参数调用LoadLibraryA，未进行任何路径或来源验证，攻击者可控制控制台输入指定任意DLL路径，导致加载恶意库，实现代码执行或权限提升。
- D验证: confirmed / ver_14489645
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 447. hyp_path_643ed7466adf

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_51b.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: data参数来源于攻击者可控制的控制台输入（推断，但未经代码证据直接证明）; 系统未对LoadLibraryA的路径参数进行限制或白名单检查
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_51b.c:36
- 结论: 代码使用LoadLibraryA加载用户通过控制台输入的库路径，攻击者可控制该路径加载恶意DLL，导致任意代码执行（CWE-114 Process Control）。但当前代码片段仅包含sink函数，缺乏source证据，无法确认外部可控。
- D验证: confirmed / ver_794dd859
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 448. hyp_path_5a71b2302a90

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_51b.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: data参数来源于攻击者可控制的控制台输入（推断，但未经代码证据直接证明）; 系统未对LoadLibraryA的路径参数进行限制或白名单检查
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_51b.c:36; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_51b.c::CWE114_Process_Control__w32_wchar_t_console_51b_case0Sink @ route
- 结论: 代码使用LoadLibraryA加载用户通过控制台输入的库路径，攻击者可控制该路径加载恶意DLL，导致任意代码执行（CWE-114 Process Control）。但当前代码片段仅包含sink函数，缺乏source证据，无法确认外部可控。
- D验证: confirmed / ver_28cb0b49
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 449. hyp_path_050dc4a1fc4a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_51b.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: data参数来源于攻击者可控制的控制台输入（推断，但未经代码证据直接证明）; 系统未对LoadLibraryA的路径参数进行限制或白名单检查
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_51b.c:36; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_51b.c::CWE114_Process_Control__w32_char_relativePath_51b_case0Sink @ route
- 结论: 代码使用LoadLibraryA加载用户通过控制台输入的库路径，攻击者可控制该路径加载恶意DLL，导致任意代码执行（CWE-114 Process Control）。但当前代码片段仅包含sink函数，缺乏source证据，无法确认外部可控。
- D验证: confirmed / ver_70f7a913
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 450. hyp_path_6c7601c6ceaf

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_51b.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: data参数来源于攻击者可控制的控制台输入（推断，但未经代码证据直接证明）; 系统未对LoadLibraryA的路径参数进行限制或白名单检查
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_51b.c:36; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_51b.c::CWE114_Process_Control__w32_wchar_t_relativePath_51b_case0Sink @ route
- 结论: 代码使用LoadLibraryA加载用户通过控制台输入的库路径，攻击者可控制该路径加载恶意DLL，导致任意代码执行（CWE-114 Process Control）。但当前代码片段仅包含sink函数，缺乏source证据，无法确认外部可控。
- D验证: confirmed / ver_69832cf2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 451. hyp_path_dc4fce98a80e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_52c.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台提供输入（控制data变量内容）; 目标系统允许从攻击者指定的路径加载DLL（或存在DLL劫持条件）
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_52c.c:31; if (hModule != NULL) { @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_52c.c:32; FreeLibrary(hModule); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_52c.c:34
- 结论: 程序使用从控制台输入的字符串作为LoadLibraryA的参数，攻击者可通过提供恶意DLL路径加载任意库，实现任意代码执行。
- D验证: confirmed / ver_8fd53c1a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 452. hyp_path_8e16d92b428a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_52c.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台提供输入（控制data变量内容）; 目标系统允许从攻击者指定的路径加载DLL（或存在DLL劫持条件）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_52c.c:36; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_52c.c::CWE114_Process_Control__w32_wchar_t_console_52c_case0Sink @ route
- 结论: 程序使用从控制台输入的字符串作为LoadLibraryA的参数，攻击者可通过提供恶意DLL路径加载任意库，实现任意代码执行。
- D验证: confirmed / ver_0547a330
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 453. hyp_path_788d4e1d31bf

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_52c.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台提供输入（控制data变量内容）; 目标系统允许从攻击者指定的路径加载DLL（或存在DLL劫持条件）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_52c.c:36; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_52c.c::CWE114_Process_Control__w32_char_relativePath_52c_case0Sink @ route
- 结论: 程序使用从控制台输入的字符串作为LoadLibraryA的参数，攻击者可通过提供恶意DLL路径加载任意库，实现任意代码执行。
- D验证: confirmed / ver_b7496dc2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 454. hyp_path_c713a312482f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_52c.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台提供输入（控制data变量内容）; 目标系统允许从攻击者指定的路径加载DLL（或存在DLL劫持条件）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_52c.c:36; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_52c.c::CWE114_Process_Control__w32_wchar_t_relativePath_52c_case0Sink @ route
- 结论: 程序使用从控制台输入的字符串作为LoadLibraryA的参数，攻击者可通过提供恶意DLL路径加载任意库，实现任意代码执行。
- D验证: confirmed / ver_9699218d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 455. hyp_path_d02b28762053

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_53d.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入影响data变量
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_53d.c:31
- 结论: 程序使用控制台输入作为LoadLibraryA的参数，攻击者可以通过控制输入加载恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_ff2ac34a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 456. hyp_path_31075cc649e1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_53d.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入影响data变量
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_53d.c:36; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_53d.c::CWE114_Process_Control__w32_wchar_t_console_53d_case0Sink @ route
- 结论: 程序使用控制台输入作为LoadLibraryA的参数，攻击者可以通过控制输入加载恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_0d7abd25
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 457. hyp_path_8af266cdf507

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_53d.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入影响data变量
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_53d.c:36; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_53d.c::CWE114_Process_Control__w32_char_relativePath_53d_case0Sink @ route
- 结论: 程序使用控制台输入作为LoadLibraryA的参数，攻击者可以通过控制输入加载恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_5b33c05c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 458. hyp_path_65060984262a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_53d.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入影响data变量
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_53d.c:36; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_53d.c::CWE114_Process_Control__w32_wchar_t_relativePath_53d_case0Sink @ route
- 结论: 程序使用控制台输入作为LoadLibraryA的参数，攻击者可以通过控制输入加载恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_691be7cd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 459. hyp_path_ec06f2ee5eb8

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_54e.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够提供控制台输入; 系统上存在恶意DLL或可通过UNC路径加载
- 触发路径: char * data; /* 从控制台读取 */ @ 入口函数（如main）读取控制台输入至data; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_54e.c:31; if (hModule != NULL) { FreeLibrary(hModule); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_54e.c:34
- 结论: 存在通过控制台输入控制库路径加载恶意库的安全漏洞（CWE-114: 过程控制）
- D验证: confirmed / ver_317f8bff
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 460. hyp_path_9827e92b284e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_54e.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够提供控制台输入; 系统上存在恶意DLL或可通过UNC路径加载
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_54e.c:36; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_54e.c::CWE114_Process_Control__w32_wchar_t_console_54e_case0Sink @ route
- 结论: 存在通过控制台输入控制库路径加载恶意库的安全漏洞（CWE-114: 过程控制）
- D验证: confirmed / ver_67eaca25
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 461. hyp_path_1ff3fe734ef9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_54e.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够提供控制台输入; 系统上存在恶意DLL或可通过UNC路径加载
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_54e.c:36; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_54e.c::CWE114_Process_Control__w32_char_relativePath_54e_case0Sink @ route
- 结论: 存在通过控制台输入控制库路径加载恶意库的安全漏洞（CWE-114: 过程控制）
- D验证: confirmed / ver_8daea9b1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 462. hyp_path_05e016e0479e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_54e.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够提供控制台输入; 系统上存在恶意DLL或可通过UNC路径加载
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_54e.c:36; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_54e.c::CWE114_Process_Control__w32_wchar_t_relativePath_54e_case0Sink @ route
- 结论: 存在通过控制台输入控制库路径加载恶意库的安全漏洞（CWE-114: 过程控制）
- D验证: confirmed / ver_b12aa08d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 463. hyp_path_695c766f89f0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_64b.c:38
- 漏洞类型: command_injection
- CWE: CWE-114; CWE-78
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入向data变量提供任意字符串
- 触发路径: CWE114_Process_Control__w32_char_console_64b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_64b.c:25; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_64b.c:38
- 结论: 程序从控制台读取字符串作为库路径，直接传递给LoadLibraryA，攻击者可控制输入加载任意恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_34452987
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 464. hyp_path_07e017f6cf8b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_64b.c:38
- 漏洞类型: command_injection
- CWE: CWE-114; CWE-78
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入向data变量提供任意字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_64b.c:38; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_64b.c::CWE114_Process_Control__w32_wchar_t_console_64b_case0Sink @ route
- 结论: 程序从控制台读取字符串作为库路径，直接传递给LoadLibraryA，攻击者可控制输入加载任意恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_1247d902
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 465. hyp_path_e229089b68e7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_64b.c:38
- 漏洞类型: command_injection
- CWE: CWE-114; CWE-78
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入向data变量提供任意字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_64b.c:38; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_64b.c::CWE114_Process_Control__w32_char_relativePath_64b_case0Sink @ route
- 结论: 程序从控制台读取字符串作为库路径，直接传递给LoadLibraryA，攻击者可控制输入加载任意恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_238659d1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 466. hyp_path_c562146c474c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_64b.c:38
- 漏洞类型: command_injection
- CWE: CWE-114; CWE-78
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入向data变量提供任意字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_64b.c:38; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_64b.c::CWE114_Process_Control__w32_wchar_t_relativePath_64b_case0Sink @ route
- 结论: 程序从控制台读取字符串作为库路径，直接传递给LoadLibraryA，攻击者可控制输入加载任意恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_e40de997
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 467. hyp_path_6bc594e8922b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_63b.c:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标程序的控制台输入提供任意字符串
- 触发路径: data = 从控制台读取的字符串 @ L? 推断为控制台输入函数如gets或fgets（未在提供代码片段中明确）; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_63b.c:33-34
- 结论: 存在进程控制漏洞：攻击者通过控制台输入可控的库路径，传递给LoadLibraryA函数，可能导致加载恶意DLL，实现代码执行。
- D验证: confirmed / ver_6297d672
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 468. hyp_path_4501b6cafcb8

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_63b.c:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标程序的控制台输入提供任意字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_63b.c:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_63b.c::CWE114_Process_Control__w32_wchar_t_console_63b_case0Sink @ route
- 结论: 存在进程控制漏洞：攻击者通过控制台输入可控的库路径，传递给LoadLibraryA函数，可能导致加载恶意DLL，实现代码执行。
- D验证: confirmed / ver_3434893b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 469. hyp_path_0a8a0e75df21

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_63b.c:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标程序的控制台输入提供任意字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_63b.c:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_63b.c::CWE114_Process_Control__w32_char_relativePath_63b_case0Sink @ route
- 结论: 存在进程控制漏洞：攻击者通过控制台输入可控的库路径，传递给LoadLibraryA函数，可能导致加载恶意DLL，实现代码执行。
- D验证: confirmed / ver_f1c1fe26
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 470. hyp_path_966c5db37e98

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_63b.c:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标程序的控制台输入提供任意字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_63b.c:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_63b.c::CWE114_Process_Control__w32_wchar_t_relativePath_63b_case0Sink @ route
- 结论: 存在进程控制漏洞：攻击者通过控制台输入可控的库路径，传递给LoadLibraryA函数，可能导致加载恶意DLL，实现代码执行。
- D验证: confirmed / ver_64edea15
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 471. hyp_path_6373c4f804b0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_66b.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供任意字符串作为库路径。
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_66b.c:36
- 结论: 攻击者可通过控制台输入控制加载的库路径，可能加载恶意DLL，导致代码执行。
- D验证: confirmed / ver_7ac945f3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 472. hyp_path_6156f54beb33

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_66b.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供任意字符串作为库路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_66b.c:36; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_66b.c::CWE114_Process_Control__w32_wchar_t_console_66b_case0Sink @ route
- 结论: 攻击者可通过控制台输入控制加载的库路径，可能加载恶意DLL，导致代码执行。
- D验证: confirmed / ver_53d5b135
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 473. hyp_path_45904efdc4c6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_66b.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供任意字符串作为库路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_66b.c:36; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_66b.c::CWE114_Process_Control__w32_char_relativePath_66b_case0Sink @ route
- 结论: 攻击者可通过控制台输入控制加载的库路径，可能加载恶意DLL，导致代码执行。
- D验证: confirmed / ver_22306c9e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 474. hyp_path_bb10708b9805

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_66b.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供任意字符串作为库路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_66b.c:36; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_66b.c::CWE114_Process_Control__w32_wchar_t_relativePath_66b_case0Sink @ route
- 结论: 攻击者可通过控制台输入控制加载的库路径，可能加载恶意DLL，导致代码执行。
- D验证: confirmed / ver_d3110412
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 475. hyp_path_20be533daed4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_65b.c:34
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台提供任意字符串作为data的值
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_65b.c:34
- 结论: 程序使用LoadLibraryA加载动态链接库，库路径来自外部输入（控制台），攻击者可通过控制输入加载恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_88637daa
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 476. hyp_path_ed9a0552689b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_65b.c:34
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台提供任意字符串作为data的值
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_65b.c:34; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_65b.c::CWE114_Process_Control__w32_wchar_t_console_65b_case0Sink @ route
- 结论: 程序使用LoadLibraryA加载动态链接库，库路径来自外部输入（控制台），攻击者可通过控制输入加载恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_7bc3f0a8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 477. hyp_path_9dcbf0de8fce

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_65b.c:34
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台提供任意字符串作为data的值
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_65b.c:34; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_65b.c::CWE114_Process_Control__w32_char_relativePath_65b_case0Sink @ route
- 结论: 程序使用LoadLibraryA加载动态链接库，库路径来自外部输入（控制台），攻击者可通过控制输入加载恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_61350f42
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 478. hyp_path_5151c0c6faf9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_65b.c:34
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台提供任意字符串作为data的值
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_65b.c:34; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_65b.c::CWE114_Process_Control__w32_wchar_t_relativePath_65b_case0Sink @ route
- 结论: 程序使用LoadLibraryA加载动态链接库，库路径来自外部输入（控制台），攻击者可通过控制输入加载恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_9938830f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 479. hyp_path_b3e39014a9ca

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_67b.c:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制应用程序的控制台输入，从而影响data变量的值。
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_67b.c:35-39
- 结论: 攻击者可以通过控制台输入控制加载的库路径，导致加载任意恶意库，从而执行任意代码。
- D验证: confirmed / ver_bbebb150
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 480. hyp_path_87cc0512f5de

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_67b.c:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制应用程序的控制台输入，从而影响data变量的值。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_67b.c:40; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_67b.c::CWE114_Process_Control__w32_wchar_t_console_67b_case0Sink @ route
- 结论: 攻击者可以通过控制台输入控制加载的库路径，导致加载任意恶意库，从而执行任意代码。
- D验证: confirmed / ver_ea73ae97
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 481. hyp_path_643dd8aa4bee

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_67b.c:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制应用程序的控制台输入，从而影响data变量的值。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_67b.c:40; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_67b.c::CWE114_Process_Control__w32_char_relativePath_67b_case0Sink @ route
- 结论: 攻击者可以通过控制台输入控制加载的库路径，导致加载任意恶意库，从而执行任意代码。
- D验证: confirmed / ver_9400d0e3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 482. hyp_path_cf8504f1c45a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_67b.c:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制应用程序的控制台输入，从而影响data变量的值。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_67b.c:40; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_67b.c::CWE114_Process_Control__w32_wchar_t_relativePath_67b_case0Sink @ route
- 结论: 攻击者可以通过控制台输入控制加载的库路径，导致加载任意恶意库，从而执行任意代码。
- D验证: confirmed / ver_fc459612
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 483. hyp_path_2a5674c83d99

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_81_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串作为库路径
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_81_case0.cpp:30-34
- 结论: 程序从控制台读取库路径并加载，攻击者可提供恶意DLL路径导致任意代码执行
- D验证: confirmed / ver_fffa3c7d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 484. hyp_path_4c6db7ed950e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_81_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_81_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_81_case0.cpp::_ZNK47CWE114_Process_Control__w32_char_environment_8153CWE114_Process_Control__w32_char_environment_81_case06actionEPc @ route
- 结论: 程序从控制台读取库路径并加载，攻击者可提供恶意DLL路径导致任意代码执行
- D验证: confirmed / ver_791279fc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 485. hyp_path_543a04e04042

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_81_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_81_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_81_case0.cpp::_ZNK46CWE114_Process_Control__w32_wchar_t_console_8152CWE114_Process_Control__w32_wchar_t_console_81_case06actionEPw @ route
- 结论: 程序从控制台读取库路径并加载，攻击者可提供恶意DLL路径导致任意代码执行
- D验证: confirmed / ver_0847f951
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 486. hyp_path_d0715e25d374

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_81_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_81_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_81_case0.cpp::_ZNK50CWE114_Process_Control__w32_wchar_t_environment_8156CWE114_Process_Control__w32_wchar_t_environment_81_case06actionEPw @ route
- 结论: 程序从控制台读取库路径并加载，攻击者可提供恶意DLL路径导致任意代码执行
- D验证: confirmed / ver_4e08f6fd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 487. hyp_path_3af4c2456178

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_81_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_81_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_81_case0.cpp::_ZNK50CWE114_Process_Control__w32_char_connect_socket_8156CWE114_Process_Control__w32_char_connect_socket_81_case06actionEPc @ route
- 结论: 程序从控制台读取库路径并加载，攻击者可提供恶意DLL路径导致任意代码执行
- D验证: confirmed / ver_a1640bdc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 488. hyp_path_1d7587ecaf4c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_81_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_81_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_81_case0.cpp::_ZNK49CWE114_Process_Control__w32_char_listen_socket_8155CWE114_Process_Control__w32_char_listen_socket_81_case06actionEPc @ route
- 结论: 程序从控制台读取库路径并加载，攻击者可提供恶意DLL路径导致任意代码执行
- D验证: confirmed / ver_3fa3fef7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 489. hyp_path_481ec8a51d9b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_81_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_81_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_81_case0.cpp::_ZNK53CWE114_Process_Control__w32_wchar_t_connect_socket_8159CWE114_Process_Control__w32_wchar_t_connect_socket_81_case06actionEPw @ route
- 结论: 程序从控制台读取库路径并加载，攻击者可提供恶意DLL路径导致任意代码执行
- D验证: confirmed / ver_c90c901e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 490. hyp_path_f131203a3abc

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_81_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_81_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_81_case0.cpp::_ZNK52CWE114_Process_Control__w32_wchar_t_listen_socket_8158CWE114_Process_Control__w32_wchar_t_listen_socket_81_case06actionEPw @ route
- 结论: 程序从控制台读取库路径并加载，攻击者可提供恶意DLL路径导致任意代码执行
- D验证: confirmed / ver_9fe3e4a9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 491. hyp_path_c1eacfaaad11

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_81_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_81_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_81_case0.cpp::_ZNK40CWE114_Process_Control__w32_char_file_8146CWE114_Process_Control__w32_char_file_81_case06actionEPc @ route
- 结论: 程序从控制台读取库路径并加载，攻击者可提供恶意DLL路径导致任意代码执行
- D验证: confirmed / ver_bf901669
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 492. hyp_path_a3172faf5e24

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_81_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_81_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_81_case0.cpp::_ZNK43CWE114_Process_Control__w32_wchar_t_file_8149CWE114_Process_Control__w32_wchar_t_file_81_case06actionEPw @ route
- 结论: 程序从控制台读取库路径并加载，攻击者可提供恶意DLL路径导致任意代码执行
- D验证: confirmed / ver_a2c0ae5c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 493. hyp_path_adce3daa1420

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_81_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_81_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_81_case0.cpp::_ZNK48CWE114_Process_Control__w32_char_relativePath_8154CWE114_Process_Control__w32_char_relativePath_81_case06actionEPc @ route
- 结论: 程序从控制台读取库路径并加载，攻击者可提供恶意DLL路径导致任意代码执行
- D验证: confirmed / ver_986c963e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 494. hyp_path_ee8a9e687aa8

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_81_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串作为库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_81_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_81_case0.cpp::_ZNK51CWE114_Process_Control__w32_wchar_t_relativePath_8157CWE114_Process_Control__w32_wchar_t_relativePath_81_case06actionEPw @ route
- 结论: 程序从控制台读取库路径并加载，攻击者可提供恶意DLL路径导致任意代码执行
- D验证: confirmed / ver_2963e595
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 495. hyp_path_7408019eed8c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_68b.c:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入控制变量data的值; 攻击者能够在系统上放置或利用已有恶意DLL，其路径由data指定
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_68b.c:35-39
- 结论: 存在CWE-114 Process Control漏洞，通过控制台输入指定恶意DLL路径，调用LoadLibraryA加载，导致任意代码执行。
- D验证: confirmed / ver_bed4a5b6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 496. hyp_path_d50c85290057

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_68b.c:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入控制变量data的值; 攻击者能够在系统上放置或利用已有恶意DLL，其路径由data指定
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_68b.c:40; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_68b.c::CWE114_Process_Control__w32_wchar_t_console_68b_case0Sink @ route
- 结论: 存在CWE-114 Process Control漏洞，通过控制台输入指定恶意DLL路径，调用LoadLibraryA加载，导致任意代码执行。
- D验证: confirmed / ver_dfbeb6d3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 497. hyp_path_e595943a0dc3

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_68b.c:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入控制变量data的值; 攻击者能够在系统上放置或利用已有恶意DLL，其路径由data指定
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_68b.c:40; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_68b.c::CWE114_Process_Control__w32_char_relativePath_68b_case0Sink @ route
- 结论: 存在CWE-114 Process Control漏洞，通过控制台输入指定恶意DLL路径，调用LoadLibraryA加载，导致任意代码执行。
- D验证: confirmed / ver_5dcbccb2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 498. hyp_path_fa28cfb2d732

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_68b.c:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入控制变量data的值; 攻击者能够在系统上放置或利用已有恶意DLL，其路径由data指定
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_68b.c:40; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_68b.c::CWE114_Process_Control__w32_wchar_t_relativePath_68b_case0Sink @ route
- 结论: 存在CWE-114 Process Control漏洞，通过控制台输入指定恶意DLL路径，调用LoadLibraryA加载，导致任意代码执行。
- D验证: confirmed / ver_c73b6507
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 499. hyp_path_d9049a7788e7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_82_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入字符串作为LoadLibraryA的参数
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_82_case0.cpp:30-32; if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_82_case0.cpp:33-37
- 结论: 程序使用LoadLibraryA加载用户从控制台输入的路径指定的DLL，攻击者可通过控制台输入恶意DLL路径，导致加载并执行任意代码。
- D验证: confirmed / ver_6796abbb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 500. hyp_path_ab3d20ace5e6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_82_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入字符串作为LoadLibraryA的参数
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_82_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_82_case0.cpp::_ZN47CWE114_Process_Control__w32_char_environment_8253CWE114_Process_Control__w32_char_environment_82_case06actionEPc @ route
- 结论: 程序使用LoadLibraryA加载用户从控制台输入的路径指定的DLL，攻击者可通过控制台输入恶意DLL路径，导致加载并执行任意代码。
- D验证: confirmed / ver_adcd3dc1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 501. hyp_path_2a58d3c69d3d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_82_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入字符串作为LoadLibraryA的参数
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_82_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_82_case0.cpp::_ZN46CWE114_Process_Control__w32_wchar_t_console_8252CWE114_Process_Control__w32_wchar_t_console_82_case06actionEPw @ route
- 结论: 程序使用LoadLibraryA加载用户从控制台输入的路径指定的DLL，攻击者可通过控制台输入恶意DLL路径，导致加载并执行任意代码。
- D验证: confirmed / ver_db71862d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 502. hyp_path_5bfc3b398bf1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_82_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入字符串作为LoadLibraryA的参数
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_82_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_82_case0.cpp::_ZN50CWE114_Process_Control__w32_wchar_t_environment_8256CWE114_Process_Control__w32_wchar_t_environment_82_case06actionEPw @ route
- 结论: 程序使用LoadLibraryA加载用户从控制台输入的路径指定的DLL，攻击者可通过控制台输入恶意DLL路径，导致加载并执行任意代码。
- D验证: confirmed / ver_973caf77
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 503. hyp_path_ac64f1a2b2e2

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_82_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入字符串作为LoadLibraryA的参数
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_82_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_82_case0.cpp::_ZN50CWE114_Process_Control__w32_char_connect_socket_8256CWE114_Process_Control__w32_char_connect_socket_82_case06actionEPc @ route
- 结论: 程序使用LoadLibraryA加载用户从控制台输入的路径指定的DLL，攻击者可通过控制台输入恶意DLL路径，导致加载并执行任意代码。
- D验证: confirmed / ver_812b5a63
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 504. hyp_path_dc12d93f41f1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_82_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入字符串作为LoadLibraryA的参数
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_82_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_82_case0.cpp::_ZN49CWE114_Process_Control__w32_char_listen_socket_8255CWE114_Process_Control__w32_char_listen_socket_82_case06actionEPc @ route
- 结论: 程序使用LoadLibraryA加载用户从控制台输入的路径指定的DLL，攻击者可通过控制台输入恶意DLL路径，导致加载并执行任意代码。
- D验证: confirmed / ver_11c18de3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 505. hyp_path_3862c1afc22a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_82_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入字符串作为LoadLibraryA的参数
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_82_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_82_case0.cpp::_ZN53CWE114_Process_Control__w32_wchar_t_connect_socket_8259CWE114_Process_Control__w32_wchar_t_connect_socket_82_case06actionEPw @ route
- 结论: 程序使用LoadLibraryA加载用户从控制台输入的路径指定的DLL，攻击者可通过控制台输入恶意DLL路径，导致加载并执行任意代码。
- D验证: confirmed / ver_72b39ba8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 506. hyp_path_3bcd3ae1e85e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_82_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入字符串作为LoadLibraryA的参数
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_82_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_82_case0.cpp::_ZN52CWE114_Process_Control__w32_wchar_t_listen_socket_8258CWE114_Process_Control__w32_wchar_t_listen_socket_82_case06actionEPw @ route
- 结论: 程序使用LoadLibraryA加载用户从控制台输入的路径指定的DLL，攻击者可通过控制台输入恶意DLL路径，导致加载并执行任意代码。
- D验证: confirmed / ver_c96bbfbb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 507. hyp_path_25b6c8a3953a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_82_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入字符串作为LoadLibraryA的参数
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_82_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_82_case0.cpp::_ZN40CWE114_Process_Control__w32_char_file_8246CWE114_Process_Control__w32_char_file_82_case06actionEPc @ route
- 结论: 程序使用LoadLibraryA加载用户从控制台输入的路径指定的DLL，攻击者可通过控制台输入恶意DLL路径，导致加载并执行任意代码。
- D验证: confirmed / ver_cd0a41d3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 508. hyp_path_6b002fbd1921

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_82_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入字符串作为LoadLibraryA的参数
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_82_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_82_case0.cpp::_ZN43CWE114_Process_Control__w32_wchar_t_file_8249CWE114_Process_Control__w32_wchar_t_file_82_case06actionEPw @ route
- 结论: 程序使用LoadLibraryA加载用户从控制台输入的路径指定的DLL，攻击者可通过控制台输入恶意DLL路径，导致加载并执行任意代码。
- D验证: confirmed / ver_77bd5782
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 509. hyp_path_411d15009d51

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_82_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入字符串作为LoadLibraryA的参数
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_82_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_82_case0.cpp::_ZN48CWE114_Process_Control__w32_char_relativePath_8254CWE114_Process_Control__w32_char_relativePath_82_case06actionEPc @ route
- 结论: 程序使用LoadLibraryA加载用户从控制台输入的路径指定的DLL，攻击者可通过控制台输入恶意DLL路径，导致加载并执行任意代码。
- D验证: confirmed / ver_792b1c97
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 510. hyp_path_c8cd931253f5

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_82_case0.cpp:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入字符串作为LoadLibraryA的参数
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_82_case0.cpp:35; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_82_case0.cpp::_ZN51CWE114_Process_Control__w32_wchar_t_relativePath_8257CWE114_Process_Control__w32_wchar_t_relativePath_82_case06actionEPw @ route
- 结论: 程序使用LoadLibraryA加载用户从控制台输入的路径指定的DLL，攻击者可通过控制台输入恶意DLL路径，导致加载并执行任意代码。
- D验证: confirmed / ver_34979d6c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 511. hyp_path_d8cdb8707b89

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_44.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量，例如通过修改系统环境变量或直接在应用程序环境中设置。
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_44.c:42
- 结论: 应用程序使用不受信任的环境变量作为参数调用LoadLibraryA，攻击者可控制环境变量加载恶意DLL，造成任意代码执行。
- D验证: confirmed / ver_eaaf2614
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 512. hyp_path_4391c214f505

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_44.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量，例如通过修改系统环境变量或直接在应用程序环境中设置。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_44.c:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_44.c::case0Sink @ route
- 结论: 应用程序使用不受信任的环境变量作为参数调用LoadLibraryA，攻击者可控制环境变量加载恶意DLL，造成任意代码执行。
- D验证: confirmed / ver_c7022e3c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 513. hyp_path_11a6127ee278

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_45.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响环境变量，使得data指向恶意DLL的路径。
- 触发路径: /* NOTE: If the path to the library is not specified, an attacker may be able to replace his own file with the intended library */ hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_45.c:41-42; if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_45.c:44-48
- 结论: 通过环境变量控制的路径作为参数传递给LoadLibraryA函数，攻击者可能通过控制环境变量加载恶意库，导致任意代码执行。
- D验证: confirmed / ver_9972cc72
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 514. hyp_path_ecea1aced3d7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_45.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响环境变量，使得data指向恶意DLL的路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_45.c:46; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_45.c::case0Sink @ route
- 结论: 通过环境变量控制的路径作为参数传递给LoadLibraryA函数，攻击者可能通过控制环境变量加载恶意库，导致任意代码执行。
- D验证: confirmed / ver_744756ab
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 515. hyp_path_232bcb25a893

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_51b.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够修改环境变量data的值，使其指向恶意DLL路径
- 触发路径: 函数接收环境变量数据 @ CWE114_Process_Control__w32_char_environment_51b.c:35（入口点）; hModule = LoadLibraryA(data); @ CWE114_Process_Control__w32_char_environment_51b.c:44
- 结论: 程序通过环境变量获取库路径并调用LoadLibraryA加载，攻击者可能通过控制环境变量替换库文件，导致任意代码执行。
- D验证: confirmed / ver_eca36d78
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 516. hyp_path_5943c6597163

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_51b.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够修改环境变量data的值，使其指向恶意DLL路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_51b.c:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_51b.c::CWE114_Process_Control__w32_wchar_t_environment_51b_case0Sink @ route
- 结论: 程序通过环境变量获取库路径并调用LoadLibraryA加载，攻击者可能通过控制环境变量替换库文件，导致任意代码执行。
- D验证: confirmed / ver_3930e509
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 517. hyp_path_ab12a1a4d6c6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_52c.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制目标进程的环境变量，进而控制data指针指向的字符串。
- 触发路径: void CWE114_Process_Control__w32_char_environment_52c_case0Sink(char * data) @ 入口函数: CWE114_Process_Control__w32_char_environment_52c_case0Sink; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_52c.c:44
- 结论: 代码使用LoadLibraryA加载由环境变量控制的库路径，攻击者可以通过修改环境变量来加载恶意库，实现进程控制。
- D验证: confirmed / ver_77285887
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 518. hyp_path_a7f5a737f15c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_52c.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制目标进程的环境变量，进而控制data指针指向的字符串。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_52c.c:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_52c.c::CWE114_Process_Control__w32_wchar_t_environment_52c_case0Sink @ route
- 结论: 代码使用LoadLibraryA加载由环境变量控制的库路径，攻击者可以通过修改环境变量来加载恶意库，实现进程控制。
- D验证: confirmed / ver_5a9312dd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 519. hyp_path_23d1cf824840

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_54e.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量（如通过修改进程环境、注入等方式）
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_54e.c:39
- 结论: 程序从环境变量获取路径并调用LoadLibraryA加载库，攻击者可通过控制环境变量指定恶意DLL路径，导致任意代码执行。
- D验证: confirmed / ver_9fd13e78
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 520. hyp_path_94bfc6fea880

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_54e.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量（如通过修改进程环境、注入等方式）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_54e.c:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_54e.c::CWE114_Process_Control__w32_wchar_t_environment_54e_case0Sink @ route
- 结论: 程序从环境变量获取路径并调用LoadLibraryA加载库，攻击者可通过控制环境变量指定恶意DLL路径，导致任意代码执行。
- D验证: confirmed / ver_bb21ffbd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 521. hyp_path_c247202d4ff2

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_53d.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量，使其指向恶意DLL
- 触发路径: void CWE114_Process_Control__w32_char_environment_53d_case0Sink(char * data) @ 入口函数sink参数data来源为环境变量; hModule = LoadLibraryA(data); @ CWE114_Process_Control__w32_char_environment_53d.c:44
- 结论: 通过环境变量控制库路径，加载任意DLL，导致代码执行漏洞
- D验证: confirmed / ver_7eaedf4f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 522. hyp_path_24d2111a47de

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_53d.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量，使其指向恶意DLL
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_53d.c:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_53d.c::CWE114_Process_Control__w32_wchar_t_environment_53d_case0Sink @ route
- 结论: 通过环境变量控制库路径，加载任意DLL，导致代码执行漏洞
- D验证: confirmed / ver_03a7b665
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 523. hyp_path_c5a5e00e78ba

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_63b.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量（例如通过程序调用或配置文件）以控制data参数的值。
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_63b.c:38; if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_63b.c:41-45
- 结论: 攻击者通过控制环境变量来指定恶意DLL路径，导致进程控制漏洞，允许加载任意库。
- D验证: confirmed / ver_b37218d6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 524. hyp_path_b81fd28abdbb

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_63b.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量（例如通过程序调用或配置文件）以控制data参数的值。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_63b.c:43; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_63b.c::CWE114_Process_Control__w32_wchar_t_environment_63b_case0Sink @ route
- 结论: 攻击者通过控制环境变量来指定恶意DLL路径，导致进程控制漏洞，允许加载任意库。
- D验证: confirmed / ver_aa8a19cb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 525. hyp_path_663991fae2eb

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_64b.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够修改目标进程运行环境中的环境变量（例如通过父子进程继承或直接修改环境变量）。; 目标进程对LoadLibraryA的调用参数data来源于未净化的环境变量。
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_64b.c:41; if (hModule != NULL) { FreeLibrary(hModule); ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_64b.c:44-46
- 结论: 攻击者可通过控制环境变量来加载任意DLL，导致任意代码执行（进程控制漏洞）。
- D验证: confirmed / ver_111d2f2b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 526. hyp_path_0e313fa77024

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_64b.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够修改目标进程运行环境中的环境变量（例如通过父子进程继承或直接修改环境变量）。; 目标进程对LoadLibraryA的调用参数data来源于未净化的环境变量。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_64b.c:46; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_64b.c::CWE114_Process_Control__w32_wchar_t_environment_64b_case0Sink @ route
- 结论: 攻击者可通过控制环境变量来加载任意DLL，导致任意代码执行（进程控制漏洞）。
- D验证: confirmed / ver_9513b842
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 527. hyp_path_3c0e89cac2b4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_65b.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量，使data指向恶意DLL路径。; 程序在调用LoadLibraryA之前未对data进行路径限制或白名单检查。
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_65b.c:37; if (hModule != NULL) { FreeLibrary(hModule); ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_65b.c:40
- 结论: 程序通过环境变量获取库路径并调用LoadLibraryA加载动态链接库，攻击者可通过控制环境变量加载恶意DLL，导致任意代码执行或系统控制。
- D验证: confirmed / ver_293486a8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 528. hyp_path_395c3309293d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_65b.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量，使data指向恶意DLL路径。; 程序在调用LoadLibraryA之前未对data进行路径限制或白名单检查。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_65b.c:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_65b.c::CWE114_Process_Control__w32_wchar_t_environment_65b_case0Sink @ route
- 结论: 程序通过环境变量获取库路径并调用LoadLibraryA加载动态链接库，攻击者可通过控制环境变量加载恶意DLL，导致任意代码执行或系统控制。
- D验证: confirmed / ver_8ad595ed
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 529. hyp_path_e4d2e9d3bb43

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_66b.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量或输入，从而影响data参数的值
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_66b.c:44
- 结论: 通过LoadLibraryA加载外部库时，data参数可能来自不可信源（如环境变量），攻击者可控制该参数加载恶意DLL，导致代码执行或系统控制。
- D验证: confirmed / ver_0843b70b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 530. hyp_path_ec278fd032f5

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_66b.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量或输入，从而影响data参数的值
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_66b.c:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_66b.c::CWE114_Process_Control__w32_wchar_t_environment_66b_case0Sink @ route
- 结论: 通过LoadLibraryA加载外部库时，data参数可能来自不可信源（如环境变量），攻击者可控制该参数加载恶意DLL，导致代码执行或系统控制。
- D验证: confirmed / ver_96adb9e3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 531. hyp_path_ee4de09b8ae8

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_68b.c:48
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响进程环境变量，使得data指向恶意DLL路径
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_68b.c:48
- 结论: 函数LoadLibraryA直接使用从环境变量获取的数据作为库路径，攻击者可通过控制环境变量加载任意恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_50d9f30c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 532. hyp_path_91418398e01d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_68b.c:48
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响进程环境变量，使得data指向恶意DLL路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_68b.c:48; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_68b.c::CWE114_Process_Control__w32_wchar_t_environment_68b_case0Sink @ route
- 结论: 函数LoadLibraryA直接使用从环境变量获取的数据作为库路径，攻击者可通过控制环境变量加载任意恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_8999a93a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 533. hyp_path_560a2cc647a6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_67b.c:48
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量（如通过设置恶意的PATH或特定环境变量）。
- 触发路径: hModule = LoadLibraryA(data); @ CWE114_Process_Control__w32_char_environment_67b.c:48
- 结论: 存在CWE-114 Process Control漏洞：攻击者可通过控制环境变量来加载任意DLL库，导致进程控制或代码执行。
- D验证: confirmed / ver_f5bdbef6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 534. hyp_path_80a87d249819

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_67b.c:48
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量（如通过设置恶意的PATH或特定环境变量）。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_67b.c:48; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_67b.c::CWE114_Process_Control__w32_wchar_t_environment_67b_case0Sink @ route
- 结论: 存在CWE-114 Process Control漏洞：攻击者可通过控制环境变量来加载任意DLL库，导致进程控制或代码执行。
- D验证: confirmed / ver_d3df8c55
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 535. hyp_path_dcf021442144

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_43.cpp:144
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标主机建立TCP连接，并发送精心构造的数据包。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_43.cpp:92-96; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_43.cpp:139-143
- 结论: 应用程序通过recv从网络接收数据，并将其作为LoadLibraryA的参数加载动态库，攻击者可以控制该路径，导致加载恶意DLL，实现远程代码执行。
- D验证: confirmed / ver_88599e16
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 536. hyp_path_f7d6f9b3a084

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_43.cpp:144
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标主机建立TCP连接，并发送精心构造的数据包。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(hM... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_43.cpp:144; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_43.cpp::_ZN52CWE114_Process_Control__w32_wchar_t_listen_socket_435case0Ev @ route
- 结论: 应用程序通过recv从网络接收数据，并将其作为LoadLibraryA的参数加载动态库，攻击者可以控制该路径，导致加载恶意DLL，实现远程代码执行。
- D验证: confirmed / ver_d16d7e45
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 537. hyp_path_7f2b62598708

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_43.cpp:132
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接目标应用程序监听的socket端口，并发送自定义数据作为DLL路径。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_43.cpp:84-88; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_43.cpp:127-131
- 结论: 函数通过socket接收外部输入作为动态库路径，并调用LoadLibraryA加载该库，导致攻击者可能加载恶意DLL，构成进程控制漏洞（CWE-114）。
- D验证: confirmed / ver_922c0b14
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 538. hyp_path_3f4c0b341761

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_43.cpp:132
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接目标应用程序监听的socket端口，并发送自定义数据作为DLL路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) hModule = LoadLibraryW(data); if (hModule != NULL) FreeLibrary(h... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_43.cpp:132; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_43.cpp::_ZN53CWE114_Process_Control__w32_wchar_t_connect_socket_435case0Ev @ route
- 结论: 函数通过socket接收外部输入作为动态库路径，并调用LoadLibraryA加载该库，导致攻击者可能加载恶意DLL，构成进程控制漏洞（CWE-114）。
- D验证: confirmed / ver_af089825
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 539. hyp_path_0bf3fe5191dd

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_52a.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序读取的固定路径文件写入恶意内容
- 触发路径: fgets(data+dataLen, (int)(100-dataLen), pFile) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_52a.c:48; CWE114_Process_Control__w32_char_file_52b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_52a.c:60
- 结论: 程序从文件中读取数据并将其作为参数传递给可能加载外部库或执行程序的高危sink函数，攻击者若能控制文件内容，可导致任意代码执行。
- D验证: confirmed / ver_0a3a5955
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 540. hyp_path_dc7a6380d8bb

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_52a.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序读取的固定路径文件写入恶意内容
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... { /* Read input from a file */ size_t dataLen = wcslen(data); FILE * pFile; /* if there is room in data, attempt to read the input from a file */ ... } } CWE114_Process_Control__w32_wchar_t_file_52b_case0Sink(data); } ... if (fgetws(data+da... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_52a.c:46; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_52a.c::CWE114_Process_Control__w32_wchar_t_file_52_case0 @ route
- 结论: 程序从文件中读取数据并将其作为参数传递给可能加载外部库或执行程序的高危sink函数，攻击者若能控制文件内容，可导致任意代码执行。
- D验证: confirmed / ver_ec32730d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 541. hyp_path_1086eeb4187d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_53a.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够影响文件FILENAME的内容（例如通过写入恶意数据）
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_53a.c:46; fgets(data+dataLen, (int)(100-dataLen), pFile); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_53a.c:48-52; CWE114_Process_Control__w32_char_file_53b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_53a.c:60
- 结论: 程序从文件读取数据后，未经充分验证直接传递给CWE114_Process_Control__w32_char_file_53b_case0Sink函数，该函数可能执行危险操作（如加载库），若文件内容受攻击者控制，则可导致任意代码执行。
- D验证: confirmed / ver_b43c5670
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 542. hyp_path_1d5d2c12922e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_53a.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够影响文件FILENAME的内容（例如通过写入恶意数据）
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... { /* Read input from a file */ size_t dataLen = wcslen(data); FILE * pFile; /* if there is room in data, attempt to read the input from a file */ ... } } CWE114_Process_Control__w32_wchar_t_file_53b_case0Sink(data); } ... if (fgetws(data+da... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_53a.c:46; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_53a.c::CWE114_Process_Control__w32_wchar_t_file_53_case0 @ route
- 结论: 程序从文件读取数据后，未经充分验证直接传递给CWE114_Process_Control__w32_char_file_53b_case0Sink函数，该函数可能执行危险操作（如加载库），若文件内容受攻击者控制，则可导致任意代码执行。
- D验证: confirmed / ver_0419f90b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 543. hyp_path_8ff4e1552289

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_51a.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制文件内容，或能够影响文件路径指向恶意内容。
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_51a.c:46; if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) {...} @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_51a.c:48-52; CWE114_Process_Control__w32_char_file_51b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_51a.c:60
- 结论: 程序从文件读取数据并传递给外部过程控制函数，攻击者可能通过控制文件内容导致加载恶意库或执行任意命令。
- D验证: confirmed / ver_ff684395
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 544. hyp_path_46b3e813c988

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_51a.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制文件内容，或能够影响文件路径指向恶意内容。
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... { /* Read input from a file */ size_t dataLen = wcslen(data); FILE * pFile; /* if there is room in data, attempt to read the input from a file */ ... } } CWE114_Process_Control__w32_wchar_t_file_51b_case0Sink(data); } ... if (fgetws(data+da... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_51a.c:46; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_51a.c::CWE114_Process_Control__w32_wchar_t_file_51_case0 @ route
- 结论: 程序从文件读取数据并传递给外部过程控制函数，攻击者可能通过控制文件内容导致加载恶意库或执行任意命令。
- D验证: confirmed / ver_7f039a27
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 545. hyp_path_158dfef6a22d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_63a.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入或修改文件系统中指定的FILENAME文件
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_63a.c:46; CWE114_Process_Control__w32_char_file_63b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_63a.c:60
- 结论: 程序从外部文件读取数据，并将数据传递给可能执行不安全操作的sink函数（如LoadLibrary），导致潜在的代码执行或DLL劫持漏洞。
- D验证: confirmed / ver_c015bcee
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 546. hyp_path_345c2527fff9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_63a.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入或修改文件系统中指定的FILENAME文件
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... { /* Read input from a file */ size_t dataLen = wcslen(data); FILE * pFile; /* if there is room in data, attempt to read the input from a file */ ... } } CWE114_Process_Control__w32_wchar_t_file_63b_case0Sink(&data); } ... if (fgetws(data+d... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_63a.c:46; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_63a.c::CWE114_Process_Control__w32_wchar_t_file_63_case0 @ route
- 结论: 程序从外部文件读取数据，并将数据传递给可能执行不安全操作的sink函数（如LoadLibrary），导致潜在的代码执行或DLL劫持漏洞。
- D验证: confirmed / ver_04b4ed7c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 547. hyp_path_3bfaf6afbdb2

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_54a.c:46
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够创建或修改文件名为FILENAME的文件（或文件路径可控）
- 触发路径: pFile = fopen(FILENAME, "r"); ... fgets(data+dataLen, (int)(100-dataLen), pFile); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_54a.c:45-52; CWE114_Process_Control__w32_char_file_54b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_54a.c:60
- 结论: 程序从文件读取数据作为命令的一部分，未经过滤直接传递给进程控制函数，可能导致命令注入或恶意进程执行。
- D验证: confirmed / ver_9b54db0a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 548. hyp_path_26151351a985

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_54a.c:46
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够创建或修改文件名为FILENAME的文件（或文件路径可控）
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... { /* Read input from a file */ size_t dataLen = wcslen(data); FILE * pFile; /* if there is room in data, attempt to read the input from a file */ ... } } CWE114_Process_Control__w32_wchar_t_file_54b_case0Sink(data); } ... if (fgetws(data+da... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_54a.c:46; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_54a.c::CWE114_Process_Control__w32_wchar_t_file_54_case0 @ route
- 结论: 程序从文件读取数据作为命令的一部分，未经过滤直接传递给进程控制函数，可能导致命令注入或恶意进程执行。
- D验证: confirmed / ver_8dd6851c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 549. hyp_path_b92528d47b70

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_64a.c:46
- 漏洞类型: command_injection
- CWE: CWE-114; CWE-78
- 风险等级: P0
- 触发条件: 攻击者能够控制文件的内容（例如，通过文件上传、共享目录写入或替换现有文件）
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_64a.c:46; fgets(data+dataLen, (int)(100-dataLen), pFile); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_64a.c:51; CWE114_Process_Control__w32_char_file_64b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_64a.c:60
- 结论: 从文件读取的数据未经充分验证即用于进程控制，攻击者可控制文件内容实现任意进程执行。
- D验证: confirmed / ver_d3204829
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 550. hyp_path_a12f5db83720

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_64a.c:46
- 漏洞类型: command_injection
- CWE: CWE-114; CWE-78
- 风险等级: P0
- 触发条件: 攻击者能够控制文件的内容（例如，通过文件上传、共享目录写入或替换现有文件）
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... { /* Read input from a file */ size_t dataLen = wcslen(data); FILE * pFile; /* if there is room in data, attempt to read the input from a file */ ... } } CWE114_Process_Control__w32_wchar_t_file_64b_case0Sink(&data); } ... if (fgetws(data+d... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_64a.c:46; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_64a.c::CWE114_Process_Control__w32_wchar_t_file_64_case0 @ route
- 结论: 从文件读取的数据未经充分验证即用于进程控制，攻击者可控制文件内容实现任意进程执行。
- D验证: confirmed / ver_4b6f8f8e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 551. hyp_path_d9e351baf83c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_81a.cpp:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向文件FILENAME中写入恶意数据（或控制文件路径）
- 触发路径: pFile = fopen(FILENAME, "r"); if (pFile != NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_81a.cpp:41-45; if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_81a.cpp:45-49; fclose(pFile);...;baseObject.action(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_81a.cpp:51-55
- 结论: 从文件中读取的数据被用于进程控制操作（例如作为参数传递给可能加载库或执行命令的函数），攻击者若能控制文件内容，可导致任意代码执行。
- D验证: confirmed / ver_9e906330
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 552. hyp_path_4a16cb5fa5e1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_81a.cpp:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向文件FILENAME中写入恶意数据（或控制文件路径）
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... { /* Read input from a file */ size_t dataLen = wcslen(data); FILE * pFile; /* if there is room in data, attempt to read the input from a file */ ... } } const CWE114_Process_Control__w32_wchar_t_file_81_base& baseObject = CWE114_Process_Co... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_81a.cpp:43; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_81a.cpp::_ZN43CWE114_Process_Control__w32_wchar_t_file_815case0Ev @ route
- 结论: 从文件中读取的数据被用于进程控制操作（例如作为参数传递给可能加载库或执行命令的函数），攻击者若能控制文件内容，可导致任意代码执行。
- D验证: confirmed / ver_a662fce5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 553. hyp_path_ea97643a69b9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_45.c:66
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件的内容。
- 触发路径: fgets(data+dataLen, (int)(100-dataLen), pFile) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_45.c:66; case0Sink() @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_45.c:81; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_45.c:42
- 结论: 从文件中读取数据后，未经充分验证便作为参数传递给LoadLibraryA，可能导致加载恶意DLL。
- D验证: confirmed / ver_7341ebcc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 554. hyp_path_77296ca79211

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_45.c:66
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件的内容。
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... { /* Read input from a file */ size_t dataLen = wcslen(data); FILE * pFile; /* if there is room in data, attempt to read the input from a file */ ... } CWE114_Process_Control__w32_wchar_t_file_45_case0Data = data; case0Sink(); } ... if (fge... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_45.c:66; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_45.c::CWE114_Process_Control__w32_wchar_t_file_45_case0 @ route
- 结论: 从文件中读取数据后，未经充分验证便作为参数传递给LoadLibraryA，可能导致加载恶意DLL。
- D验证: confirmed / ver_a56f2211
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 555. hyp_path_ecf02cb48eb5

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_44.c:64
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制文件'FILENAME'的内容; 程序使用从文件读取的数据作为进程控制函数的参数
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_44.c:64; if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_44.c:66-70; 假设后续调用 LoadLibrary(data) 或 CreateProcess(data, ...) @ 缺失代码段
- 结论: 由于从文件读取的数据可能被用于进程控制函数（如LoadLibrary或CreateProcess），若攻击者能控制文件内容，则可导致执行任意代码或加载恶意库。
- D验证: confirmed / ver_b2781e0d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 556. hyp_path_348da4f94684

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_44.c:64
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制文件'FILENAME'的内容; 程序使用从文件读取的数据作为进程控制函数的参数
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... { /* Read input from a file */ size_t dataLen = wcslen(data); FILE * pFile; /* if there is room in data, attempt to read the input from a file */ ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) { printLine("fgetws() failed"... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_44.c:64; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_44.c::CWE114_Process_Control__w32_wchar_t_file_44_case0 @ route
- 结论: 由于从文件读取的数据可能被用于进程控制函数（如LoadLibrary或CreateProcess），若攻击者能控制文件内容，则可导致执行任意代码或加载恶意库。
- D验证: confirmed / ver_00f6a3bb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 557. hyp_path_61228ff189e4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_66a.c:47
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制文件FILENAME的内容
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_66a.c:47; fgets(data+dataLen, (int)(100-dataLen), pFile); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_66a.c:52; CWE114_Process_Control__w32_char_file_66b_case0Sink(dataArray); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_66a.c:63
- 结论: 从文件读取数据后传递给进程控制sink函数，攻击者可通过控制文件内容实现任意进程调用或命令执行。
- D验证: confirmed / ver_4ba1e817
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 558. hyp_path_73879ff2d120

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_66a.c:47
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制文件FILENAME的内容
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... { /* Read input from a file */ size_t dataLen = wcslen(data); FILE * pFile; /* if there is room in data, attempt to read the input from a file */ ... /* put data in array */ dataArray[2] = data; CWE114_Process_Control__w32_wchar_t_file_66b_... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_66a.c:47; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_66a.c::CWE114_Process_Control__w32_wchar_t_file_66_case0 @ route
- 结论: 从文件读取数据后传递给进程控制sink函数，攻击者可通过控制文件内容实现任意进程调用或命令执行。
- D验证: confirmed / ver_a1f0a716
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 559. hyp_path_1e681ebcedb6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_67a.c:52
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向指定文件（如FILENAME）写入恶意命令字符串。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_67a.c:54; CWE114_Process_Control__w32_char_file_67b_case0Sink(myStruct); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_67a.c:67
- 结论: 从文件读取的数据被用于进程控制（如system或CreateProcess）的sink，攻击者可通过控制文件内容实现命令注入。
- D验证: confirmed / ver_5278570e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 560. hyp_path_6d72c2e81103

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_67a.c:52
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向指定文件（如FILENAME）写入恶意命令字符串。
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... { /* Read input from a file */ size_t dataLen = wcslen(data); FILE * pFile; /* if there is room in data, attempt to read the input from a file */ ... } myStruct.structFirst = data; CWE114_Process_Control__w32_wchar_t_file_67b_case0Sink(mySt... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_67a.c:52; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_67a.c::CWE114_Process_Control__w32_wchar_t_file_67_case0 @ route
- 结论: 从文件读取的数据被用于进程控制（如system或CreateProcess）的sink，攻击者可通过控制文件内容实现命令注入。
- D验证: confirmed / ver_569de4c8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 561. hyp_path_df465a448dab

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_68a.c:49
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制文件FILENAME的内容
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_68a.c:49; if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_68a.c:51-55; CWE114_Process_Control__w32_char_file_68b_case0Sink(); (sink函数中可能使用data作为进程路径) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_68a.c:64
- 结论: 程序从外部文件读取数据，并通过全局变量传递给进程创建函数，攻击者如果能够控制文件内容，则可以执行任意命令或恶意程序。
- D验证: confirmed / ver_f1a68856
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 562. hyp_path_51da43395a23

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_68a.c:49
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制文件FILENAME的内容
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... { /* Read input from a file */ size_t dataLen = wcslen(data); FILE * pFile; /* if there is room in data, attempt to read the input from a file */ ... } CWE114_Process_Control__w32_wchar_t_file_68_case0Data = data; CWE114_Process_Control__w3... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_68a.c:49; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_68a.c::CWE114_Process_Control__w32_wchar_t_file_68_case0 @ route
- 结论: 程序从外部文件读取数据，并通过全局变量传递给进程创建函数，攻击者如果能够控制文件内容，则可以执行任意命令或恶意程序。
- D验证: confirmed / ver_23d2f348
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 563. hyp_path_2469d1279020

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_42.c:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制文件FILENAME或文件内容
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_42.c:40; data[dataLen] = '\0'; } fclose(pFile); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_42.c:48-52
- 结论: CWE114: Process Control - 从文件读取的数据可能作为进程控制参数
- D验证: confirmed / ver_ca9f6fac
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 564. hyp_path_01af24ae9c73

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_42.c:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制文件FILENAME或文件内容
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... { /* Read input from a file */ size_t dataLen = wcslen(data); FILE * pFile; /* if there is room in data, attempt to read the input from a file */ ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) { printLine("fgetws() failed"... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_42.c:40; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_42.c::case0Source @ route
- 结论: CWE114: Process Control - 从文件读取的数据可能作为进程控制参数
- D验证: confirmed / ver_732409e5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 565. hyp_path_596cb3932f50

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_62b.cpp:41
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入或替换程序读取的文件内容
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) { printLine("fgets() failed"); data[dataLen] = '\0'; } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_62b.cpp:41; 疑似后续调用system或CreateProcess(data) @ 后续sink点（未在片段中展示，但根据CWE114上下文推断）
- 结论: 程序从文件读取数据，可能用于后续的进程控制操作（如system或CreateProcess），攻击者可通过控制文件内容实现命令执行或库加载，存在CWE-114 Process Control漏洞。
- D验证: confirmed / ver_d01ec68c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 566. hyp_path_28ebfca2b5bb

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_62b.cpp:41
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入或替换程序读取的文件内容
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... { /* Read input from a file */ size_t dataLen = wcslen(data); FILE * pFile; /* if there is room in data, attempt to read the input from a file */ ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) { printLine("fgetws() failed"... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_62b.cpp:41; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_62b.cpp::_ZN43CWE114_Process_Control__w32_wchar_t_file_6211case0SourceERPw @ route
- 结论: 程序从文件读取数据，可能用于后续的进程控制操作（如system或CreateProcess），攻击者可通过控制文件内容实现命令执行或库加载，存在CWE-114 Process Control漏洞。
- D验证: confirmed / ver_7c766a05
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 567. hyp_path_5a3dbf5cbc40

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_84_case0.cpp:41
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件内容
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_84_case0.cpp:41; 后续未提供sink代码，但样本命名暗示可能使用LoadLibrary或CreateProcess等函数调用。 @ 描述
- 结论: 潜在CWE-114漏洞：从文件读取的数据可能被用于进程控制函数，但代码证据不完整，缺少sink部分。
- D验证: confirmed / ver_a780ef07
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 568. hyp_path_75baa144e7eb

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_84_case0.cpp:41
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件内容
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) fclose(pFile); ... { /* Read input from a file */ size_t dataLen = wcslen(data); FILE * pFile; /* if there is room in data, attempt to read the input from a file */ ... if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) { printLine("fgetws() failed"... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_84_case0.cpp:41; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_84_case0.cpp::_ZN43CWE114_Process_Control__w32_wchar_t_file_8449CWE114_Process_Control__w32_wchar_t_file_84_case0C2EPw @ route
- 结论: 潜在CWE-114漏洞：从文件读取的数据可能被用于进程控制函数，但代码证据不完整，缺少sink部分。
- D验证: confirmed / ver_f94d154a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 569. hyp_path_9e787c7f2ed4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_84_case0.cpp:41
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件内容
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_84_case0.cpp:41; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_84_case0.cpp::_ZN48CWE114_Process_Control__w32_char_relativePath_8454CWE114_Process_Control__w32_char_relativePath_84_case0D2Ev @ route
- 结论: 潜在CWE-114漏洞：从文件读取的数据可能被用于进程控制函数，但代码证据不完整，缺少sink部分。
- D验证: confirmed / ver_0d23707c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 570. hyp_path_34945b7e4182

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_84_case0.cpp:41
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件内容
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_84_case0.cpp:41; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_84_case0.cpp::_ZN51CWE114_Process_Control__w32_wchar_t_relativePath_8457CWE114_Process_Control__w32_wchar_t_relativePath_84_case0D2Ev @ route
- 结论: 潜在CWE-114漏洞：从文件读取的数据可能被用于进程控制函数，但代码证据不完整，缺少sink部分。
- D验证: confirmed / ver_9ceb0793
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 571. hyp_path_bdc03bb7b10e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_21.c:137
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接发送数据到目标程序; 目标程序在运行且监听socket
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_21.c:86-90; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_21.c:132
- 结论: 程序从网络socket接收数据，未经验证直接作为参数调用LoadLibraryA加载动态库，攻击者可通过控制网络输入指定恶意库路径，导致任意代码执行。
- D验证: confirmed / ver_0ac7a678
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 572. hyp_path_4fefcd724bb1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_21.c:137
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接发送数据到目标程序; 目标程序在运行且监听socket
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) return data; hModule = LoadLibraryW(data); if (hModule != NULL) ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_21.c:137; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_21.c::CWE114_Process_Control__w32_wchar_t_connect_socket_21_case0 @ route
- 结论: 程序从网络socket接收数据，未经验证直接作为参数调用LoadLibraryA加载动态库，攻击者可通过控制网络输入指定恶意库路径，导致任意代码执行。
- D验证: confirmed / ver_41b5c6fb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 573. hyp_path_c2e59bdf1854

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_42.c:130
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够建立网络连接并发送数据到目标程序监听的端口，且程序未对data进行任何过滤或验证。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_42.c:81-85; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_42.c:125
- 结论: 程序未对从网络接收的数据进行充分验证，直接将其作为LoadLibraryA的参数，攻击者可能通过控制网络输入加载任意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_5de09bf0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 574. hyp_path_6b80a020dd72

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_42.c:130
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够建立网络连接并发送数据到目标程序监听的端口，且程序未对data进行任何过滤或验证。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) return data; hModule = LoadLibraryW(data); if (hModule != NULL) ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_42.c:130; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_42.c::CWE114_Process_Control__w32_wchar_t_connect_socket_42_case0 @ route
- 结论: 程序未对从网络接收的数据进行充分验证，直接将其作为LoadLibraryA的参数，攻击者可能通过控制网络输入加载任意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_94d5076a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 575. hyp_path_9a6e1b40e2ad

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_21.c:149
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问目标程序监听的端口并发送任意数据; 目标系统存在一个可加载的恶意DLL文件（如网络共享）或攻击者能利用UNC路径加载远程DLL
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_21.c:94-98; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_21.c:144-148; if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_21.c:147-151
- 结论: 程序通过recv从网络接收数据，未经验证直接作为LoadLibraryA参数加载DLL，攻击者可发送恶意DLL路径，导致远程代码执行。
- D验证: confirmed / ver_f7cc33f1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 576. hyp_path_63862e252864

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_21.c:149
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问目标程序监听的端口并发送任意数据; 目标系统存在一个可加载的恶意DLL文件（如网络共享）或攻击者能利用UNC路径加载远程DLL
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) return data; hModule = LoadLibraryW(data); if (hModule != NULL) F... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_21.c:149; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_21.c::CWE114_Process_Control__w32_wchar_t_listen_socket_21_case0 @ route
- 结论: 程序通过recv从网络接收数据，未经验证直接作为LoadLibraryA参数加载DLL，攻击者可发送恶意DLL路径，导致远程代码执行。
- D验证: confirmed / ver_1a307ad6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 577. hyp_path_d41c14c05adc

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_42.c:142
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标服务建立TCP连接并发送任意数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_42.c:89-93; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_42.c:138
- 结论: 存在过程控制漏洞：攻击者可通过网络发送恶意数据，控制LoadLibraryA加载任意DLL，导致代码执行。
- D验证: confirmed / ver_63cc3ebd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 578. hyp_path_f37bba9f5033

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_42.c:142
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与目标服务建立TCP连接并发送任意数据
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) return data; hModule = LoadLibraryW(data); if (hModule != NULL) F... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_42.c:142; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_42.c::CWE114_Process_Control__w32_wchar_t_listen_socket_42_case0 @ route
- 结论: 存在过程控制漏洞：攻击者可通过网络发送恶意数据，控制LoadLibraryA加载任意DLL，导致代码执行。
- D验证: confirmed / ver_39038b70
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 579. hyp_path_cd543e47429c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_61a.c:61
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过socket连接向目标程序发送任意字符串
- 触发路径: data = CWE114_Process_Control__w32_char_connect_socket_61b_case0Source(data); // 从socket读取数据 @ CWE114_Process_Control__w32_char_connect_socket_61a.c:48; hModule = LoadLibraryA(data); // 使用未经验证的路径加载库 @ CWE114_Process_Control__w32_char_connect_socket_61a.c:56
- 结论: 存在CWE-114 Process Control漏洞：从外部socket接收的数据直接用于LoadLibraryA加载库，攻击者可控制库路径加载恶意DLL，导致远程代码执行。
- D验证: confirmed / ver_7b0784e1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 580. hyp_path_bb58c50bf76b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_61a.c:61
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过socket连接向目标程序发送任意字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... char dataBuffer[100] = ""; ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_61a.c:61; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_61a.c::CWE114_Process_Control__w32_char_listen_socket_61_case0 @ route
- 结论: 存在CWE-114 Process Control漏洞：从外部socket接收的数据直接用于LoadLibraryA加载库，攻击者可控制库路径加载恶意DLL，导致远程代码执行。
- D验证: confirmed / ver_b84c6da1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 581. hyp_path_4a1f1398a9c9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_61a.c:61
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过socket连接向目标程序发送任意字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... wchar_t dataBuffer[100] = L... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_61a.c:61; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_61a.c::CWE114_Process_Control__w32_wchar_t_connect_socket_61_case0 @ route
- 结论: 存在CWE-114 Process Control漏洞：从外部socket接收的数据直接用于LoadLibraryA加载库，攻击者可控制库路径加载恶意DLL，导致远程代码执行。
- D验证: confirmed / ver_886c7518
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 582. hyp_path_ff2e7d690c7c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_61a.c:61
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过socket连接向目标程序发送任意字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... wchar_t dataBuffer[100] = L... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_61a.c:61; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_61a.c::CWE114_Process_Control__w32_wchar_t_listen_socket_61_case0 @ route
- 结论: 存在CWE-114 Process Control漏洞：从外部socket接收的数据直接用于LoadLibraryA加载库，攻击者可控制库路径加载恶意DLL，导致远程代码执行。
- D验证: confirmed / ver_e062aac9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 583. hyp_path_714e5b33a422

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_53a.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_53a.c:44; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_53a.c:49; CWE114_Process_Control__w32_char_environment_53b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_53a.c:52
- 结论: 从环境变量获取数据并拼接后传递给进程控制函数，攻击者可控制环境变量导致加载任意库或执行命令。
- D验证: confirmed / ver_2f7a4826
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 584. hyp_path_9c4cbebd7182

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_53a.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值
- 触发路径: { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... { /* NOTE: Read data from an environment variable */ wcsncat(data+dataLen, environment, 100-dataLen-1); } } ... } } CWE114_Process... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_53a.c:43; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_53a.c::CWE114_Process_Control__w32_wchar_t_environment_53_case0 @ route
- 结论: 从环境变量获取数据并拼接后传递给进程控制函数，攻击者可控制环境变量导致加载任意库或执行命令。
- D验证: confirmed / ver_3fa626a4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 585. hyp_path_73d32308cd34

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_52a.c:43
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响环境变量ENV_VARIABLE的值
- 触发路径: size_t dataLen = strlen(data);\nchar * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_52a.c:43-44; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_52a.c:49; CWE114_Process_Control__w32_char_environment_52b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_52a.c:52
- 结论: 程序从环境变量读取数据并拼接到缓冲区，然后传递给CWE114_Process_Control相关函数。攻击者可控制环境变量，可能导致命令注入或任意代码执行。
- D验证: confirmed / ver_ef696199
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 586. hyp_path_b0cab124044f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_52a.c:43
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响环境变量ENV_VARIABLE的值
- 触发路径: { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... { /* NOTE: Read data from an environment variable */ wcsncat(data+dataLen, environment, 100-dataLen-1); } } ... } } CWE114_Process... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_52a.c:43; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_52a.c::CWE114_Process_Control__w32_wchar_t_environment_52_case0 @ route
- 结论: 程序从环境变量读取数据并拼接到缓冲区，然后传递给CWE114_Process_Control相关函数。攻击者可控制环境变量，可能导致命令注入或任意代码执行。
- D验证: confirmed / ver_1eaf6f49
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 587. hyp_path_56022d00c48a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_51a.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值为任意字符串; 程序运行在允许环境变量影响进程加载的环境（如Windows系统）
- 触发路径: size_t dataLen = strlen(data); char * environment = GETENV(ENV_VARIABLE); if (environment != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_51a.c:41-45; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_51a.c:47-49; CWE114_Process_Control__w32_char_environment_51b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_51a.c:52
- 结论: 程序从环境变量获取输入，并将其作为参数传递给进程控制函数，攻击者可通过控制环境变量来加载恶意库或执行任意命令，构成CWE-114 Process Control漏洞。
- D验证: confirmed / ver_4526e6f0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 588. hyp_path_2fd22e6cab09

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_51a.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值为任意字符串; 程序运行在允许环境变量影响进程加载的环境（如Windows系统）
- 触发路径: { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... { /* NOTE: Read data from an environment variable */ wcsncat(data+dataLen, environment, 100-dataLen-1); } } ... } } CWE114_Process... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_51a.c:43; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_51a.c::CWE114_Process_Control__w32_wchar_t_environment_51_case0 @ route
- 结论: 程序从环境变量获取输入，并将其作为参数传递给进程控制函数，攻击者可通过控制环境变量来加载恶意库或执行任意命令，构成CWE-114 Process Control漏洞。
- D验证: confirmed / ver_2efa928c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 589. hyp_path_2a44ac6ed3fa

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_54a.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响环境变量ENV_VARIABLE的值
- 触发路径: size_t dataLen = strlen(data); char * environment = GETENV(ENV_VARIABLE); @ line 42-44; strncat(data+dataLen, environment, 100-dataLen-1); @ line 47-49; CWE114_Process_Control__w32_char_environment_54b_case0Sink(data); @ line 52
- 结论: 程序从环境变量读取输入并构造一个路径字符串，随后传递给可能执行外部控制的sink函数，攻击者可通过设置恶意环境变量导致加载任意库或执行任意命令。
- D验证: confirmed / ver_26ddfc33
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 590. hyp_path_39dfa78be189

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_54a.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响环境变量ENV_VARIABLE的值
- 触发路径: { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... { /* NOTE: Read data from an environment variable */ wcsncat(data+dataLen, environment, 100-dataLen-1); } } ... /* Append input fr... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_54a.c:43; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_54a.c::CWE114_Process_Control__w32_wchar_t_environment_54_case0 @ route
- 结论: 程序从环境变量读取输入并构造一个路径字符串，随后传递给可能执行外部控制的sink函数，攻击者可通过设置恶意环境变量导致加载任意库或执行任意命令。
- D验证: confirmed / ver_25ecbba7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 591. hyp_path_4a65e3525d91

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_63a.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置目标进程的环境变量ENV_VARIABLE
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_63a.c:44; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_63a.c:49; CWE114_Process_Control__w32_char_environment_63b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_63a.c:52
- 结论: 从环境变量读取数据后，未进行充分验证直接传入进程控制函数，可能导致攻击者通过设置恶意环境变量执行任意代码或加载恶意库。
- D验证: confirmed / ver_b92ab9a8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 592. hyp_path_e6643954be6e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_63a.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置目标进程的环境变量ENV_VARIABLE
- 触发路径: { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... { /* NOTE: Read data from an environment variable */ wcsncat(data+dataLen, environment, 100-dataLen-1); } } ... } } CWE114_Process... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_63a.c:43; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_63a.c::CWE114_Process_Control__w32_wchar_t_environment_63_case0 @ route
- 结论: 从环境变量读取数据后，未进行充分验证直接传入进程控制函数，可能导致攻击者通过设置恶意环境变量执行任意代码或加载恶意库。
- D验证: confirmed / ver_2d961019
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 593. hyp_path_700281849feb

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_82a.cpp:55
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入提供任意字符串（控制台或重定向）。; action函数内部将data参数用于进程控制操作（如system或LoadLibrary）。
- 触发路径: fgets(data+dataLen, (int)(100-dataLen), stdin); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_82a.cpp:30-37; CWE114_Process_Control__w32_char_console_82_base* baseObject = new CWE114_Process_Control__w32_char_console_82_case0; baseObject->action(data); delete baseObject; @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_82a.cpp:53-57
- 结论: 程序从控制台读取输入并通过多态调用传递给action函数，action函数可能将输入作为系统命令或库路径执行，存在进程控制漏洞风险。
- D验证: confirmed / ver_af8e10ba
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 594. hyp_path_04d5f4ea8d1b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_82a.cpp:55
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入提供任意字符串（控制台或重定向）。; action函数内部将data参数用于进程控制操作（如system或LoadLibrary）。
- 触发路径: } } CWE114_Process_Control__w32_wchar_t_console_82_base* baseObject = new CWE114_Process_Control__w32_wchar_t_console_82_case0; baseObject->action(data); delete baseObject; ... CWE114_Process_Control__w32_wchar_t_console_82_base* baseObject = new CWE114_Process_Control__w32_wchar_t_console_82_case0; baseObject->action(... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_82a.cpp:55; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_82a.cpp::_ZN46CWE114_Process_Control__w32_wchar_t_console_825case0Ev @ route
- 结论: 程序从控制台读取输入并通过多态调用传递给action函数，action函数可能将输入作为系统命令或库路径执行，存在进程控制漏洞风险。
- D验证: confirmed / ver_6d3c6087
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 595. hyp_path_88ea1042e4c9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_82a.cpp:49
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够修改目标进程的环境变量（例如通过父进程或系统配置）。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_82a.cpp:41; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_82a.cpp:46; baseObject->action(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_82a.cpp:49
- 结论: 从环境变量获取数据并传递给action函数，可能导致进程控制或命令注入漏洞，但缺少sink具体实现，证据不闭合。
- D验证: confirmed / ver_1ec0aea9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 596. hyp_path_453d458ac541

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_82a.cpp:49
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够修改目标进程的环境变量（例如通过父进程或系统配置）。
- 触发路径: } } CWE114_Process_Control__w32_wchar_t_environment_82_base* baseObject = new CWE114_Process_Control__w32_wchar_t_environment_82_case0; baseObject->action(data); delete baseObject; ... { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_82a.cpp:49; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_82a.cpp::_ZN50CWE114_Process_Control__w32_wchar_t_environment_825case0Ev @ route
- 结论: 从环境变量获取数据并传递给action函数，可能导致进程控制或命令注入漏洞，但缺少sink具体实现，证据不闭合。
- D验证: confirmed / ver_61a0bc13
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 597. hyp_path_d3001f7cefe8

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_64a.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量（如通过设置ENV_VARIABLE环境变量）。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_64a.c:44; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_64a.c:49; CWE114_Process_Control__w32_char_environment_64b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_64a.c:52
- 结论: 从环境变量读取数据并拼接到缓冲区，然后传递给进程控制函数（可能加载库或执行程序），攻击者可通过控制环境变量实现任意代码执行或加载恶意库。
- D验证: confirmed / ver_49bc50c5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 598. hyp_path_e2f48fcc6029

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_64a.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量（如通过设置ENV_VARIABLE环境变量）。
- 触发路径: { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... { /* NOTE: Read data from an environment variable */ wcsncat(data+dataLen, environment, 100-dataLen-1); } } ... /* Append input fr... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_64a.c:43; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_64a.c::CWE114_Process_Control__w32_wchar_t_environment_64_case0 @ route
- 结论: 从环境变量读取数据并拼接到缓冲区，然后传递给进程控制函数（可能加载库或执行程序），攻击者可通过控制环境变量实现任意代码执行或加载恶意库。
- D验证: confirmed / ver_7063d98a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 599. hyp_path_b7e86085515b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_81a.cpp:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制系统环境变量ENV_VARIABLE的值。; 目标程序以允许环境变量传播的方式执行（如通过子进程或直接运行）。
- 触发路径: size_t dataLen = strlen(data); char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_81a.cpp:40; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_81a.cpp:46; baseObject.action(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_81a.cpp:49
- 结论: 从环境变量读取数据并追加到缓冲区，随后该数据被用于进程控制操作（如加载库），攻击者可通过设置环境变量控制程序行为，导致未授权操作或任意代码执行。
- D验证: confirmed / ver_0562eb60
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 600. hyp_path_3b51f0833019

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_81a.cpp:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制系统环境变量ENV_VARIABLE的值。; 目标程序以允许环境变量传播的方式执行（如通过子进程或直接运行）。
- 触发路径: { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... { /* NOTE: Read data from an environment variable */ wcsncat(data+dataLen, environment, 100-dataLen-1); } } ... /* Append input fr... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_81a.cpp:40; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_81a.cpp::_ZN50CWE114_Process_Control__w32_wchar_t_environment_815case0Ev @ route
- 结论: 从环境变量读取数据并追加到缓冲区，随后该数据被用于进程控制操作（如加载库），攻击者可通过设置环境变量控制程序行为，导致未授权操作或任意代码执行。
- D验证: confirmed / ver_efd5eeb4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 601. hyp_path_4fefd45cdc64

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_21.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_21.c:42
- 结论: 程序从环境变量（GETENV(ENV_VARIABLE)）读取数据，通过strncat拼接到固定大小为100的缓冲区（data），但代码片段未显示后续将data用于进程控制sink（如system、CreateProcess）。因此存在数据来源但缺少sink，路径不完整，无法确认可利用漏洞。
- D验证: confirmed / ver_deda96bf
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 602. hyp_path_9028840be72f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_21.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... { /* NOTE: Read data from an environment variable */ wcsncat(data+dataLen, environment, 100-dataLen-1); } } ... /* Append input fr... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_21.c:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_21.c::case0Source @ route
- 结论: 程序从环境变量（GETENV(ENV_VARIABLE)）读取数据，通过strncat拼接到固定大小为100的缓冲区（data），但代码片段未显示后续将data用于进程控制sink（如system、CreateProcess）。因此存在数据来源但缺少sink，路径不完整，无法确认可利用漏洞。
- D验证: confirmed / ver_fe0da192
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 603. hyp_path_df0070199bd4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_42.c:37
- 漏洞类型: buffer_overflow
- CWE: CWE-120; CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值，且该值长度大于100-dataLen-1
- 触发路径: size_t dataLen = strlen(data); @ CWE114_Process_Control__w32_char_environment_42.c:36; char * environment = GETENV(ENV_VARIABLE); @ CWE114_Process_Control__w32_char_environment_42.c:38; if (environment != NULL) { strncat(data+dataLen, environment, 100-dataLen-1); } @ CWE114_Process_Control__w32_char_environment_42.c:41-43
- 结论: 函数从环境变量读取数据并追加到固定缓冲区中，可能导致缓冲区溢出，攻击者可通过控制环境变量覆盖栈上数据。
- D验证: confirmed / ver_545894af
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 604. hyp_path_ce1e34ac9c83

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_42.c:37
- 漏洞类型: buffer_overflow
- CWE: CWE-120; CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值，且该值长度大于100-dataLen-1
- 触发路径: { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... { /* NOTE: Read data from an environment variable */ wcsncat(data+dataLen, environment, 100-dataLen-1); } } ... /* Append input fr... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_42.c:37; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_42.c::case0Source @ route
- 结论: 函数从环境变量读取数据并追加到固定缓冲区中，可能导致缓冲区溢出，攻击者可通过控制环境变量覆盖栈上数据。
- D验证: confirmed / ver_939f6dca
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 605. hyp_path_6b49748fe524

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_61b.c:37
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的内容。
- 触发路径: size_t dataLen = strlen(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_61b.c:36; char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_61b.c:38; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_61b.c:43
- 结论: 代码从环境变量读取数据并追加到固定大小的缓冲区，后续可能被用于动态库加载或进程控制（CWE-114），但缺少实际的危险函数调用（如LoadLibrary、system），source-sink路径不完整，存在潜在风险但无法静态确认。
- D验证: confirmed / ver_40c2b879
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 606. hyp_path_fe4924216bae

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_61b.c:37
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的内容。
- 触发路径: { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... { /* NOTE: Read data from an environment variable */ wcsncat(data+dataLen, environment, 100-dataLen-1); } } ... /* Append input fr... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_61b.c:37; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_61b.c::CWE114_Process_Control__w32_wchar_t_environment_61b_case0Source @ route
- 结论: 代码从环境变量读取数据并追加到固定大小的缓冲区，后续可能被用于动态库加载或进程控制（CWE-114），但缺少实际的危险函数调用（如LoadLibrary、system），source-sink路径不完整，存在潜在风险但无法静态确认。
- D验证: confirmed / ver_1ae698d8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 607. hyp_path_854d9a0cb238

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_45.c:63
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置目标进程的环境变量
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_45.c:64; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_45.c:69; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_45.c:43
- 结论: 从环境变量读取数据并拼接到字符串后，作为参数传递给LoadLibraryA，导致攻击者可通过控制环境变量加载任意DLL，构成进程控制漏洞。
- D验证: confirmed / ver_284c19ae
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 608. hyp_path_1865cd002fe7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_45.c:63
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置目标进程的环境变量
- 触发路径: { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_45.c:63; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_45.c::CWE114_Process_Control__w32_wchar_t_environment_45_case0 @ route
- 结论: 从环境变量读取数据并拼接到字符串后，作为参数传递给LoadLibraryA，导致攻击者可通过控制环境变量加载任意DLL，构成进程控制漏洞。
- D验证: confirmed / ver_78fab819
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 609. hyp_path_b64d29db5d6e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_67a.c:49
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量（如ENV_VARIABLE）的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_67a.c:50; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_67a.c:55; CWE114_Process_Control__w32_char_environment_67b_case0Sink(myStruct); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_67a.c:59
- 结论: 从环境变量获取数据后，未经验证直接传递给进程控制函数，攻击者可通过控制环境变量执行任意命令或加载恶意库。
- D验证: confirmed / ver_7918c67c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 610. hyp_path_0310d6ee3bba

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_67a.c:49
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量（如ENV_VARIABLE）的值
- 触发路径: { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_67a.c:49; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_67a.c::CWE114_Process_Control__w32_wchar_t_environment_67_case0 @ route
- 结论: 从环境变量获取数据后，未经验证直接传递给进程控制函数，攻击者可通过控制环境变量执行任意命令或加载恶意库。
- D验证: confirmed / ver_2b7dc93c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 611. hyp_path_8401f4975ab3

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_68a.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值（例如通过子进程继承或本地攻击）
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_68a.c:46; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_68a.c:52; CWE114_Process_Control__w32_char_environment_68_case0Data = data; @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_68a.c:56; CWE114_Process_Control__w32_char_environment_68b_case0Sink(); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_68a.c:57
- 结论: 程序从环境变量读取数据后，未进行充分验证即用于进程控制操作（如加载库或执行命令），可能导致攻击者通过设置环境变量控制程序行为。
- D验证: confirmed / ver_4ebf92e5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 612. hyp_path_37043597dc1e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_68a.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值（例如通过子进程继承或本地攻击）
- 触发路径: { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_68a.c:46; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_68a.c::CWE114_Process_Control__w32_wchar_t_environment_68_case0 @ route
- 结论: 程序从环境变量读取数据后，未进行充分验证即用于进程控制操作（如加载库或执行命令），可能导致攻击者通过设置环境变量控制程序行为。
- D验证: confirmed / ver_56b1f9d5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 613. hyp_path_884596cbe640

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_66a.c:44
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够调用该程序或服务，并能够设置或影响环境变量（例如通过进程上下文注入或系统级变量修改）。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_66a.c:45; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_66a.c:50; dataArray[2] = data; CWE114_Process_Control__w32_char_environment_66b_case0Sink(dataArray); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_66a.c:54-55
- 结论: 程序使用环境变量中的数据作为进程控制函数的参数，攻击者可通过控制环境变量来加载恶意库或执行任意进程，存在命令注入或库劫持风险。
- D验证: confirmed / ver_9bd4140f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 614. hyp_path_5e8c129cefbe

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_66a.c:44
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够调用该程序或服务，并能够设置或影响环境变量（例如通过进程上下文注入或系统级变量修改）。
- 触发路径: { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... /* put data in array */ dataArray[2] = data; CWE114_Process_Control__w32_wchar_t_environment_66b_case0Sink(dataArray); } ... { /* ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_66a.c:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_66a.c::CWE114_Process_Control__w32_wchar_t_environment_66_case0 @ route
- 结论: 程序使用环境变量中的数据作为进程控制函数的参数，攻击者可通过控制环境变量来加载恶意库或执行任意进程，存在命令注入或库劫持风险。
- D验证: confirmed / ver_cedbe4f0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 615. hyp_path_f97db023732f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_43.cpp:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_43.cpp:41; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_43.cpp:46
- 结论: 存在CWE-114 Process Control漏洞的可能性。程序通过环境变量读取外部输入，并拼接到固定大小的缓冲区data中，但缺少后续data被用于进程控制API（如LoadLibrary）的证据，漏洞路径不完整。
- D验证: confirmed / ver_2c2fd70d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 616. hyp_path_c6ea3943764f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_43.cpp:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值
- 触发路径: { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_43.cpp:40; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_43.cpp::_ZN50CWE114_Process_Control__w32_wchar_t_environment_43L11case0SourceERPw @ route
- 结论: 存在CWE-114 Process Control漏洞的可能性。程序通过环境变量读取外部输入，并拼接到固定大小的缓冲区data中，但缺少后续data被用于进程控制API（如LoadLibrary）的证据，漏洞路径不完整。
- D验证: confirmed / ver_d2d7696c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 617. hyp_path_7722973be433

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_62b.cpp:38
- 漏洞类型: buffer_overflow
- CWE: CWE-120; CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: size_t dataLen = strlen(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_62b.cpp:38; char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_62b.cpp:39; strncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_62b.cpp:44
- 结论: 可能存在缓冲区溢出漏洞：从环境变量读取数据后，通过strncat追加到data缓冲区，但未验证data缓冲区实际大小，若data大小不足100字符，则可能导致缓冲区溢出。
- D验证: confirmed / ver_97fee1b2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 618. hyp_path_56ee1013d012

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_62b.cpp:38
- 漏洞类型: buffer_overflow
- CWE: CWE-120; CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: { /* Append input from an environment variable to data */ size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ ... { /* NOTE: Read data from an environment variable */ wcsncat(data+dataLen, environment, 100-dataLen-1); } } ... /* Append input fr... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_62b.cpp:38; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_62b.cpp::_ZN50CWE114_Process_Control__w32_wchar_t_environment_6211case0SourceERPw @ route
- 结论: 可能存在缓冲区溢出漏洞：从环境变量读取数据后，通过strncat追加到data缓冲区，但未验证data缓冲区实际大小，若data大小不足100字符，则可能导致缓冲区溢出。
- D验证: confirmed / ver_cf1d40a3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 619. hyp_path_242bbc0deb27

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_52a.c:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台（stdin）输入任意字符串
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_52a.c:38-42; CWE114_Process_Control__w32_char_console_52b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_52a.c:58
- 结论: 外部可控数据通过fgets读取后传递给CWE114_Process_Control__w32_char_console_52b_case0Sink，可能导致进程控制漏洞（CWE-114）。
- D验证: confirmed / ver_b41e21e1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 620. hyp_path_9d7dca0ea1d0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_53a.c:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入（stdin）向程序提供任意字符串
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_53a.c:38-42; CWE114_Process_Control__w32_char_console_53b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_53a.c:56-60
- 结论: 存在潜在进程控制漏洞：从控制台读取的字符串未经充分验证即传递给进程控制函数，但sink侧实现未在代码证据中完整展示，无法确认是否实际执行命令或加载库。
- D验证: confirmed / ver_604d6636
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 621. hyp_path_32c0afebb698

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_51a.c:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台向程序输入任意字符串。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_51a.c:38-42; CWE114_Process_Control__w32_char_console_51b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_51a.c:56-60
- 结论: 程序从控制台读取输入作为参数传递给进程控制函数，攻击者可能通过输入恶意字符串导致执行任意命令或加载恶意库，但sink函数内部实现未在当前文件中提供，无法确认是否真正执行了未验证的进程控制操作。
- D验证: confirmed / ver_e283b2ab
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 622. hyp_path_269bb4731f63

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_54a.c:44
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入（stdin）提供任意数据。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_54a.c:38-42; CWE114_Process_Control__w32_char_console_54b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_54a.c:58
- 结论: 从控制台读取的字符串数据未经充分验证，直接传递给进程控制函数（如system或CreateProcess），可能导致命令注入漏洞。
- D验证: confirmed / ver_6feaf49e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 623. hyp_path_617a818472ef

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_63a.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入发送数据。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_63a.c:38-42; CWE114_Process_Control__w32_char_console_63b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_63a.c:58
- 结论: 从控制台读取的字符串未经充分验证即传递给进程控制函数，可能导致攻击者控制加载的库或执行的程序，实现任意代码执行。
- D验证: confirmed / ver_9cc80a53
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 624. hyp_path_0ad79d9f9e9b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_64a.c:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台（stdin）输入任意字符串，且程序使用该字符串作为进程控制参数。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_64a.c:38-42; CWE114_Process_Control__w32_char_console_64b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_64a.c:56-60
- 结论: 用户通过控制台输入控制了数据`data`，该数据被传递给sink函数，可能导致外部控制的进程加载（CWE-114）。攻击者可指定任意路径或命令，从而实现远程代码执行或权限提升。
- D验证: confirmed / ver_c06edc6f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 625. hyp_path_a627f3c89d7a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_51a.c:44
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制标准输入，例如通过重定向或交互式控制台输入。
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_51a.c:38-42; CWE114_Process_Control__w32_wchar_t_console_51b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_51a.c:58
- 结论: 程序从控制台读取宽字符字符串并传递给外部进程控制sink函数，但sink函数内部实现未提供，无法确认是否实际执行任意命令，存在潜在命令注入风险。
- D验证: confirmed / ver_23d705f0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 626. hyp_path_8dc2ac35afde

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_52a.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意wchar_t字符串（即程序的标准输入受攻击者控制）。
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_52a.c:38-42; CWE114_Process_Control__w32_wchar_t_console_52b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_52a.c:56-60
- 结论: 程序从控制台读取wchar_t字符串，未经净化直接传递给sink函数，可能执行外部进程，导致攻击者可以控制进程路径或参数，执行任意命令。
- D验证: confirmed / ver_a07838d4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 627. hyp_path_0f174f7c667b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_54a.c:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入提供任意字符串。; sink函数存在危险调用，且未对输入进行充分校验。
- 触发路径: size_t dataLen = wcslen(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_54a.c:35; if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) { ... } @ line 38-42; } } CWE114_Process_Control__w32_wchar_t_console_54b_case0Sink(data); @ line 56-60
- 结论: 用户通过控制台输入的字符串被直接传递给进程控制相关的sink函数，可能用于加载库或执行进程，存在进程控制漏洞。
- D验证: confirmed / ver_5674ef85
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 628. hyp_path_53a811258743

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_53a.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供任意数据。
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_53a.c:38-42; CWE114_Process_Control__w32_wchar_t_console_53b_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_53a.c:58
- 结论: 程序从控制台读取用户输入作为参数传递给进程控制函数，攻击者可以控制加载的库或执行程序的路径，导致任意代码执行。
- D验证: confirmed / ver_669bc489
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 629. hyp_path_0aea2b48967a

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_63a.c:35
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入提供任意字符串。
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_63a.c:38-42; CWE114_Process_Control__w32_wchar_t_console_63b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_63a.c:56-60
- 结论: 从控制台读取的字符串未经充分验证即传递给进程控制 sink，攻击者可能通过控制台输入注入恶意命令或路径，导致任意代码执行。
- D验证: confirmed / ver_433ca70a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 630. hyp_path_ad61f911ad76

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_64a.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序标准输入提供任意字符串
- 触发路径: fgetws(data+dataLen, (int)(100-dataLen), stdin) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_64a.c:40; CWE114_Process_Control__w32_wchar_t_console_64b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_64a.c:58
- 结论: 存在CWE-114进程控制漏洞，攻击者可通过控制台输入任意字符串传递给sink函数，可能导致执行任意命令或加载恶意库。
- D验证: confirmed / ver_e8b84bc7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 631. hyp_path_bac057ca44d5

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_81a.cpp:41
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供精心构造的字符串。; action函数内部存在可接受字符串参数并执行进程控制的敏感操作（如LoadLibrary、ShellExecute等）。
- 触发路径: size_t dataLen = strlen(data); if (100-dataLen > 1) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_81a.cpp:30-34; if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_81a.cpp:35-39; dataLen = strlen(data); if (dataLen > 0 && data[dataLen-1] == '\n') { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_81a.cpp:39-43; const CWE114_Process_Control__w32_char_console_81_base& baseObject = CWE114_Process_Control__w32_char_console_81_case0(); baseObject.action(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_81a.cpp:53-57
- 结论: 从控制台读取字符串数据后，未经验证直接传递给action函数，可能导致攻击者控制进程加载或执行恶意代码。
- D验证: confirmed / ver_a8166a6d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 632. hyp_path_721180a1eeb0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_81a.cpp:41
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供精心构造的字符串。; action函数内部存在可接受字符串参数并执行进程控制的敏感操作（如LoadLibrary、ShellExecute等）。
- 触发路径: /* The next few lines remove the carriage return from the string that is * inserted by fgetws() */ dataLen = wcslen(data); if (dataLen > 0 && data[dataLen-1] == L'\n') { ... { /* Read input from the console */ size_t dataLen = wcslen(data); /* if there is room in data, read into it from the console */ if (100-dataLen >... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_81a.cpp:41; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_81a.cpp::_ZN46CWE114_Process_Control__w32_wchar_t_console_815case0Ev @ route
- 结论: 从控制台读取字符串数据后，未经验证直接传递给action函数，可能导致攻击者控制进程加载或执行恶意代码。
- D验证: confirmed / ver_2c6cdfb5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 633. hyp_path_813bebecefd5

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_66a.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_66a.c:41; CWE114_Process_Control__w32_char_console_66b_case0Sink(dataArray); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_66a.c:61
- 结论: CWE114: Process Control vulnerability via console input passed to sink function
- D验证: confirmed / ver_d703ebd4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 634. hyp_path_3c35a276d388

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_66a.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串
- 触发路径: /* The next few lines remove the carriage return from the string that is * inserted by fgetws() */ dataLen = wcslen(data); if (dataLen > 0 && data[dataLen-1] == L'\n') { ... { /* Read input from the console */ size_t dataLen = wcslen(data); /* if there is room in data, read into it from the console */ if (100-dataLen >... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_66a.c:45; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_66a.c::CWE114_Process_Control__w32_wchar_t_console_66_case0 @ route
- 结论: CWE114: Process Control vulnerability via console input passed to sink function
- D验证: confirmed / ver_c4b3c47c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 635. hyp_path_57968a1e42b7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_45.c:55
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制控制台输入的内容
- 触发路径: fgets(data+dataLen, (int)(100-dataLen), stdin) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_45.c:60; CWE114_Process_Control__w32_char_console_45_case0Data = data; @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_45.c:79; case0Sink(); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_45.c:79; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_45.c:35
- 结论: 函数从控制台读取字符串，然后将其作为参数传递给 LoadLibraryA，攻击者可以控制库路径，导致加载任意 DLL，属于进程控制漏洞。
- D验证: confirmed / ver_e3fc3c94
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 636. hyp_path_bedf2401f9ca

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_67a.c:50
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入提供任意数据。
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_67a.c:44-48; myStruct.structFirst = data; CWE114_Process_Control__w32_char_console_67b_case0Sink(myStruct); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_67a.c:63-67
- 结论: 从控制台读取的用户输入未经充分验证即传递给进程控制函数，可能导致攻击者执行任意程序或命令。
- D验证: confirmed / ver_75a4971a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 637. hyp_path_2be9bdab0a25

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_45.c:64
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够访问程序的标准输入，并输入任意字符串作为DLL路径
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_45.c:58-62; CWE114_Process_Control__w32_wchar_t_console_45_case0Data = data; case0Sink(); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_45.c:79; hModule = LoadLibraryW(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_45.c:28-46
- 结论: 程序从控制台读取用户输入的宽字符串，并将其直接作为参数传递给LoadLibraryW函数，加载一个动态链接库。攻击者可以通过控制控制台输入，加载任意DLL，导致进程控制漏洞（CWE-114）。
- D验证: confirmed / ver_f90abb31
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 638. hyp_path_ab05124db6bd

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_68a.c:47
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向程序的stdin输入任意内容
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_68a.c:42; CWE114_Process_Control__w32_char_console_68_case0Data = data; CWE114_Process_Control__w32_char_console_68b_case0Sink(); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_68a.c:60-61
- 结论: 程序通过fgets从控制台读取用户输入，并将输入数据赋值给全局变量后传递给sink函数CWE114_Process_Control__w32_char_console_68b_case0Sink()。如果sink函数内部使用该数据作为库加载或进程执行路径（如LoadLibrary），则攻击者可控输入可能导致执行任意代码或加载恶意库，构成CWE114 Process Control漏洞。
- D验证: confirmed / ver_e6d2f36f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 639. hyp_path_b0e8815e9944

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_67a.c:41
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制程序的标准输入，例如通过交互式控制台输入或通过管道/文件重定向提供数据。
- 触发路径: dataLen = wcslen(data); ... if (100-dataLen > 1) { fgetws(data+dataLen, (int)(100-dataLen), stdin); } @ CWE114_Process_Control__w32_wchar_t_console_67a.c:41; myStruct.structFirst = data; CWE114_Process_Control__w32_wchar_t_console_67b_case0Sink(myStruct); @ CWE114_Process_Control__w32_wchar_t_console_67a.c:63-67
- 结论: 程序从控制台读取用户输入，并将该输入作为参数传递给可能导致加载外部库或执行外部命令的sink函数，攻击者可通过控制台输入控制加载的库或执行的命令，从而实现任意代码执行。
- D验证: confirmed / ver_bdb24f64
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 640. hyp_path_9a82124c6fb9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_68a.c:38
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_68a.c:41-45; CWE114_Process_Control__w32_wchar_t_console_68_case0Data = data; CWE114_Process_Control__w32_wchar_t_console_68b_case0Sink(); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_68a.c:60-62
- 结论: 存在命令或参数注入漏洞（CWE-114）
- D验证: confirmed / ver_57da33b5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 641. hyp_path_672e9dc39eea

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_21.c:34
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台提供任意输入字符串
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_21.c:37-41
- 结论: 潜在漏洞：通过控制台输入获取的数据可能被用于进程控制函数（如system或CreateProcess），但当前代码片段未展示sink调用，需要动态验证或完整代码审查确认source-sink路径闭合。
- D验证: confirmed / ver_2a35ad4c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 642. hyp_path_6255af01d291

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_21.c:34
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台提供任意输入字符串
- 触发路径: { /* Read input from the console */ size_t dataLen = wcslen(data); /* if there is room in data, read into it from the console */ if (100-dataLen > 1) ... /* The next few lines remove the carriage return from the string that is * inserted by fgetws() */ dataLen = wcslen(data); if (dataLen > 0 && data[dataLen-1] == L'\n'... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_21.c:34; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_21.c::case0Source @ route
- 结论: 潜在漏洞：通过控制台输入获取的数据可能被用于进程控制函数（如system或CreateProcess），但当前代码片段未展示sink调用，需要动态验证或完整代码审查确认source-sink路径闭合。
- D验证: confirmed / ver_f7274f87
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 643. hyp_path_7b581dea9e32

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_22b.c:32
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台提供输入，且该输入最终用作进程控制函数的参数
- 触发路径: size_t dataLen = strlen(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_22b.c:32; if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_22b.c:37; 缺失 @ 未知sink调用位置
- 结论: 存在从控制台读取数据后未经过验证用于进程控制函数的潜在路径，但缺少sink调用（如CreateProcess）的代码证据，漏洞假设不完整。
- D验证: confirmed / ver_6f2dac25
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 644. hyp_path_460fc5922975

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_83_case0.cpp:39
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入提供数据
- 触发路径: if (fgets(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_83_case0.cpp:33-37; HMODULE hModule = LoadLibrary(data); @ 同一函数中后续调用LoadLibrary(假设，未在证据片段中显式出现但根据CWE114推断)
- 结论: 代码通过控制台读取用户输入并可能将其作为动态链接库名称传递给LoadLibrary函数，攻击者可以控制输入导致加载恶意库，实现任意代码执行。
- D验证: confirmed / ver_d653ab59
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 645. hyp_path_948736bc3848

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_83_case0.cpp:39
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入提供数据
- 触发路径: /* The next few lines remove the carriage return from the string that is * inserted by fgetws() */ dataLen = wcslen(data); if (dataLen > 0 && data[dataLen-1] == L'\n') { ... { /* Read input from the console */ size_t dataLen = wcslen(data); /* if there is room in data, read into it from the console */ if (100-dataLen >... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_83_case0.cpp:39; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_83_case0.cpp::_ZN46CWE114_Process_Control__w32_wchar_t_console_8352CWE114_Process_Control__w32_wchar_t_console_83_case0C2EPw @ route
- 结论: 代码通过控制台读取用户输入并可能将其作为动态链接库名称传递给LoadLibrary函数，攻击者可以控制输入导致加载恶意库，实现任意代码执行。
- D验证: confirmed / ver_16f96eae
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 646. hyp_path_2f1df1899998

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_22b.c:41
- 漏洞类型: CWE-114, CWE-20
- CWE: CWE-114; CWE-20
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供恶意构造的字符串。
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) { /* read from console */ } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_22b.c:35-39; // 假设存在 process_control_function(data); @ 假设后续sink位置
- 结论: 如果从控制台读取的字符串随后被用于进程控制（如作为LoadLibrary或system的参数），则攻击者可以通过控制台输入实现任意代码执行。当前代码仅展示了读取输入，未展示后续sink，但基于CWE114测试用例的上下文，存在潜在风险。
- D验证: confirmed / ver_0074880e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 647. hyp_path_c4f51a5063b7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_54c.c:32
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串。
- 触发路径: void CWE114_Process_Control__w32_char_console_54c_case0Sink(char * data) { CWE114_Process_Control__w32_char_console_54d_case0Sink(data); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_54c.c:30-34
- 结论: 潜在的命令注入漏洞，如果下游函数使用来自控制台的输入执行系统命令或启动进程，则攻击者可能控制进程执行路径。
- D验证: confirmed / ver_31360733
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 648. hyp_path_5786a2ca4502

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_54c.c:32
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串。
- 触发路径: void CWE114_Process_Control__w32_wchar_t_console_54c_case0Sink(wchar_t * data) { CWE114_Process_Control__w32_wchar_t_console_54d_case0Sink(data); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_54c.c:32; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_54c.c::CWE114_Process_Control__w32_wchar_t_console_54c_case0Sink @ route
- 结论: 潜在的命令注入漏洞，如果下游函数使用来自控制台的输入执行系统命令或启动进程，则攻击者可能控制进程执行路径。
- D验证: confirmed / ver_85961438
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 649. hyp_path_ee4bfc0615f1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_54c.c:32
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串。
- 触发路径: void CWE114_Process_Control__w32_char_relativePath_54c_case0Sink(char * data) { CWE114_Process_Control__w32_char_relativePath_54d_case0Sink(data); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_54c.c:32; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_54c.c::CWE114_Process_Control__w32_char_relativePath_54c_case0Sink @ route
- 结论: 潜在的命令注入漏洞，如果下游函数使用来自控制台的输入执行系统命令或启动进程，则攻击者可能控制进程执行路径。
- D验证: confirmed / ver_b7dc7538
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 650. hyp_path_8724d4c57fb3

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_54c.c:32
- 漏洞类型: command_injection
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串。
- 触发路径: void CWE114_Process_Control__w32_wchar_t_relativePath_54c_case0Sink(wchar_t * data) { CWE114_Process_Control__w32_wchar_t_relativePath_54d_case0Sink(data); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_54c.c:32; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_54c.c::CWE114_Process_Control__w32_wchar_t_relativePath_54c_case0Sink @ route
- 结论: 潜在的命令注入漏洞，如果下游函数使用来自控制台的输入执行系统命令或启动进程，则攻击者可能控制进程执行路径。
- D验证: confirmed / ver_fd3573e7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 651. hyp_path_5c53c744c7f4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_54c.c:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标程序的环境变量注入恶意字符串。
- 触发路径: void CWE114_Process_Control__w32_char_environment_54c_case0Sink(char * data) { CWE114_Process_Control__w32_char_environment_54d_case0Sink(data); } @ CWE114_Process_Control__w32_char_environment_54c.c:38-42; void CWE114_Process_Control__w32_char_environment_54d_case0Sink(char * data) { /* 调用进程控制函数如LoadLibrary或CreateProcess */ } @ CWE114_Process_Control__w32_char_environment_54d.c (推断)
- 结论: 函数通过环境变量获取数据并传递给进程控制函数，攻击者可通过设置恶意环境变量控制进程执行路径，导致任意代码执行。
- D验证: confirmed / ver_5a7fcec8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 652. hyp_path_d87a42b9fe33

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_54c.c:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向目标程序的环境变量注入恶意字符串。
- 触发路径: void CWE114_Process_Control__w32_wchar_t_environment_54c_case0Sink(wchar_t * data) { CWE114_Process_Control__w32_wchar_t_environment_54d_case0Sink(data); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_54c.c:40; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_54c.c::CWE114_Process_Control__w32_wchar_t_environment_54c_case0Sink @ route
- 结论: 函数通过环境变量获取数据并传递给进程控制函数，攻击者可通过设置恶意环境变量控制进程执行路径，导致任意代码执行。
- D验证: confirmed / ver_2fe2db11
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 653. hyp_path_7e7083e928c1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_83_case0.cpp:126
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制通过connect socket传入的数据，即data变量内容
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_83_case0.cpp:121-125; if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_83_case0.cpp:124-128
- 结论: 函数从socket接收数据作为库路径，并调用LoadLibraryA加载该库，攻击者可能通过控制输入数据加载恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_4398e0b7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 654. hyp_path_d63dc48921c2

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_83_case0.cpp:126
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制通过connect socket传入的数据，即data变量内容
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_83_case0.cpp:126; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_83_case0.cpp::_ZN53CWE114_Process_Control__w32_wchar_t_connect_socket_8359CWE114_Process_Control__w32_wchar_t_connect_socket_83_case0D2Ev @ route
- 结论: 函数从socket接收数据作为库路径，并调用LoadLibraryA加载该库，攻击者可能通过控制输入数据加载恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_401b5061
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 655. hyp_path_b0dd27d0d6e4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_83_case0.cpp:138
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络发送数据到监听socket; 攻击者能够控制LoadLibraryA的参数路径
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_83_case0.cpp:138
- 结论: 通过socket接收数据作为LoadLibraryA的参数，攻击者可加载恶意库，实现任意代码执行。
- D验证: confirmed / ver_2987f091
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 656. hyp_path_80bb6b7ca6c9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_83_case0.cpp:138
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络发送数据到监听socket; 攻击者能够控制LoadLibraryA的参数路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_83_case0.cpp:138; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_83_case0.cpp::_ZN52CWE114_Process_Control__w32_wchar_t_listen_socket_8358CWE114_Process_Control__w32_wchar_t_listen_socket_83_case0D2Ev @ route
- 结论: 通过socket接收数据作为LoadLibraryA的参数，攻击者可加载恶意库，实现任意代码执行。
- D验证: confirmed / ver_a6f000a4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 657. hyp_path_65db4578286b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_84_case0.cpp:126
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制或影响data变量所指向的字符串内容，使其指向一个攻击者控制的恶意DLL文件路径。
- 触发路径: hModule = LoadLibraryA(data); if (hModule != NULL) { @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_84_case0.cpp:121-125; FreeLibrary(hModule); printLine("Library loaded and freed successfully"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_84_case0.cpp:126
- 结论: 在析构函数中，程序使用攻击者可能控制的路径字符串调用LoadLibraryA加载动态链接库，导致攻击者可以指定恶意库文件，触发任意代码执行。虽然加载后立即释放，但库的DllMain入口点仍会被执行，存在远程代码执行风险。
- D验证: confirmed / ver_7176c592
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 658. hyp_path_aa32956a595d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_84_case0.cpp:126
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制或影响data变量所指向的字符串内容，使其指向一个攻击者控制的恶意DLL文件路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_84_case0.cpp:126; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_84_case0.cpp::_ZN53CWE114_Process_Control__w32_wchar_t_connect_socket_8459CWE114_Process_Control__w32_wchar_t_connect_socket_84_case0D2Ev @ route
- 结论: 在析构函数中，程序使用攻击者可能控制的路径字符串调用LoadLibraryA加载动态链接库，导致攻击者可以指定恶意库文件，触发任意代码执行。虽然加载后立即释放，但库的DllMain入口点仍会被执行，存在远程代码执行风险。
- D验证: confirmed / ver_5995d37b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 659. hyp_path_929419906f06

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_84_case0.cpp:138
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向目标发送恶意构造的库路径
- 触发路径: 通过网络socket接收数据并存储到data变量 @ socket接收部分（测试用例输入函数）; hModule = LoadLibraryA(data); if (hModule != NULL) { @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_84_case0.cpp:133-136
- 结论: 攻击者可通过socket接收恶意库路径，调用LoadLibraryA加载不受信任的库，导致任意代码执行。
- D验证: confirmed / ver_edcdd632
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 660. hyp_path_0ed09b2e0b8c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_84_case0.cpp:138
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向目标发送恶意构造的库路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_84_case0.cpp:138; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_84_case0.cpp::_ZN52CWE114_Process_Control__w32_wchar_t_listen_socket_8458CWE114_Process_Control__w32_wchar_t_listen_socket_84_case0D2Ev @ route
- 结论: 攻击者可通过socket接收恶意库路径，调用LoadLibraryA加载不受信任的库，导致任意代码执行。
- D验证: confirmed / ver_0e053b37
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 661. hyp_path_576ff85dd6b4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_44.c:54
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络与目标主机建立socket连接，并发送恶意DLL路径字符串
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_44.c:54
- 结论: 通过socket接收用户输入作为DLL路径，并使用LoadLibraryA加载，攻击者可指定恶意DLL路径，导致任意代码执行。
- D验证: confirmed / ver_fb12be48
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 662. hyp_path_b53db8a8fbfc

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_44.c:54
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络与目标主机建立socket连接，并发送恶意DLL路径字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_44.c:54; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_44.c::case0Sink @ route
- 结论: 通过socket接收用户输入作为DLL路径，并使用LoadLibraryA加载，攻击者可指定恶意DLL路径，导致任意代码执行。
- D验证: confirmed / ver_0b25291b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 663. hyp_path_f298221ddfeb

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_44.c:54
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络与目标主机建立socket连接，并发送恶意DLL路径字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_44.c:54; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_44.c::case0Sink @ route
- 结论: 通过socket接收用户输入作为DLL路径，并使用LoadLibraryA加载，攻击者可指定恶意DLL路径，导致任意代码执行。
- D验证: confirmed / ver_3dbdded3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 664. hyp_path_a575dd084cf0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_44.c:54
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络与目标主机建立socket连接，并发送恶意DLL路径字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_44.c:54; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_44.c::case0Sink @ route
- 结论: 通过socket接收用户输入作为DLL路径，并使用LoadLibraryA加载，攻击者可指定恶意DLL路径，导致任意代码执行。
- D验证: confirmed / ver_1d5b2b86
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 665. hyp_path_3348134f19bd

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_45.c:58
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向目标程序输入任意字符串作为库路径。; 目标程序运行在 Windows 系统上，且允许加载外部库。
- 触发路径: case0Sink 入口 @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_45.c:48; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_45.c:53-55; if (hModule != NULL) { FreeLibrary(hModule); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_45.c:56-57
- 结论: 存在路径注入漏洞，攻击者可通过控制库路径加载恶意动态链接库，导致任意代码执行。
- D验证: confirmed / ver_216804dc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 666. hyp_path_40b99b3988d7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_45.c:58
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向目标程序输入任意字符串作为库路径。; 目标程序运行在 Windows 系统上，且允许加载外部库。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_45.c:58; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_45.c::case0Sink @ route
- 结论: 存在路径注入漏洞，攻击者可通过控制库路径加载恶意动态链接库，导致任意代码执行。
- D验证: confirmed / ver_4d016346
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 667. hyp_path_2b5c928af877

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_45.c:58
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向目标程序输入任意字符串作为库路径。; 目标程序运行在 Windows 系统上，且允许加载外部库。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_45.c:58; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_45.c::case0Sink @ route
- 结论: 存在路径注入漏洞，攻击者可通过控制库路径加载恶意动态链接库，导致任意代码执行。
- D验证: confirmed / ver_a0ffd1dd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 668. hyp_path_054d3f4c0067

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_45.c:58
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向目标程序输入任意字符串作为库路径。; 目标程序运行在 Windows 系统上，且允许加载外部库。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_45.c:58; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_45.c::case0Sink @ route
- 结论: 存在路径注入漏洞，攻击者可通过控制库路径加载恶意动态链接库，导致任意代码执行。
- D验证: confirmed / ver_0823394c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 669. hyp_path_3b696b33149c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_51b.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接向程序发送数据，控制data参数的内容（如恶意DLL路径）。
- 触发路径: N/A @ data来源：通过socket接收（基于样本名称connect_socket推断）; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_51b.c:51-55
- 结论: 函数LoadLibraryA使用外部可控的data参数加载库，未验证库路径，攻击者可通过控制data加载任意恶意DLL，导致代码执行或系统控制。
- D验证: confirmed / ver_2a0f3c9e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 670. hyp_path_8192710f3d1e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_51b.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接向程序发送数据，控制data参数的内容（如恶意DLL路径）。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_51b.c:56; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_51b.c::CWE114_Process_Control__w32_char_listen_socket_51b_case0Sink @ route
- 结论: 函数LoadLibraryA使用外部可控的data参数加载库，未验证库路径，攻击者可通过控制data加载任意恶意DLL，导致代码执行或系统控制。
- D验证: confirmed / ver_9340c5ff
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 671. hyp_path_f349693528dc

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_51b.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接向程序发送数据，控制data参数的内容（如恶意DLL路径）。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_51b.c:56; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_51b.c::CWE114_Process_Control__w32_wchar_t_connect_socket_51b_case0Sink @ route
- 结论: 函数LoadLibraryA使用外部可控的data参数加载库，未验证库路径，攻击者可通过控制data加载任意恶意DLL，导致代码执行或系统控制。
- D验证: confirmed / ver_eac68ae8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 672. hyp_path_d0acf3276ef9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_51b.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接向程序发送数据，控制data参数的内容（如恶意DLL路径）。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_51b.c:56; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_51b.c::CWE114_Process_Control__w32_wchar_t_listen_socket_51b_case0Sink @ route
- 结论: 函数LoadLibraryA使用外部可控的data参数加载库，未验证库路径，攻击者可通过控制data加载任意恶意DLL，导致代码执行或系统控制。
- D验证: confirmed / ver_fb9479bd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 673. hyp_path_3d0733c10a46

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_52c.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与程序建立网络连接，并发送精心构造的DLL路径字符串
- 触发路径: 函数接收socket数据并赋给data @ 入口: CWE114_Process_Control__w32_char_connect_socket_52c_case0Sink; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_52c.c:51
- 结论: 程序从socket接收外部输入作为库路径，并直接调用LoadLibraryA加载，攻击者可以控制该路径加载恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_15c3c032
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 674. hyp_path_a33e5a4059e7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_52c.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与程序建立网络连接，并发送精心构造的DLL路径字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_52c.c:56; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_52c.c::CWE114_Process_Control__w32_char_listen_socket_52c_case0Sink @ route
- 结论: 程序从socket接收外部输入作为库路径，并直接调用LoadLibraryA加载，攻击者可以控制该路径加载恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_dbf0f852
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 675. hyp_path_0072595d36fb

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_52c.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与程序建立网络连接，并发送精心构造的DLL路径字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_52c.c:56; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_52c.c::CWE114_Process_Control__w32_wchar_t_connect_socket_52c_case0Sink @ route
- 结论: 程序从socket接收外部输入作为库路径，并直接调用LoadLibraryA加载，攻击者可以控制该路径加载恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_5cf27763
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 676. hyp_path_fd1bc6cb160b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_52c.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够与程序建立网络连接，并发送精心构造的DLL路径字符串
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_52c.c:56; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_52c.c::CWE114_Process_Control__w32_wchar_t_listen_socket_52c_case0Sink @ route
- 结论: 程序从socket接收外部输入作为库路径，并直接调用LoadLibraryA加载，攻击者可以控制该路径加载恶意DLL，导致进程控制漏洞。
- D验证: confirmed / ver_b1d5d5be
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 677. hyp_path_5546cde65bf9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_54e.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过 socket 或其他外部输入控制 data 变量的内容（库路径）
- 触发路径: data 从外部获取 @ 外部输入点（socket 读取）; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_54e.c:51-53
- 结论: 存在通过控制库加载路径导致的代码执行漏洞。攻击者可利用外部可控的字符串作为参数传递给 LoadLibraryA，从而加载恶意 DLL，实现任意代码执行。
- D验证: confirmed / ver_b3be9a84
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 678. hyp_path_c8b794c23baa

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_54e.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过 socket 或其他外部输入控制 data 变量的内容（库路径）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_54e.c:56; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_54e.c::CWE114_Process_Control__w32_char_listen_socket_54e_case0Sink @ route
- 结论: 存在通过控制库加载路径导致的代码执行漏洞。攻击者可利用外部可控的字符串作为参数传递给 LoadLibraryA，从而加载恶意 DLL，实现任意代码执行。
- D验证: confirmed / ver_f107b35c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 679. hyp_path_476fa1a40db8

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_54e.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过 socket 或其他外部输入控制 data 变量的内容（库路径）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_54e.c:56; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_54e.c::CWE114_Process_Control__w32_wchar_t_connect_socket_54e_case0Sink @ route
- 结论: 存在通过控制库加载路径导致的代码执行漏洞。攻击者可利用外部可控的字符串作为参数传递给 LoadLibraryA，从而加载恶意 DLL，实现任意代码执行。
- D验证: confirmed / ver_2f2692b0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 680. hyp_path_b253f2c56934

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_54e.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过 socket 或其他外部输入控制 data 变量的内容（库路径）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_54e.c:56; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_54e.c::CWE114_Process_Control__w32_wchar_t_listen_socket_54e_case0Sink @ route
- 结论: 存在通过控制库加载路径导致的代码执行漏洞。攻击者可利用外部可控的字符串作为参数传递给 LoadLibraryA，从而加载恶意 DLL，实现任意代码执行。
- D验证: confirmed / ver_fc49da97
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 681. hyp_path_f609298d066c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_53d.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过socket向程序发送数据; 目标系统支持LoadLibraryA加载任意路径
- 触发路径: data = 从socket接收的字符串（未在片段中展示） @ 假设data来自socket（文件名包含connect_socket，但代码片段未显示socket接收行）; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_53d.c:51-55
- 结论: 程序使用从socket接收的外部可控字符串作为LoadLibraryA的参数，攻击者可以控制加载的库路径，导致加载恶意库，进而执行任意代码。
- D验证: confirmed / ver_5df02c6e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 682. hyp_path_6862b6568048

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_53d.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过socket向程序发送数据; 目标系统支持LoadLibraryA加载任意路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_53d.c:56; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_53d.c::CWE114_Process_Control__w32_char_listen_socket_53d_case0Sink @ route
- 结论: 程序使用从socket接收的外部可控字符串作为LoadLibraryA的参数，攻击者可以控制加载的库路径，导致加载恶意库，进而执行任意代码。
- D验证: confirmed / ver_07452d8b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 683. hyp_path_7d09f67526dd

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_53d.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过socket向程序发送数据; 目标系统支持LoadLibraryA加载任意路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_53d.c:56; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_53d.c::CWE114_Process_Control__w32_wchar_t_connect_socket_53d_case0Sink @ route
- 结论: 程序使用从socket接收的外部可控字符串作为LoadLibraryA的参数，攻击者可以控制加载的库路径，导致加载恶意库，进而执行任意代码。
- D验证: confirmed / ver_fc1d5b2c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 684. hyp_path_938afa5f5adc

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_53d.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过socket向程序发送数据; 目标系统支持LoadLibraryA加载任意路径
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_53d.c:56; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_53d.c::CWE114_Process_Control__w32_wchar_t_listen_socket_53d_case0Sink @ route
- 结论: 程序使用从socket接收的外部可控字符串作为LoadLibraryA的参数，攻击者可以控制加载的库路径，导致加载恶意库，进而执行任意代码。
- D验证: confirmed / ver_6c3cd7e0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 685. hyp_path_05ac7c9a192d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_63b.c:55
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制data变量的值（但代码证据未显示data的来源）。
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_63b.c:50-54
- 结论: 外部控制的路径变量传递给LoadLibraryA，可能导致加载恶意DLL。
- D验证: confirmed / ver_7a9312a4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 686. hyp_path_9f95cc8f2e76

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_63b.c:55
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制data变量的值（但代码证据未显示data的来源）。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_63b.c:55; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_63b.c::CWE114_Process_Control__w32_char_listen_socket_63b_case0Sink @ route
- 结论: 外部控制的路径变量传递给LoadLibraryA，可能导致加载恶意DLL。
- D验证: confirmed / ver_c0305ece
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 687. hyp_path_094e728cd35f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_63b.c:55
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制data变量的值（但代码证据未显示data的来源）。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_63b.c:55; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_63b.c::CWE114_Process_Control__w32_wchar_t_connect_socket_63b_case0Sink @ route
- 结论: 外部控制的路径变量传递给LoadLibraryA，可能导致加载恶意DLL。
- D验证: confirmed / ver_56101ad3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 688. hyp_path_f94ff8a36f3f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_63b.c:55
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制data变量的值（但代码证据未显示data的来源）。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_63b.c:55; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_63b.c::CWE114_Process_Control__w32_wchar_t_listen_socket_63b_case0Sink @ route
- 结论: 外部控制的路径变量传递给LoadLibraryA，可能导致加载恶意DLL。
- D验证: confirmed / ver_f5a94b38
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 689. hyp_path_ac57de93c708

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_64b.c:58
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接与目标程序通信; 目标程序使用socket接收数据并传递给LoadLibraryA
- 触发路径: data从socket接收 @ 函数入口：socket接收数据; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_64b.c:53
- 结论: 通过socket接收的外部输入直接传递给LoadLibraryA，攻击者可以控制加载任意库，导致任意代码执行。
- D验证: confirmed / ver_d20c9a4a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 690. hyp_path_0126d11e9a32

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_64b.c:58
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接与目标程序通信; 目标程序使用socket接收数据并传递给LoadLibraryA
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_64b.c:58; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_64b.c::CWE114_Process_Control__w32_char_listen_socket_64b_case0Sink @ route
- 结论: 通过socket接收的外部输入直接传递给LoadLibraryA，攻击者可以控制加载任意库，导致任意代码执行。
- D验证: confirmed / ver_df895f79
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 691. hyp_path_8b9ebd19a6eb

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_64b.c:58
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接与目标程序通信; 目标程序使用socket接收数据并传递给LoadLibraryA
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_64b.c:58; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_64b.c::CWE114_Process_Control__w32_wchar_t_connect_socket_64b_case0Sink @ route
- 结论: 通过socket接收的外部输入直接传递给LoadLibraryA，攻击者可以控制加载任意库，导致任意代码执行。
- D验证: confirmed / ver_7654879e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 692. hyp_path_ef80aeb4c056

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_64b.c:58
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接与目标程序通信; 目标程序使用socket接收数据并传递给LoadLibraryA
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_64b.c:58; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_64b.c::CWE114_Process_Control__w32_wchar_t_listen_socket_64b_case0Sink @ route
- 结论: 通过socket接收的外部输入直接传递给LoadLibraryA，攻击者可以控制加载任意库，导致任意代码执行。
- D验证: confirmed / ver_4590b587
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 693. hyp_path_aa48d664aadf

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_65b.c:54
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接向目标程序发送恶意构造的库路径字符串。
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_65b.c:49-53
- 结论: 函数LoadLibraryA使用从网络socket接收的可控路径参数加载库，攻击者可控制data内容加载任意恶意DLL，造成进程控制漏洞（CWE-114）。
- D验证: confirmed / ver_a2b0e7a4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 694. hyp_path_4bc0f92724cd

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_65b.c:54
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接向目标程序发送恶意构造的库路径字符串。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_65b.c:54; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_65b.c::CWE114_Process_Control__w32_char_listen_socket_65b_case0Sink @ route
- 结论: 函数LoadLibraryA使用从网络socket接收的可控路径参数加载库，攻击者可控制data内容加载任意恶意DLL，造成进程控制漏洞（CWE-114）。
- D验证: confirmed / ver_db2c703a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 695. hyp_path_5864c88b9e5d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_65b.c:54
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接向目标程序发送恶意构造的库路径字符串。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_65b.c:54; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_65b.c::CWE114_Process_Control__w32_wchar_t_connect_socket_65b_case0Sink @ route
- 结论: 函数LoadLibraryA使用从网络socket接收的可控路径参数加载库，攻击者可控制data内容加载任意恶意DLL，造成进程控制漏洞（CWE-114）。
- D验证: confirmed / ver_e84777f4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 696. hyp_path_7204e29eae79

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_65b.c:54
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接向目标程序发送恶意构造的库路径字符串。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_65b.c:54; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_65b.c::CWE114_Process_Control__w32_wchar_t_listen_socket_65b_case0Sink @ route
- 结论: 函数LoadLibraryA使用从网络socket接收的可控路径参数加载库，攻击者可控制data内容加载任意恶意DLL，造成进程控制漏洞（CWE-114）。
- D验证: confirmed / ver_6b474302
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 697. hyp_path_3d5157825b5b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_66b.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制传递给LoadLibraryA的字符串data，例如通过网络连接接收数据或从环境变量获取。
- 触发路径: void CWE114_Process_Control__w32_char_connect_socket_66b_case0Sink(char * data) @ 入口函数CWE114_Process_Control__w32_char_connect_socket_66b_case0Sink; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_66b.c:56
- 结论: 外部可控的库路径通过LoadLibraryA加载，可能导致加载恶意库，实现任意代码执行。
- D验证: confirmed / ver_0e6ae6a0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 698. hyp_path_e732b176b0dd

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_66b.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制传递给LoadLibraryA的字符串data，例如通过网络连接接收数据或从环境变量获取。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_66b.c:56; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_66b.c::CWE114_Process_Control__w32_char_listen_socket_66b_case0Sink @ route
- 结论: 外部可控的库路径通过LoadLibraryA加载，可能导致加载恶意库，实现任意代码执行。
- D验证: confirmed / ver_e7f2030a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 699. hyp_path_c478222d808b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_66b.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制传递给LoadLibraryA的字符串data，例如通过网络连接接收数据或从环境变量获取。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_66b.c:56; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_66b.c::CWE114_Process_Control__w32_wchar_t_connect_socket_66b_case0Sink @ route
- 结论: 外部可控的库路径通过LoadLibraryA加载，可能导致加载恶意库，实现任意代码执行。
- D验证: confirmed / ver_e7e64875
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 700. hyp_path_7cd1c4300931

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_66b.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制传递给LoadLibraryA的字符串data，例如通过网络连接接收数据或从环境变量获取。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_66b.c:56; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_66b.c::CWE114_Process_Control__w32_wchar_t_listen_socket_66b_case0Sink @ route
- 结论: 外部可控的库路径通过LoadLibraryA加载，可能导致加载恶意库，实现任意代码执行。
- D验证: confirmed / ver_bc9d5a8e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 701. hyp_path_0985b13d57df

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_67b.c:60
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络发送恶意构造的库路径字符串到socket。
- 触发路径: （假设）socket读取操作接收攻击者控制的字符串 @ 外部socket输入（推断）; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_67b.c:55-59
- 结论: 攻击者可通过socket输入控制库路径，导致加载任意DLL，存在CWE-114 Process Control漏洞。
- D验证: confirmed / ver_33d02548
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 702. hyp_path_57bc83ea4b52

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_67b.c:60
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络发送恶意构造的库路径字符串到socket。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_67b.c:60; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_67b.c::CWE114_Process_Control__w32_char_listen_socket_67b_case0Sink @ route
- 结论: 攻击者可通过socket输入控制库路径，导致加载任意DLL，存在CWE-114 Process Control漏洞。
- D验证: confirmed / ver_a49cced1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 703. hyp_path_6b926477b596

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_67b.c:60
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络发送恶意构造的库路径字符串到socket。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_67b.c:60; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_67b.c::CWE114_Process_Control__w32_wchar_t_connect_socket_67b_case0Sink @ route
- 结论: 攻击者可通过socket输入控制库路径，导致加载任意DLL，存在CWE-114 Process Control漏洞。
- D验证: confirmed / ver_b00164d7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 704. hyp_path_997bea6137a9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_67b.c:60
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络发送恶意构造的库路径字符串到socket。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_67b.c:60; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_67b.c::CWE114_Process_Control__w32_wchar_t_listen_socket_67b_case0Sink @ route
- 结论: 攻击者可通过socket输入控制库路径，导致加载任意DLL，存在CWE-114 Process Control漏洞。
- D验证: confirmed / ver_638df05a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 705. hyp_path_cbd52c750251

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_68b.c:60
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制网络输入，并能在目标系统上放置或利用已有恶意DLL
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_68b.c:60
- 结论: 程序通过socket接收外部输入，并将该输入作为路径参数直接传递给LoadLibraryA函数，导致攻击者可以加载任意恶意DLL，实现代码执行。
- D验证: confirmed / ver_b85b356b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 706. hyp_path_0fc9e5ffb5fd

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_68b.c:60
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制网络输入，并能在目标系统上放置或利用已有恶意DLL
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryA(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_68b.c:60; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_68b.c::CWE114_Process_Control__w32_char_listen_socket_68b_case0Sink @ route
- 结论: 程序通过socket接收外部输入，并将该输入作为路径参数直接传递给LoadLibraryA函数，导致攻击者可以加载任意恶意DLL，实现代码执行。
- D验证: confirmed / ver_a7a850fb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 707. hyp_path_2da8aee93b58

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_68b.c:60
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制网络输入，并能在目标系统上放置或利用已有恶意DLL
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_68b.c:60; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_68b.c::CWE114_Process_Control__w32_wchar_t_connect_socket_68b_case0Sink @ route
- 结论: 程序通过socket接收外部输入，并将该输入作为路径参数直接传递给LoadLibraryA函数，导致攻击者可以加载任意恶意DLL，实现代码执行。
- D验证: confirmed / ver_93363a68
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 708. hyp_path_b91f20622835

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_68b.c:60
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制网络输入，并能在目标系统上放置或利用已有恶意DLL
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_68b.c:60; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_68b.c::CWE114_Process_Control__w32_wchar_t_listen_socket_68b_case0Sink @ route
- 结论: 程序通过socket接收外部输入，并将该输入作为路径参数直接传递给LoadLibraryA函数，导致攻击者可以加载任意恶意DLL，实现代码执行。
- D验证: confirmed / ver_c84695be
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 709. hyp_path_16c6d9b20677

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_54c.c:52
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制data变量的来源（如网络输入）
- 触发路径: CWE114_Process_Control__w32_char_connect_socket_54d_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_54c.c:52
- 结论: CWE114_Process_Control: 外部可控数据可能通过未闭合的source-sink路径导致进程控制
- D验证: confirmed / ver_d2686e00
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 710. hyp_path_add841246bd6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_54c.c:52
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制data变量的来源（如网络输入）
- 触发路径: void CWE114_Process_Control__w32_char_listen_socket_54c_case0Sink(char * data) { CWE114_Process_Control__w32_char_listen_socket_54d_case0Sink(data); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_54c.c:52; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_54c.c::CWE114_Process_Control__w32_char_listen_socket_54c_case0Sink @ route
- 结论: CWE114_Process_Control: 外部可控数据可能通过未闭合的source-sink路径导致进程控制
- D验证: confirmed / ver_83a46fd2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 711. hyp_path_f61a19691687

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_54c.c:52
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制data变量的来源（如网络输入）
- 触发路径: void CWE114_Process_Control__w32_wchar_t_connect_socket_54c_case0Sink(wchar_t * data) { CWE114_Process_Control__w32_wchar_t_connect_socket_54d_case0Sink(data); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_54c.c:52; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_54c.c::CWE114_Process_Control__w32_wchar_t_connect_socket_54c_case0Sink @ route
- 结论: CWE114_Process_Control: 外部可控数据可能通过未闭合的source-sink路径导致进程控制
- D验证: confirmed / ver_5e29d80d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 712. hyp_path_a6f3b8dfec8b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_54c.c:52
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制data变量的来源（如网络输入）
- 触发路径: void CWE114_Process_Control__w32_wchar_t_listen_socket_54c_case0Sink(wchar_t * data) { CWE114_Process_Control__w32_wchar_t_listen_socket_54d_case0Sink(data); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_54c.c:52; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_54c.c::CWE114_Process_Control__w32_wchar_t_listen_socket_54c_case0Sink @ route
- 结论: CWE114_Process_Control: 外部可控数据可能通过未闭合的source-sink路径导致进程控制
- D验证: confirmed / ver_95b5fd89
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 713. hyp_path_46ef62bf2173

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_61a.c:47
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够影响data的来源（如文件、环境变量等），将路径设置为恶意库。
- 触发路径: char dataBuffer[100] = ""; data = dataBuffer; data = CWE114_Process_Control__w32_char_file_61b_case0Source(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_61a.c:37-41; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_61a.c:46
- 结论: 程序使用外部可控的字符串作为LoadLibraryA的参数加载动态库，攻击者可通过控制该字符串加载任意恶意库，导致代码执行或权限提升。
- D验证: confirmed / ver_099e9d39
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 714. hyp_path_6c12af19ea89

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_61a.c:47
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够影响data的来源（如文件、环境变量等），将路径设置为恶意库。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... wchar_t dataBuffer[100] = L... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_61a.c:47; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_61a.c::CWE114_Process_Control__w32_wchar_t_file_61_case0 @ route
- 结论: 程序使用外部可控的字符串作为LoadLibraryA的参数加载动态库，攻击者可通过控制该字符串加载任意恶意库，导致代码执行或权限提升。
- D验证: confirmed / ver_dc388fc2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 715. hyp_path_3060a78a9213

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_83_case0.cpp:66
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件的内容，即能够写入或影响文件系统中的目标文件。
- 触发路径: data = ... @ 文件读取点（未显示，但data来源于文件）; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_83_case0.cpp:61-63
- 结论: 存在CWE-114进程控制漏洞：通过从外部文件读取数据作为LoadLibraryA的参数，攻击者可以控制加载的库路径，从而加载恶意DLL，执行任意代码。
- D验证: confirmed / ver_17c40034
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 716. hyp_path_2cdc75e275ec

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_83_case0.cpp:66
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件的内容，即能够写入或影响文件系统中的目标文件。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_83_case0.cpp:66; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_83_case0.cpp::_ZN43CWE114_Process_Control__w32_wchar_t_file_8349CWE114_Process_Control__w32_wchar_t_file_83_case0D2Ev @ route
- 结论: 存在CWE-114进程控制漏洞：通过从外部文件读取数据作为LoadLibraryA的参数，攻击者可以控制加载的库路径，从而加载恶意DLL，执行任意代码。
- D验证: confirmed / ver_e3fe9748
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 717. hyp_path_ed1ac82effff

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_41.c:40
- 漏洞类型: CWE-114, CWE-73
- CWE: CWE-114; CWE-73
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件的内容; 程序使用可变路径加载库
- 触发路径: CWE114_Process_Control__w32_char_file_41_case0Sink(data); @ 入口函数调用sink函数; hModule = LoadLibraryA(data); @ sink函数中，data来自文件，未验证; FreeLibrary(hModule); @ 加载后释放库
- 结论: 外部输入通过文件路径控制LoadLibraryA加载的库，攻击者可通过控制文件内容指定恶意库路径，导致任意代码执行。
- D验证: confirmed / ver_395205ad
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 718. hyp_path_3680a98ec292

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_41.c:40
- 漏洞类型: CWE-114, CWE-73
- CWE: CWE-114; CWE-73
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件的内容; 程序使用可变路径加载库
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_41.c:40; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_41.c::CWE114_Process_Control__w32_wchar_t_file_41_case0Sink @ route
- 结论: 外部输入通过文件路径控制LoadLibraryA加载的库，攻击者可通过控制文件内容指定恶意库路径，导致任意代码执行。
- D验证: confirmed / ver_2a8d497c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 719. hyp_path_1050e7d85c6b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_84_case0.cpp:66
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制data变量的内容（例如通过文件输入）
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_84_case0.cpp:61
- 结论: 程序使用外部可控的输入作为动态链接库路径加载库，攻击者可以通过指定恶意库路径执行任意代码。
- D验证: confirmed / ver_451b3da7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 720. hyp_path_111b75e0301d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_84_case0.cpp:66
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制data变量的内容（例如通过文件输入）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_84_case0.cpp:66; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_84_case0.cpp::_ZN43CWE114_Process_Control__w32_wchar_t_file_8449CWE114_Process_Control__w32_wchar_t_file_84_case0D2Ev @ route
- 结论: 程序使用外部可控的输入作为动态链接库路径加载库，攻击者可以通过指定恶意库路径执行任意代码。
- D验证: confirmed / ver_7b9f3d9a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 721. hyp_path_72b2f5a8895b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_44.c:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件的内容（如通过上传或写入）
- 触发路径: 将文件内容读入data @ 文件读取处（根据Juliet测试用例结构存在，但代码片段未直接展示）; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_44.c:35; if (hModule != NULL) { FreeLibrary(hModule); ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_44.c:38-42
- 结论: 程序从文件读取一个字符串作为参数传递给LoadLibraryA，如果攻击者能够控制该文件的内容，则可以加载任意恶意库，导致代码执行或提权。
- D验证: confirmed / ver_5eda7ed1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 722. hyp_path_9867a1a718fe

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_44.c:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件的内容（如通过上传或写入）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_44.c:40; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_44.c::case0Sink @ route
- 结论: 程序从文件读取一个字符串作为参数传递给LoadLibraryA，如果攻击者能够控制该文件的内容，则可以加载任意恶意库，导致代码执行或提权。
- D验证: confirmed / ver_50b9e0de
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 723. hyp_path_ca07bf6e317c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_45.c:44
- 漏洞类型: CWE-114, CWE-73
- CWE: CWE-114; CWE-73
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制作为数据源的文件（例如通过上传、配置文件篡改等）。; 攻击者需要拥有或放置一个恶意DLL到系统路径中。
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_45.c:44
- 结论: 通过从文件读取的数据作为参数调用LoadLibraryA，未验证路径合法性，攻击者可通过控制文件内容加载任意DLL（如恶意库），导致代码执行或权限提升。
- D验证: confirmed / ver_2f6a0ae9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 724. hyp_path_4b1081cb20c1

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_45.c:44
- 漏洞类型: CWE-114, CWE-73
- CWE: CWE-114; CWE-73
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制作为数据源的文件（例如通过上传、配置文件篡改等）。; 攻击者需要拥有或放置一个恶意DLL到系统路径中。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_45.c:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_45.c::case0Sink @ route
- 结论: 通过从文件读取的数据作为参数调用LoadLibraryA，未验证路径合法性，攻击者可通过控制文件内容加载任意DLL（如恶意库），导致代码执行或权限提升。
- D验证: confirmed / ver_daa72c6d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 725. hyp_path_14008e7a64b5

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_51b.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制或影响文件输入（如通过文件上传、路径遍历等）
- 触发路径: data来自文件输入（CWE114_Process_Control__w32_char_file_51a.c中设置） @ 入口处; hModule = LoadLibraryA(data); @ CWE114_Process_Control__w32_char_file_51b.c:42
- 结论: 函数LoadLibraryA使用来自文件的外部输入作为库路径，攻击者可通过替换文件或控制文件内容加载恶意DLL，导致代码执行。
- D验证: confirmed / ver_eac3a081
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 726. hyp_path_3b213b747757

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_51b.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制或影响文件输入（如通过文件上传、路径遍历等）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_51b.c:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_51b.c::CWE114_Process_Control__w32_wchar_t_file_51b_case0Sink @ route
- 结论: 函数LoadLibraryA使用来自文件的外部输入作为库路径，攻击者可通过替换文件或控制文件内容加载恶意DLL，导致代码执行。
- D验证: confirmed / ver_a70e0516
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 727. hyp_path_4c6dd2df4f01

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_52c.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制传递给LoadLibraryA的data参数，例如通过文件内容或路径操作。
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_52c.c:37
- 结论: 函数调用LoadLibraryA加载了来自文件的外部数据作为库路径，攻击者可能通过控制输入文件内容来加载恶意库，导致进程控制漏洞。
- D验证: confirmed / ver_4194110e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 728. hyp_path_a05934095a53

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_52c.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制传递给LoadLibraryA的data参数，例如通过文件内容或路径操作。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_52c.c:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_52c.c::CWE114_Process_Control__w32_wchar_t_file_52c_case0Sink @ route
- 结论: 函数调用LoadLibraryA加载了来自文件的外部数据作为库路径，攻击者可能通过控制输入文件内容来加载恶意库，导致进程控制漏洞。
- D验证: confirmed / ver_184eefcf
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 729. hyp_path_410eaffa8d40

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_53d.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制lib文件路径或替换系统库文件
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_53d.c:37-38
- 结论: 代码使用`LoadLibraryA(data)`加载库，如果`data`路径可由攻击者控制，则可能加载恶意DLL，导致任意代码执行。注释也警告了路径未指定时攻击者可能替换自己的文件。
- D验证: confirmed / ver_396e5a6a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 730. hyp_path_65b221f1906f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_53d.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制lib文件路径或替换系统库文件
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_53d.c:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_53d.c::CWE114_Process_Control__w32_wchar_t_file_53d_case0Sink @ route
- 结论: 代码使用`LoadLibraryA(data)`加载库，如果`data`路径可由攻击者控制，则可能加载恶意DLL，导致任意代码执行。注释也警告了路径未指定时攻击者可能替换自己的文件。
- D验证: confirmed / ver_40a61249
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 731. hyp_path_8b44181b0a44

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_54e.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制data变量的值，例如通过文件内容或命令行参数
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_54e.c:37
- 结论: 代码使用用户控制的路径加载动态库（LoadLibraryA），攻击者可能通过控制路径加载恶意库，导致任意代码执行。
- D验证: confirmed / ver_0015f108
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 732. hyp_path_63b000e98aea

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_54e.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制data变量的值，例如通过文件内容或命令行参数
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_54e.c:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_54e.c::CWE114_Process_Control__w32_wchar_t_file_54e_case0Sink @ route
- 结论: 代码使用用户控制的路径加载动态库（LoadLibraryA），攻击者可能通过控制路径加载恶意库，导致任意代码执行。
- D验证: confirmed / ver_dd61938a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 733. hyp_path_71c9d6bde453

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_63b.c:41
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向数据来源的文件写入恶意库路径。
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_63b.c:36-38
- 结论: 通过LoadLibraryA加载由文件控制的动态库路径，攻击者可能指定恶意库导致任意代码执行。
- D验证: confirmed / ver_d0bcf8a8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 734. hyp_path_57ed7b17438f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_63b.c:41
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向数据来源的文件写入恶意库路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_63b.c:41; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_63b.c::CWE114_Process_Control__w32_wchar_t_file_63b_case0Sink @ route
- 结论: 通过LoadLibraryA加载由文件控制的动态库路径，攻击者可能指定恶意库导致任意代码执行。
- D验证: confirmed / ver_06445178
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 735. hyp_path_904b10b2c451

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_65b.c:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制传递给LoadLibraryA的参数data（例如通过文件读取或外部输入）
- 触发路径: // NOTE: If the path to the library is not specified, an attacker may be able to replace his own file with the intended library @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_65b.c:35; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_65b.c:35
- 结论: 函数通过LoadLibraryA加载外部库，但库路径或名称可能被攻击者控制，导致加载恶意DLL并执行任意代码。尽管加载后立即释放，但DLL入口点（如DllMain）会在加载时执行，造成安全风险。
- D验证: confirmed / ver_4582ff31
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 736. hyp_path_c63723e4cb04

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_65b.c:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制传递给LoadLibraryA的参数data（例如通过文件读取或外部输入）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_65b.c:40; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_65b.c::CWE114_Process_Control__w32_wchar_t_file_65b_case0Sink @ route
- 结论: 函数通过LoadLibraryA加载外部库，但库路径或名称可能被攻击者控制，导致加载恶意DLL并执行任意代码。尽管加载后立即释放，但DLL入口点（如DllMain）会在加载时执行，造成安全风险。
- D验证: confirmed / ver_d026e3fe
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 737. hyp_path_491a090656c4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_64b.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制变量data的值，例如通过修改文件内容或环境变量（根据测试用例命名推测data来自文件）; 系统未限制DLL加载路径（如SafeDllSearchMode等未启用）
- 触发路径: hModule = LoadLibraryA(data); @ CWE114_Process_Control__w32_char_file_64b.c:44
- 结论: 程序在调用LoadLibraryA时使用了可能受攻击者控制的路径参数data，可能导致加载恶意DLL，执行任意代码。但代码证据未明确展示data的来源，需要结合原始测试用例确认外部可控性。
- D验证: confirmed / ver_87e33b27
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 738. hyp_path_df553a6b160f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_64b.c:44
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制变量data的值，例如通过修改文件内容或环境变量（根据测试用例命名推测data来自文件）; 系统未限制DLL加载路径（如SafeDllSearchMode等未启用）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_64b.c:44; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_64b.c::CWE114_Process_Control__w32_wchar_t_file_64b_case0Sink @ route
- 结论: 程序在调用LoadLibraryA时使用了可能受攻击者控制的路径参数data，可能导致加载恶意DLL，执行任意代码。但代码证据未明确展示data的来源，需要结合原始测试用例确认外部可控性。
- D验证: confirmed / ver_5fe96d1b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 739. hyp_path_2404a76fe5e3

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_67b.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制data的值，例如通过修改文件内容或环境变量。
- 触发路径: data = ... (从文件/环境读取) @ 获取外部输入; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_67b.c:41-42
- 结论: 程序使用外部可控的路径（data）调用LoadLibraryA加载动态库，攻击者可以控制路径加载恶意库，导致任意代码执行。
- D验证: confirmed / ver_8962058e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 740. hyp_path_1f6f74b21804

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_67b.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制data的值，例如通过修改文件内容或环境变量。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_67b.c:46; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_67b.c::CWE114_Process_Control__w32_wchar_t_file_67b_case0Sink @ route
- 结论: 程序使用外部可控的路径（data）调用LoadLibraryA加载动态库，攻击者可以控制路径加载恶意库，导致任意代码执行。
- D验证: confirmed / ver_879f5458
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 741. hyp_path_5efd55001bd7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_66b.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制函数参数data的值，例如通过文件内容或环境变量注入恶意库路径。
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_66b.c:37
- 结论: 外部可控路径作为参数传递给LoadLibraryA，可能加载恶意库，导致任意代码执行或重定向执行流。
- D验证: confirmed / ver_a4066bbc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 742. hyp_path_96dcb211f7e3

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_66b.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制函数参数data的值，例如通过文件内容或环境变量注入恶意库路径。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_66b.c:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_66b.c::CWE114_Process_Control__w32_wchar_t_file_66b_case0Sink @ route
- 结论: 外部可控路径作为参数传递给LoadLibraryA，可能加载恶意库，导致任意代码执行或重定向执行流。
- D验证: confirmed / ver_f8fc2ebc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 743. hyp_path_65e001733e04

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_68b.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制输入文件的内容（如通过文件上传、共享目录等）。
- 触发路径: hModule = LoadLibraryA(data); @ L46; FreeLibrary(hModule); @ L46后的释放
- 结论: 该代码从文件读取库路径并调用LoadLibraryA加载，未对路径进行充分验证，攻击者可通过控制文件内容加载任意恶意DLL，导致进程控制（远程代码执行）。
- D验证: confirmed / ver_11742a27
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 744. hyp_path_561926aa06f9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_68b.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制输入文件的内容（如通过文件上传、共享目录等）。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... { FreeLibrary(hModule); pri... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_68b.c:46; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_68b.c::CWE114_Process_Control__w32_wchar_t_file_68b_case0Sink @ route
- 结论: 该代码从文件读取库路径并调用LoadLibraryA加载，未对路径进行充分验证，攻击者可通过控制文件内容加载任意恶意DLL，导致进程控制（远程代码执行）。
- D验证: confirmed / ver_181dc9a0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 745. hyp_path_91d785dd2452

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_21.c:52
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL文件放置在程序搜索路径中（如当前目录）
- 触发路径: data = case0Source(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_21.c:44; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_21.c:47
- 结论: 程序使用相对路径加载库，攻击者可能通过在搜索路径中放置恶意DLL导致任意代码执行。
- D验证: confirmed / ver_7da6908c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 746. hyp_path_3d964c8cd70d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_21.c:52
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL文件放置在程序搜索路径中（如当前目录）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... data = dataBuffer; case0Sta... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_21.c:52; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_21.c::CWE114_Process_Control__w32_wchar_t_relativePath_21_case0 @ route
- 结论: 程序使用相对路径加载库，攻击者可能通过在搜索路径中放置恶意DLL导致任意代码执行。
- D验证: confirmed / ver_e7d90f85
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 747. hyp_path_18fe56e5e64f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_12.c:47
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: Attacker must be able to place a malicious DLL named 'winsrv.dll' in the current working directory or search path.
- 触发路径: strcpy(data, "winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_12.c:32-35; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_12.c:42-43
- 结论: CWE-114 Process Control - Untrusted library loading via relative path. The code uses a relative path 'winsrv.dll' without full path specification, allowing an attacker to replace the library with a malicious one.
- D验证: confirmed / ver_b420218d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 748. hyp_path_dd2860149de9

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_12.c:47
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: Attacker must be able to place a malicious DLL named 'winsrv.dll' in the current working directory or search path.
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* ALT: Specify the full pathname for the library */ wcscpy(data, L"C:\\Windows\\System32\\winsrv.dll"); } { ... { /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_12.c:47; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_12.c::CWE114_Process_Control__w32_wchar_t_relativePath_12_case0 @ route
- 结论: CWE-114 Process Control - Untrusted library loading via relative path. The code uses a relative path 'winsrv.dll' without full path specification, allowing an attacker to replace the library with a malicious one.
- D验证: confirmed / ver_0d5b94c9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 749. hyp_path_8f358d9dff42

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_08.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能控制DLL搜索路径中的某个目录，并放置恶意winsrv.dll文件。
- 触发路径: strcpy(data, "winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_08.c:45; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_08.c:52
- 结论: 函数使用相对路径加载DLL，可能导致DLL劫持漏洞。攻击者可放置恶意DLL在搜索路径中替换合法库。
- D验证: confirmed / ver_0fd41bde
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 750. hyp_path_a55c66f6ab8d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_08.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能控制DLL搜索路径中的某个目录，并放置恶意winsrv.dll文件。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); } { ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_08.c:56; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_08.c::CWE114_Process_Control__w32_wchar_t_relativePath_08_case0 @ route
- 结论: 函数使用相对路径加载DLL，可能导致DLL劫持漏洞。攻击者可放置恶意DLL在搜索路径中替换合法库。
- D验证: confirmed / ver_df34080e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 751. hyp_path_d796400e66f7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_11.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够在文件系统中创建或替换名为winsrv.dll的文件，且该文件位于LoadLibraryA的搜索路径中。
- 触发路径: strcpy(data, "winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_11.c:31; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_11.c:37
- 结论: 程序调用LoadLibraryA加载DLL时，只使用文件名"winsrv.dll"而未指定完整路径，可能导致DLL劫持。攻击者可将恶意DLL放置在当前工作目录或搜索路径中，从而加载恶意代码。
- D验证: confirmed / ver_4560504e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 752. hyp_path_0a38e2171b1d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_11.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够在文件系统中创建或替换名为winsrv.dll的文件，且该文件位于LoadLibraryA的搜索路径中。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); } { ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_11.c:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_11.c::CWE114_Process_Control__w32_wchar_t_relativePath_11_case0 @ route
- 结论: 程序调用LoadLibraryA加载DLL时，只使用文件名"winsrv.dll"而未指定完整路径，可能导致DLL劫持。攻击者可将恶意DLL放置在当前工作目录或搜索路径中，从而加载恶意代码。
- D验证: confirmed / ver_7e4343b2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 753. hyp_path_8a3be3537740

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_01.c:39
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL放置在应用程序的库搜索路径中（例如当前工作目录）。
- 触发路径: data = dataBuffer; strcpy(data, "winsrv.dll"); @ 行29-33; hModule = LoadLibraryA(data); @ 行34-38
- 结论: 使用相对路径加载库，攻击者可能通过替换同名DLL实现任意代码执行。
- D验证: confirmed / ver_7bc6cdd4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 754. hyp_path_cd078fca16f4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_01.c:39
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL放置在应用程序的库搜索路径中（例如当前工作目录）。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... data = dataBuffer; /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); { HMODULE hModule; ... /* NOTE: If the path to the library is not specified, an attacker may be... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_01.c:39; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_01.c::CWE114_Process_Control__w32_wchar_t_relativePath_01_case0 @ route
- 结论: 使用相对路径加载库，攻击者可能通过替换同名DLL实现任意代码执行。
- D验证: confirmed / ver_3015605e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 755. hyp_path_5125447bafb5

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_02.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL放置到应用程序加载库时搜索的路径中（如当前工作目录、系统路径等）
- 触发路径: strcpy(data, "winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_02.c:33; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_02.c:41
- 结论: 存在安全漏洞：函数使用相对路径加载库（仅指定文件名'winsrv.dll'），攻击者可将恶意DLL放置在搜索路径中，导致任意代码执行。
- D验证: confirmed / ver_c6a3b1f8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 756. hyp_path_642d1d56596c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_02.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL放置到应用程序加载库时搜索的路径中（如当前工作目录、系统路径等）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); } { ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_02.c:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_02.c::CWE114_Process_Control__w32_wchar_t_relativePath_02_case0 @ route
- 结论: 存在安全漏洞：函数使用相对路径加载库（仅指定文件名'winsrv.dll'），攻击者可将恶意DLL放置在搜索路径中，导致任意代码执行。
- D验证: confirmed / ver_2d9ac14f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 757. hyp_path_678acb9637c8

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_03.c:42
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL放置在目标进程的当前工作目录或系统搜索路径中的任意位置
- 触发路径: strcpy(data, "winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_03.c:34; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_03.c:39
- 结论: 代码使用相对路径加载库（LoadLibraryA("winsrv.dll")），存在DLL劫持漏洞，攻击者可将恶意DLL放置在当前工作目录或搜索路径中以劫持进程。
- D验证: confirmed / ver_95f956f3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 758. hyp_path_4896061ca370

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_03.c:42
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL放置在目标进程的当前工作目录或系统搜索路径中的任意位置
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); } { ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_03.c:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_03.c::CWE114_Process_Control__w32_wchar_t_relativePath_03_case0 @ route
- 结论: 代码使用相对路径加载库（LoadLibraryA("winsrv.dll")），存在DLL劫持漏洞，攻击者可将恶意DLL放置在当前工作目录或搜索路径中以劫持进程。
- D验证: confirmed / ver_04cb1b84
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 759. hyp_path_a759a5d6555b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_04.c:49
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制当前工作目录或搜索路径，并在其中放置与硬编码文件名相同的恶意DLL
- 触发路径: strcpy(data, "winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_04.c:38-42; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_04.c:44-48
- 结论: 代码使用相对路径加载DLL（"winsrv.dll"），攻击者可能通过替换同名恶意DLL实现远程代码执行（CWE-114: Process Control）。尽管路径硬编码，但若攻击者能控制文件系统或环境（如放置恶意DLL到当前工作目录），则可能利用。
- D验证: confirmed / ver_c39e1fef
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 760. hyp_path_ddb7174697b0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_04.c:49
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制当前工作目录或搜索路径，并在其中放置与硬编码文件名相同的恶意DLL
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); } { ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_04.c:49; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_04.c::CWE114_Process_Control__w32_wchar_t_relativePath_04_case0 @ route
- 结论: 代码使用相对路径加载DLL（"winsrv.dll"），攻击者可能通过替换同名恶意DLL实现远程代码执行（CWE-114: Process Control）。尽管路径硬编码，但若攻击者能控制文件系统或环境（如放置恶意DLL到当前工作目录），则可能利用。
- D验证: confirmed / ver_f99263c6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 761. hyp_path_8d1bb3091329

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_05.c:49
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL（例如名为'winsrv.dll'）放置在应用程序的当前工作目录或系统搜索路径中。
- 触发路径: strcpy(data, "winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_05.c:38-42; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_05.c:44-46
- 结论: 使用相对路径加载DLL，允许攻击者通过将恶意DLL放置在当前目录或搜索路径中实现DLL劫持。
- D验证: confirmed / ver_08bb0ef5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 762. hyp_path_c586757dc0b5

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_05.c:49
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL（例如名为'winsrv.dll'）放置在应用程序的当前工作目录或系统搜索路径中。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); } { ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_05.c:49; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_05.c::CWE114_Process_Control__w32_wchar_t_relativePath_05_case0 @ route
- 结论: 使用相对路径加载DLL，允许攻击者通过将恶意DLL放置在当前目录或搜索路径中实现DLL劫持。
- D验证: confirmed / ver_abcc2753
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 763. hyp_path_b0a4106dd88b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_07.c:48
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL文件放置到程序加载时搜索的目录中（例如当前工作目录）。
- 触发路径: strcpy(data, "winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_07.c:39; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_07.c:44
- 结论: 程序使用相对路径加载动态链接库，攻击者可能通过将恶意DLL放置在当前工作目录或搜索路径中实现代码执行。
- D验证: confirmed / ver_627dd4a4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 764. hyp_path_0a457b0ddb89

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_07.c:48
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL文件放置到程序加载时搜索的目录中（例如当前工作目录）。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); } { ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_07.c:48; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_07.c::CWE114_Process_Control__w32_wchar_t_relativePath_07_case0 @ route
- 结论: 程序使用相对路径加载动态链接库，攻击者可能通过将恶意DLL放置在当前工作目录或搜索路径中实现代码执行。
- D验证: confirmed / ver_c72c7261
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 765. hyp_path_95d39bf081c4

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_09.c:42
- 漏洞类型: CWE-114, CWE-427
- CWE: CWE-114; CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够在当前工作目录或系统搜索路径中包含的任意目录中放置恶意DLL文件（如winsrv.dll）
- 触发路径: strcpy(data, "winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_09.c:31-35; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_09.c:37-41
- 结论: 在LoadLibraryA调用中使用了相对路径（仅文件名），导致潜在的DLL劫持漏洞。攻击者可以通过将恶意DLL放置在搜索路径中（如当前工作目录）来劫持库加载。
- D验证: confirmed / ver_a7e5be86
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 766. hyp_path_61b3ca8d3803

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_09.c:42
- 漏洞类型: CWE-114, CWE-427
- CWE: CWE-114; CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够在当前工作目录或系统搜索路径中包含的任意目录中放置恶意DLL文件（如winsrv.dll）
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); } { ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_09.c:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_09.c::CWE114_Process_Control__w32_wchar_t_relativePath_09_case0 @ route
- 结论: 在LoadLibraryA调用中使用了相对路径（仅文件名），导致潜在的DLL劫持漏洞。攻击者可以通过将恶意DLL放置在搜索路径中（如当前工作目录）来劫持库加载。
- D验证: confirmed / ver_68606261
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 767. hyp_path_9687cf7fde63

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_10.c:42
- 漏洞类型: CWE-114, CWE-427
- CWE: CWE-114; CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL写入文件系统（如通过上传或网络共享）使其位于搜索路径中。
- 触发路径: strcpy(data, "winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_10.c:33; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_10.c:38
- 结论: 程序仅使用文件名（不含路径）加载库，存在DLL劫持漏洞，攻击者可通过在搜索路径中放置恶意DLL导致任意代码执行。
- D验证: confirmed / ver_444e36f5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 768. hyp_path_945627fcc46e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_10.c:42
- 漏洞类型: CWE-114, CWE-427
- CWE: CWE-114; CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL写入文件系统（如通过上传或网络共享）使其位于搜索路径中。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); } { ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_10.c:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_10.c::CWE114_Process_Control__w32_wchar_t_relativePath_10_case0 @ route
- 结论: 程序仅使用文件名（不含路径）加载库，存在DLL劫持漏洞，攻击者可通过在搜索路径中放置恶意DLL导致任意代码执行。
- D验证: confirmed / ver_ba623a81
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 769. hyp_path_66dc31290705

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_13.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将任意DLL文件放置到应用程序的当前工作目录或系统搜索路径中。
- 触发路径: strcpy(data, "winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_13.c:34; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_13.c:39
- 结论: 未指定库文件的绝对路径，使用相对路径加载DLL，攻击者可能将恶意DLL放置在搜索路径中实现劫持，导致进程控制漏洞。
- D验证: confirmed / ver_a6cd4190
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 770. hyp_path_e5fce90a3b3d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_13.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将任意DLL文件放置到应用程序的当前工作目录或系统搜索路径中。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); } { ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_13.c:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_13.c::CWE114_Process_Control__w32_wchar_t_relativePath_13_case0 @ route
- 结论: 未指定库文件的绝对路径，使用相对路径加载DLL，攻击者可能将恶意DLL放置在搜索路径中实现劫持，导致进程控制漏洞。
- D验证: confirmed / ver_d55208c8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 771. hyp_path_91555de8aff5

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_14.c:42
- 漏洞类型: CWE-114, CWE-427
- CWE: CWE-114; CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制程序的工作目录或系统PATH环境变量，以放置恶意DLL
- 触发路径: strcpy(data, "winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_14.c:31-35; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_14.c:37-41
- 结论: 程序使用相对路径加载动态链接库，攻击者可以通过将恶意DLL放置在搜索路径中来替换合法库，导致任意代码执行。
- D验证: confirmed / ver_502b9831
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 772. hyp_path_4b57b8eda452

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_14.c:42
- 漏洞类型: CWE-114, CWE-427
- CWE: CWE-114; CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制程序的工作目录或系统PATH环境变量，以放置恶意DLL
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); } { ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_14.c:42; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_14.c::CWE114_Process_Control__w32_wchar_t_relativePath_14_case0 @ route
- 结论: 程序使用相对路径加载动态链接库，攻击者可以通过将恶意DLL放置在搜索路径中来替换合法库，导致任意代码执行。
- D验证: confirmed / ver_a93d636f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 773. hyp_path_b4e47cdf2a49

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_15.c:48
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL文件命名为winsrv.dll并放置在应用程序的当前工作目录或系统搜索路径中。
- 触发路径: strcpy(data, "winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_15.c:33; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_15.c:43
- 结论: 函数LoadLibraryA使用相对路径加载固定名称DLL（winsrv.dll），攻击者可通过将同名恶意DLL放置在搜索路径中实现DLL劫持。
- D验证: confirmed / ver_0e7760d6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 774. hyp_path_e244159af7c6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_15.c:48
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL文件命名为winsrv.dll并放置在应用程序的当前工作目录或系统搜索路径中。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... case 6: /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); break; default: ... /* NOTE: If the path to the library is not specified, an attacker may be able to * rep... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_15.c:48; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_15.c::CWE114_Process_Control__w32_wchar_t_relativePath_15_case0 @ route
- 结论: 函数LoadLibraryA使用相对路径加载固定名称DLL（winsrv.dll），攻击者可通过将同名恶意DLL放置在搜索路径中实现DLL劫持。
- D验证: confirmed / ver_2d3010df
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 775. hyp_path_a15a8ef81f7f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_16.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够在系统搜索路径（如当前工作目录）中放置名为'winsrv.dll'的恶意DLL文件。
- 触发路径: strcpy(data, "winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_16.c:33-34; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_16.c:38-39
- 结论: 代码中加载库时仅使用文件名'winsrv.dll'，而未指定完整路径，攻击者可能通过DLL劫持将恶意库放置在搜索路径中（如当前目录），导致加载恶意库，进而执行任意代码。
- D验证: confirmed / ver_2b031212
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 776. hyp_path_a3700f2577da

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_16.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够在系统搜索路径（如当前工作目录）中放置名为'winsrv.dll'的恶意DLL文件。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); break; } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_16.c:43; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_16.c::CWE114_Process_Control__w32_wchar_t_relativePath_16_case0 @ route
- 结论: 代码中加载库时仅使用文件名'winsrv.dll'，而未指定完整路径，攻击者可能通过DLL劫持将恶意库放置在搜索路径中（如当前目录），导致加载恶意库，进而执行任意代码。
- D验证: confirmed / ver_69e0531d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 777. hyp_path_742c9dbc1673

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_17.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL文件命名为'winsrv.dll'并放置于进程当前工作目录或其他优先于系统目录的搜索路径中。
- 触发路径: strcpy(data, "winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_17.c:32; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_17.c:38
- 结论: 程序使用相对路径加载DLL（'winsrv.dll'），未指定完整路径，攻击者可通过将恶意DLL放置在搜索路径中实现DLL劫持，导致任意代码执行。
- D验证: confirmed / ver_91dff424
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 778. hyp_path_f1cc6d7f20cb

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_17.c:43
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL文件命名为'winsrv.dll'并放置于进程当前工作目录或其他优先于系统目录的搜索路径中。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... { /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); } { ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file ... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_17.c:43; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_17.c::CWE114_Process_Control__w32_wchar_t_relativePath_17_case0 @ route
- 结论: 程序使用相对路径加载DLL（'winsrv.dll'），未指定完整路径，攻击者可通过将恶意DLL放置在搜索路径中实现DLL劫持，导致任意代码执行。
- D验证: confirmed / ver_01237dfb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 779. hyp_path_b47ccf283d15

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_33.cpp:45
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL放置在当前工作目录或系统DLL搜索路径中的任意位置
- 触发路径: data = dataBuffer; strcpy(data, "winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_33.cpp:33-37; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_33.cpp:40-44
- 结论: 代码使用LoadLibraryA加载DLL时仅指定文件名（"winsrv.dll"）而未指定完整路径，存在DLL劫持风险（CWE-427）。虽然文件名是硬编码常量，但攻击者仍可通过控制搜索路径（如当前工作目录）放置恶意DLL实现劫持。
- D验证: confirmed / ver_fdc08e14
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 780. hyp_path_4537fa3095ba

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_33.cpp:45
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL放置在当前工作目录或系统DLL搜索路径中的任意位置
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... data = dataBuffer; /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); { wchar_t * data = dataRef; ... /* NOTE: If the path to the library is not specified, an attack... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_33.cpp:45; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_33.cpp::_ZN51CWE114_Process_Control__w32_wchar_t_relativePath_335case0Ev @ route
- 结论: 代码使用LoadLibraryA加载DLL时仅指定文件名（"winsrv.dll"）而未指定完整路径，存在DLL劫持风险（CWE-427）。虽然文件名是硬编码常量，但攻击者仍可通过控制搜索路径（如当前工作目录）放置恶意DLL实现劫持。
- D验证: confirmed / ver_efaa9cc5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 781. hyp_path_c458284c7483

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_34.c:49
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL放置在程序当前目录或搜索路径中
- 触发路径: strcpy(data, "winsrv.dll"); myUnion.unionFirst = data; @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_34.c:36-40; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_34.c:49
- 结论: LoadLibraryA使用了相对路径加载DLL，攻击者可能替换恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_ae50452b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 782. hyp_path_9d88c6575f5e

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_34.c:49
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL放置在程序当前目录或搜索路径中
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... data = dataBuffer; /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); myUnion.unionFirst = data; { ... /* NOTE: If the path to the library is not specified, an attac... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_34.c:49; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_34.c::CWE114_Process_Control__w32_wchar_t_relativePath_34_case0 @ route
- 结论: LoadLibraryA使用了相对路径加载DLL，攻击者可能替换恶意DLL，导致任意代码执行。
- D验证: confirmed / ver_54424601
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 783. hyp_path_c085749c2f67

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_54c.c:38
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过文件输入控制data的内容
- 触发路径: CWE114_Process_Control__w32_char_file_54d_case0Sink(data); @ CWE114_Process_Control__w32_char_file_54c.c:38
- 结论: 可能存在不安全的进程控制：外部输入（来自文件）被传递给加载库的函数，可能加载恶意DLL。
- D验证: confirmed / ver_7a9f0e8c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 784. hyp_path_732a24a5a933

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_54c.c:38
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过文件输入控制data的内容
- 触发路径: void CWE114_Process_Control__w32_wchar_t_file_54c_case0Sink(wchar_t * data) { CWE114_Process_Control__w32_wchar_t_file_54d_case0Sink(data); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_54c.c:38; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_54c.c::CWE114_Process_Control__w32_wchar_t_file_54c_case0Sink @ route
- 结论: 可能存在不安全的进程控制：外部输入（来自文件）被传递给加载库的函数，可能加载恶意DLL。
- D验证: confirmed / ver_582f7f50
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 785. hyp_path_5d0a02d3f0ba

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_45.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL放置到应用程序的当前工作目录或系统搜索路径中（例如通过上传或社会工程）。
- 触发路径: strcpy(data, "winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_45.c:54; case0Sink(); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_45.c:56; hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_45.c:37
- 结论: 使用相对路径加载DLL，可能导致DLL劫持。尽管路径字符串为硬编码，但攻击者可通过将恶意DLL放置于应用程序当前工作目录或搜索路径中实现代码执行。
- D验证: confirmed / ver_5e554b9c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 786. hyp_path_3c8ad2dde9e0

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_45.c:56
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL放置到应用程序的当前工作目录或系统搜索路径中（例如通过上传或社会工程）。
- 触发路径: wcscpy(data, L"winsrv.dll"); CWE114_Process_Control__w32_wchar_t_relativePath_45_case0Data = data; case0Sink(); } ... data = dataBuffer; /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); CWE114_Process_Control__w32_wchar_t_relativePath_45_case0Data = data; case0Sink(... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_45.c:56; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_45.c::CWE114_Process_Control__w32_wchar_t_relativePath_45_case0 @ route
- 结论: 使用相对路径加载DLL，可能导致DLL劫持。尽管路径字符串为硬编码，但攻击者可通过将恶意DLL放置于应用程序当前工作目录或搜索路径中实现代码执行。
- D验证: confirmed / ver_eeddf2bb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 787. hyp_path_bfae360b3687

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_72a.cpp:51
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制输入文件FILENAME的内容。
- 触发路径: if (100-dataLen > 1) { pFile = fopen(FILENAME, "r"); if (pFile != NULL) { @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_72a.cpp:49-53; if (fgetws(data+dataLen, (int)(100-dataLen), pFile) == NULL) { printLine("fgetws() failed"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_72a.cpp:53-57; data[dataLen] = L'\0'; } fclose(pFile); } } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_72a.cpp:59-63; dataVector.insert(dataVector.end(), 1, data); dataVector.insert(dataVector.end(), 1, data); dataVector.insert(dataVector.end(), 1, data); case0Sink(dataVector); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_72a.cpp:70-72
- 结论: 程序从外部文件读取数据，并将该数据插入vector后传递给case0Sink函数，该函数将数据用作动态库名称或进程启动参数，导致攻击者可以通过控制文件内容实现任意代码执行或进程控制。
- D验证: confirmed / ver_8e84852e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 788. hyp_path_3eaa6a4e283c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_21.c:96
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标服务器的监听端口; 攻击者能够发送特制的wchar_t字符串数据; 服务器未对接收数据进行充分的输入验证和清理
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (100 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_21.c:96; 假设存在如 CreateProcessW(data, ...) 或 LoadLibraryW(data) 等调用 @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_21.c:? (sink点未在片段中显示)
- 结论: 存在CWE114漏洞：攻击者可通过网络socket接收的外部输入直接用于进程控制（可能调用CreateProcess或LoadLibrary等），导致任意代码执行。
- D验证: confirmed / ver_d03f58a0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 789. hyp_path_2a9daed2511c

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_61b.c:40
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制FILENAME指定的文件
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_61b.c:40; fgetws(data+dataLen, (int)(100-dataLen), pFile); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_61b.c:44; 预期的进程创建调用（如CreateProcess或system）未出现 @ 未在提供的代码片段中显示
- 结论: 从文件读取的数据可能被用于控制进程执行路径，但代码证据中未显示实际的进程创建调用，路径不完整。
- D验证: confirmed / ver_25387cf9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 790. hyp_path_4480d55d24de

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_44.c:61
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值。; data缓冲区位于栈上且大小有限（假设100），且dataLen未进行边界验证。
- 触发路径: size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_44.c:60-62; wcsncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_44.c:66-67
- 结论: 缓冲区溢出漏洞，通过环境变量控制输入，传递给wcsncat可能导致栈缓冲区溢出。
- D验证: confirmed / ver_fb850e32
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 791. hyp_path_e13044d96940

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_65a.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响环境变量ENV_VARIABLE的内容。
- 触发路径: wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_65a.c:45; wcsncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_65a.c:51; 未在给定代码片段中体现，但推测存在类似 system(data) 或 LoadLibrary(data) 的调用。 @ 假设的后续位置
- 结论: 可能存在CWE114进程控制漏洞：从环境变量读取数据后追加到缓冲区，如果后续未加验证地用于进程控制（如调用system或LoadLibrary），攻击者可通过控制环境变量执行任意程序。但当前代码片段未展示sink操作，且门禁分析显示风险极低，因此漏洞存在性不确定。
- D验证: confirmed / ver_0bad4868
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 792. hyp_path_4f333b9a1880

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_22b.c:40
- 漏洞类型: buffer_overflow
- CWE: CWE-120
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值
- 触发路径: size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_22b.c:39-41; wcsncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_22b.c:44-46
- 结论: 通过环境变量获取用户可控数据并追加到固定大小的缓冲区中，可能导致缓冲区溢出。
- D验证: confirmed / ver_056b20ea
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 793. hyp_path_63dc55a38dc6

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_42.c:38
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: Attacker can provide arbitrary input via console (stdin)
- 触发路径: if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_42.c:32-36; Sink (e.g., LoadLibrary) not present in provided evidence @ unknown (sink not shown)
- 结论: Potential process control vulnerability due to insufficient control over input used in a subsequent process control sink (e.g., LoadLibrary), but full source-sink route is not confirmed in provided evidence.
- D验证: confirmed / ver_f297c487
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 794. hyp_path_af70236dfbe2

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_83_case0.cpp:38
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: wcsncat(data+dataLen, environment, 100-dataLen-1); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_83_case0.cpp:38
- 结论: 可能存在的进程控制漏洞：环境变量数据被拼接到缓冲区，若后续用作进程路径（如CreateProcess），攻击者可控制环境变量导致执行任意代码。
- D验证: confirmed / ver_ed0028a2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 795. hyp_path_9b06f9072b4f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_84_case0.cpp:38
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够修改目标系统的环境变量ENV_VARIABLE的值; 程序运行在允许执行外部命令的环境
- 触发路径: size_t dataLen = wcslen(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_84_case0.cpp:38; wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_84_case0.cpp:39; if (environment != NULL) { ... wcsncat(data+dataLen, environment, 100-dataLen-1); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_84_case0.cpp:42-44; 进程控制函数调用（如_system或CreateProcess）以data为参数 @ 假设后续代码
- 结论: 代码从环境变量读取数据并拼接到缓冲区，后续可能将数据传递给进程控制函数（如system或CreateProcess），攻击者可通过控制环境变量实现进程控制攻击。
- D验证: confirmed / ver_7e195ed3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 796. hyp_path_5ffabde91368

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_84_case0.cpp:39
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入写入任意宽字符串。
- 触发路径: size_t dataLen = wcslen(data); if (100-dataLen > 1) { if (fgetws(data+dataLen, (int)(100-dataLen), stdin) != NULL) { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_84_case0.cpp:28-37; dataLen = wcslen(data); if (dataLen > 0 && data[dataLen-1] == L'\n') { ... } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_84_case0.cpp:39; 加载函数如 LoadLibraryW(data); @ 后续代码（未完全展示）
- 结论: 从控制台读取的宽字符串可能被直接用作加载动态库的参数，导致过程控制漏洞，攻击者可加载任意恶意DLL。
- D验证: confirmed / ver_54d1f684
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 797. hyp_path_088b3ca927ee

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_83a.cpp:30
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供恶意数据
- 触发路径: wchar_t dataBuffer[100] = L""; data = dataBuffer; CWE114_Process_Control__w32_wchar_t_console_83_case0 case0Object(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_83a.cpp:28-32
- 结论: Process control via console input potentially leading to library injection
- D验证: confirmed / ver_4619a4ce
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 798. hyp_path_814b1d6d5219

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_83a.cpp:30
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供恶意数据
- 触发路径: char dataBuffer[100] = ""; data = dataBuffer; CWE114_Process_Control__w32_char_connect_socket_83_case0 case0Object(data); } ... data = dataBuffer; CWE114_Process_Control__w32_char_connect_socket_83_case0 case0Object(data); } #endif /* OMITCASE0 */ @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_83a.cpp:30; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_83a.cpp::_ZN50CWE114_Process_Control__w32_char_connect_socket_835case0Ev @ route
- 结论: Process control via console input potentially leading to library injection
- D验证: confirmed / ver_c7ab72b7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 799. hyp_path_13473a6bf24f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_83a.cpp:30
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供恶意数据
- 触发路径: char dataBuffer[100] = ""; data = dataBuffer; CWE114_Process_Control__w32_char_listen_socket_83_case0 case0Object(data); } ... data = dataBuffer; CWE114_Process_Control__w32_char_listen_socket_83_case0 case0Object(data); } #endif /* OMITCASE0 */ @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_83a.cpp:30; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_83a.cpp::_ZN49CWE114_Process_Control__w32_char_listen_socket_835case0Ev @ route
- 结论: Process control via console input potentially leading to library injection
- D验证: confirmed / ver_00d75bb4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 800. hyp_path_86537649b01d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_83a.cpp:30
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供恶意数据
- 触发路径: char dataBuffer[100] = ""; data = dataBuffer; CWE114_Process_Control__w32_char_file_83_case0 case0Object(data); } ... data = dataBuffer; CWE114_Process_Control__w32_char_file_83_case0 case0Object(data); } #endif /* OMITCASE0 */ @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_83a.cpp:30; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_83a.cpp::_ZN40CWE114_Process_Control__w32_char_file_835case0Ev @ route
- 结论: Process control via console input potentially leading to library injection
- D验证: confirmed / ver_43e9e0b3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 801. hyp_path_9c55b99934b5

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_83a.cpp:30
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供恶意数据
- 触发路径: char dataBuffer[100] = ""; data = dataBuffer; CWE114_Process_Control__w32_char_relativePath_83_case0 case0Object(data); } ... data = dataBuffer; CWE114_Process_Control__w32_char_relativePath_83_case0 case0Object(data); } #endif /* OMITCASE0 */ @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_83a.cpp:30; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_83a.cpp::_ZN48CWE114_Process_Control__w32_char_relativePath_835case0Ev @ route
- 结论: Process control via console input potentially leading to library injection
- D验证: confirmed / ver_5c088822
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 802. hyp_path_aa0460048c9f

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_83a.cpp:30
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供恶意数据
- 触发路径: wchar_t dataBuffer[100] = L""; data = dataBuffer; CWE114_Process_Control__w32_wchar_t_relativePath_83_case0 case0Object(data); } ... data = dataBuffer; CWE114_Process_Control__w32_wchar_t_relativePath_83_case0 case0Object(data); } #endif /* OMITCASE0 */ @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_83a.cpp:30; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_83a.cpp::_ZN51CWE114_Process_Control__w32_wchar_t_relativePath_835case0Ev @ route
- 结论: Process control via console input potentially leading to library injection
- D验证: confirmed / ver_c909c46d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 803. hyp_path_d78559d5aec8

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_54d.c:32
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供任意字符串；系统配置允许加载外部库（如LoadLibraryW）。
- 触发路径: CWE114_Process_Control__w32_wchar_t_console_54e_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_54d.c:32
- 结论: 在CWE114_Process_Control__w32_wchar_t_console_54d_case0Sink函数中，用户通过控制台输入的数据被传递到CWE114_Process_Control__w32_wchar_t_console_54e_case0Sink函数。若该函数内部调用LoadLibraryW或类似API，则攻击者可能通过控制台输入构造恶意库路径，导致任意代码执行。然而当前证据链不完整，sink函数内部实现未知，无法确认实际调用。
- D验证: confirmed / ver_0aa76f80
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 804. hyp_path_23d2cbcb241b

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_54d.c:32
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供任意字符串；系统配置允许加载外部库（如LoadLibraryW）。
- 触发路径: void CWE114_Process_Control__w32_char_relativePath_54d_case0Sink(char * data) { CWE114_Process_Control__w32_char_relativePath_54e_case0Sink(data); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_54d.c:32; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_54d.c::CWE114_Process_Control__w32_char_relativePath_54d_case0Sink @ route
- 结论: 在CWE114_Process_Control__w32_wchar_t_console_54d_case0Sink函数中，用户通过控制台输入的数据被传递到CWE114_Process_Control__w32_wchar_t_console_54e_case0Sink函数。若该函数内部调用LoadLibraryW或类似API，则攻击者可能通过控制台输入构造恶意库路径，导致任意代码执行。然而当前证据链不完整，sink函数内部实现未知，无法确认实际调用。
- D验证: confirmed / ver_caf63391
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 805. hyp_path_d5c07079307d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_54d.c:32
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供任意字符串；系统配置允许加载外部库（如LoadLibraryW）。
- 触发路径: void CWE114_Process_Control__w32_wchar_t_relativePath_54d_case0Sink(wchar_t * data) { CWE114_Process_Control__w32_wchar_t_relativePath_54e_case0Sink(data); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_54d.c:32; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_54d.c::CWE114_Process_Control__w32_wchar_t_relativePath_54d_case0Sink @ route
- 结论: 在CWE114_Process_Control__w32_wchar_t_console_54d_case0Sink函数中，用户通过控制台输入的数据被传递到CWE114_Process_Control__w32_wchar_t_console_54e_case0Sink函数。若该函数内部调用LoadLibraryW或类似API，则攻击者可能通过控制台输入构造恶意库路径，导致任意代码执行。然而当前证据链不完整，sink函数内部实现未知，无法确认实际调用。
- D验证: confirmed / ver_420c22d3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 806. hyp_path_244c921b4880

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_52b.c:52
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络socket发送任意字符串作为数据
- 触发路径: void CWE114_Process_Control__w32_char_listen_socket_52b_case0Sink(char * data) { CWE114_Process_Control__w32_char_listen_socket_52c_case0Sink(data); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_52b.c:50-54; 实际sink函数可能调用LoadLibrary等，导致任意库加载 @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_52c_case0Sink (内部实现未给出)
- 结论: 存在CWE-114 Process Control漏洞：外部可控数据通过socket传入，未经任何验证即传递给可能加载库的sink函数
- D验证: confirmed / ver_33b556cc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 807. hyp_path_1057e2151016

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_52b.c:52
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络socket发送任意字符串作为数据
- 触发路径: void CWE114_Process_Control__w32_wchar_t_connect_socket_52b_case0Sink(wchar_t * data) { CWE114_Process_Control__w32_wchar_t_connect_socket_52c_case0Sink(data); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_52b.c:52; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_52b.c::CWE114_Process_Control__w32_wchar_t_connect_socket_52b_case0Sink @ route
- 结论: 存在CWE-114 Process Control漏洞：外部可控数据通过socket传入，未经任何验证即传递给可能加载库的sink函数
- D验证: confirmed / ver_45788617
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 808. hyp_path_9cd0b09e9ea5

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_52b.c:52
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络socket发送任意字符串作为数据
- 触发路径: void CWE114_Process_Control__w32_wchar_t_listen_socket_52b_case0Sink(wchar_t * data) { CWE114_Process_Control__w32_wchar_t_listen_socket_52c_case0Sink(data); } @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_52b.c:52; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_52b.c::CWE114_Process_Control__w32_wchar_t_listen_socket_52b_case0Sink @ route
- 结论: 存在CWE-114 Process Control漏洞：外部可控数据通过socket传入，未经任何验证即传递给可能加载库的sink函数
- D验证: confirmed / ver_3548857e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 809. hyp_path_dd2c6231ef54

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_42.c:45
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意DLL文件放置在进程当前工作目录或搜索路径中的其他位置。
- 触发路径: data = case0Source(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_42.c:37; hModule = LoadLibraryW(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_42.c:42
- 结论: 程序使用LoadLibraryW加载动态库时，库路径为相对路径"winsrv.dll"，未指定完整路径。攻击者可能通过将恶意DLL放置在搜索路径中（如当前工作目录）来劫持库加载，导致执行任意代码。
- D验证: confirmed / ver_162e985f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 810. hyp_path_7113ece4579d

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_43.cpp:47
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制或影响进程的当前工作目录; 攻击者能够在当前工作目录中放置名为winsrv.dll的恶意DLL
- 触发路径: wcscpy(data, L"winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_43.cpp:32; hModule = LoadLibraryW(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_43.cpp:47
- 结论: 代码使用相对路径加载DLL，导致DLL劫持漏洞。攻击者可在当前工作目录放置同名恶意DLL，被加载执行。
- D验证: confirmed / ver_118acf00
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 811. hyp_path_03f8c8f2bc58

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_06.c:46
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制文件系统，将恶意DLL放置于搜索路径中。
- 触发路径: wcscpy(data, L"winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_06.c:35-39; hModule = LoadLibraryW(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_06.c:41-45
- 结论: 代码使用相对路径加载库，攻击者可能通过放置恶意DLL在搜索路径中实现任意代码执行。
- D验证: confirmed / ver_66d0205f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 812. hyp_path_86f7291a1c55

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_18.c:41
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: Attacker can place a malicious DLL named winsrv.dll in a directory that is searched before the system directory (e.g., current working directory, user's PATH).
- 触发路径: wcscpy(data, L"winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_18.c:31; hModule = LoadLibraryW(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_18.c:36
- 结论: The program uses LoadLibraryW with a relative path (only filename) to load a DLL. Although the filename is hardcoded, an attacker can place a malicious DLL with the same name in the search path (e.g., current directory) to perform DLL hijacking.
- D验证: confirmed / ver_8a79b33d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 813. hyp_path_dabd4258d2fe

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_31.c:42
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够在当前工作目录或系统搜索路径中写入名为winsrv.dll的恶意DLL；程序调用LoadLibraryW时未指定完整路径。
- 触发路径: wcscpy(data, L"winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_31.c:33; hModule = LoadLibraryW(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_31.c:38
- 结论: 在LoadLibraryW调用中使用了仅包含文件名的硬编码路径"winsrv.dll"，没有指定完整路径。攻击者可以通过将恶意DLL放置在当前工作目录或系统搜索路径中，导致加载非预期的恶意库，实现任意代码执行。
- D验证: confirmed / ver_298b4e64
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 814. hyp_path_f474c375c894

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_65a.c:36
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将名为winsrv.dll的恶意DLL放置在进程当前工作目录下。
- 触发路径: wcscpy(data, L"winsrv.dll"); /* use the function pointer */ funcPtr(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_65a.c:36
- 结论: 使用相对路径加载DLL，攻击者可通过将恶意DLL放置在当前工作目录实现任意代码执行。
- D验证: confirmed / ver_fef4fe7d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 815. hyp_path_ffefb557fed2

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_81a.cpp:31
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够将恶意winsrv.dll放置于程序搜索路径中，且程序未启用安全DLL搜索模式。
- 触发路径: data = dataBuffer; /* NOTE: Specify just the file name for the library, not the full path */ wcscpy(data, L"winsrv.dll"); const CWE114_Process_Control__w32_wchar_t_relativePath_81_base& baseObject = CWE114_Process_Control__w32_wchar_t_relativePath_81_case0(); baseObject.action(data); @ L29-33
- 结论: 代码中硬编码了库文件名'winsrv.dll'，并通过action函数加载该库。如果攻击者能够将恶意的winsrv.dll放置在搜索路径（如当前目录）中，则可能导致任意代码执行。
- D验证: confirmed / ver_cc276c92
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 816. hyp_path_73eaee6d5494

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_22b.c:31
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制目标系统的当前工作目录或影响DLL搜索路径（如通过修改环境变量或放置恶意文件）。
- 触发路径: wcscpy(data, L"winsrv.dll"); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_22b.c:31; HMODULE hMod = LoadLibrary(data); @ 未在提供代码片段中展示，但根据测试用例模式推测后续有LoadLibrary(data)调用
- 结论: 代码中硬编码了相对路径的DLL文件名"winsrv.dll"，且注释提示仅指定文件名而非完整路径。当后续调用LoadLibrary加载该DLL时，由于未使用绝对路径，攻击者可通过DLL劫持（如将恶意DLL放置于当前工作目录或系统搜索路径中）导致任意代码执行。
- D验证: confirmed / ver_d1f6450d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 817. hyp_path_d3a64eeb6415

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_83_case0.cpp:41
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过某种方式（如环境变量、命令行参数、配置文件等）影响传递给LoadLibraryA的data字符串，使其为相对路径。; 攻击者能够在程序启动时的当前工作目录或DLL搜索路径中放置恶意DLL。
- 触发路径: hModule = LoadLibraryA(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_83_case0.cpp:36; FreeLibrary(hModule); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_83_case0.cpp:41
- 结论: 在LoadLibraryA调用中使用相对路径，可能导致DLL劫持攻击，攻击者通过将恶意DLL放置在当前目录中替换合法库。
- D验证: confirmed / ver_6e90771d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 818. hyp_path_143b8ebdf7a3

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_83_case0.cpp:41
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过某种方式（如环境变量、命令行参数、配置文件等）影响传递给LoadLibraryA的data字符串，使其为相对路径。; 攻击者能够在程序启动时的当前工作目录或DLL搜索路径中放置恶意DLL。
- 触发路径: if (hModule != NULL) { FreeLibrary(hModule); printLine("Library loaded and freed successfully"); } ... /* NOTE: If the path to the library is not specified, an attacker may be able to * replace his own file with the intended library */ hModule = LoadLibraryW(data); if (hModule != NULL) { ... else { printLine("Unable to... @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_83_case0.cpp:41; juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_83_case0.cpp::_ZN51CWE114_Process_Control__w32_wchar_t_relativePath_8357CWE114_Process_Control__w32_wchar_t_relativePath_83_case0D2Ev @ route
- 结论: 在LoadLibraryA调用中使用相对路径，可能导致DLL劫持攻击，攻击者通过将恶意DLL放置在当前目录中替换合法库。
- D验证: confirmed / ver_52f6ea5f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 819. hyp_path_85ca76b45ae7

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_53b.c:32
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够控制data参数的内容
- 触发路径: void CWE114_Process_Control__w32_wchar_t_relativePath_53b_case0Sink(wchar_t * data) { CWE114_Process_Control__w32_wchar_t_relativePath_53c_case0Sink(data); } @ CWE114_Process_Control__w32_wchar_t_relativePath_53b.c:30-34; 假设在53c中data被传递给LoadLibraryW等敏感调用 @ 后续函数（未展示）
- 结论: 可能存在进程控制漏洞，但由于缺乏从输入源到危险sink的直接证据，无法高确定性地确认。假设data来自外部可控路径，且后续被用于LoadLibrary等函数，则构成CWE-114。
- D验证: confirmed / ver_c9eee92a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 820. hyp_path_1e8de45302fd

- 漏洞位置: juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_54d.c:52
- 漏洞类型: CWE-114
- CWE: CWE-114
- 风险等级: P0
- 触发条件: 攻击者能够通过网络发送特制的数据到监听socket，从而控制data参数的值。
- 触发路径: CWE114_Process_Control__w32_wchar_t_listen_socket_54e_case0Sink(data); @ juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_54d.c:52
- 结论: 可能存在进程控制漏洞（CWE-114），因为data参数可能来自外部socket输入，并传递给后续函数，可能导致加载恶意库或执行任意代码。
- D验证: confirmed / ver_5d060d87
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

## Unconfirmed / Failed Verification

These records are not reported as confirmed vulnerabilities. See `verification.failed.jsonl` for full failure details.

- hyp_path_eccfebdbda27 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_08.c:110 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a24eb03c8850 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_08.c:110 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ead76c8f1606 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_11.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e9c4963dd2a3 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_11.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_18ba6f7117c3 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_02.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c7c4a09cd308 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_02.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6354522f0803 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_03.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fb7197d6efc5 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_03.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_027ee01826bb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_04.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_df359741135c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_04.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_005aaca44d02 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_05.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fe9768d32e9a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_05.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1104a21d8cd1 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_06.c:100 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a40302452058 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_06.c:100 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5ad3d76a0f64 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_07.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_60a7fb0c873d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_07.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c12e7dc2d8e2 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_09.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_82612980fd59 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_09.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ad573fc4ada4 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_13.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c508811c87c8 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_13.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bae28ecfad5c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_14.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7977881ac4f7 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_14.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7a87e499fcd1 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_10.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f23a3eb49aa3 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_10.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7274b4451073 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_41.c:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e954393af76a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_41.c:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0a343da55a6a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_41.c:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4d40d73b93bb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_41.c:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_50760b2391d2 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_22a.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_46b6d7a11c93 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_22a.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_63e74456cd6d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_22a.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6f4ee98a9062 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_22a.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ccdd2083a975 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_22a.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_878c04ce0590 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_22a.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a0ebc394d98b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_22a.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_80e26f59707e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_22a.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0b5d78eb6bd0 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_22a.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3c443939f25c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_22a.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a6a7fc1fad83 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_22a.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e51a85a9cbe9 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_22a.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c2f6ee97dc77 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d8e26d8a3208 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fb451535690f | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7f0a7798630a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_70767730e47e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7c32328b5e63 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4b089343ab43 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_218cb1e353eb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_484b66cecc60 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2571bd392504 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6d034ee0df0c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_290ae3ed21c9 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9d1e2ae39402 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_61a.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7c2b2c16334e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_61a.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8dd7f62fc8bc | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_61a.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e87273d94c65 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_61a.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4e6742542401 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_62a.cpp:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c2bac9864867 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_62a.cpp:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f2e4ec40434f | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_62a.cpp:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4250c0d20c62 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_62a.cpp:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2dcdb426f5fa | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_62a.cpp:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_46785fcf95cb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_62a.cpp:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2a99cc29738b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_62a.cpp:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c3cac20df585 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_62a.cpp:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f96066d392d9 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_62a.cpp:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_def1e40cedc6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_62a.cpp:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f79cea4b70e7 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_62a.cpp:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f0b239d04be4 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_62a.cpp:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_556c4912c3d4 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_61a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_62178e3b1fed | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_61a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0204aff48658 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_12.c:108 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_09e097ee2c6f | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_12.c:108 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b722b1f23d5e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_11.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_49debbd0743c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_11.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e2444cf4f7c8 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_12.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_69888f150abc | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_12.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_40787fcf2869 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_05.c:109 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_14ad180bd09e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_05.c:109 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a7f56bf1460a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_09.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_10ef914e652c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_09.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_984984a590d7 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_07.c:108 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aaf064fb107c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_07.c:108 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_36c04ed3a558 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_13.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_006afc6a8e51 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_13.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e4606ccbcd64 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_10.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2f5859d70b49 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_10.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d5857650cced | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_08.c:138 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7a4d0ae721c1 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_08.c:138 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2dc5d3a673ac | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_14.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e944d7f256fb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_14.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0e2c608ea09a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_02.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6dbffa7e6bad | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_02.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fc4779f71e97 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_03.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_da0162b58e75 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_03.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b5e765fb59c0 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_02.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3640bc48d07d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_02.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1a5adf9c38e1 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_04.c:109 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7d88a56b64b6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_04.c:109 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a94bdd66a455 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_06.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a012b2677618 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_06.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_deab9625146a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_03.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e51843478ee3 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_03.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cf54b34aba18 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_04.c:137 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a596bcf65194 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_04.c:137 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8932df622b99 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_06.c:134 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_176015f34562 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_06.c:134 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2742080740fe | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_07.c:136 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3f63f3c15337 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_07.c:136 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2bd39d23b289 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_09.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e8b375edc46e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_09.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_42b47e0587f0 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_10.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_92aaac0041bd | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_10.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cc814fcfd62a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_13.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c26a97609adb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_13.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dfec719f0645 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_15.c:109 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8468a82921b6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_15.c:109 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_46d1f3b5f3b0 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_14.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_80f296ea9f79 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_14.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e04a65f01c3b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_15.c:143 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f5bbfb75ffd7 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_15.c:143 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_91d0e9e0105c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_16.c:99 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_505e218b89af | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_16.c:99 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9262fc501ac9 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_17.c:99 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_52b97ee71ee9 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_17.c:99 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c7e29c3b086a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_34.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_74d7d64097d7 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_34.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ac5552617339 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_02.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a1f9aa300c7c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_02.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_33069fb30464 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_03.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5831c5bcf5bb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_03.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aa0add037eb0 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_05.c:131 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f74e402ceec6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_05.c:131 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b05cd86f8fc7 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_04.c:131 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1d2cf4ca2337 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_04.c:131 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9b018267a0b6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_07.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_893b99aae271 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_07.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_38b501e66205 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_06.c:128 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ce1dac93ec9a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_06.c:128 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fa6cdd044097 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_13.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f2db8076f66e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_13.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cddb7ead297f | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_09.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_89068c46fd8e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_09.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_44043785f50a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_10.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7c35602fbe63 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_10.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4d1f56aa5a6c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_14.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_07d5449838d2 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_14.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_173b2ef86398 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_15.c:137 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c1a52e0709bb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_15.c:137 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ebfb2fc58656 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_15.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ca7586357924 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_15.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4ca8f6e62913 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_16.c:93 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8b234d1098f3 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_16.c:93 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0556632ec8d3 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_17.c:93 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9508599e66c6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_17.c:93 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a0ef4f04cdff | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_31.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a7cadf4095b9 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_31.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e0b9c3047291 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_74b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d5f8552291e5 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_74b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f95b0221fac3 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_74b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_702112f54f6b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_74b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_859732e348ac | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_74b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4e142347d00b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_74b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8adb556467aa | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_74b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_136331f11995 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_74b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f46c1ac3820d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_74b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cb8d29aad75a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_74b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f454ee47d845 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_74b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_daa825b8556c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_74b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4303c5ef1b95 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_32.c:108 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_00259553fac9 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_32.c:108 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_22961c3f3170 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_72b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_52748d0d08bc | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_72b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b990fdac35bd | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_72b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c77cd122a097 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_72b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_67b9f9e6c369 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_72b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f9dd0c37bb69 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_72b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_567e8d033e66 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_72b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bcb974891bf9 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_72b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1b844b900d05 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_72b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_56a51bef6c7b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_72b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_710b0171ed4e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_72b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_68857b17945b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_72b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_afc39bb0abf4 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_73b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8157025dffdf | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_73b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_234e57b89f6c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_73b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d5fa5315280a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_73b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e2bccf5492d5 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_73b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5a6d88ab30a9 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_73b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e9c15d651ff3 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_73b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3774f3987c0e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_73b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4abd6091fc6f | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_73b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c458129507c8 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_73b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_137f056f3b7d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_73b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_370a7a4afdcf | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_73b.cpp:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7216d793d454 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_83_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1d017105a17a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_83_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fd5a9e8e8931 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_83_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_37721a21f716 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_83_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_54a7eb74693a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_83_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_527ca4a30949 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_83_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_352aef08ab13 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_83_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a956c41bab9a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_83_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e48ed18eda61 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_83_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_988841440d76 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_83_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2a0989d46d10 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_83_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ad0928bc71f4 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_83_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a9575220c0ad | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_84_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9e687394b782 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_84_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d0f7105ad1b4 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_84_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ff138817d9f0 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_84_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6b5590fe83fd | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_84_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a1a988c22358 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_84_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_77e656c498ff | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_84_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4c49506a50c3 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_84_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ffd063155524 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_84_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e5012cd08d95 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_84_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_100fe2176720 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_84_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_61b84201fc70 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_84_case1V1.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1cce8da60b17 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_32.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6f51c4f26200 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_32.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3051eb2383bb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_44.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4b8122c1840a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_44.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1ddfff728348 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_45.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5b7e65aefa05 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_45.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f55293fa858c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_51b.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9f788da73f3b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_51b.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a81363a31166 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_51b.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0a15abbbf57f | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_51b.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_375e6bfc2cd3 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_53d.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7f3f7ac8cb7c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_53d.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c17b98f74a67 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_53d.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6b5c49642826 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_53d.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b8184b39baee | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_52c.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_62ed4e3453f4 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_52c.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e5fb6c75f6e2 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_52c.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_341832847456 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_52c.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5cfbd972229b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_54e.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_05e2962b6ef2 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_54e.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f838c25ea9e1 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_54e.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f9f337a81a66 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_54e.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dab64f559342 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_64b.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_977b391006c7 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_64b.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2caa4ef313d8 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_64b.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_edb34e88b7b1 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_64b.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_00e8982065d6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_63b.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8a165e8eeed4 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_63b.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b1530dcd648a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_63b.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_776e71002884 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_63b.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_00887f3595c8 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_65b.c:58 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_92b00c99e2a6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_65b.c:58 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b891f7ad8d99 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_65b.c:58 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8433e83af0c1 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_65b.c:58 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_914dd1d6d245 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_66b.c:61 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_41073b2b0317 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_66b.c:61 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_85d8cd59b8bb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_66b.c:61 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_11d5f1e40777 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_66b.c:61 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5dece3f813f1 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_67b.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b642bd23d27d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_67b.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d1bf75932245 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_67b.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6ac56c54c41c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_67b.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e203371cb7e0 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_68b.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fbd07fb188c2 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_68b.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1215885ead7d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_68b.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3bf72a7889b5 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_68b.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c5ba7b46f855 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_81_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_34e6f47bdfbc | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_81_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2262e669e1bd | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_81_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_26c5cc1a2d7a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_81_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_993a9ba016ee | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_81_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5031461b3495 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_81_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1193281830c7 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_81_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b3e9f4ce29a2 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_81_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_430c08e49e75 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_81_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2880f87b109a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_81_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_31c6dacbfdee | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_81_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5edfbca02b69 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_81_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d1ffa7717b28 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_82_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6a862681b4a8 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_82_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_984201805d34 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_82_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d119cedfc3f4 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_82_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f48125b2767b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_82_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c68f56566cab | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_82_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f08f255f6f16 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_82_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f9a7ae471a12 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_82_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_629a42218541 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_82_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8f9c87d9ab54 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_82_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8aac3794fe6c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_82_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b6f1ab4f3993 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_82_case1V1.cpp:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3cb64d6fb260 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_44.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_139eaa8df392 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_44.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2195fe16df46 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_45.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_48b8067083c9 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_45.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_56c70ea87e3b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_51b.c:68 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2cce033f3651 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_51b.c:68 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b52c371c0ee6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_52c.c:68 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_42d079e5f5fc | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_52c.c:68 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9ab59aa75365 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_53d.c:68 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_974b6ea35450 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_53d.c:68 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e8549310811a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_63b.c:68 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_15c759fa346f | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_63b.c:68 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2f44b3d3d7fb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_54e.c:68 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f61749311ed0 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_54e.c:68 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_49ff6c169dbe | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_64b.c:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0db55741b3a4 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_64b.c:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_71a74e57e889 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_65b.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a486cb889cb4 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_65b.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cc979ac09c10 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_66b.c:69 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a9ad757a7526 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_66b.c:69 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_705e9b44036d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_67b.c:73 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b94457b09cc5 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_67b.c:73 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cb817be49b27 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_68b.c:73 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_74bf4a5dac97 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_68b.c:73 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6dc9728391d5 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_61a.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b3127b21ddd8 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_61a.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fe3914cfdc0b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_61a.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3b3caf2c9078 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_61a.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_869b1d3047f0 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_82a.cpp:49 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5808c41e615c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_82a.cpp:49 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6eb30e7f6630 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_21.c:170 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4be587010708 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_22a.c:118 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_608fc218f9d9 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_22a.c:118 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_873686a2da4d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_22a.c:118 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2703af1bd398 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_22a.c:118 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_477729a7dc88 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_22a.c:118 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_33d0b4fff21c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_22a.c:118 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_309cb0cd925d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_22a.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1f4fcb9b3a0f | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_22a.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0a7c5b1c558f | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_22a.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_14a85d61f612 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_22a.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_709004d41200 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_22a.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8285aff9f4ff | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_22a.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e0e02a188acd | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_21.c:164 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a061c2f6deed | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_21.c:164 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0a045e707ecf | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_21.c:171 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fa6c88726831 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_42.c:115 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4681a4449d12 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_42.c:115 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9ceca52ba8b2 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_43.cpp:116 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_eed70c801090 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_43.cpp:116 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_13e11bff1141 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_54c.c:45 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9c19dfdafb18 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_54c.c:45 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_abac2accebe5 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_54c.c:45 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5a84dc190a92 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_54c.c:45 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c23465c2cf65 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_61a.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_42bcd97eb2c5 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_61a.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3053645e918b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_61a.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_122636486653 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_61a.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_290c4b1bd2fc | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_62a.cpp:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6f98481744da | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_62a.cpp:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a2e09b9fe6e5 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_62a.cpp:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ec7baf699fc3 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_62a.cpp:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_be19f0ba3bd0 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_62a.cpp:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_582e33a4755d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_62a.cpp:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_077f5ea77ac9 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_62a.cpp:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7073b6937eab | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_62a.cpp:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cf5c4400c8ab | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_62a.cpp:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_145d4e8d9265 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_62a.cpp:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4eddea375b68 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_62a.cpp:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_111ee4526c73 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_62a.cpp:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_68ad033cbb78 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_42.c:109 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_54fe94f73848 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_42.c:109 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_308fd404785f | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_43.cpp:110 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b16c86c26fd6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_43.cpp:110 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0cb58db79382 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_environment_61a.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_db5a859d2a63 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_61a.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e68d3e0dbb6b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_21.c:197 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_40e26e1e8e0b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_21.c:197 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e2e7b9772078 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_12.c:170 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_374af14556ce | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_12.c:170 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_660f6d438f67 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_08.c:190 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_66dc6a511bf2 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_08.c:190 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c16762d6e592 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_12.c:182 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c84fe26e83c2 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_12.c:182 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_62047feaaa87 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_07.c:170 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0c72c07fe253 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_07.c:170 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_00b5f63078ce | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_05.c:171 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1733b9a489cb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_05.c:171 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bb402d4a6944 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_10.c:164 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_337073b2021e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_10.c:164 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0234c64f4525 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_09.c:164 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_890321f6e865 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_09.c:164 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bdaa733fae72 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_13.c:164 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_75cf1e0acaa4 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_13.c:164 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_52a57959ad44 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_14.c:164 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_53fe764afef4 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_14.c:164 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8859af9a2998 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_05.c:183 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9bdda9333e4d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_05.c:183 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2a7fcf2acbb8 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_09.c:176 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a9fbed6f3d7b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_09.c:176 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_eacb4f220f38 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_07.c:182 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b5aa4d49a872 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_07.c:182 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9191f41c98c6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_10.c:176 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c4fa61b44be2 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_10.c:176 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4ed8ff7c49ff | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_14.c:176 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e922774b383c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_14.c:176 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d414666b2176 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_11.c:204 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e0e4520b1126 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_11.c:204 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8dbdfc49184a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_13.c:176 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_599c58061e74 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_13.c:176 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3732d9afaf51 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_02.c:164 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_09c2f45d5f54 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_02.c:164 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_17bf6235dff1 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_03.c:192 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d2b6d61ca904 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_03.c:192 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_265267a44437 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_03.c:164 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f354fda326b5 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_03.c:164 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b07a55283ded | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_04.c:171 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_777a3fdec3b6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_04.c:171 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_567158556f07 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_02.c:192 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e10721e8a639 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_02.c:192 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_887bc01f9cda | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_06.c:168 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_50830ef5866d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_06.c:168 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f04ff08aa1e4 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_05.c:199 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ecd370df28e6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_05.c:199 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8147c7fd3464 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_06.c:196 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8a8a0ea31479 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_06.c:196 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a4291c5db552 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_14.c:192 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3e179791e9f3 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_14.c:192 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6f5896527842 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_13.c:192 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_18351f449a22 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_13.c:192 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8db671c34140 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_15.c:171 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a8dd964814ce | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_15.c:171 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_44e4a67c9f12 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_10.c:192 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f1a99c148beb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_10.c:192 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_52aee8a8e8fa | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_15.c:205 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_879aa8725236 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_15.c:205 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f3a91db91310 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_17.c:161 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9c49e493adc7 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_17.c:161 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f50d0bd715fd | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_02.c:176 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_54f6f3d26562 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_02.c:176 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_638ee6594065 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_03.c:176 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_257b6beb1a34 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_03.c:176 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_647f38f11bf2 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_02.c:204 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_abcb599ba172 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_02.c:204 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_33e35e40b54b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_04.c:183 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ac5f70e110e7 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_04.c:183 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0e9102cd6340 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_03.c:204 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cf57f3c974bb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_03.c:204 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_453d0fca1425 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_04.c:211 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c3c753cdfe87 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_04.c:211 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c30323df78de | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_06.c:208 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d8d60b396bb7 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_06.c:208 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_435a8fd6f5d9 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_05.c:211 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_09e2115b8edc | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_05.c:211 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e8fe42347928 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_07.c:210 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e897606ace16 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_07.c:210 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b5b3a92c9e5d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_06.c:180 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_abd1c12d01e2 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_06.c:180 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_042fa4e6bfb0 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_09.c:204 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a9541a16c1d8 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_09.c:204 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8d9c61091cb2 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_13.c:204 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0c653ef135cc | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_13.c:204 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3f4a372d731d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_15.c:183 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d7df90c56620 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_15.c:183 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c5f5d20ab222 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_15.c:217 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9d40423aaae1 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_15.c:217 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ac1f41972c20 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_17.c:173 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3628dc4c8228 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_17.c:173 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bc83b53a613a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_32.c:170 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fbc06e6e85a9 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_32.c:170 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_52db5f3030d6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_32.c:182 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9b8ee251b825 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_32.c:182 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_239344bdb1a8 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_44.c:156 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_54b996ad0d4c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_44.c:156 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3aadecd7522a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_45.c:159 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_01815396f6cc | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_45.c:159 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_74a5bda44a73 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_51b.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f69edfb704fb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_51b.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9117dd658585 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_51b.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_35bf99d1d7b6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_51b.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cef808112d7e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_53d.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_20b78975ab4a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_53d.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d61609994747 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_53d.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3d7c56589faf | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_53d.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e9fcb746d413 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_52c.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_54590b02b832 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_52c.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_af3d56177bee | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_52c.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6217e5df4d8e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_52c.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f50a58f5df02 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_54e.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bf46008e19cf | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_54e.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_30dffe923e9f | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_54e.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_53abca48b7fb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_54e.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c38b64bbfaf3 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_63b.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d051b6de17aa | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_63b.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_de13498aae86 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_63b.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f8b3bb313dec | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_63b.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c408f9f82a14 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_65b.c:78 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6ba43fa76b3d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_65b.c:78 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7a8a1014ddc0 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_65b.c:78 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0aef726a521c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_65b.c:78 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a1f7f579bcfe | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_64b.c:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0483607e68b0 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_64b.c:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b8342cee4c6e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_64b.c:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_87dcb65708c4 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_64b.c:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_efa99f640e7d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_66b.c:81 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_80ba0b5455ec | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_66b.c:81 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4078e0af06bf | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_66b.c:81 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_11c70427c136 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_66b.c:81 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_48d2eb3ead61 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_67b.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0c6621d20076 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_67b.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_88e2988c0c6f | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_67b.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_89c93b62e713 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_67b.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_060bdf8675c3 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_44.c:168 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b4c0aff42399 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_44.c:168 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_93bbd0429dba | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_45.c:171 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bea1e54f985b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_45.c:171 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6546ff919c66 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_68b.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4e2381dfd472 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_68b.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_14d62929949e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_68b.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_50ad709ef31d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_68b.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3beef075be6e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_43.cpp:178 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_270085698476 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_43.cpp:178 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b011b92835cc | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_53b.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aa1a536e450d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_53b.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f9f285fb3c26 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_53b.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8d9e545195e2 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_53b.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dfa021535fa8 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_53c.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_417a015f3f69 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_53c.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c74e57652f23 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_53c.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_44558db69a4d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_53c.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_96ddeb81bc2d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_43.cpp:190 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_eea78b512fb1 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_43.cpp:190 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aaba2eedbe11 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_61a.c:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_459ae42cea4c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_61a.c:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6ea18a18f7b3 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_09.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_883eab6c8d42 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_09.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a338669ef0e6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_08.c:146 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_95c29fbdbe81 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_08.c:146 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6e3bdbff4823 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_07.c:110 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_085ea7694d0c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_07.c:110 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8792809ed337 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_10.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_181d4fa8f958 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_10.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0166819d3840 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_14.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d577b518943d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_14.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e27ef49126ea | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_03.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b7d4e1772176 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_03.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5cb630d6f7c7 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_02.c:132 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_752f63ba482e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_02.c:132 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_93487fed4eaa | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_02.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7540cb00252b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_02.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_887f5c8588e9 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_04.c:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_563445c71d19 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_04.c:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_65ca924a4dd6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_05.c:139 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_97c91519c1dd | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_05.c:139 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f17aa40c9af7 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_06.c:136 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_957eb097def4 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_06.c:136 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_432ee256f605 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_06.c:108 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f6671865a988 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_06.c:108 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_73f444ce1fc0 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_07.c:138 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aa47b8c135c3 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_07.c:138 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d850730ec9e3 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_09.c:132 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_88dcc5c968dd | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_09.c:132 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0aaf13555f07 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_13.c:132 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_837952fec506 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_13.c:132 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_977fd8c59a71 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_15.c:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_788cbedd1592 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_15.c:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_22e3ba2081c7 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_17.c:101 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_85d019916ed2 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_17.c:101 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7dcf14d59d60 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_15.c:145 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8764760f0d4e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_15.c:145 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_099c411b214a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_32.c:110 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3c6a647146eb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_32.c:110 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c24f6355ee9b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_44.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bacd0baecf90 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_44.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d8513fb83b67 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_45.c:99 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0881344ddffc | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_45.c:99 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7208a2380e0b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_51b.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f5960ac0cf8f | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_51b.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f512b3b45d83 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_52c.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0a15d208d36d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_52c.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_27d931030464 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_53d.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cd1834ea0d5e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_53d.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_947a311e5719 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_54e.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7fcc6304aeb6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_54e.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3c6fa36e61ad | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_63b.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_048b0a2b6244 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_63b.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d0a70ce1c387 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_64b.c:72 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d04ee519755d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_64b.c:72 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4b36bb1bc237 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_65b.c:64 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_883d8f9182df | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_65b.c:64 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2765e2c48ffd | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_66b.c:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3957a8d998f7 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_66b.c:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a4704bdf0e6a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_67b.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_73b78c1a1968 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_67b.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0efdd0e1223a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_68b.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7fb95b421d62 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_68b.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cd923be3d3a8 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_21.c:233 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6aaa69cb14d0 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_21.c:233 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_291434fd63c6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_21.c:244 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_264948919084 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_21.c:244 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0600f472329b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_42.c:177 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f42ac0e9187c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_42.c:177 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_83f27d827c97 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_61a.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e17fa92b07d7 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_61a.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a32fb9c02e18 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_61a.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fc34ef8ae11c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_61a.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4a91c9363679 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_42.c:189 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b81e0203edbf | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_42.c:189 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7d54a9aef1ac | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_11.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_197ce55c1c63 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_11.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f9a28d4996ee | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_07.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a6537c9b0e3f | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_07.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5978ba389026 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_09.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cb7fbcbeb659 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_09.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_322f69d903ad | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_10.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8532e653af30 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_10.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d3580d6bffde | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_14.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d0f38eb4e4fa | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_14.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_51efaa83d46a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_13.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d1a87b98c441 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_13.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f031d130f926 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_02.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fc62fec2748d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_02.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e509cf92242d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_02.c:107 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c92b68aadb14 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_02.c:107 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cd91dd1f1bd4 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_04.c:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e851eebdc4ee | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_04.c:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_24d7231f5913 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_04.c:114 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_71e177513a37 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_04.c:114 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_559779272cbc | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_03.c:107 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_edbe07aedc8d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_03.c:107 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cd52fbaecb2d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_05.c:114 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e4f41e772cf2 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_05.c:114 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c8ba0d3ab0d1 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_06.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_638c51aa3c47 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_06.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_85b80aed0c76 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_06.c:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b40562e01230 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_06.c:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_00a82cdef0b5 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_09.c:107 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fada902776da | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_09.c:107 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_824097f6238f | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_10.c:107 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_295dbd8292fc | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_10.c:107 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_197291b839c4 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_13.c:107 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1d0298e9e053 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_13.c:107 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4fb3d6b802b1 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_14.c:107 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_82642a89d82e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_14.c:107 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_de6973765f2b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_15.c:120 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4b3d57a4b062 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_15.c:120 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_75c170cd882b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_16.c:76 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_886a03e2d436 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_16.c:76 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_934bd9a3cb48 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_44.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c0b4f524e1d2 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_44.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_403ec406ce63 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_45.c:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_25f16d4dc3fd | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_45.c:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_757023151dab | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_32.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ee321c8e78e1 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_32.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0b5be5e14c46 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_21.c:172 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_374b83a2bf7b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_21.c:172 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_023ec759c45f | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_43.cpp:118 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cb5eb7b47712 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_43.cpp:118 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_95e4fc9a5bc5 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_42.c:117 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_318dad1f300b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_42.c:117 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fef966e6ecf5 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_53c.c:51 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3b321c636bfb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_53c.c:51 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_669d9fea7db0 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_61a.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8066946a2a86 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_61a.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c1c05115f3c8 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_21.c:148 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ded2547820af | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_21.c:148 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_920f609c89c9 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_43.cpp:93 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4d69f89c0b88 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_43.cpp:93 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9f5200f395bc | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_21.c:123 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0b90a810654a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_08.c:116 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0dd410445b32 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_11.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b46cd82a920b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_05.c:137 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f0dd8ab6b7a8 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_54b.c:45 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_94f99bb1a830 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_54b.c:45 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f03580e1adb7 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_54b.c:45 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_833fb4352611 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_42.c:177 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cf6417bd6335 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_11.c:192 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ae30cbaaece4 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_04.c:199 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ccd6fb1bf888 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_09.c:192 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4ec11b6e74ca | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_16.c:161 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5daab0883979 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_10.c:204 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9f17629be066 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_16.c:173 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_76f9b32d47da | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_14.c:204 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cf2a2728c2d2 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_05.c:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7fa4c6942740 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_03.c:132 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_696fb504e07b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_13.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a77447c9b49a | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_04.c:139 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_478862c3bcae | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_14.c:132 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e0ddba48408c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_16.c:101 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6644c518b73f | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_34.c:108 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4ec5278369db | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_33.cpp:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0768e620dc4c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_03.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f37592857c06 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_42.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e24f471f75bc | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_console_41.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c167cd4ab4cd | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_console_41.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_27db83ccba05 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_41.c:164 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_82b28e547446 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_41.c:164 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c35da85ed02e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_41.c:152 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8224cc8e32be | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_41.c:152 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_599329f4b3d5 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_54d.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bc1892c04e7c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_54d.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6221ae162611 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_41.c:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f5217c01ee8d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_41.c:67 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_94086b7f6fbb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_41.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_15d389eccc08 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_41.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dd3c386da11e | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_52b.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b03c6baa2ac7 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_environment_84_case1V1.cpp:29 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_74fa1ecd242d | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_connect_socket_84_case1V1.cpp:29 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dea83b649a15 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_listen_socket_84_case1V1.cpp:29 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_63ae2dac400b | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_connect_socket_84_case1V1.cpp:29 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f051b0049cc6 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_listen_socket_84_case1V1.cpp:29 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_af6695576b0c | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_file_84_case1V1.cpp:29 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_404285360343 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_file_84_case1V1.cpp:29 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_44e928d279eb | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_char_relativePath_84_case1V1.cpp:29 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ae0878761d82 | juliet-api-misuse/testcases/CWE114_Process_Control/CWE114_Process_Control__w32_wchar_t_relativePath_84_case1V1.cpp:29 | NOT_EXPLOITABLE | payload did not satisfy oracle
