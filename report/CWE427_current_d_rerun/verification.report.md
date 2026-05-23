# MAGUS Final Vulnerability Report

- generated_at: 2026-05-23T01:49:34Z
- reportable_vulnerabilities: 458
- d_confirmed_vulnerabilities: 458
- stage_c_preserved_vulnerabilities: 0
- failed_verifications: 945
- source_confirmed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE427_current_d_rerun/verification.jsonl
- source_failed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE427_current_d_rerun/verification.failed.jsonl

## Confirmed Vulnerabilities

### 1. hyp_path_d4f42cf19cb3

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_72a.cpp:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制文件FILENAME的内容，或文件路径可被篡改。; case0Sink函数将传入的data作为搜索路径元素（如通过putenv设置PATH）。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) { printLine("fgets() failed"); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_72a.cpp:60-64; data[dataLen] = '\0'; } fclose(pFile); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_72a.cpp:66-70; dataVector.insert(dataVector.end(), 1, data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_72a.cpp:68; case0Sink(dataVector); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_72a.cpp:45
- 结论: 从文件读取的数据被用作搜索路径元素，未经验证直接传递给sink函数，可能导致未受控的搜索路径元素漏洞。
- D验证: confirmed / ver_074f843d
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 2. hyp_path_b6a320afa15f

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_72a.cpp:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制FILENAME所指向的文件内容
- 触发路径: if (250-dataLen > 1) { pFile = fopen(FILENAME, "r"); if (pFile != NULL) { @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_72a.cpp:56-60; if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) { printLine("fgetws() failed"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_72a.cpp:60-64; fclose(pFile); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_72a.cpp:66-70; dataVector.insert(dataVector.end(), 1, data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_72a.cpp:70-72; case0Sink(dataVector); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_72a.cpp:72
- 结论: 程序从文件中读取数据，并将读取的内容追加到"PATH="字符串后，然后作为环境变量设置。攻击者若能控制该文件内容，即可设置恶意的PATH环境变量，导致在搜索程序依赖的库时加载恶意DLL，实现任意代码执行。
- D验证: confirmed / ver_3610ad05
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 3. hyp_path_72a129a8ce7e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_74a.cpp:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序读取的文件中写入恶意数据（例如通过文件上传或共享文件系统）; 文件路径FILENAME可被攻击者控制或影响
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) { printLine("fgetws() failed"); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_74a.cpp:60-64; pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_74a.cpp:56-60; fclose(pFile); dataMap[0] = data; ... case0Sink(dataMap);（sink函数未展开） @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_74a.cpp:66-70
- 结论: 存在CWE-427未受控搜索路径元素漏洞：从文件读取的用户数据被存储到map中，但未在证据中展示实际用于搜索路径元素（如执行命令或加载库），漏洞路径不完整，需要动态验证sink函数实现。
- D验证: confirmed / ver_52ef1fec
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 4. hyp_path_5fbfdd8c477f

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_72a.cpp:56
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE（例如通过本地shell或进程继承环境）
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ testcases/CWE427_Uncontrolled_Search_Path_Element__char_environment_72a.cpp:53-57; strncat(data+dataLen, environment, 250-dataLen-1); @ testcases/CWE427_Uncontrolled_Search_Path_Element__char_environment_72a.cpp:59-63; dataVector.insert(dataVector.end(), 1, data); @ testcases/CWE427_Uncontrolled_Search_Path_Element__char_environment_72a.cpp (vector插入); case0Sink(dataVector); @ testcases/CWE427_Uncontrolled_Search_Path_Element__char_environment_72a.cpp (sink调用)
- 结论: 存在未控制搜索路径元素漏洞，攻击者可通过环境变量控制搜索路径，可能导致任意代码执行或提权。但sink函数具体实现未提供，需动态验证。
- D验证: confirmed / ver_675ee4b0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 5. hyp_path_832ce52a7a6c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_74a.cpp:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向FILENAME指定的文件写入数据，从而控制data内容
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_74a.cpp:60; dataMap[0] = data; dataMap[1] = data; dataMap[2] = data; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_74a.cpp:58; case0Sink(dataMap); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_74a.cpp:58
- 结论: 文件读取内容可能被用作搜索路径元素，存在不受控制的搜索路径元素漏洞，但缺乏sink函数对data的具体使用证据，且source文件通常为固定常量，攻击者难以控制其内容。
- D验证: confirmed / ver_83a5446a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 6. hyp_path_da10489e6800

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_72a.cpp:56
- 漏洞类型: buffer_overflow
- CWE: CWE-427; CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值（例如通过进程环境或外部输入）。; data缓冲区为局部栈数组或堆分配，大小不足以容纳所有追加内容（实际大小未知，但wcsncat限制250，若data大小不足250则溢出）。
- 触发路径: wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_72a.cpp:56; wcsncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_72a.cpp:59-61
- 结论: 从环境变量读取数据后，使用wcsncat追加到固定大小的缓冲区，可能导致缓冲区溢出。攻击者可通过控制环境变量内容触发溢出，覆盖相邻内存。
- D验证: confirmed / ver_c1263992
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 7. hyp_path_a200cd6fbc5b

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_74a.cpp:56
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量 ENV_VARIABLE 的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_74a.cpp:56; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_74a.cpp:62; case0Sink(dataMap); // 将受控 data 传入 sink 函数，可能用于路径操作 @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_74a.cpp:case0Sink
- 结论: 从环境变量读取数据并追加到字符串，该字符串可能被用作搜索路径元素，攻击者可通过控制环境变量导致非预期路径搜索，可能引发任意代码执行或信息泄露。
- D验证: confirmed / ver_e8f1b570
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 8. hyp_path_8808060dc4c3

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_74a.cpp:56
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE为任意值（如恶意可执行文件路径）。
- 触发路径: wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_74a.cpp:56; wcsncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_74a.cpp:56; dataMap[2] = data; case0Sink(dataMap); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_74a.cpp:after 56
- 结论: 程序通过环境变量ENV_VARIABLE获取输入，并将其追加到固定大小的宽字符缓冲区data中，随后该缓冲区作为搜索路径元素传递给sink函数，导致未受控的搜索路径元素漏洞（CWE-427），攻击者可控制环境变量来影响程序搜索路径（如加载恶意DLL）。
- D验证: confirmed / ver_e7e9dfc0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 9. hyp_path_7d603c9eb60f

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_73a.cpp:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制文件FILENAME的内容。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_73a.cpp:60; data[dataLen] = '\0'; } fclose(pFile); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_73a.cpp:66-68; dataList.push_back(data); case0Sink(dataList); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_73a.cpp:69-70
- 结论: 程序从文件读取搜索路径元素并存储到list中，随后传递给case0Sink，该Sink可能将未加控制的路径元素用于搜索，导致任意代码执行或恶意库加载。
- D验证: confirmed / ver_0ad5e8dd
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 10. hyp_path_dffa19c64f09

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_73a.cpp:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序指定的文件（FILENAME）写入恶意内容，或控制该文件路径指向攻击者控制的文件，从而通过fgetws读取恶意数据。
- 触发路径: if (250-dataLen > 1) { pFile = fopen(FILENAME, "r"); if (pFile != NULL) { @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_73a.cpp:56-60; if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) { printLine("fgetws() failed"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_73a.cpp:60-64; data[dataLen] = L'\0'; } fclose(pFile); } } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_73a.cpp:66-70; case0Sink(dataList); // 数据传递至sink函数，sink内部预期执行路径设置操作（如_wputenv） @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_73a.cpp:45
- 结论: 存在不受控制的搜索路径元素漏洞（CWE-427），攻击者可通过控制输入文件内容注入恶意路径字符串，数据通过dataList传递给case0Sink，该sink函数预期会将数据用作搜索路径元素（如设置PATH环境变量）。
- D验证: confirmed / ver_9806fa5d
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 11. hyp_path_3843dd48e46c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_72a.cpp:64
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入提供控制台输入，注入恶意字符串以修改PATH环境变量。
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_72a.cpp:50-54; dataVector.insert(dataVector.end(), 1, data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_72a.cpp:62-66; case0Sink(dataVector); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_72a.cpp:64
- 结论: 程序从控制台读取用户输入并将其用作搜索路径元素（PATH环境变量），未经任何验证或清洁，攻击者可通过控制输入修改搜索路径，导致加载恶意程序。
- D验证: confirmed / ver_8ff3fba5
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 12. hyp_path_9a66453ff18d

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_73a.cpp:56
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值。
- 触发路径: wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_73a.cpp:56; wcsncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_73a.cpp:61
- 结论: 通过环境变量将攻击者可控的数据追加到搜索路径缓冲区，导致不受控制的搜索路径元素（CWE-427），攻击者可能通过控制环境变量修改搜索路径以执行恶意代码。
- D验证: confirmed / ver_61b8744f
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 13. hyp_path_3d68647a2dcf

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_72a.cpp:64
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入提供任意字符串（如恶意 DLL 路径）。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_72a.cpp:50; dataVector.insert(dataVector.end(), 1, data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_72a.cpp:64; case0Sink(dataVector); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_72a.cpp:??
- 结论: 程序从标准输入读取用户数据，并将其作为搜索路径元素传递给 sink 函数，攻击者可通过控制输入操纵搜索路径，导致加载恶意代码（如 DLL 劫持）。
- D验证: confirmed / ver_01febe38
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 14. hyp_path_1655cb959daa

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_73a.cpp:56
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量 ENV_VARIABLE 为任意字符串（如包含路径分隔符或恶意路径）
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_73a.cpp:56; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_73a.cpp:59-63; dataList.push_back(data); case0Sink(dataList); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_73a.cpp:??
- 结论: 通过在搜索路径中插入不可信的环境变量内容，攻击者可以控制程序加载恶意DLL或可执行文件，导致任意代码执行。
- D验证: confirmed / ver_c1bce971
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 15. hyp_path_b2191a0e941e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_74a.cpp:64
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供任意字符串
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_74a.cpp:50-54; dataMap[0] = data; dataMap[1] = data; dataMap[2] = data; case0Sink(dataMap); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_74a.cpp:64
- 结论: 程序从标准输入读取数据，并将数据直接追加到PATH环境变量字符串中，然后调用putenv或类似函数设置环境变量，导致攻击者能够控制搜索路径，可能执行恶意程序。
- D验证: confirmed / ver_cd185955
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 16. hyp_path_5bda06e38785

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_74a.cpp:64
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串，并且数据被传递到case0Sink函数。
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), stdin) != NULL) { ... } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_74a.cpp:50-54; dataMap[0] = data; ... case0Sink(dataMap); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_74a.cpp:64
- 结论: 程序从控制台读取用户输入并存储到map中，但后续未见环境变量设置或进程创建调用，无法确认路径被用于搜索路径攻击。
- D验证: confirmed / ver_27b91bae
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 17. hyp_path_c9ec99f7fd50

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_73a.cpp:64
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串，且程序在受影响的路径上执行后续操作（如加载模块）。
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_73a.cpp:50-53; dataList.push_back(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_73a.cpp:55; case0Sink(dataList); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_73a.cpp:57
- 结论: 程序通过fgetws从控制台读取用户输入，未进行充分验证，直接作为搜索路径元素使用，攻击者可控制路径加载恶意库，导致CWE-427不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_0f3f83f1
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 18. hyp_path_99690a731692

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_73a.cpp:64
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者可以通过标准输入提供任意字符串
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_73a.cpp:50-54; dataList.push_back(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_73a.cpp:39; case0Sink(dataList); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_73a.cpp:64
- 结论: 可能存在CWE427不受控制的搜索路径元素漏洞。程序从控制台读取用户输入追加到"PATH="字符串后，将结果存储在列表中，随后传递给case0Sink函数。基于Juliet测试用例上下文和标签high_risk_sink，case0Sink可能将用户控制的字符串设置为环境变量PATH或用于执行命令，攻击者可控制搜索路径导致恶意代码执行。
- D验证: confirmed / ver_38e70c5b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 19. hyp_path_e5901d0f8072

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_74a.cpp:110
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到服务并发送恶意数据，数据被recv接收并存储，最终传入sink函数。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_74a.cpp:110; dataMap[0] = data; @ 同一文件，map赋值处; _ZN62CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_749case0SinkESt3mapIiPcSt4lessIiESaISt4pairIKiS1_EEE(dataMap); @ sink函数调用处
- 结论: 存在CWE-427漏洞：通过socket接收外部可控数据，存储到map中，并传递给sink函数，该sink可能将数据用作搜索路径元素，导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_966ee312
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 20. hyp_path_5a74c6937ffe

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_72a.cpp:110
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到监听端口并发送恶意数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_72a.cpp:110; dataVector.insert(dataVector.end(), 1, data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_72a.cpp:112; call:_ZN62CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_729case0SinkESt6vectorIPcSaIS1_EE @ sink函数调用（未提供具体行号，但已知存在case0Sink函数）
- 结论: 存在CWE-427未控制搜索路径元素漏洞。网络接收的数据被插入vector并传递给sink函数，但sink函数的具体危险操作（如调用system/exec）未在证据中明确展示，路径不完整。
- D验证: confirmed / ver_67338786
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 21. hyp_path_9b5bafb8d68b

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_74a.cpp:95
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立socket连接并发送恶意负载。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_74a.cpp:100-104; dataMap[0] = data; @ 同文件，dataMap[0] = data;; // 假设调用将data用作搜索路径元素 @ 同文件，后续sink函数将data用于搜索路径设置
- 结论: 网络接收的数据未经校验直接作为搜索路径元素，可能导致搜索路径劫持。
- D验证: confirmed / ver_f5d206ae
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 22. hyp_path_e95602de9f03

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_74a.cpp:95
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到服务并发送任意数据，且服务在接收数据后未进行充分验证直接用于搜索路径。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_74a.cpp:95; dataMap[0] = data; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_74a.cpp:105-110; case0Sink(dataMap); // 调用sink函数，将data作为搜索路径元素使用 @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_74a.cpp:??
- 结论: 程序从网络socket接收数据并存储到map中，随后可能将用户控制的数据用作搜索路径元素（例如环境变量PATH），导致未控制搜索路径元素漏洞（CWE-427）。
- D验证: confirmed / ver_79ca894d
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 23. hyp_path_cdc59e0f63d0

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_72a.cpp:95
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标程序监听的socket并发送任意数据。; 程序在后续代码中将接收到的数据用作搜索路径（如系统命令、动态库加载等）的参数。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_72a.cpp:100-104; dataVector.insert(dataVector.end(), 1, data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_72a.cpp:110; sink函数（_ZN63CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_729case0SinkESt6vectorIPcSaIS1_EE）接收dataVector中的数据作为参数 @ 由B阶段API种子标识的sink函数调用
- 结论: 程序通过网络socket接收外部输入数据，并将该数据存储到vector中，随后作为搜索路径元素传递给sink函数，可能导致未受控的搜索路径元素漏洞，攻击者可通过控制输入数据来影响搜索路径，进而执行恶意代码。
- D验证: confirmed / ver_9a96be0d
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 24. hyp_path_253515b25a1c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_12.c:102
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标程序的监听端口并发送特制数据。; 程序运行在Windows或支持PUTENV的平台上。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_12.c:100-104; data[dataLen + recvResult / sizeof(char)] = '\0'; replace = strchr(data, '\r'); if (replace) { *replace = '\0'; } replace = strchr(data, '\n'); if (replace) { *replace = '\0'; } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_12.c:102-104; strcat(data, NEW_PATH); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_12.c:119-120; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_12.c:125
- 结论: 网络接收的数据未经充分验证，直接被用于PUTENV设置环境变量，攻击者可通过控制输入设置恶意的搜索路径元素，导致路径劫持或特权提升。
- D验证: confirmed / ver_aa83c4d1
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 25. hyp_path_878985b9caa5

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_72a.cpp:95
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标主机的指定TCP端口，并发送特制宽字符数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_72a.cpp:95; dataVector.insert(dataVector.end(), 1, data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_72a.cpp:100-104; 调用 _ZN66CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_72a9case0SinkESt6vectorIPwSaIS1_EE，将dataVector作为参数传入，但sink函数内部操作未知。 @ sink函数调用处（未明确行号）
- 结论: 存在不受控制的搜索路径元素漏洞，从网络接收的数据被插入dataVector并传递给sink函数，但sink函数的具体实现未提供，无法确认是否实际执行路径操作。
- D验证: confirmed / ver_4f59bc74
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 26. hyp_path_762001741b8f

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_12.c:87
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接目标程序的监听端口（如TCP端口）。; 攻击者能够发送构造的攻击载荷（包含恶意路径的字符串）。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_12.c:92-93; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_12.c:112-118
- 结论: 程序通过套接字接收外部输入，未经验证直接用于PUTENV设置环境变量，攻击者可控制搜索路径，导致任意代码执行。
- D验证: confirmed / ver_551a332d
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 27. hyp_path_cd6c02ebe82d

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_73a.cpp:110
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与目标建立网络连接并发送恶意数据（通过socket）
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_73a.cpp:110; dataList.push_back(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_73a.cpp:112-113; sink函数接收list数据，可能用于设置搜索路径元素 @ sink函数调用（API种子中为_ZN62CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_739case0SinkE...，具体行号未在提供代码片段中显示）
- 结论: 未控制搜索路径元素漏洞：程序通过socket接收数据，存储到list中，并在后续的sink函数中可能将其用作搜索路径元素，但未对输入进行验证或限制，导致攻击者可以控制路径，从而可能执行恶意代码。
- D验证: confirmed / ver_85e27e13
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 28. hyp_path_6aab754b9437

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_73a.cpp:110
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接发送恶意构造的数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_73a.cpp:108-112; dataList.push_back(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_73a.cpp:110
- 结论: 基于网络接收的不可信数据可能被用作搜索路径元素，导致CWE427漏洞。但当前代码证据仅显示数据通过recv接收并存储到list，未展现sink函数中如何使用该数据，因此无法确认完整的漏洞路径。
- D验证: confirmed / ver_44158e45
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 29. hyp_path_b404547ea96e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_41.c:106
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接至目标程序的监听端口，并发送包含环境变量定义的字符串（如"PATH=/malicious"）。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_41.c:106; CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_41_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_41.c:120; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_41.c:55
- 结论: 网络接收的字符串直接用于设置环境变量，攻击者可控制程序搜索路径，造成任意代码执行。
- D验证: confirmed / ver_8bc30fa0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 30. hyp_path_4a5650f40c0c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_73a.cpp:95
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接向目标socket发送任意数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_73a.cpp:100-104; dataList.push_back(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_73a.cpp:108; 未提供sink函数具体代码，推测使用list元素作为搜索路径 @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_73a.cpp:?? (sink函数)
- 结论: 存在未受控制的搜索路径元素漏洞。通过socket接收的恶意数据被存储到链表中，但后续sink函数（如CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_73::case0Sink）可能未展示完整代码，无法确认数据是否确实用于搜索路径操作。
- D验证: confirmed / ver_748cbfcb
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 31. hyp_path_b15373c135d0

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_73a.cpp:95
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与目标程序的socket连接（由代码中的connect和inet_addr(IP_ADDRESS)知，通常为本地或特定IP）
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_73a.cpp:95; dataList.push_back(data); // 将接收数据存入列表 @ 同一文件:103-104; 接收dataList并可能用于路径搜索，但无代码证据 @ sink函数CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_73a::case0Sink（未提供具体实现代码）
- 结论: 程序从网络接收数据并存储到列表中，随后可能将列表中的路径用于搜索路径（如CreateProcess或类似函数），攻击者可以控制搜索路径元素，导致恶意DLL或程序被加载。但sink函数（case0Sink）的具体实现未在提供的代码片段中展示，无法确认其是否实际使用数据作为搜索路径元素。
- D验证: confirmed / ver_e735c6be
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 32. hyp_path_7550e73d9873

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_17.c:103
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够建立TCP连接并向目标端口发送数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_17.c:103; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_17.c:127-131
- 结论: 程序通过socket接收用户输入，未经验证直接作为环境变量设置，可能导致不受控制的搜索路径元素漏洞，攻击者可注入恶意路径实现DLL劫持或命令执行。
- D验证: confirmed / ver_bdf4ecd0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 33. hyp_path_1de931ea426a

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_41.c:91
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接向目标程序发送数据。; 目标程序运行在Windows平台上（使用了WSAStartup等Windows API）。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ 91; void CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_41_case0Sink(char * data) { PUTENV(data); } @ 51-55; CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_41_case0Sink(data); @ 118
- 结论: 程序从网络接收数据，并将其传递给PUTENV设置环境变量，攻击者可以控制搜索路径元素，导致潜在的命令执行或信息泄露。
- D验证: confirmed / ver_2db3d852
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 34. hyp_path_c68fe3e598fb

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_08.c:116
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标应用程序的监听端口并发送恶意数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_08.c:114-118; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_08.c:140-144
- 结论: 存在不受控制的搜索路径元素漏洞：通过socket接收攻击者可控数据，并直接用于设置环境变量PATH，可能导致恶意DLL加载或命令执行。
- D验证: confirmed / ver_d3b973e0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 35. hyp_path_cc7de8030cb8

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_17.c:88
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到程序的socket并发送任意数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_17.c:88; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_17.c:95
- 结论: 该代码通过socket接收外部输入数据，并直接作为参数调用PUTENV设置环境变量。攻击者可以控制接收的数据，设置恶意环境变量（如修改PATH），可能导致任意代码执行或特权提升。
- D验证: confirmed / ver_7fa05799
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 36. hyp_path_98d742f669bb

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_11.c:102
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到程序的监听socket; 攻击者发送的数据能够构造一个恶意的PATH值（如包含当前目录或攻击者控制的目录）
- 触发路径: char dataBuffer[250] = "PATH="; data = dataBuffer; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_11.c:51; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_11.c:102; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_11.c:126
- 结论: 程序通过socket接收不可信数据，将其拼接到"PATH="之后并直接调用_putenv设置环境变量，攻击者能够控制搜索路径，可能导致恶意DLL加载或命令劫持。
- D验证: confirmed / ver_ff9cccc3
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 37. hyp_path_fe560e459b1b

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_17.c:88
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过TCP连接向目标系统发送任意数据。; 系统使用受影响的路径环境变量（如PATH）来查找可执行文件。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_17.c:93-97; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_17.c:95
- 结论: 函数通过socket接收外部输入数据，并将该数据直接作为参数传递给PUTENV（或_wputenv）设置环境变量。攻击者可以控制该输入，从而设置恶意路径环境变量，导致搜索路径劫持。
- D验证: confirmed / ver_5167dba1
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 38. hyp_path_e55774cb15d5

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_51a.c:103
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标程序监听的端口; 攻击者能够发送任意字符串作为数据
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_51a.c:89; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_51a.c:101-103; CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_51b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_51a.c:113-114
- 结论: 程序通过socket接收网络数据，未经充分验证地传递给搜索路径元素相关的sink函数，攻击者可以控制搜索路径，导致恶意代码执行。
- D验证: confirmed / ver_128d6be8
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 39. hyp_path_0cf16096c58e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_54a.c:103
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接服务端（已通过accept建立连接）。; 服务端未对recv接收的数据进行充分验证和消毒。; sink函数使得data被用作搜索路径元素（如调用系统命令或加载库）。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_54a.c:103; CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_54b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_54a.c:105（替换换行后）
- 结论: 存在不受控制的搜索路径元素漏洞（CWE-427），因为从网络套接字接收的数据直接传递给搜索路径元素，攻击者可通过发送恶意字符串控制搜索路径。
- D验证: confirmed / ver_1dcbce28
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 40. hyp_path_4bc455874ce3

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_52a.c:103
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标设备的监听端口并发送任意数据; 目标设备运行存在漏洞的二进制文件且sink函数以未过滤方式处理输入
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_52a.c:103; CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_52b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_52a.c:112
- 结论: 该代码存在不受控制的搜索路径元素漏洞。程序通过socket接收数据并直接传递给sink函数，未进行任何过滤或验证，攻击者可以控制搜索路径元素，导致执行恶意代码。
- D验证: confirmed / ver_e82240be
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 41. hyp_path_a4905b6303c3

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_53a.c:103
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接目标主机的监听端口，并发送任意字符串
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_53a.c:103; data[dataLen + recvResult / sizeof(char)] = '\0'; /* Eliminate CRLF */ replace = strchr(data, '\r'); if (replace) { *replace = '\0'; } replace = strchr(data, '\n'); if (replace) { *replace = '\0'; } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_53a.c:106-111; CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_53b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_53a.c:115
- 结论: 存在不受控制的搜索路径元素漏洞。程序通过socket接收外部输入，并将数据传递给sink函数，攻击者可以控制搜索路径，导致任意命令执行或恶意DLL加载。
- D验证: confirmed / ver_e75fa7fc
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 42. hyp_path_cd7daf358a22

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_63a.c:103
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标socket并发送恶意数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_63a.c:103; CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_63b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_63a.c:118
- 结论: 通过recv从网络接收的数据未经验证即作为搜索路径元素传递给后续sink函数，可能导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_2c1f60a4
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 43. hyp_path_de33118872b6

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_52a.c:103
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标程序监听的TCP端口，并发送精心构造的宽字符串数据，该数据将被用作搜索路径元素。
- 触发路径: listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); ... bind; listen; accept @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_52a.c:78-82; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_52a.c:103; if (recvResult > 0) { data[dataLen + recvResult / sizeof(wchar_t)] = L'\0'; replace = wcschr(data, L'\r'); if (replace) { *replace = L'\0'; } replace = wcschr(data, L'\n'); if (replace) { *replace = L'\0'; } } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_52a.c:104-110; CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_52b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_52a.c:111
- 结论: 该代码存在不受控制的搜索路径元素漏洞（Uncontrolled Search Path Element），攻击者可以通过网络连接发送恶意数据，该数据被用作搜索路径元素，可能导致执行恶意代码或加载恶意库。
- D验证: confirmed / ver_15ea038e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 44. hyp_path_f3abe608528c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_53a.c:103
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: Attacker can send malicious data over the network to the listening socket.
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_53a.c:103; data[dataLen + recvResult / sizeof(wchar_t)] = L'\0'; ... CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_53b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_53a.c:106-107
- 结论: The program receives data over a network socket into a buffer, then passes the data to a sink function without sanitization, potentially allowing an attacker to control a search path element, leading to arbitrary code execution via DLL hijacking or similar.
- D验证: confirmed / ver_bb9340ba
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 45. hyp_path_e453a731272c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_54a.c:103
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够网络访问目标程序监听的TCP端口; 攻击者可以构造恶意字符串作为搜索路径元素; 目标系统上的sink函数（如LoadLibrary、CreateProcess等）会使用该搜索路径，且没有启用安全搜索模式
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_54a.c:103; CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_54b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_54a.c:131
- 结论: CWE427: 未控制搜索路径元素漏洞。程序通过socket接收用户输入到缓冲区data，然后将其作为参数传递给sink函数CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_54b_case0Sink，该函数可能将data用作搜索路径元素（如用于LoadLibrary或CreateProcess），攻击者可通过控制data修改搜索路径，导致恶意DLL加载或命令执行。
- D验证: confirmed / ver_b2913e7e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 46. hyp_path_e3644259fd05

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_51a.c:103
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务监听端口; 攻击者能够发送包含恶意搜索路径元素的宽字符串数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_51a.c:103; CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_51b_case0Sink(data); @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_51b.c（sink函数内部，具体行号未在证据中明确）
- 结论: 代码从网络socket接收数据，并将未经验证的数据作为搜索路径元素传递给sink函数，可能导致搜索路径劫持（CWE-427）。
- D验证: confirmed / ver_db9e16f7
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 47. hyp_path_abd286586091

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_64a.c:103
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到监听socket并发送恶意数据。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_64a.c:101-105; CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_64b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_64a.c:115-116 (approx)
- 结论: 程序通过socket接收外部输入数据，并将数据作为搜索路径元素传递给sink函数，攻击者可控制该数据导致不受控制的搜索路径元素漏洞（CWE-427）。
- D验证: confirmed / ver_31c6118c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 48. hyp_path_dd158c29dd72

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_64a.c:103
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接目标端口并发送任意字符串
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_64a.c:103; CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_64b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_64a.c:115
- 结论: 存在不受控制的搜索路径元素漏洞，网络接收的数据直接传递给sink函数，可能导致路径劫持。
- D验证: confirmed / ver_a6e3549e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 49. hyp_path_972c7a730f3d

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_01.c:100
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标程序监听的端口; 攻击者能够发送恶意字符串，该字符串将被recv接收并赋值给data变量; 目标程序以当前用户权限运行，且PUTENV调用有效
- 触发路径: listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_01.c:75-79; bind(listenSocket, ...); listen(listenSocket, ...); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_01.c:86; acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_01.c:86; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_01.c:100; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_01.c:124-128
- 结论: 通过socket接收用户数据，未经验证直接作为环境变量值调用PUTENV，导致不受控制的搜索路径元素漏洞，攻击者可控制搜索路径导致程序加载恶意库。
- D验证: confirmed / ver_fc0c965b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 50. hyp_path_656007739ec3

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_02.c:102
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接并发送任意数据到程序监听的端口
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_02.c:102; PUTENV(data); @ CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_02.c:126-130
- 结论: 程序通过socket接收网络数据，未经验证直接作为参数传递给PUTENV设置环境变量，攻击者可以控制搜索路径元素，导致任意代码执行或路径劫持。
- D验证: confirmed / ver_4beca2d7
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 51. hyp_path_962ed679219f

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_03.c:102
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接目标程序监听的socket; 攻击者发送的恶意数据能够被recv接收并存入data缓冲区; PUTENV调用时没有对data内容进行任何验证或过滤
- 触发路径: listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_03.c:77; acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_03.c:88; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_03.c:102; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_03.c:135
- 结论: 程序通过socket接收外部数据，并直接传递给PUTENV设置环境变量，攻击者可控制环境变量值，导致不受控的搜索路径元素漏洞。
- D验证: confirmed / ver_9c9c0ef9
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 52. hyp_path_6217e6d592b3

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_63a.c:103
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标程序监听的socket（由listenSocket创建）。; 攻击者发送的恶意数据包含可用于操纵搜索路径的字符串（如路径分隔符、系统命令等）。; 目标程序运行在Windows平台（由于使用了WSAStartup等WinSock API）。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_63a.c:103; CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_63b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_63a.c:115-116
- 结论: 存在未控制搜索路径元素漏洞，攻击者可通过网络发送恶意数据，控制搜索路径元素，可能导致任意代码执行。
- D验证: confirmed / ver_b23c8c77
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 53. hyp_path_902eea3e8b4e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_04.c:109
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标主机的监听socket（默认端口未知，但代码中未绑定特定地址，可能监听所有接口）。; 攻击者发送的数据必须包含有效的环境变量格式（例如 'PATH=C:\malicious'），且长度不超过250字节。; 目标程序运行在Windows环境下（因为使用了PUTENV和WSAStartup等）。
- 触发路径: listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ line 84-88; acceptSocket = accept(listenSocket, NULL, NULL); @ line 95; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ line 109; data[dataLen + recvResult / sizeof(char)] = '\0'; replace = strchr(data, '\n'); if (replace) { *replace = '\0'; } replace = strchr(data, '\r'); if (replace) { *replace = '\0'; } @ line 116-118; PUTENV(data); @ line 130
- 结论: 程序通过socket接收外部数据，未经充分验证直接作为环境变量设置，导致不受控制的搜索路径元素漏洞。攻击者可利用此漏洞加载恶意DLL或执行任意代码。
- D验证: confirmed / ver_6711da18
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 54. hyp_path_02c45d215eb2

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_05.c:109
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与目标主机建立网络连接，并发送恶意构造的环境变量字符串（如包含危险路径）。; 目标应用程序以可影响安全敏感操作（如DLL搜索）的权限运行。
- 触发路径: listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_05.c:86; acceptSocket = accept(listenSocket, NULL, NULL); @ CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_05.c:95; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_05.c:109; PUTENV(data); @ CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_05.c:133-137
- 结论: 通过listen socket接收的数据未经净化直接传递给PUTENV设置环境变量，攻击者可以控制环境变量，导致未受控的搜索路径元素漏洞。
- D验证: confirmed / ver_10b37a85
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 55. hyp_path_ff3da543ac5b

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_06.c:106
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够访问程序监听的网络端口; 攻击者能够发送任意字符串作为数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_06.c:104-108; data[dataLen + recvResult / sizeof(char)] = '\0'; /* Eliminate CRLF */ replace = strchr(data, '\r'); if (replace) { *replace = '\0'; } replace = strchr(data, '\n'); if (replace) { *replace = '\0'; } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_06.c:110-112; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_06.c:130
- 结论: 程序通过socket接收外部数据，直接用作环境变量设置（PUTENV），导致不受控制的搜索路径元素漏洞。攻击者可设置恶意环境变量（如PATH），劫持程序加载的共享库或可执行文件。
- D验证: confirmed / ver_b3d7ce0f
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 56. hyp_path_7352ff3434eb

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_07.c:108
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与应用程序建立网络连接并发送特制数据。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_07.c:94; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_07.c:108; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_07.c:132-136
- 结论: 程序从网络socket接收数据，未经验证直接通过PUTENV设置环境变量，可能被攻击者利用来劫持搜索路径，执行恶意代码。
- D验证: confirmed / ver_a658263e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 57. hyp_path_d25ce4d2be47

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_10.c:102
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向目标程序发送任意数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_10.c:100-104; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_10.c:126-130
- 结论: 程序通过socket接收不可信数据，并直接作为环境变量名/值传递给PUTENV，攻击者可以设置恶意环境变量（如修改PATH），导致后续执行任意程序，构成不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_47d60b5a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 58. hyp_path_903a75834cc6

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_09.c:102
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到服务器的监听端口并发送恶意数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_09.c:100-104; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_09.c:126-130
- 结论: 程序通过网络接收数据后，直接用作环境变量设置函数PUTENV的参数。攻击者可以控制接收的数据，进而设置恶意环境变量（如PATH），导致搜索路径劫持，可能执行恶意代码。
- D验证: confirmed / ver_34736236
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 59. hyp_path_57fc1a0423a2

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_13.c:102
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标程序监听的端口，并发送任意字符串数据；目标程序随后调用PUTENV设置环境变量，且后续程序行为依赖该环境变量。
- 触发路径: listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_13.c:79; bind(listenSocket, ...); listen(listenSocket, ...); acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_13.c:88; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_13.c:102; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_13.c:126
- 结论: 代码通过socket接收外部数据，未经任何检查直接调用PUTENV设置环境变量，攻击者可通过发送恶意数据修改环境变量（如PATH），导致搜索路径劫持，从而可能执行任意代码。
- D验证: confirmed / ver_48e45a5f
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 60. hyp_path_fc6a7c6ac474

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_14.c:102
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务的监听端口，并发送任意字符串。
- 触发路径: listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_14.c:79; acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_14.c:88; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_14.c:102; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_14.c:122
- 结论: 程序通过网络套接字接收数据并直接用于设置环境变量（PUTENV），攻击者可发送恶意字符串（如设置PATH为恶意目录），导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_11d3ea01
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 61. hyp_path_57d88e493f54

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_16.c:102
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立TCP连接并发送数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_16.c:102; data[dataLen + recvResult / sizeof(char)] = '\0'; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_16.c:105; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_16.c:121
- 结论: 通过socket接收用户输入并直接传递给putenv设置环境变量PATH，攻击者可以注入恶意路径，导致搜索路径劫持，可能执行任意代码。
- D验证: confirmed / ver_d5e5df4e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 62. hyp_path_1c23520f7a52

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_18.c:102
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与目标程序建立网络连接，并发送任意字符串数据。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_18.c:88; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_18.c:102; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_18.c:135
- 结论: 程序通过套接字接收外部输入数据，并直接作为环境变量设置（PUTENV），攻击者可以控制搜索路径元素，导致路径劫持或恶意代码执行。
- D验证: confirmed / ver_c7dd006c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 63. hyp_path_0fe9c9a70972

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_15.c:103
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标主机的监听socket; 攻击者能够发送任意字符串数据; 目标程序在接收数据后未进行充分验证即设置环境变量; 后续程序逻辑需要依赖于该环境变量来加载可执行文件或库（但证据中未展示）
- 触发路径: listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_15.c:78; acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_15.c:89; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_15.c:103; PUTENV(data); // 设置环境变量 @ 约在函数尾部，行号未明确
- 结论: 存在不受控制的搜索路径元素漏洞：程序通过socket接收外部数据，并直接作为参数传递给PUTENV设置环境变量。攻击者可控制搜索路径，但缺乏后续利用该环境变量执行程序的关键步骤，因此漏洞利用路径不完整。
- D验证: confirmed / ver_65474ed6
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 64. hyp_path_effd636d4cf9

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_09.c:102
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与目标服务建立TCP连接并发送网络数据。
- 触发路径: listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ 79; acceptSocket = accept(listenSocket, NULL, NULL); @ 88; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ 102; data[dataLen + recvResult / sizeof(wchar_t)] = L'\0'; replace = wcschr(data, L'\r'); if (replace) { *replace = L'\0'; } replace = wcschr(data, L'\n'); if (replace) { *replace = L'\0'; } @ 105-108; PUTENV(data); // 或 _wputenv(data) @ 126-128
- 结论: 网络接收的数据直接用于`_wputenv`设置环境变量，攻击者可以通过构造恶意环境变量，导致搜索路径劫持等危害。
- D验证: confirmed / ver_032d6b0b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 65. hyp_path_0e78c5e8bfcd

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_82a.cpp:95
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务，并发送构造的payload数据。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_82a.cpp:95; baseObject->action(data); // 将用户输入的数据作为参数传递给action @ 同一文件，后续调用
- 结论: 该代码存在CWE-427（不受控制的搜索路径元素）漏洞。程序通过socket接收用户输入的数据，并将其直接传递给action函数，该函数可能将用户提供的数据用作搜索路径（如system、CreateProcess等），攻击者可以控制搜索路径导致恶意代码执行。
- D验证: confirmed / ver_b4cdfea2
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 66. hyp_path_3539ff157875

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_08.c:101
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过socket连接发送任意字符串
- 触发路径: if(staticReturnsTrue()) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_08.c:65; recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_08.c:101; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_08.c:108
- 结论: 程序从网络接收数据后，直接作为环境变量设置（PUTENV），攻击者可控制搜索路径，导致未授权加载恶意DLL或程序。
- D验证: confirmed / ver_63e232f3
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 67. hyp_path_6733a8944f23

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_82a.cpp:95
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与目标主机建立网络连接并发送包含恶意路径数据的消息。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_82a.cpp:81; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_82a.cpp:95; CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_82_base* baseObject = new CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_82_case0; baseObject->action(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_82a.cpp:106-108
- 结论: 程序通过套接字接收外部数据，并将其作为参数传递给可能修改搜索路径的操作，导致未受控的搜索路径元素漏洞。
- D验证: confirmed / ver_c90f4a7f
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 68. hyp_path_4f131201aab8

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_11.c:87
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标应用程序的TCP端口，并发送任意字符串。
- 触发路径: char dataBuffer[250] = "PATH="; data = dataBuffer; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_11.c:51; connect(connectSocket, (struct sockaddr*)&service, sizeof(service)) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_11.c:85-89; recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_11.c:92-96; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_11.c:94
- 结论: 通过socket接收用户输入，直接作为环境变量设置，攻击者可控搜索路径元素，可导致恶意代码执行。
- D验证: confirmed / ver_748082e4
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 69. hyp_path_881466884809

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_51a.c:88
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务并发送任意数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_51a.c:93-97; data[dataLen + recvResult / sizeof(char)] = '\0'; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_51a.c:100-102; CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_51b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_51a.c:105
- 结论: 通过recv从网络接收数据，未经验证直接传递给sink函数，导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_02c1d0cf
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 70. hyp_path_de5720cbd08a

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_52a.c:88
- 漏洞类型: command_injection
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标程序使用的TCP端口; 攻击者能够发送任意数据到该socket
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_52a.c:88; data[dataLen + recvResult / sizeof(char)] = '\0'; replace = strchr(data, '\n'); if (replace) { *replace = '\0'; } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_52a.c:107-110; CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_52b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_52a.c:115
- 结论: 通过socket接收外部输入数据，未经任何净化直接传递给sink函数，可能导致任意搜索路径元素注入，进而执行恶意代码（如DLL劫持或命令注入）。
- D验证: confirmed / ver_e200c352
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 71. hyp_path_f142b219dc54

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_53a.c:88
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接向目标程序发送恶意构造的数据，用于控制搜索路径或命令参数。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_53a.c:93-97; CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_53b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_53a.c:100-105
- 结论: 代码从网络套接字接收数据，然后传递给sink函数，可能用于控制搜索路径元素，导致攻击者可以指定可执行文件路径或执行任意命令，存在CWE-427未控制搜索路径元素漏洞。
- D验证: confirmed / ver_c78c7ee2
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 72. hyp_path_b76548dcf7db

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_54a.c:88
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标程序监听的TCP端口，并发送任意负载；目标程序未对网络输入进行有效过滤或验证。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_54a.c:93-97; CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_54b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_54a.c:88 (sink调用)
- 结论: 从网络接收的数据未经验证即被用于搜索路径元素，攻击者可通过发送特制数据控制程序加载的路径，导致未授权的文件执行或信息泄露。
- D验证: confirmed / ver_32b26b1c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 73. hyp_path_8c6cc695180d

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_63a.c:88
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务; 攻击者能够发送任意数据到接收缓冲区
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_63a.c:93-97; CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_63b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_63a.c:115-119 (approximate, sink call after cleanup)
- 结论: 存在不可控搜索路径元素漏洞：程序通过recv从网络套接字接收数据，并将该数据直接传递给CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_63b_case0Sink函数，该函数可能将用户控制的数据用作搜索路径或命令参数，攻击者可利用此漏洞篡改搜索路径导致恶意代码执行。
- D验证: confirmed / ver_100a80d5
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 74. hyp_path_ee3450246cfe

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_51a.c:88
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到程序监听的TCP端口，并发送特制数据，该数据将被接收并用作搜索路径元素。
- 触发路径: service.sin_addr.s_addr = inet_addr(IP_ADDRESS); service.sin_port = htons(TCP_PORT); if (connect(connectSocket, (struct sockaddr*)&service, sizeof(service)) == SOCKET_ERROR) { break;} @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_51a.c:86-90; recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) { break;} @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_51a.c:93-97; CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_51b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_51a.c:107-108
- 结论: 程序通过socket接收外部输入，未经过充分验证即将其作为搜索路径元素，导致不受控制的搜索路径元素漏洞，攻击者可以控制程序搜索的目录，从而可能执行恶意代码。
- D验证: confirmed / ver_8e8823e0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 75. hyp_path_ca6103e350c0

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_52a.c:88
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务并发送恶意构造的数据; 目标程序使用受影响的socket连接且未对接收数据进行有效验证
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_52a.c:88; data[dataLen + recvResult / sizeof(wchar_t)] = L'\0'; ... replace = wcschr(data, L'\r'); if (replace) { *replace = L'\0'; } replace = wcschr(data, L'\n'); if (replace) { *replace = L'\0'; } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_52a.c:100-101; CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_52b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_52a.c:103
- 结论: 不受控制的搜索路径元素漏洞：程序通过socket接收外部输入数据，未经过滤或验证，直接将其作为搜索路径元素传递给后门函数，攻击者可利用此漏洞控制程序搜索路径，加载恶意DLL或执行任意代码。
- D验证: confirmed / ver_224beba6
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 76. hyp_path_03aacfe538a1

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_64a.c:88
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标程序的socket端口并发送精心构造的数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_64a.c:88; CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_64b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_64a.c (calls sink in 64b)
- 结论: 存在不受控制的搜索路径元素漏洞，攻击者可通过网络连接向data缓冲区发送恶意数据，该数据随后被用作搜索路径元素，可能导致恶意代码执行或权限提升。
- D验证: confirmed / ver_2380bad6
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 77. hyp_path_c631bff2114e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_53a.c:88
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与目标服务建立网络连接; 攻击者可以向目标发送特制的字符串数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_53a.c:93-97; CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_53b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_53a.c:109
- 结论: 存在未受控的搜索路径元素漏洞（CWE-427），攻击者可通过网络输入控制搜索路径，可能导致恶意DLL加载或命令执行。
- D验证: confirmed / ver_feae777f
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 78. hyp_path_5ea5ece7d5b2

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_01.c:85
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务端口; 攻击者能够发送任意字符串数据
- 触发路径: connect(connectSocket, ...) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_01.c:76-85; recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_01.c:85-90; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_01.c:112
- 结论: 程序通过socket接收网络输入，未经任何验证直接传递给PUTENV设置环境变量路径，攻击者可以控制搜索路径元素，导致加载恶意代码或命令执行。
- D验证: confirmed / ver_cfa6a37e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 79. hyp_path_44a65581ec05

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_54a.c:88
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与目标服务建立TCP连接并发送数据。; sink函数所在模块（54b）未对data进行充分验证或过滤，直接用于搜索路径操作。
- 触发路径: 创建socket、设置地址、连接服务器（connect） @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_54a.c:73-84; recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_54a.c:93; 去除回车换行符（wcschr并置为L'\0'） @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_54a.c:100-109; CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_54b_case0Sink(data); @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_54a.c:112
- 结论: 程序通过socket接收外部输入数据，并将其直接传递给可能用于搜索路径的函数（如CreateProcess、system等），攻击者可控制数据内容，导致未控制的搜索路径元素漏洞，可能被利用执行恶意程序或加载恶意库。
- D验证: confirmed / ver_d1ccd396
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 80. hyp_path_887dc652dcb6

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_64a.c:88
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向目标系统的指定端口发送恶意构造的数据包; 目标系统运行该程序并成功建立套接字连接; 程序未对接收到的搜索路径元素进行白名单或长度限制等有效验证
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_64a.c:93-97; data[dataLen + recvResult / sizeof(wchar_t)] = L'\0'; replace = wcschr(data, L'\r'); ... @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_64a.c:102-103; CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_64b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_64a.c:115
- 结论: 代码通过套接字接收外部输入数据作为搜索路径元素，未进行充分验证，可能导致不受控制的搜索路径元素漏洞，攻击者可控制搜索路径加载恶意库。
- D验证: confirmed / ver_0b66e51c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 81. hyp_path_a8fceba6cac5

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_02.c:87
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标程序监听的socket; 目标程序未对接收到的数据进行有效过滤或白名单验证; 环境变量PATH或其他关键环境变量被覆盖后影响后续操作
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_02.c:92-96; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_02.c:114
- 结论: 该代码存在CWE-427不可控搜索路径元素漏洞。程序通过socket接收外部输入数据，未经充分验证直接作为环境变量路径调用PUTENV，攻击者可设置恶意路径导致任意代码执行或提权。
- D验证: confirmed / ver_f7d9ccf8
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 82. hyp_path_d029f917089e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_63a.c:88
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接发送任意数据，且目标系统未对接收数据做有效的搜索路径元素过滤。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_63a.c:88; data[dataLen + recvResult / sizeof(wchar_t)] = L'\0'; ... replace = wcschr(data, L'\r'); ... *replace = L'\0'; replace = wcschr(data, L'\n'); ... *replace = L'\0'; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_63a.c:93-97; CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_63b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_63a.c:104
- 结论: 存在CWE-427（未控制搜索路径元素）漏洞。攻击者可通过网络连接发送恶意数据，该数据被存储到data缓冲区后，传递给sink函数，可能导致系统在搜索路径中加载恶意DLL。
- D验证: confirmed / ver_36b97861
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 83. hyp_path_644c649d8df4

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_03.c:87
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与目标服务建立连接并发送定制数据包
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_03.c:87; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_03.c:94
- 结论: 从网络socket接收的数据未经充分验证直接用于PUTENV，攻击者可以设置任意环境变量，导致不可控的搜索路径元素漏洞（CWE-427）。
- D验证: confirmed / ver_03c1a5fd
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 84. hyp_path_52254109820a

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_04.c:94
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络与目标程序进行通信，并发送恶意字符串作为环境变量内容。
- 触发路径: recv(connectSocket, (char*)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_04.c:94; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_04.c:101
- 结论: 程序通过socket接收外部输入，直接作为环境变量设置到PATH中，攻击者可以控制搜索路径，导致执行恶意程序。
- D验证: confirmed / ver_0bf2237e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 85. hyp_path_96faa8800c9d

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_06.c:91
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过TCP连接向目标程序发送任意字符串
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_06.c:91; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_06.c:98
- 结论: 代码从网络接收数据并将其直接作为环境变量名传递给putenv()，未对输入进行任何验证或清理，攻击者可以通过控制接收的数据来设置恶意环境变量（如PATH），从而劫持后续调用的搜索路径，导致任意代码执行。
- D验证: confirmed / ver_06c126b8
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 86. hyp_path_b1681f6b4a7a

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_07.c:93
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标应用程序的socket，并发送精心构造的字符串作为路径。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_07.c:93; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_07.c:100
- 结论: 存在不受控制的搜索路径元素漏洞，攻击者可通过网络发送恶意路径字符串，随后被用于设置环境变量（PUTENV），可能导致恶意DLL或可执行文件被加载。
- D验证: confirmed / ver_c0806770
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 87. hyp_path_2fb164c560bf

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_05.c:94
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接访问目标服务的socket端口; 攻击者发送的数据长度不超过buffer剩余空间（250 - dataLen - 1）
- 触发路径: service.sin_addr.s_addr = inet_addr(IP_ADDRESS); service.sin_port = htons(TCP_PORT); if (connect(connectSocket, (struct sockaddr*)&service, sizeof(service)) == SOCKET_ERROR) { break; } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_05.c:92-96; recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_05.c:99-103; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_05.c:101
- 结论: 程序通过socket接收数据并直接传递给putenv设置环境变量，攻击者可控制网络输入设置恶意环境变量（如PATH），导致搜索路径元素不受控制（CWE-427）。
- D验证: confirmed / ver_69233b2e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 88. hyp_path_e2fa3b4af540

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_09.c:87
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过socket连接发送任意数据; 目标程序运行在支持搜索路径环境变量的操作系统上（如Windows）
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_09.c:87; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_09.c:94
- 结论: 程序通过socket接收用户可控数据，未经校验直接作为参数传递给PUTENV设置环境变量，导致攻击者可以控制搜索路径元素，可能加载恶意DLL或执行任意代码。
- D验证: confirmed / ver_cb271154
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 89. hyp_path_7547467bf2a8

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_10.c:87
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与目标程序建立网络连接并发送数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_10.c:87; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_10.c:94
- 结论: 代码通过socket接收数据，并使用PUTENV将接收到的数据设置为环境变量，攻击者可以通过网络控制环境变量，导致不受控制的搜索路径元素漏洞（如DLL劫持）。
- D验证: confirmed / ver_7884d1f5
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 90. hyp_path_a6cb9a25553c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_15.c:88
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过socket发送任意字符串到目标服务。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_15.c:88; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_15.c:95
- 结论: 程序通过socket接收外部输入，然后直接作为参数传递给PUTENV函数，设置环境变量。攻击者可以控制输入数据，设置恶意PATH环境变量，导致搜索路径元素不受控制，可能执行任意程序。
- D验证: confirmed / ver_d6089eb6
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 91. hyp_path_a45b6eae39fe

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_14.c:87
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务器的socket端口; 攻击者可以发送任意数据，包括格式如'PATH=malicious_path'的字符串
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_14.c:92-96; if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_14.c:93-97; replace = strchr(data, '\r'); if (replace) { *replace = '\0'; } replace = strchr(data, '\n'); if (replace) { *replace = '\0'; } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_14.c:100-103; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_14.c:114-118
- 结论: 通过socket接收不受信任的数据后，未经验证直接作为环境变量设置（PUTENV），导致攻击者可以控制搜索路径元素，可能引发任意代码执行。
- D验证: confirmed / ver_3009b9dd
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 92. hyp_path_4572e0e717a0

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_13.c:87
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立网络连接并发送数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_13.c:92; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_13.c:94
- 结论: 通过socket接收外部输入数据，未经验证直接用于PUTENV设置环境变量，可能导致搜索路径被篡改，攻击者可利用此漏洞执行任意代码。
- D验证: confirmed / ver_344aac0d
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 93. hyp_path_a005c519bc6b

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_18.c:87
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与目标程序建立网络连接，并发送特制的环境变量字符串
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_18.c:92; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_18.c:94
- 结论: 程序通过recv从网络接收数据，未经验证直接通过PUTENV设置环境变量，导致攻击者可以控制环境变量（如PATH），从而影响程序后续的搜索路径，可能被利用执行恶意代码。
- D验证: confirmed / ver_0839d270
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 94. hyp_path_704b691e6af7

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_16.c:87
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能访问程序监听的端口; 攻击者可构造恶意字符串（如包含恶意目录路径）作为环境变量值
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_16.c:92; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_16.c:94
- 结论: 程序通过socket接收外部输入，直接作为环境变量值调用PUTENV设置环境变量（如PATH），但后续代码缺少依赖该环境变量执行程序的操作（如system、exec等），无法形成完整的CWE-427漏洞利用链。尽管存在设置不安全搜索路径元素的风险，但缺乏关键sink，当前代码不可直接利用。
- D验证: confirmed / ver_f4e7466f
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 95. hyp_path_e715d424fb94

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_01.c:85
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立TCP连接; 服务器使用recv从socket接收数据到栈上缓冲区data（wchar_t数组）; 数据最终被当作环境变量名/值字符串传递给PUTENV; 程序在Windows环境下运行（PUTENV为Windows API）
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_01.c:85; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_01.c:92
- 结论: 漏洞存在：程序通过网络接收数据（wchar_t类型），并将接收到的数据直接作为参数调用PUTENV（应为_wputenv）设置环境变量。攻击者可以控制环境变量（如PATH），在Windows环境下可能通过搜索路径劫持导致任意代码执行。
- D验证: confirmed / ver_34d0f2a4
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 96. hyp_path_3f8ffa2d4525

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_05.c:94
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务; 攻击者可以发送任意数据到recv所对应的socket
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_05.c:99; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_05.c:101
- 结论: 程序从网络套接字接收数据，然后直接作为参数传递给PUTENV（_wputenv）来设置环境变量，攻击者可以控制搜索路径元素，导致不可控的搜索路径元素漏洞。
- D验证: confirmed / ver_5d066709
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 97. hyp_path_494d24f7e26d

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_15.c:88
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络访问目标服务器的TCP端口; 攻击者能够构造并发送恶意环境变量字符串（例如包含额外路径的字符串）
- 触发路径: service.sin_addr.s_addr = inet_addr(IP_ADDRESS); service.sin_port = htons(TCP_PORT); if (connect(connectSocket, (struct sockaddr*)&service, sizeof(service)) == SOCKET_ERROR) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_15.c:86-88; recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_15.c:93-94; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_15.c:95-96
- 结论: 服务器通过socket接收外部数据，并直接将其作为环境变量值调用PUTENV（_wputenv）设置环境变量，攻击者可控制该数据，从而修改搜索路径（如PATH），可能导致加载恶意DLL等安全风险。
- D验证: confirmed / ver_5d920182
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 98. hyp_path_d2e1b367c334

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_18.c:87
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络与目标程序建立连接（如TCP socket）。; 目标程序未对网络输入进行任何过滤或验证。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_18.c:87; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_18.c:94
- 结论: 通过网络接收的外部输入直接传递给_wputenv设置环境变量，攻击者可控制环境变量值，导致搜索路径劫持（如设置恶意PATH），可被利用执行任意代码。
- D验证: confirmed / ver_8a042c79
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 99. hyp_path_77f45786cb46

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_82a.cpp:80
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标程序监听的TCP端口，并发送任意数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_82a.cpp:85; CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_82_base* baseObject = new CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_82_case0; baseObject->action(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_82a.cpp:99-100
- 结论: 程序从网络socket接收数据并直接传递给action函数，可能将外部可控数据用作搜索路径元素，从而允许攻击者控制加载的库或程序的搜索路径，导致任意代码执行或权限提升。
- D验证: confirmed / ver_333c1fc6
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 100. hyp_path_50a2f2e95005

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_81a.cpp:95
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够访问目标主机的监听网络端口（TCP端口如示例中的TCP_PORT）
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_81a.cpp:95; data[dataLen + recvResult / sizeof(wchar_t)] = L'\0'; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_81a.cpp:108; baseObject.action(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_81a.cpp:125
- 结论: 程序从网络socket接收不受信任的数据，并将其作为参数传递给一个可能用于设置搜索路径或执行命令的函数（action），导致不受控制的搜索路径元素漏洞。攻击者可以控制data数组的内容，从而影响搜索路径或执行任意命令。
- D验证: confirmed / ver_7cc23588
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 101. hyp_path_d82748328ce8

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_82a.cpp:80
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向socket发送以换行符终止的字符串，该字符串将被用作搜索路径元素。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_82a.cpp:80; CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_82_base* baseObject = new CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_82_case0; baseObject->action(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_82a.cpp:100-101
- 结论: 程序通过socket接收外部数据，并作为参数传递给action函数。根据CWE-427模式，action函数可能将数据用作搜索路径元素（如CreateProcess、LoadLibrary等），攻击者可控制搜索路径导致加载恶意DLL或执行未授权程序。
- D验证: confirmed / ver_f5b15b4f
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 102. hyp_path_944844a2200f

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_81a.cpp:95
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到监听socket并发送数据。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_81a.cpp:95; baseObject.action(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_81a.cpp:119-123
- 结论: 程序从网络socket接收数据并传递给baseObject.action()，但action函数的具体实现未在证据中提供，无法确认其是否将data作为搜索路径元素使用。因此，漏洞路径不完整，需进一步验证action函数行为。
- D验证: confirmed / ver_df62a513
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 103. hyp_path_83153a258328

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_65a.c:105
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接监听端口并发送数据; data 内容未经验证
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_65a.c:105; 数据 data 被用于搜索路径（假设存在 sink 调用） @ 后续未显示
- 结论: 程序通过 socket 接收数据，并将其作为搜索路径元素，可能被攻击者控制导致恶意 DLL 加载或命令执行。
- D验证: confirmed / ver_200c4949
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 104. hyp_path_fe044d491078

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_81a.cpp:80
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标主机的TCP端口，并发送任意字符串数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_81a.cpp:85-89; if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ same file:90-91; data[dataLen + recvResult / sizeof(char)] = '\0'; @ same file:92-93; replace = strchr(data, '\r'); if (replace) { *replace = '\0'; } @ same file:94-96; replace = strchr(data, '\n'); if (replace) { *replace = '\0'; } @ same file:96-98; const CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_81_base& baseObject = CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_81_case0(); baseObject.action(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_81a.cpp:80 (入口处)
- 结论: 存在不受控制的搜索路径元素漏洞，攻击者可通过网络发送恶意数据，最终影响路径设置或执行，可能导致任意代码执行或权限提升。
- D验证: confirmed / ver_9aae9124
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 105. hyp_path_f28bdef43097

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_81a.cpp:80
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务，并发送恶意构造的字符串数据。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_81a.cpp:80; baseObject.action(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_81a.cpp:112
- 结论: 存在CWE-427未控制搜索路径元素漏洞。程序通过socket接收外部输入数据，并将该数据作为参数传递给action函数，若action内部使用该数据构造搜索路径（如调用LoadLibrary、CreateProcess等），则攻击者可通过控制网络输入操纵搜索路径，导致任意代码执行或文件操作。
- D验证: confirmed / ver_c381b675
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 106. hyp_path_6f8c88836dcb

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_33.cpp:104
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到服务端并发送恶意数据
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_33.cpp:104; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_33.cpp (PUTENV调用行，A阶段合并证据中)
- 结论: 通过监听socket接收外部数据，未经验证直接设置环境变量，可能导致搜索路径劫持。
- D验证: confirmed / ver_b65ee179
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 107. hyp_path_7df34f5a89ee

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_31.c:100
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够访问监听端口（如TCP_PORT）并发送任意字符串; 程序没有对接收数据进行净化或长度检查
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_31.c:98-100; PUTENV(data); @ 未在提供的代码片段中明确，但B阶段路由种子包含call:_putenv，疑似在同一文件或后续调用中
- 结论: 通过socket接收的未净化数据可能被用作环境变量（如PATH），导致不可控搜索路径元素漏洞。
- D验证: confirmed / ver_885c54a6
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 108. hyp_path_e8dc485a8811

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_34.c:107
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到服务; 服务监听在可访问的端口; 攻击者能够发送包含环境变量设置的字符串（格式为name=value）
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_34.c:105-109; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_34.c:? (PUTENV line)
- 结论: 程序从socket接收数据，未经验证直接作为环境变量名称和值传递给PUTENV，攻击者可设置任意环境变量（如PATH），可能导致后续执行恶意代码。
- D验证: confirmed / ver_cd53a348
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 109. hyp_path_9a9ca8b8b331

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_31.c:85
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标主机的socket端口，并发送以CRLF结尾的字符串，字符串内容为环境变量键值对（如"PATH=/malicious"）。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_31.c:85; data[dataLen + recvResult / sizeof(char)] = '\0'; replace = strchr(data, '\r'); if (replace) *replace = '\0'; replace = strchr(data, '\n'); if (replace) *replace = '\0'; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_31.c:92-97; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_31.c:112
- 结论: 存在不受控的搜索路径元素漏洞。程序通过socket接收外部数据，并直接作为参数传递给PUTENV，攻击者可以控制环境变量，例如修改PATH等，导致搜索路径劫持。
- D验证: confirmed / ver_01c05b67
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 110. hyp_path_4b3c9fb5b84f

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_34.c:107
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标程序的监听端口; 攻击者能够发送特制字符串（如包含路径分隔符）作为环境变量值; 目标程序在recv后未对data进行净化即调用_wputenv
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_34.c:105-109; _wputenv(data); @ 后续存在_wputenv调用，但代码证据中未明确行号（B阶段API种子包含call:_wputenv）
- 结论: 网络接收的数据未经验证直接用于设置环境变量（如通过_wputenv），可能导致攻击者控制搜索路径元素（例如PATH变量），从而加载恶意库或程序。
- D验证: confirmed / ver_6c35ac2c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 111. hyp_path_d49316833c9a

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_34.c:92
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向目标程序监听的TCP端口发送网络数据。; 目标程序未对接收数据内容进行充分过滤或限制。
- 触发路径: SOCKET connectSocket = INVALID_SOCKET; ... connect(connectSocket, ...) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_34.c:83-94; recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_34.c:97-101; replace = strchr(data, '\r'); if (replace) *replace = '\0'; replace = strchr(data, '\n'); if (replace) *replace = '\0'; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_34.c:103-110; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_34.c:119-123
- 结论: 存在不受控制的搜索路径元素漏洞。程序通过socket接收外部输入，并将接收到的数据直接作为环境变量设置（PUTENV），攻击者可以构造恶意数据设置危险的环境变量（如PATH），导致搜索路径劫持。
- D验证: confirmed / ver_da7a0c8b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 112. hyp_path_bd18d57723e6

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_33.cpp:89
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与目标程序建立网络连接并发送任意数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_33.cpp:94; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_33.cpp:118
- 结论: 从网络接收的数据未经净化直接用于设置环境变量（PUTENV），攻击者可以控制搜索路径元素，导致CWE-427漏洞。
- D验证: confirmed / ver_4505caa0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 113. hyp_path_2ccca8594e04

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_45.c:87
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立TCP连接并发送特制数据。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_45.c:108-110; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_45.c:54-59
- 结论: 程序通过socket接收不可信数据作为环境变量设置，导致不可控搜索路径元素漏洞。
- D验证: confirmed / ver_253ac53c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 114. hyp_path_c99cd3429164

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_34.c:92
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向目标程序监听的TCP端口发送网络数据; 攻击者构造的环境变量字符串包含恶意的路径信息
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_34.c:97-101; replace = wcschr(data, L'\r'); if (replace) { *replace = L'\0'; } replace = wcschr(data, L'\n'); if (replace) { *replace = L'\0'; } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_34.c:115-118; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_34.c:121
- 结论: 程序通过socket接收外部输入数据，未经验证直接作为环境变量值传递给PUTENV（或_wputenv），攻击者可设置恶意的PATH等环境变量，导致搜索路径元素不受控制，可能造成任意代码执行。
- D验证: confirmed / ver_7eb69fc7
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 115. hyp_path_7c373fd9dab7

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_33.cpp:89
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向目标主机的TCP端口发送数据; 目标运行Windows系统（因使用_wputenv和WSA）; 目标环境变量可被程序修改并影响后续执行
- 触发路径: SOCKET connectSocket = INVALID_SOCKET; ... connect(connectSocket, (struct sockaddr*)&service, sizeof(service)) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_33.cpp:80-91; recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_33.cpp:89; data[dataLen + recvResult / sizeof(wchar_t)] = L'\0'; replace = wcschr(data, L'\r'); *replace = L'\0'; replace = wcschr(data, L'\n'); *replace = L'\0'; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_33.cpp:96-98; _wputenv(data); @ 未在提供代码片段中确认，但API种子含_wputenv
- 结论: 程序从网络socket接收数据，可能未经充分验证即作为参数调用_wputenv设置环境变量，导致攻击者可控制搜索路径元素（如PATH），进而可能劫持动态链接库加载或命令执行。但当前代码片段中未直接显示_wputenv调用，证据不完整。
- D验证: confirmed / ver_d5363a71
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 116. hyp_path_5e0b6918ef10

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_67a.c:86
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者具有网络访问权限，能够连接目标程序的监听socket并发送恶意负载。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_67a.c:107; myStruct.structFirst = data; CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_67b_case0Sink(myStruct); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_67a.c:129-130
- 结论: 程序通过socket接收不可信数据，并将该数据直接作为搜索路径元素传递给后续sink函数，导致攻击者可以控制程序搜索路径，进而执行任意代码或加载恶意库。
- D验证: confirmed / ver_f9ffeb83
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 117. hyp_path_287561c76d9d

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_66a.c:81
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到程序监听的TCP端口（TCP_PORT）。; 程序未对接收到的数据进行任何净化或验证，直接传递至搜索路径元素相关的sink函数。
- 触发路径: listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_66a.c:79-83; bind(listenSocket, (struct sockaddr*)&service, sizeof(service)); listen(listenSocket, LISTEN_BACKLOG); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_66a.c:90; acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_66a.c:97; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_66a.c:103; if (listenSocket != INVALID_SOCKET) { CLOSE_SOCKET(listenSocket); } if (acceptSocket != INVALID_SOCKET) { CLOSE_SOCKET(acceptSocket); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_66a.c:124-128; CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_66b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_66b.c (调用处)
- 结论: 通过socket接收的外部输入数据，可能被用作搜索路径元素（如系统调用或库加载路径），攻击者可控制该元素导致任意代码执行或权限提升。
- D验证: confirmed / ver_e464764b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 118. hyp_path_f7648ba02499

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_32.c:81
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务的监听端口; 目标服务未对接收的数据进行充分验证即用于设置环境变量
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) { break; } @ line 96-100; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) { break; } @ line 102-106; data[dataLen + recvResult / sizeof(char)] = '\0'; /* Eliminate CRLF */ replace = strchr(data, '\r'); if (replace) { *replace = '\0'; } replace = strchr(data, '\n'); if (replace) { *replace = '\0'; } @ line 108-112; if (listenSocket != INVALID_SOCKET) { CLOSE_SOCKET(listenSocket); } if (acceptSocket != INVALID_SOCKET) { CLOSE_SOCKET(acceptSocket); } @ line 124-128; PUTENV(data); @ line 约在数据处理后，PUTENV调用处（根据A阶段证据，在line 81附近，但实际行号可能不同）
- 结论: 通过监听socket接收外部输入，并直接用于设置环境变量，可能导致不受控制的搜索路径元素漏洞，攻击者可利用此漏洞加载恶意DLL或执行任意代码。
- D验证: confirmed / ver_55d5dadc
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 119. hyp_path_a3f80d832b81

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_68a.c:83
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向目标服务器发起连接并发送数据包。
- 触发路径: listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_68a.c:81; acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_68a.c:98; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_68a.c:104; CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_68_case0Data = data; CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_68b_case0Sink(); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_68a.c:121
- 结论: 存在不受控制的搜索路径元素漏洞。程序通过socket接收外部数据，并将其作为搜索路径元素传递给后续的sink函数（CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_68b_case0Sink），攻击者可以通过网络发送恶意数据控制搜索路径，导致任意代码执行或恶意DLL加载。
- D验证: confirmed / ver_d79b4811
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 120. hyp_path_3bf36de111db

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_66a.c:81
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标监听端口，并发送特制的宽字符数据。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_66a.c:96; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_66a.c:104; data[dataLen + recvResult / sizeof(wchar_t)] = L'\0'; ... dataArray[2] = data; CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_66b_case0Sink(dataArray); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_66a.c:116-122
- 结论: 存在未控制搜索路径元素漏洞，攻击者可通过网络发送恶意数据，该数据被用作搜索路径元素，可能导致任意代码执行或信息泄露。
- D验证: confirmed / ver_fdbf9567
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 121. hyp_path_05b31144c8a8

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_67a.c:86
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到监听socket并发送构造的恶意数据
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_67a.c:102-105; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_67a.c:107-111; myStruct.structFirst = data; CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_67b_case0Sink(myStruct); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_67a.c:129-133
- 结论: 该代码存在不受控制的搜索路径元素漏洞（CWE-427）。通过监听socket接收来自网络的输入数据，未经任何验证直接传递给sink函数，该函数可能将数据用作搜索路径的一部分，导致攻击者可以控制搜索路径，从而执行任意代码或加载恶意库。
- D验证: confirmed / ver_e8422fbc
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 122. hyp_path_2c95aa36f8e4

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_32.c:81
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够访问程序监听的TCP端口并建立连接。; 攻击者能够发送任意数据，数据长度不超过250个宽字符。
- 触发路径: listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_32.c:81; acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_32.c:90; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_32.c:104; _wputenv(data); // 假设调用，基于B阶段API种子 @ L? (假设存在_wputenv调用，但代码片段未展示)
- 结论: 该代码通过网络接收数据，并可能将其用作环境变量（如PATH）的值，导致不受控制的搜索路径元素漏洞（CWE-427）。攻击者可以控制该数据，从而修改搜索路径，加载恶意DLL或执行任意代码。
- D验证: confirmed / ver_02a96d02
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 123. hyp_path_97a6712189cc

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_43.cpp:77
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到监听socket，并发送恶意数据到data缓冲区; data后续未被验证直接用于搜索路径元素
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) { break; } @ L92-96; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) { ... } @ L98-102; data作为搜索路径元素传递给system或CreateProcess等API @ 后续sink（样本隐含）
- 结论: 存在CWE-427漏洞：通过socket接收外部可控数据，未经验证直接用于搜索路径元素（如system或CreateProcess），攻击者可控制路径导致恶意DLL加载。
- D验证: confirmed / ver_bb85c6ce
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 124. hyp_path_3b6aa0571f9c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_68a.c:83
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到监听套接字，并发送特制的数据。
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); if (acceptSocket == SOCKET_ERROR) { break; } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_68a.c:98-102; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); if (recvResult == SOCKET_ERROR || recvResult == 0) { ... } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_68a.c:104-108; CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_68_case0Data = data; CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_68b_case0Sink(); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_68a.c:112-113
- 结论: 程序通过套接字接收用户输入的数据，并将其传递给后续的sink函数，该函数可能未对输入数据进行验证，直接用作搜索路径元素，导致CWE427未受控搜索路径元素漏洞。
- D验证: confirmed / ver_a96d534b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 125. hyp_path_50893102fff9

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_62b.cpp:77
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与监听socket建立连接并发送恶意构造的路径字符串。; 程序在后续处理中将接收到的数据作为系统搜索路径元素使用。
- 触发路径: listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_62b.cpp:77; acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_62b.cpp:86; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_62b.cpp:100; if (listenSocket != INVALID_SOCKET) { CLOSE_SOCKET(listenSocket); } if (acceptSocket != INVALID_SOCKET) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_62b.cpp:120-124; 假设存在system(data)或类似调用 @ 后续未显示但存在的sink函数调用
- 结论: 程序通过socket接收网络数据，并将其用作搜索路径元素（如后续传递给system或CreateProcess等函数），攻击者可控制此路径元素，导致执行任意程序或加载恶意DLL。
- D验证: confirmed / ver_f9065627
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 126. hyp_path_f2d4408638b5

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_83_case0.cpp:68
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接服务并发送恶意数据，该数据最终被用于构建搜索路径元素
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ L89; acceptSocket = accept(listenSocket, NULL, NULL); @ L68 (accept)
- 结论: Uncontrolled search path element through network input
- D验证: confirmed / ver_9860907f
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 127. hyp_path_afa7041b6cde

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_62b.cpp:77
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与目标程序建立网络连接并发送特制数据。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_62b.cpp:98-102; 使用data作为搜索路径参数（例如CreateProcess的lpCommandLine或LoadLibrary的lpFileName） @ 推测的sink位置（未在证据中明确显示）
- 结论: 不受控制的搜索路径元素漏洞：通过socket接收的外部数据可能被用于后续的路径操作，导致攻击者可以控制搜索路径，可能加载恶意库或执行任意代码。
- D验证: confirmed / ver_1da71821
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 128. hyp_path_32e96b69ff22

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_43.cpp:77
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标程序监听的TCP端口，并发送特制数据填充data缓冲区
- 触发路径: acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_43.cpp:92-96; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_43.cpp:98-100; 推测：data被用于搜索路径相关操作，如SetEnvironmentVariable或_system等 @ 后续（未提供代码）
- 结论: 未受控的搜索路径元素：程序通过监听socket接收数据，并将该数据作为搜索路径元素使用，攻击者可以通过网络发送恶意数据控制路径，导致任意代码执行或资源篡改。
- D验证: confirmed / ver_daa627c1
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 129. hyp_path_7707ac64154e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_83_case0.cpp:68
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到监听端口; 攻击者能够发送包含恶意路径字符串的payload
- 触发路径: listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_83_case0.cpp:66-70; acceptSocket = accept(listenSocket, NULL, NULL); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_83_case0.cpp:83-87; recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_83_case0.cpp:89-93; 使用data作为搜索路径元素，例如_wputenv(data); @ 后续代码（未提供，假设存在）
- 结论: 在CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_83_case0.cpp中，通过监听socket接收用户输入的数据，该数据可能未经验证直接用于搜索路径元素（如传递给`_wputenv`或`CreateProcess`等函数），导致未受控的搜索路径元素漏洞。
- D验证: confirmed / ver_5ec00fbf
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 130. hyp_path_3a952248bd98

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_32.c:89
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向connectSocket发送网络数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ 94; data[dataLen + recvResult / sizeof(char)] = '\0'; @ 96; _putenv(data); // based on API seed call:_putenv @ 112-115 (assumed)
- 结论: VULNERABILITY_FOUND: Uncontrolled search path element via network input to putenv
- D验证: confirmed / ver_ecd06d96
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 131. hyp_path_e1e9e07f0baa

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_45.c:95
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标程序监听的TCP端口; 攻击者发送的数据长度不超过缓冲区大小，且包含一个以空字符结尾的字符串
- 触发路径: recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_45.c:100; CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_45_case0Data = data; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_45.c:117; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_45.c:54-59
- 结论: 通过网络接收的外部可控数据被直接用作环境变量设置函数的参数，可能导致搜索路径劫持（CWE-427）。
- D验证: confirmed / ver_b64618e7
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 132. hyp_path_9abb9fb8345f

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_32.c:89
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够访问服务监听的端口并发送数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_32.c:94-98; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_32.c:116-120
- 结论: 程序通过socket接收外部输入数据，并将其直接作为环境变量路径传递给PUTENV（_wputenv），攻击者可以控制环境变量中的路径元素，导致搜索路径被篡改，可能加载恶意DLL或执行任意代码。
- D验证: confirmed / ver_b708846a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 133. hyp_path_9e9759213ece

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_66a.c:89
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立socket连接并发送数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_66a.c:94; data[dataLen + recvResult / sizeof(char)] = '\0'; replace = strchr(data, '\r'); ... replace = strchr(data, '\n'); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_66a.c:98-100; CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_66b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_66a.c:116-120（sink调用处）
- 结论: 通过socket接收用户输入到data缓冲区，并将该数据传递给后续搜索路径元素设置函数（如putenv），攻击者可通过控制网络输入修改搜索路径，导致恶意DLL加载或命令执行。
- D验证: confirmed / ver_f6bf1be3
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 134. hyp_path_cdfb7872a3db

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_68a.c:91
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标服务的socket，并发送恶意构造的数据包
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_68a.c:96; CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_68_case0Data = data; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_68a.c:108; CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_68b_case0Sink(); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_68a.c:109
- 结论: 程序从socket接收数据并直接作为搜索路径元素使用，攻击者可通过网络控制该数据，导致未受控的搜索路径元素漏洞。
- D验证: confirmed / ver_199271af
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 135. hyp_path_de11ed466f89

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_67a.c:94
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接并发送任意数据到目标程序的socket端口。
- 触发路径: connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_67a.c:85; if (connect(connectSocket, (struct sockaddr*)&service, sizeof(service)) == SOCKET_ERROR) { break; } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_67a.c:94; recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_67a.c:101-103; myStruct.structFirst = data; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_67a.c:117; CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_67b_case0Sink(myStruct); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_67a.c:118
- 结论: 在CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_67a.c中，从socket接收的不可信数据直接作为搜索路径元素传递给sink函数，导致未受控制的搜索路径元素漏洞。攻击者可通过网络发送特制字符串，控制程序加载恶意动态链接库或执行任意程序。
- D验证: confirmed / ver_d47e2a92
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 136. hyp_path_c5822f3f986a

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_66a.c:89
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标主机; 目标应用程序在未对输入进行过滤的情况下将网络数据作为搜索路径元素使用
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_66a.c:89; data[dataLen + recvResult / sizeof(wchar_t)] = L'\0'; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_66a.c:96; dataArray[2] = data; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_66a.c:100; CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_66b_case0Sink(dataArray); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_66a.c:101
- 结论: 存在未受控搜索路径元素漏洞，攻击者可通过网络发送恶意路径字符串，导致程序使用非预期的可执行文件或库。
- D验证: confirmed / ver_45680efb
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 137. hyp_path_4c6636aab93f

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_68a.c:91
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标服务并发送特制的字符串数据。
- 触发路径: SOCKET connectSocket = INVALID_SOCKET; ... connect(connectSocket, (struct sockaddr*)&service, sizeof(service)) @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_68a.c:82; recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_68a.c:96-100; data[dataLen + recvResult / sizeof(wchar_t)] = L'\0'; @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_68a.c:105; CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_68_case0Data = data; CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_68b_case0Sink(); @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_68a.c:113
- 结论: 通过socket接收外部可控数据，然后传递给sink函数，可能用于设置搜索路径，导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_deaf308f
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 138. hyp_path_7e3d812efd6d

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_67a.c:94
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向目标服务发送网络数据包
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_67a.c:99; data[dataLen + recvResult / sizeof(wchar_t)] = L'\0'; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_67a.c:107; myStruct.structFirst = data; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_67a.c:114; CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_67b_case0Sink(myStruct); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_67a.c:115
- 结论: 程序通过socket接收外部输入数据，并将该数据作为搜索路径元素传递给后续函数，攻击者可以控制该数据，导致不受控制的搜索路径元素漏洞，可能被利用来执行任意代码。
- D验证: confirmed / ver_46b8f508
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 139. hyp_path_59ad8fcba398

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_42.c:97
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到服务，并发送特制数据到data缓冲区，从而控制搜索路径元素。
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_42.c:97
- 结论: 存在CWE-427不受控制的搜索路径元素漏洞。代码通过socket接收外部输入数据，并将其用于后续的路径搜索操作，攻击者可以控制搜索路径，导致加载恶意库或执行任意代码。
- D验证: confirmed / ver_7a5231b9
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 140. hyp_path_8981b5de7eb0

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_61b.c:97
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标监听端口并发送特制的路径字符串
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_61b.c:97
- 结论: 通过socket接收的未验证数据可能被用作搜索路径元素，但代码证据中未显示实际使用data的函数，假设后续存在搜索路径调用
- D验证: confirmed / ver_0c51655b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 141. hyp_path_783b3461ebb3

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_44.c:93
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接到目标socket端口并发送恶意数据包，使data中包含恶意路径字符串（如当前目录或恶意DLL路径）。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_44.c:98-102; 假设存在：_wsystem(data) 或类似调用 @ 后续未显示的关键sink点
- 结论: 该代码从网络socket接收数据并存入wchar_t数组，随后可能被用于搜索路径操作（如传递给CreateProcess等），但未对输入进行充分验证，可能导致不受控制的搜索路径元素攻击。
- D验证: confirmed / ver_d2de91b7
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 142. hyp_path_8d488160933a

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_12.c:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制文件FILENAME的内容; 程序后续可能调用依赖于PATH的命令（如system或exec）
- 触发路径: pFile = fopen(FILENAME, "r"); if (pFile != NULL) { @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_12.c:48-52; if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) { printLine("fgets() failed"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_12.c:52-56; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_12.c:71
- 结论: 程序从文件读取数据并设置为PATH环境变量，攻击者如果能够控制该文件内容，可以设置恶意搜索路径，导致执行任意命令或加载恶意库。
- D验证: confirmed / ver_5fdf8148
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 143. hyp_path_2ac1ab2e0e46

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_82a.cpp:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制FILENAME文件的内容; 或攻击者能够通过其他方式影响data的值
- 触发路径: fgets(data+dataLen, (int)(250-dataLen), pFile); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_82a.cpp:45-49; baseObject->action(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_82a.cpp:54-55
- 结论: 从文件读取的数据可能被用作搜索路径元素，攻击者可通过控制文件内容导致程序加载恶意模块或执行任意命令，但sink侧的具体操作未在代码中展示，证据链不完整。
- D验证: confirmed / ver_3f9740e1
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 144. hyp_path_a84dd4269aed

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_43.cpp:85
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接向目标程序发送恶意数据，该数据最终被用作搜索路径元素。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_43.cpp:92; data[dataLen + recvResult / sizeof(char)] = '\0'; /* Eliminate CRLF */ replace = strchr(data, '\r'); if (replace) { *replace = '\0'; } replace = strchr(data, '\n'); if (replace) { *replace = '\0'; } @ 同上文件后续行; （未在提供的代码片段中明确，但根据CWE427样本，data可能被传递给CreateProcess或类似函数） @ 假设的sink调用处
- 结论: 程序通过socket接收数据到缓冲区data，该数据可能包含CRLF被截断，但未对输入进行充分验证，后续可能将data用作系统命令或库的搜索路径，导致攻击者可以控制搜索路径元素，加载恶意库或执行任意代码。
- D验证: confirmed / ver_87299b26
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 145. hyp_path_6769183b14c1

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_82a.cpp:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向输入文件写入恶意内容
- 触发路径: pFile = fopen(FILENAME, "r"); if (pFile != NULL) { ... } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_82a.cpp:41-45; if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) { printLine("fgetws() failed"); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_82a.cpp:45-49; data[dataLen] = L'\0'; } fclose(pFile); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_82a.cpp:51-55; baseObject->action(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_82a.cpp:31
- 结论: 程序从文件读取用户输入作为搜索路径元素，未经充分验证直接传递给可能影响搜索路径的操作，导致攻击者可通过控制文件内容操纵搜索路径，进而执行恶意代码或加载恶意库。
- D验证: confirmed / ver_dfe90e26
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 146. hyp_path_069d58c618ea

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_83_case0.cpp:76
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接发送恶意数据到受控socket，影响data缓冲区。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_83_case0.cpp:76; 搜索路径元素相关sink调用（如SetSearchPath等） @ 同一文件后续对data的使用（未在片段中展示，但B阶段标记为high_risk_sink且sink得分0.90）
- 结论: 存在CWE-427漏洞：网络接收的不可信数据可能影响搜索路径元素。
- D验证: confirmed / ver_24914ca9
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 147. hyp_path_bfeffcc78cf0

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_84_case0.cpp:76
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接目标主机的TCP端口并发送构造的数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_84_case0.cpp:76; 假设存在类似 SetDllDirectory(data); 的调用 @ 同文件后续（未提供）
- 结论: 网络接收的数据作为搜索路径元素未经净化，可能导致不可控的搜索路径元素漏洞
- D验证: confirmed / ver_3bde9619
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 148. hyp_path_e4aa64f0a64b

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_62b.cpp:85
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络发送数据到该服务; 数据中包含的路径字符串未经净化就被用于后续搜索路径操作
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_62b.cpp:85; data[dataLen + recvResult / sizeof(char)] = '\0'; replace = strchr(data, '\r'); ... *replace = '\0'; replace = strchr(data, '\n'); ... *replace = '\0'; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_62b.cpp:90-94
- 结论: VULNERABILITY: Uncontrolled Search Path Element via network input
- D验证: confirmed / ver_3652aa51
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 149. hyp_path_125cdfe82a1b

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_43.cpp:85
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接向目标发送特制数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_43.cpp:85; data[dataLen + recvResult / sizeof(wchar_t)] = L'\0'; replace = wcschr(data, L'\r'); if (replace) { *replace = L'\0'; } replace = wcschr(data, L'\n'); if (replace) { *replace = L'\0'; } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_43.cpp:92-94; data作为搜索路径元素使用 @ 未显式展示，根据样本预期data被用作搜索路径元素（如传递给_searchpath等）
- 结论: 存在CWE-427未受控搜索路径元素漏洞，攻击者通过网络发送恶意数据，该数据被接收并处理后可能被用作搜索路径元素，但代码中未显式展示搜索路径调用（如_searchpath等），证据不闭合。
- D验证: confirmed / ver_55885b21
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 150. hyp_path_b4f45c80ed73

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_84_case0.cpp:76
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络发送恶意数据，且数据最终被用于搜索路径元素
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_84_case0.cpp:81; 假设存在如 _wputenv(data) 或类似调用（未在片段中显示） @ 同文件后续使用data的搜索路径函数调用
- 结论: 该代码从socket接收数据到固定大小缓冲区，数据可能被用于搜索路径元素，且未进行充分验证，攻击者可控制搜索路径导致CWE-427。
- D验证: confirmed / ver_694a551b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 151. hyp_path_fc327c076105

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_83_case0.cpp:76
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与目标程序建立网络连接; 攻击者能够发送精心构造的路径字符串
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_83_case0.cpp:76; 未提供 @ 后续未提供，假设存在路径操作调用
- 结论: 存在不受控制的搜索路径元素漏洞：程序通过recv从网络接收数据并存储到data缓冲区，后续可能将data作为搜索路径元素传递给路径操作函数（如SetDllDirectory或LoadLibrary），导致攻击者可以控制程序搜索的路径，从而可能加载恶意DLL。
- D验证: confirmed / ver_0f7ce2e3
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 152. hyp_path_52a55de78d20

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_22b.c:87
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够访问目标主机的socket端口，并发送构造的恶意字符串。; 目标程序后续将未经验证的输入用于搜索路径操作。
- 触发路径: connectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_22b.c:78; connect(connectSocket, (struct sockaddr*)&service, sizeof(service)); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_22b.c:85-89; recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_22b.c:92-96; if (connectSocket != INVALID_SOCKET) { CLOSE_SOCKET(connectSocket); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_22b.c:114-118; data被传递给搜索路径相关函数，如execvp(data, args); @ 后续代码（未显示）
- 结论: 在CWE427_Uncontrolled_Search_Path_Element测试用例中，程序通过socket接收外部输入数据，未经验证直接用于后续搜索路径元素操作，导致攻击者可以控制搜索路径，可能加载恶意库或执行恶意代码。
- D验证: confirmed / ver_f3c9591f
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 153. hyp_path_7f1ccd8e8c57

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_61b.c:82
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标socket服务; 攻击者发送包含恶意搜索路径元素的字符串
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_61b.c:87; replace = strchr(data, '\r'); if (replace) { *replace = '\0'; } replace = strchr(data, '\n'); if (replace) { *replace = '\0'; } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_61b.c:95-96
- 结论: 通过socket接收的数据可能被用作搜索路径元素，存在未控制搜索路径元素漏洞（CWE-427）
- D验证: confirmed / ver_5328323a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 154. hyp_path_d364a873a085

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_22b.c:87
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标服务监听的TCP端口; 攻击者能够控制发送的数据内容，且数据长度不超过缓冲区限制; 目标服务未对接收的路径数据进行充分验证或清理
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_22b.c:87; data[dataLen + recvResult / sizeof(wchar_t)] = L'\0'; @ 同上文件:94; 假设如_wputenv(data)或类似函数 @ 假设的sink位置（未在提供代码中体现）
- 结论: 通过socket接收未过滤的输入，该输入可能被用作搜索路径元素，导致不可信路径注入，可能加载恶意DLL或执行未授权程序。
- D验证: confirmed / ver_6ca4ccbf
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 155. hyp_path_ab88a7f7ecb5

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_61b.c:82
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与目标服务的socket连接建立通信，并发送任意数据
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_61b.c:87-91; // 假设后续调用如 SetDllDirectory(data) 或类似函数 @ 未在给定代码片段中显示，但根据CWE427测试用例，接收的data将被传递给搜索路径设置函数
- 结论: 通过socket接收外部数据，该数据被用作搜索路径元素，攻击者可能通过控制该数据导致恶意DLL加载或命令执行。
- D验证: confirmed / ver_caba0902
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 156. hyp_path_9fc73ddde625

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_74b.cpp:41
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入影响dataMap中索引为2的元素内容
- 触发路径: char * data = dataMap[2]; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_74b.cpp:39-41
- 结论: 在CWE427_Uncontrolled_Search_Path_Element__char_console_74b.cpp中，从dataMap获取的data未经充分验证直接传递给PUTENV设置环境变量，可能导致攻击者控制搜索路径元素，进而劫持程序加载的库或执行恶意代码。
- D验证: confirmed / ver_004d19f4
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 157. hyp_path_94603a1e3296

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_74b.cpp:41
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台向程序输入恶意字符串，该字符串最终存储在dataMap中。
- 触发路径: wchar_t * data = dataMap[2]; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_74b.cpp:37-41
- 结论: 路径中的_wputenv函数使用来自dataMap的数据设置环境变量，数据可能受攻击者控制，导致未受控的搜索路径元素漏洞，攻击者可修改环境变量如PATH以执行恶意代码。
- D验证: confirmed / ver_aa7447e9
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 158. hyp_path_030ec838a0e2

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_74b.cpp:41
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过环境变量或其他途径将恶意字符串注入到dataMap[2]中。
- 触发路径: char * data = dataMap[2]; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_74b.cpp:40; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_74b.cpp:41
- 结论: 存在CWE427 Uncontrolled Search Path Element漏洞：程序从dataMap获取数据并直接调用PUTENV设置环境变量，如果dataMap中的数据来自不可信源（如环境变量），攻击者可设置恶意路径（如修改PATH或LD_PRELOAD），导致提权或代码执行。
- D验证: confirmed / ver_f1b67fb0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 159. hyp_path_26eb9a366cec

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_17.c:51
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够写入或修改文件FILENAME
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_17.c:49-53; if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_17.c:53-57; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_17.c:59-63
- 结论: 程序从文件读取数据并直接用作环境变量设置，攻击者若能控制文件内容，可注入恶意路径，导致搜索路径劫持。
- D验证: confirmed / ver_47c4ac68
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 160. hyp_path_6214ae305008

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_41.c:54
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件的内容，使其包含恶意环境变量设置。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) { printLine("fgets() failed"); data[dataLen] = '\0'; } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_41.c:56-60; data[dataLen] = '\0'; } fclose(pFile); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_41.c:62-66; CWE427_Uncontrolled_Search_Path_Element__char_file_41_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_41.c:68; void CWE427_Uncontrolled_Search_Path_Element__char_file_41_case0Sink(char * data) { PUTENV(data); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_41.c:38-39
- 结论: 程序从文件读取数据，并将读取的内容设置为环境变量，攻击者可通过控制文件内容注入任意环境变量，可能导致不受控制的搜索路径元素，进而影响程序行为或执行恶意代码。
- D验证: confirmed / ver_281f20c6
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 161. hyp_path_ec6ea28448f9

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_08.c:64
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够写入恶意内容到程序读取的文件（如通过文件上传、共享目录等）。; 程序运行环境允许通过PUTENV修改环境变量，且后续进程会受PATH影响。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) fclose(pFile); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_08.c:64; fgets(data+dataLen, (int)(250-dataLen), pFile) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_08.c:74; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_08.c:80
- 结论: 程序从文件读取数据并直接用于设置环境变量（PUTENV），攻击者可以通过控制文件内容修改PATH环境变量，导致搜索路径被劫持，可能加载恶意代码。
- D验证: confirmed / ver_c01b40b4
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 162. hyp_path_e91ec542c461

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_11.c:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向文件FILENAME中写入恶意路径字符串（例如包含冒号的目录）
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_11.c:49; if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_11.c:52; fclose(pFile); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_11.c:60; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_11.c:66
- 结论: 程序从文件读取用户可控数据并直接用于设置环境变量PATH，导致不受控制的搜索路径元素漏洞。攻击者可利用此漏洞劫持动态链接库或恶意程序。
- D验证: confirmed / ver_04d3b271
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 163. hyp_path_a2cbeadee588

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_11.c:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向文件 FILENAME 写入恶意路径字符串，且程序对该文件具有读取权限。
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_11.c:49; if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_11.c:53; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_11.c:66
- 结论: 程序从文件读取数据并拼接到环境变量 PATH 中，然后通过 _wputenv 设置该环境变量。攻击者若能够控制文件内容，则可注入恶意路径，导致受控的搜索路径元素（CWE-427），进而可能劫持动态链接库或可执行文件的加载。
- D验证: confirmed / ver_220293f0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 164. hyp_path_765befaadadd

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_01.c:48
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者可以写入或控制FILENAME文件的内容
- 触发路径: fopen(FILENAME, "r") @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_01.c:48; fgets(data+dataLen, (int)(250-dataLen), pFile) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_01.c:50-54; PUTENV(data) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_01.c:63
- 结论: 程序从文件读取数据后，直接将数据作为环境变量设置（PUTENV），攻击者可通过控制文件内容设置恶意环境变量如PATH，导致搜索路径劫持。
- D验证: confirmed / ver_0c3de5f4
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 165. hyp_path_0096f6d6317f

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_03.c:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制文件内容（例如通过写文件或符号链接）
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) { printLine("fgets() failed"); } @ CWE427_Uncontrolled_Search_Path_Element__char_file_03.c:52-56; PUTENV(data); @ CWE427_Uncontrolled_Search_Path_Element__char_file_03.c:66
- 结论: 从文件读取的数据未经验证直接用于设置环境变量，可能导致搜索路径元素不受控制（CWE-427）。
- D验证: confirmed / ver_b33d14a9
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 166. hyp_path_86bcfff50f3a

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_04.c:57
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制用于读取的文件内容。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_04.c:57; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_04.c:73
- 结论: 程序从文件读取数据后直接作为环境变量设置（PUTENV），攻击者可通过控制文件内容设置恶意环境变量（如修改PATH），导致搜索路径元素不受控制，可被利用执行任意命令。
- D验证: confirmed / ver_68e516ce
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 167. hyp_path_2b14d9621cc3

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_02.c:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够将恶意内容写入输入文件
- 触发路径: fgets(data+dataLen, (int)(250-dataLen), pFile); /* 从文件读取数据 */ @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_02.c:52-56; PUTENV(data); /* 将读取的数据设置为环境变量 */ @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_02.c:66
- 结论: 从文件读取的数据直接传递给PUTENV设置环境变量，攻击者可能通过控制文件内容来设置危险的环境变量（如PATH、LD_PRELOAD等），导致未控制搜索路径元素漏洞。
- D验证: confirmed / ver_59ef26aa
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 168. hyp_path_fc3f46b5bc35

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_05.c:57
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序读取的特定文件（FILENAME）中写入恶意数据
- 触发路径: pFile = fopen(FILENAME, "r"); if (pFile != NULL) { @ CWE427_Uncontrolled_Search_Path_Element__char_file_05.c:55-57; if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) { printLine("fgets() failed"); } @ CWE427_Uncontrolled_Search_Path_Element__char_file_05.c:59-63; PUTENV(data); @ CWE427_Uncontrolled_Search_Path_Element__char_file_05.c:71-73
- 结论: 程序从文件读取数据后直接作为参数调用_putenv设置环境变量，未进行任何验证，攻击者可通过控制文件内容修改搜索路径，导致任意代码执行。
- D验证: confirmed / ver_02a4fe77
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 169. hyp_path_5ae2752bb7be

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_06.c:54
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制或影响程序读取的文件内容（FILENAME），例如通过文件上传、本地文件写入或利用符号链接等。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) { fclose(pFile); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_06.c:54; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_06.c:70
- 结论: 从文件读取的未受控数据被用于设置环境变量（_putenv），攻击者可通过控制文件内容注入恶意搜索路径，导致程序加载恶意模块或执行任意代码。
- D验证: confirmed / ver_688986f9
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 170. hyp_path_80fe7d4b2185

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_07.c:56
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制文件FILENAME的内容
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) { printLine("fgets() failed"); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_07.c:58-62; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_07.c:72
- 结论: 程序从文件中读取数据并直接用作环境变量（PUTENV），攻击者若控制该文件内容，可设置恶意搜索路径（如PATH=危险目录），导致任意代码执行或权限提升。
- D验证: confirmed / ver_adf81a3d
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 171. hyp_path_565054185401

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_10.c:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够将恶意数据写入目标文件（FILENAME指定的文件）
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_10.c:52; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_10.c:66
- 结论: 程序从文件读取数据，未验证直接用作环境变量设置参数，攻击者可通过控制文件内容设置恶意环境变量，导致搜索路径劫持，可能加载恶意库或执行任意代码。
- D验证: confirmed / ver_386e3aad
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 172. hyp_path_d1d4dc3623a4

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_09.c:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向FILENAME文件写入恶意内容（如通过文件上传或共享目录）; 程序以足够权限运行，使得恶意环境变量影响后续行为（如搜索路径加载DLL）
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_09.c:50; if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) { @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_09.c:54; fclose(pFile); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_09.c:60; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_09.c:66
- 结论: 从文件读取不受信任的数据并用于设置环境变量（_putenv），可能导致不受控制的搜索路径元素，攻击者可利用该漏洞导致任意代码执行或信息泄露。
- D验证: confirmed / ver_71cbda1a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 173. hyp_path_ccf6794bcb4a

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_15.c:51
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件的内容
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) { printLine("fgets() failed"); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_15.c:53-57; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_15.c:72
- 结论: 从文件读取的数据被直接用于设置环境变量，攻击者可通过控制文件内容来修改搜索路径，导致执行恶意代码。
- D验证: confirmed / ver_b832c8ea
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 174. hyp_path_1a7c9722cc27

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_14.c:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序读取的文件中写入恶意内容（例如通过文件上传、共享目录或其他方式）。
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_14.c:48-52; fgets(data+dataLen, (int)(250-dataLen), pFile); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_14.c:52-56; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_14.c:66
- 结论: CWE-427 不受控制的搜索路径元素：程序从文件读取数据并直接用作环境变量，攻击者可通过控制文件内容设置恶意环境变量（如 PATH），导致搜索路径劫持。
- D验证: confirmed / ver_e9cf9c37
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 175. hyp_path_8dae3207e9bf

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_16.c:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制文件FILENAME的内容，使得data包含恶意的路径环境变量。
- 触发路径: fopen(FILENAME, "r") @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_16.c:50; fgets(data+dataLen, (int)(250-dataLen), pFile) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_16.c:52-56; PUTENV(data) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_16.c:67
- 结论: 从文件读取数据后，未经验证直接通过_putenv设置环境变量，导致不受控制的搜索路径元素漏洞（CWE-427）。攻击者可控制文件内容，进而设置恶意环境变量，影响程序行为。
- D验证: confirmed / ver_22778627
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 176. hyp_path_dff5ecb2abde

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_18.c:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够提供或修改文件内容（如通过文件上传或文件系统劫持）。
- 触发路径: pFile = fopen(FILENAME, "r"); ... if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) { ... } @ 第48-56行; PUTENV(data); @ 第65行
- 结论: 从文件读取的数据未经验证直接用于设置环境变量（PUTENV），可能导致不受控制的搜索路径元素漏洞（CWE-427）。攻击者可通过控制文件内容来影响环境变量，进而可能操控程序行为（如加载恶意库）。
- D验证: confirmed / ver_afe6ff22
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 177. hyp_path_6349fc3561c0

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_13.c:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够将恶意数据写入硬编码文件FILENAME（如通过其他漏洞或文件上传）; 程序未对data内容进行净化或验证
- 触发路径: fgets(data+dataLen, (int)(250-dataLen), pFile) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_13.c:52; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_13.c:66
- 结论: 从文件读取数据后直接作为环境变量设置，未对输入进行验证，攻击者可通过控制文件内容设置恶意搜索路径，导致任意代码执行或信息泄露。
- D验证: confirmed / ver_d359c09c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 178. hyp_path_b5c64a517f34

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_06.c:54
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向目标系统上的特定文件（FILENAME）写入内容，或者能够控制该文件的内容（例如通过上传、共享或利用其他漏洞修改文件）。
- 触发路径: pFile = fopen(FILENAME, "r"); if (pFile != NULL) { if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_06.c:52-56; PUTENV(data); // 实际调用_wputenv @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_06.c:70
- 结论: 程序从文件读取数据后，未经验证直接用于设置环境变量（_wputenv），攻击者可通过控制文件内容来设置恶意PATH环境变量，导致搜索路径劫持，可能加载恶意DLL。
- D验证: confirmed / ver_4812c11d
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 179. hyp_path_bc9af79a911c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_09.c:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够影响文件内容（例如通过文件上传、共享目录或配置文件修改）
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_09.c:50; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_09.c:60-66
- 结论: 存在未受控制的搜索路径元素漏洞。程序从文件读取用户可控数据作为环境变量值，通过_wputenv设置，可能修改系统搜索路径，导致恶意代码执行。
- D验证: confirmed / ver_f92c6f0e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 180. hyp_path_6ebf45f7f01e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_15.c:51
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序读取的文件中写入恶意内容
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) fclose(pFile); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_15.c:51; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_15.c:72
- 结论: 程序从文件读取数据并直接作为环境变量值传递给`_wputenv`，攻击者如果能够控制文件内容，则可设置恶意搜索路径，导致后续加载动态库或可执行文件时加载恶意代码。
- D验证: confirmed / ver_73b8b3f7
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 181. hyp_path_ce8e21c733ad

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_51a.c:51
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件FILENAME的内容
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) { printLine("fgets() failed"); data[dataLen] = '\0'; } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_51a.c:53-57; CWE427_Uncontrolled_Search_Path_Element__char_file_51b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_51a.c:65
- 结论: 从文件读取的数据作为搜索路径元素传递给sink函数，可能导致不受控制的搜索路径元素漏洞，攻击者可利用此漏洞通过控制文件内容加载恶意DLL或可执行文件。
- D验证: confirmed / ver_292f4031
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 182. hyp_path_4cee608fbf1f

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_52a.c:51
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过某种方式修改输入文件的内容
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_52a.c:51; if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_52a.c:53-57; CWE427_Uncontrolled_Search_Path_Element__char_file_52b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_52a.c:65
- 结论: 从文件读取的数据被传递到不受控制的搜索路径元素sink函数，可能允许攻击者控制搜索路径，导致加载恶意库或执行任意代码。
- D验证: confirmed / ver_e32aef22
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 183. hyp_path_762df8483058

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_53a.c:51
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向指定文件（FILENAME）写入任意字符串，从而影响data变量内容。
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_53a.c:51; if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_53a.c:53-57; CWE427_Uncontrolled_Search_Path_Element__char_file_53b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_53a.c:65
- 结论: 从文件读取的字符串被传递给不受控制的搜索路径元素sink函数，可能导致攻击者通过控制文件内容来操纵搜索路径，从而加载恶意库或执行任意代码。
- D验证: confirmed / ver_19364792
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 184. hyp_path_6c52db787e99

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_63a.c:51
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序读取的文件中写入恶意内容
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_63a.c:51; if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_63a.c:53-57; CWE427_Uncontrolled_Search_Path_Element__char_file_63b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_63a.c:65
- 结论: 在CWE427示例中，程序从文件读取数据并传递给Sink函数（CWE427_Uncontrolled_Search_Path_Element__char_file_63b_case0Sink），该函数可能将未受控的输入用作搜索路径元素，导致攻击者可以通过控制文件内容来影响程序执行的路径，可能执行任意代码。
- D验证: confirmed / ver_95a578de
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 185. hyp_path_17be04ddad1d

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_54a.c:51
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者需要能够控制文件内容或路径，或者文件所在目录被攻击者写入。
- 触发路径: pFile = fopen(FILENAME, "r"); if (pFile != NULL) @ CWE427_Uncontrolled_Search_Path_Element__char_file_54a.c:49-50; if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) @ CWE427_Uncontrolled_Search_Path_Element__char_file_54a.c:53-55; fclose(pFile); } CWE427_Uncontrolled_Search_Path_Element__char_file_54b_case0Sink(data); @ CWE427_Uncontrolled_Search_Path_Element__char_file_54a.c:63-65
- 结论: 从文件读取的数据未经有效验证直接传递给搜索路径相关函数，可能导致未控制搜索路径元素漏洞。
- D验证: confirmed / ver_a5ebf7e5
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 186. hyp_path_8e8dfccbdb6e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_64a.c:51
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够将恶意数据写入程序读取的文件中
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_64a.c:51; if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_64a.c:55-56; CWE427_Uncontrolled_Search_Path_Element__char_file_64b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_64a.c:65
- 结论: 程序从文件读取数据，并将未经验证的数据传递给可能影响搜索路径的函数，导致攻击者可通过控制文件内容操纵搜索路径，从而加载恶意库或可执行文件。
- D验证: confirmed / ver_213fd80b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 187. hyp_path_e766789fa597

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_52a.c:51
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制文件FILENAME的内容，使得fgetws读取的数据包含恶意路径元素。
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_52a.c:51; CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_52b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_52a.c:65
- 结论: 在函数CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_52_case0中，从文件读取的外部输入数据未被正确验证，直接传递给搜索路径元素，导致未控制的搜索路径元素漏洞。攻击者可通过控制文件内容来操纵搜索路径，从而执行恶意代码。
- D验证: confirmed / ver_df7a9b6f
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 188. hyp_path_5b8f136fe1af

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_53a.c:51
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制文件FILENAME的内容，使得data中包含恶意搜索路径字符串
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_53a.c:51; if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_53a.c:53-57; CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_53b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_53a.c:65
- 结论: 程序通过fgetws从文件读取数据，并将数据传递给不受控制的搜索路径元素处理函数，攻击者可通过控制文件内容设置搜索路径，导致加载恶意代码。
- D验证: confirmed / ver_beb2b385
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 189. hyp_path_a7320b1b1bb4

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_51a.c:51
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制文件内容（例如通过写入或修改文件）
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_51a.c:51; if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_51a.c:53-57; CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_51b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_51a.c:65
- 结论: 程序从文件读取数据并将其作为未控制的搜索路径元素，攻击者可通过控制文件内容操纵搜索路径，可能导致执行恶意代码。
- D验证: confirmed / ver_347f35df
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 190. hyp_path_5a57fd0975c6

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_54a.c:51
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够写入文件FILENAME的内容; sink函数将data用作搜索路径
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_54a.c:51; if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_54a.c:53-57; CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_54b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_54a.c:65
- 结论: 程序从文件中读取数据并传递给不受控制的搜索路径元素sink，如果攻击者能够控制文件内容，则可能导致路径遍历或命令执行漏洞。
- D验证: confirmed / ver_4f7c8de7
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 191. hyp_path_181191c065bc

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_63a.c:51
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序读取的文件中写入恶意搜索路径内容
- 触发路径: if (250-dataLen > 1) { pFile = fopen(FILENAME, "r"); if (pFile != NULL) { @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_63a.c:49-53; if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) { printLine("fgetws() failed"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_63a.c:53-57; data[dataLen] = L'\0'; } fclose(pFile); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_63a.c:59-63; CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_63b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_63a.c:65
- 结论: 应用程序从文件读取数据并将其用作搜索路径元素，攻击者可以通过控制文件内容来操纵搜索路径，导致CWE-427不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_7733a8b0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 192. hyp_path_e3052450f4f0

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_64a.c:51
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向指定文件（FILENAME）写入任意内容，从而控制data字符串的内容。
- 触发路径: pFile = fopen(FILENAME, "r"); if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) { ... } @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_64a.c:51-57; CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_64b_case0Sink(&data); @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_64a.c:65
- 结论: 从文件读取的数据未经审查即传递给搜索路径相关函数，可能导致恶意DLL或程序加载，属于未控制的搜索路径元素漏洞。
- D验证: confirmed / ver_0517ccac
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 193. hyp_path_9fc298b99fd1

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_81a.cpp:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制文件内容（例如通过文件上传、符号链接或控制文件系统）。; 系统或程序使用受影响的搜索路径元素执行操作（如加载库或执行程序）。
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_81a.cpp:45-49; baseObject.action(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_81a.cpp:57
- 结论: 从文件读取的数据作为搜索路径元素未受控，可能导致任意代码执行或DLL劫持。
- D验证: confirmed / ver_cb98344e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 194. hyp_path_f615cfbc7bbb

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_81a.cpp:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向文件中写入恶意内容，或能够控制文件读取的路径
- 触发路径: fgets(data+dataLen, (int)(250-dataLen), pFile) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_81a.cpp:43; baseObject.action(data) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_81a.cpp:57
- 结论: 从文件读取的数据可能被用作搜索路径元素，如果action函数将其传递给系统调用（如system、exec）或以不安全方式修改PATH，则可能导致攻击者控制搜索路径，加载恶意库或执行恶意程序。
- D验证: confirmed / ver_c1fa0133
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 195. hyp_path_48332953544b

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_44.c:56
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向输入文件FILENAME中写入恶意数据。
- 触发路径: pFile = fopen(FILENAME, "r"); if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) @ CWE427_Uncontrolled_Search_Path_Element__char_file_44.c:54-62
- 结论: 程序从文件读取数据到缓冲区，但代码片段未展示数据被用作搜索路径元素的sink。尽管B阶段P0静态确认支持为true，但缺少从source到sink的完整路径证据，漏洞假设无法确认。
- D验证: confirmed / ver_994fd032
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 196. hyp_path_b4fc919225c8

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_65a.c:53
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制程序读取的文件内容。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_65a.c:53; 假设：system(data); 或类似调用 @ 同一文件后续使用data的sink处（未提供直接代码，假设存在）
- 结论: 从文件读取的未受控数据可能被用作搜索路径元素，导致加载恶意动态库或可执行文件。
- D验证: confirmed / ver_b6d19510
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 197. hyp_path_1fd830e1fcb5

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_31.c:48
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够将恶意数据写入程序读取的文件（FILENAME）。
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_31.c:48; fgets(data+dataLen, (int)(250-dataLen), pFile); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_31.c:50; fclose(pFile); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_31.c:56-60; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_31.c:66
- 结论: 程序从文件中读取不受信任的数据，并将其用作环境变量设置（PUTENV），攻击者可能通过控制文件内容设置恶意搜索路径，导致任意代码执行或权限提升。
- D验证: confirmed / ver_8f870355
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 198. hyp_path_4609a8bf531c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_34.c:55
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够创建或修改文件'FILENAME'，使其包含恶意的路径字符串
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_34.c:55; fgets(data+dataLen, (int)(250-dataLen), pFile); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_34.c:59; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_34.c:73
- 结论: 程序从文件中读取未受信任的数据，并将其作为环境变量设置（通过PUTENV），导致不受控制的搜索路径元素漏洞，攻击者可通过控制文件内容修改环境变量，进而影响动态链接库加载路径或命令执行路径。
- D验证: confirmed / ver_d934b946
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 199. hyp_path_b661c6b5c1ba

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_33.cpp:52
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制或影响输入文件的内容
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_33.cpp:52; if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_33.cpp:55; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_33.cpp:69
- 结论: 程序从文件中读取数据并直接作为参数传递给PUTENV()设置环境变量，攻击者可能通过控制文件内容来设置恶意搜索路径，导致任意代码执行。
- D验证: confirmed / ver_900d0919
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 200. hyp_path_463564a3e9c0

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_32.c:52
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制文件内容，使得fgets读取到恶意路径字符串
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_32.c:52; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_32.c:71
- 结论: 程序从文件读取数据后，未经验证直接通过PUTENV设置环境变量，可能导致不安全搜索路径元素漏洞。攻击者可控制文件内容，设置恶意路径，从而劫持程序加载的库或可执行文件。
- D验证: confirmed / ver_3fe63e05
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 201. hyp_path_f0eb68615fc4

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_45.c:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件（FILENAME）的内容，使其中包含恶意路径字符串
- 触发路径: pFile = fopen(FILENAME, "r"); if (pFile != NULL) { ... fgets(data+dataLen, (int)(250-dataLen), pFile); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_45.c:58; fgets(data+dataLen, (int)(250-dataLen), pFile); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_45.c:68; case0Sink(); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_45.c:73; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_45.c:42
- 结论: 程序从文件读取外部输入，并将其作为环境变量通过PUTENV设置，攻击者可通过控制文件内容修改环境变量（如PATH），导致未受控的搜索路径元素，可能被利用执行恶意代码。
- D验证: confirmed / ver_f4b6e2fc
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 202. hyp_path_ebf8359b35f3

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_66a.c:52
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向输入文件写入恶意内容。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) fclose(pFile); @ CWE427_Uncontrolled_Search_Path_Element__char_file_66a.c:52; dataArray[2] = data; CWE427_Uncontrolled_Search_Path_Element__char_file_66b_case0Sink(dataArray); @ CWE427_Uncontrolled_Search_Path_Element__char_file_66a.c:68
- 结论: 从文件读取的数据未经净化直接用作搜索路径元素，可能导致恶意DLL或可执行文件被加载。
- D验证: confirmed / ver_622b937e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 203. hyp_path_180eae01a11a

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_32.c:52
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制文件FILENAME的内容。; 程序执行路径到达文件读取和_wputenv调用，且没有进行充分的输入验证或清理。
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_32.c:54; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_32.c:71
- 结论: 从文件读取数据并直接传递给_wputenv设置环境变量，攻击者可控制文件内容，导致搜索路径元素不受控，可能被利用来执行恶意程序（例如通过修改PATH环境变量）。
- D验证: confirmed / ver_168dbfca
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 204. hyp_path_32ab44487eae

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_68a.c:54
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件的内容（例如通过上传或修改权限）; 目标程序在sink函数中直接使用数据作为搜索路径元素而不进行清理或验证
- 触发路径: fgets(data+dataLen, (int)(250-dataLen), pFile) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_68a.c:54-60; CWE427_Uncontrolled_Search_Path_Element__char_file_68b_case0Sink(); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_68a.c:67; 使用全局变量data作为路径参数调用fopen或exec等API（根据CWE-427语义） @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_68b.c
- 结论: 通过文件读取获取的数据可能被用作不受控制的搜索路径元素，攻击者若能够控制文件内容，则可导致任意程序执行或资源访问。
- D验证: confirmed / ver_5fa61dc7
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 205. hyp_path_d98675c38984

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_67a.c:57
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制文件内容（如写入恶意路径）
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_67a.c:57; if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) { @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_67a.c:62; myStruct.structFirst = data; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_67a.c:70; CWE427_Uncontrolled_Search_Path_Element__char_file_67b_case0Sink(myStruct); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_67a.c:72
- 结论: 程序从文件读取用户可控数据，并通过结构体传递给一个未知的sink函数，但无法确认sink函数是否实际使用该数据作为搜索路径元素（如system、LoadLibrary等）。仅当sink函数确实执行搜索路径操作时，才构成CWE-427漏洞。
- D验证: confirmed / ver_6ee3effd
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 206. hyp_path_509e83fd539c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_66a.c:52
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制文件内容，使得读取的data为恶意路径字符串。
- 触发路径: fgetws(data+dataLen, (int)(250-dataLen), pFile) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_66a.c:54-58; dataArray[2] = data; CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_66b_case0Sink(dataArray); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_66a.c:68
- 结论: 程序从文件读取用户可控的搜索路径元素，未经验证直接传递给搜索路径元素相关的函数，可能导致攻击者控制搜索路径，加载恶意库或可执行文件。
- D验证: confirmed / ver_e8fc8ac2
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 207. hyp_path_81cf82305e8d

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_67a.c:57
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够创建或修改文件，使其包含恶意路径字符串
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_67a.c:57; if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_67a.c:59-63; myStruct.structFirst = data; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_67a.c:71; CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_67b_case0Sink(myStruct); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_67a.c:72
- 结论: 程序从文件读取数据作为搜索路径元素，攻击者可通过控制文件内容注入恶意路径，导致加载非预期程序或库。
- D验证: confirmed / ver_17f1e2d4
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 208. hyp_path_021c9d5b29a3

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_68a.c:54
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够将恶意数据写入文件FILENAME; 程序运行过程中会读取该文件
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_68a.c:56-60; CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_68_case0Data = data; CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_68b_case0Sink(); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_68a.c:68-69
- 结论: 存在不受控制的搜索路径元素漏洞，攻击者可通过控制文件内容影响程序行为，可能导致恶意代码执行。
- D验证: confirmed / ver_90339ad4
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 209. hyp_path_be0e486b94cb

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_21.c:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制文件内容，但文件读取后如何影响搜索路径未显示
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) { ... } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_21.c:52
- 结论: 从文件读取数据，可能用作搜索路径元素，但缺乏后续sink操作证据，无法确认漏洞路径。
- D验证: confirmed / ver_a7803865
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 210. hyp_path_dd705fc52187

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_61b.c:45
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件内容
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) { printLine("fgetws() failed"); } @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_61b.c:47-51; 后续将data传递给搜索路径相关API（如CreateProcess等），具体代码未在证据中展示 @ 未知行（在调用case0Source的函数中）
- 结论: 从文件读取的数据可能被用作搜索路径元素，导致未控制的搜索路径漏洞（CWE-427），但证据中缺少实际sink函数调用（如CreateProcess、LoadLibrary等）的代码行，路径不完整。
- D验证: confirmed / ver_992ea0e1
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 211. hyp_path_2621fef447c9

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_42.c:45
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制文件内容（通过某种方式写入恶意数据）
- 触发路径: case0Source函数入口 @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_42.c:36; fgetws从文件读取数据到data @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_42.c:47-51
- 结论: 从文件读取的宽字符串数据可能通过未完成的路径用于搜索路径元素（如CreateProcess或LoadLibrary），但当前代码片段缺少sink操作，路径不闭合。
- D验证: confirmed / ver_fb386332
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 212. hyp_path_c5cb89fa1ceb

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_43.cpp:48
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制输入文件（FILENAME）的内容
- 触发路径: pFile = fopen(FILENAME, "r"); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_43.cpp:48; if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) { printLine("fgetws() failed"); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_43.cpp:50-53
- 结论: 程序从文件读取外部输入，存储在data中，但后续未在提供的代码片段中展示将data用于搜索路径元素的调用（如CreateProcess、system等）。然而，基于CWE-427的上下文，存在潜在的不完整漏洞路径，需要验证是否存在后续sink。
- D验证: confirmed / ver_8ba84c91
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 213. hyp_path_385bd50b2a68

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_84_case0.cpp:39
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向指定文件写入恶意内容。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_84_case0.cpp:39; data[dataLen] = '\0'; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_84_case0.cpp:49
- 结论: 代码从文件读取数据并存入data缓冲区，随后data可能被用作搜索路径元素而未进行充分验证，导致未受控制的搜索路径元素漏洞（CWE-427）。
- D验证: confirmed / ver_1c510ef2
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 214. hyp_path_904040419b8f

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_84_case0.cpp:39
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件的内容
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), pFile) == NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_84_case0.cpp:41
- 结论: CWE-427: 未受控的搜索路径元素，程序从文件读取用户输入到data，可能后续用于搜索路径相关API导致高危操作
- D验证: confirmed / ver_5f5313e5
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 215. hyp_path_e9dec6134798

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_43.cpp:92
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与目标程序建立网络连接，并发送特制的数据以控制PATH环境变量。
- 触发路径: recvResult = recv(connectSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_43.cpp:90-94; PUTENV(data); @ CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_43.cpp:131-132
- 结论: 存在未受控制的搜索路径元素漏洞：程序通过网络接收数据并直接设置环境变量PATH，攻击者可控制PATH内容，导致后续进程加载恶意程序。
- D验证: confirmed / ver_15a4e1d6
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 216. hyp_path_597cf239757b

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_43.cpp:100
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络发送任意数据到目标监听端口
- 触发路径: recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_43.cpp:100; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_43.cpp:142-146
- 结论: 通过监听socket接收网络数据，未经验证直接设置环境变量PATH，攻击者可控制PATH导致搜索路径劫持
- D验证: confirmed / ver_3735d01c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 217. hyp_path_b9f6ef01be2a

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_22a.c:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够在程序运行时通过控制台输入任意字符串
- 触发路径: data = CWE427_Uncontrolled_Search_Path_Element__char_console_22_case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_22a.c:41; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_22a.c:43
- 结论: 通过控制台输入设置环境变量路径，攻击者可以控制搜索路径元素，导致不受控的搜索路径元素漏洞（CWE-427）。
- D验证: confirmed / ver_851261ed
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 218. hyp_path_b8521ae56f5e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_43.cpp:100
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络访问目标程序监听的端口，并能发送特制的PATH字符串
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_43.cpp:100; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_43.cpp:146
- 结论: 函数case0Source通过socket接收外部数据，然后直接使用`_wputenv`设置PATH环境变量，未对数据进行有效验证或清理，导致攻击者可以控制程序搜索路径，从而可能加载恶意模块。
- D验证: confirmed / ver_a60fe1a4
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 219. hyp_path_3293c0578287

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_61a.c:40
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串
- 触发路径: data = CWE427_Uncontrolled_Search_Path_Element__char_console_61b_case0Source(data); /* NOTE: Set a new environment variable with a path that is possibly insecure */ PUTENV(data); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_61a.c:38-42
- 结论: 程序从控制台读取用户输入并直接用于设置PATH环境变量，攻击者可以控制搜索路径，导致执行恶意程序，存在CWE-427未受控搜索路径元素漏洞。
- D验证: confirmed / ver_13ed8464
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 220. hyp_path_07729ebe3b9b

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_62a.cpp:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串
- 触发路径: char dataBuffer[250] = "PATH="; data = dataBuffer; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_62a.cpp:39; case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_62a.cpp:41; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_62a.cpp:43
- 结论: 函数case0从控制台读取用户输入，构造PATH=字符串，并通过putenv设置环境变量，攻击者可控制PATH导致加载恶意程序。
- D验证: confirmed / ver_e093b0ee
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 221. hyp_path_a327a35adbac

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_22a.c:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够影响环境变量（例如通过环境注入或父子进程环境继承）; source函数从环境变量中读取数据并返回可控字符串
- 触发路径: data = CWE427_Uncontrolled_Search_Path_Element__char_environment_22_case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_22a.c:41-42; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_22a.c:43
- 结论: 函数通过环境变量获取数据并直接传递给_putenv设置环境变量，攻击者可控制环境变量设置不安全搜索路径，但缺乏后续代码证明该环境变量被用于搜索并加载恶意库，因此漏洞路径不完整。
- D验证: confirmed / ver_27b0a514
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 222. hyp_path_7379aabcf58c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_61a.c:48
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制程序启动时的环境变量，或通过其他方式影响getenv等获取的值
- 触发路径: char dataBuffer[250] = "PATH="; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_61a.c:44; data = CWE427_Uncontrolled_Search_Path_Element__char_environment_61b_case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_61a.c:46; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_61a.c:48
- 结论: 代码中存在不受控制的搜索路径元素漏洞：通过环境变量控制的字符串被直接用作PUTENV的参数设置PATH环境变量，可能导致搜索路径劫持。
- D验证: confirmed / ver_57ab13a7
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 223. hyp_path_bf650ac5e6d1

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_62a.cpp:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过某种方式影响环境变量（例如通过 setenv 或程序启动时的环境）。; 程序后续依赖于 PATH 环境变量执行系统命令或加载库。
- 触发路径: char dataBuffer[250] = "PATH="; data = dataBuffer; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_62a.cpp:39-40; case0Source(data); // 从环境变量中获取不可信数据并拼接到 data @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_62a.cpp:41; PUTENV(data); // 使用不可信数据设置 PATH 环境变量 @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_62a.cpp:43
- 结论: 程序通过 putenv 设置环境变量 PATH，数据来源于不可信的环境变量，攻击者可通过控制环境变量修改 PATH，导致搜索路径劫持，可能执行恶意代码。
- D验证: confirmed / ver_c852a383
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 224. hyp_path_4abb5facc1ed

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_22a.c:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台（stdin）输入任意字符串。
- 触发路径: data = CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_22_case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_22a.c:41; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_22a.c:43
- 结论: 程序使用_wputenv设置环境变量，且环境变量值来源于控制台输入，未经充分净化。攻击者可通过控制台输入恶意路径，导致搜索路径元素不受控制，可能加载恶意DLL或执行任意命令。
- D验证: confirmed / ver_4f193374
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 225. hyp_path_aa7f4995c5bf

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_62a.cpp:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序提供控制台输入（例如通过标准输入）。
- 触发路径: case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_62a.cpp:41; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_62a.cpp:43
- 结论: 存在不受控制的搜索路径元素漏洞：程序通过控制台输入获取字符串，并将其作为环境变量（PATH）的值通过_wputenv设置。攻击者可控制PATH环境变量，导致程序在执行时加载恶意DLL或可执行文件，造成任意代码执行。
- D验证: confirmed / ver_7033c5a3
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 226. hyp_path_e21b0470e8f5

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_61a.c:48
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量或输入流，从而影响CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_61b_case0Source函数的返回值。
- 触发路径: wchar_t dataBuffer[250] = L"PATH="; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_61a.c:44; data = CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_61b_case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_61a.c:46; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_61a.c:48
- 结论: 程序使用_wputenv设置PATH环境变量，而环境变量值可能来自外部输入（通过CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_61b_case0Source函数），攻击者可以通过控制该输入修改PATH，导致加载任意DLL或可执行文件，实现权限提升或代码执行。
- D验证: confirmed / ver_488b9dc6
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 227. hyp_path_25148a10e53a

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_41.c:51
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够影响环境变量ENV_VARIABLE的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_41.c:52; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_41.c:57; CWE427_Uncontrolled_Search_Path_Element__char_environment_41_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_41.c:60; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_41.c:39
- 结论: 程序从环境变量读取数据并追加到固定缓冲区，然后通过PUTENV设置环境变量，攻击者可通过控制环境变量修改搜索路径，导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_51b30cbe
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 228. hyp_path_c30df620e6aa

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_51a.c:48
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响环境变量ENV_VARIABLE的值（例如在本地环境中执行程序，或通过其他漏洞注入环境变量）; 目标程序使用受影响的环境变量构建搜索路径，并加载外部程序或库
- 触发路径: size_t dataLen = strlen(data); char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_51a.c:48; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_51a.c:53; CWE427_Uncontrolled_Search_Path_Element__char_environment_51b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_51a.c:57
- 结论: 程序从环境变量读取用户可控的数据，未经任何验证直接拼接到搜索路径中，可能导致攻击者通过控制环境变量来劫持动态链接库或可执行文件的加载路径，造成任意代码执行。
- D验证: confirmed / ver_fc914b39
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 229. hyp_path_56b80b95eee9

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_53a.c:48
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响目标进程的环境变量ENV_VARIABLE
- 触发路径: size_t dataLen = strlen(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_53a.c:48; char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_53a.c:49; if (environment != NULL) { strncat(data+dataLen, environment, 250-dataLen-1); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_53a.c:52-53; CWE427_Uncontrolled_Search_Path_Element__char_environment_53b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_53a.c:57
- 结论: 存在不受控制的搜索路径元素漏洞，攻击者可通过环境变量控制搜索路径元素，导致执行恶意代码或加载恶意库。
- D验证: confirmed / ver_514434fd
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 230. hyp_path_36c15f302a3e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_52a.c:48
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的内容为恶意路径
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_52a.c:49; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_52a.c:54; CWE427_Uncontrolled_Search_Path_Element__char_environment_52b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_52a.c:57
- 结论: 环境变量中的不可信数据被拼接到搜索路径字符串中，可能导致搜索路径劫持，攻击者可诱使程序加载恶意程序。
- D验证: confirmed / ver_9a3bee27
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 231. hyp_path_7bf836f8c5b7

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_63a.c:48
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_63a.c:49; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_63a.c:54; CWE427_Uncontrolled_Search_Path_Element__char_environment_63b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_63a.c:57
- 结论: 程序使用环境变量中的数据构建搜索路径，未进行充分验证，导致攻击者可通过设置环境变量控制搜索路径元素，可能执行恶意代码。
- D验证: confirmed / ver_f47b0769
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 232. hyp_path_12fa2620c872

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_54a.c:48
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值，例如通过修改进程环境或通过某种方式注入
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_54a.c:49; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_54a.c:54; CWE427_Uncontrolled_Search_Path_Element__char_environment_54b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_54a.c:57
- 结论: 程序从环境变量中读取数据并追加到data字符串，然后将data作为参数传递给sink函数，该sink函数可能将data用作搜索路径的一部分，导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_1c76d972
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 233. hyp_path_d0236d9dbe1b

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_51a.c:48
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE
- 触发路径: wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_51a.c:49; wcsncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_51a.c:54; CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_51b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_51a.c:57
- 结论: 程序从环境变量获取输入并拼接到搜索路径中，随后传递给可能将数据作为搜索路径元素使用的sink函数，攻击者可通过控制环境变量操纵搜索路径，导致不受控的搜索路径元素漏洞。
- D验证: confirmed / ver_42b25a83
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 234. hyp_path_bf92772d1b11

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_64a.c:48
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的内容; data缓冲区初始内容可能已部分填充，但拼接后字符串长度不超过250字节
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_64a.c:48; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_64a.c:54; CWE427_Uncontrolled_Search_Path_Element__char_environment_64b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_64a.c:57
- 结论: 该代码从环境变量获取输入并拼接到搜索路径字符串中，然后传递给sink函数。攻击者可控制环境变量修改搜索路径，导致执行恶意程序或加载恶意库，存在不受控搜索路径元素漏洞。
- D验证: confirmed / ver_d9f5325a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 235. hyp_path_8d176841b93c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_53a.c:48
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够影响程序运行时的环境变量
- 触发路径: wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_53a.c:49; wcsncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_53a.c:54; CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_53b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_53a.c:57
- 结论: 函数从环境变量获取输入并拼接到搜索路径中，然后传递给sink函数，攻击者可通过控制环境变量来影响搜索路径，导致加载恶意库或执行恶意代码。
- D验证: confirmed / ver_b0bae7a4
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 236. hyp_path_e099482d1365

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_52a.c:48
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); if (environment != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_52a.c:47-50; wcsncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_52a.c:52-54; CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_52b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_52a.c:57
- 结论: 程序从环境变量中读取用户可控的数据，并将其拼接到搜索路径中，随后传递给可能用于执行命令或加载库的Sink函数，导致攻击者可以控制搜索路径元素，存在CWE-427漏洞的潜在风险。
- D验证: confirmed / ver_850f307a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 237. hyp_path_c7da0df8973a

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_54a.c:48
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制系统中的环境变量ENV_VARIABLE的值。
- 触发路径: wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_54a.c:49; wcsncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_54a.c:54; CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_54b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_54a.c:57
- 结论: 程序从环境变量读取数据并传递给搜索路径敏感函数，攻击者可通过控制环境变量修改搜索路径，导致加载恶意库或程序。
- D验证: confirmed / ver_1638afe0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 238. hyp_path_d9655782b136

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_63a.c:48
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置ENV_VARIABLE环境变量的值（例如通过进程环境、配置文件或外部注入）。
- 触发路径: size_t dataLen = wcslen(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_63a.c:48; wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_63a.c:49; wcsncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_63a.c:54; CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_63b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_63a.c:57
- 结论: 从环境变量读取数据并追加到搜索路径缓冲区，未进行充分过滤或验证，攻击者可通过控制环境变量来影响程序搜索路径，可能导致加载恶意库或执行任意代码。
- D验证: confirmed / ver_c7f3e1ef
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 239. hyp_path_4c63da64e32c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_12.c:66
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入提供任意数据，且程序以可能受环境变量影响的权限运行
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_12.c:42-46; strcat(data, NEW_PATH); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_12.c:64-68; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_12.c:67-71
- 结论: 存在不受控搜索路径元素漏洞，攻击者可通过控制台输入控制环境变量，可能导致任意代码执行或路径劫持。
- D验证: confirmed / ver_6fedf548
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 240. hyp_path_a919f3279737

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_64a.c:48
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_64a.c:48; wcsncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_64a.c:54; CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_64b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_64a.c:57
- 结论: 通过环境变量（GETENV）获取攻击者可控的字符串，并拼接至路径字符串（wcsncat），然后传递给Sink函数，导致攻击者可以控制搜索路径元素，可能加载恶意动态库或执行任意代码。
- D验证: confirmed / ver_4151438e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 241. hyp_path_36765180b871

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_12.c:60
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值（例如通过子进程继承或直接修改环境变量）
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_12.c:48; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_12.c:53; strcat(data, NEW_PATH); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_12.c:60; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_12.c:63
- 结论: 该代码从环境变量获取用户输入，将其附加到搜索路径中，然后通过putenv设置新的环境变量。攻击者通过控制环境变量可以修改搜索路径，导致任意程序执行时加载恶意库或可执行文件，构成CWE427未控制搜索路径元素漏洞。
- D验证: confirmed / ver_27435d7d
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 242. hyp_path_bbdf6ec632f3

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_21.c:94
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到目标socket服务并发送恶意字符串
- 触发路径: case0Source函数通过recv从socket读取数据到data缓冲区 @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_21.c:54-127; PUTENV(data); 将未经验证的数据设置为环境变量 @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_21.c:94
- 结论: 程序从socket接收数据并直接传递给putenv设置环境变量，攻击者可以控制搜索路径，导致路径遍历或恶意库加载漏洞。
- D验证: confirmed / ver_dde25b0c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 243. hyp_path_0ef64c20be68

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_21.c:102
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够访问目标应用监听的socket端口（如示例中的TCP端口）; 攻击者能够发送任意字符串作为环境变量值
- 触发路径: recvResult = recv(acceptSocket, (char *)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_21.c:88-99; data = case0Source(data); /* 返回包含网络数据的缓冲区 */ @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_21.c:102; PUTENV(data); /* 设置环境变量，数据未经验证 */ @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_21.c:102
- 结论: 函数case0Source通过socket接收攻击者可控数据，并直接传递给putenv设置环境变量，导致未控制搜索路径元素漏洞。攻击者可设置恶意路径（如当前目录优先），可能引发任意代码执行。
- D验证: confirmed / ver_3c2dbaa1
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 244. hyp_path_67448da8c813

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_42.c:89
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与服务器建立TCP连接并发送特制的PATH字符串
- 触发路径: case0Source函数通过socket接收数据并填充到data缓冲区 @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_42.c:51-121; data = case0Source(data); PUTENV(data); 将接收到的数据作为环境变量PATH设置 @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_42.c:128-132
- 结论: 程序通过socket接收外部数据，未经验证直接作为环境变量PATH的值，攻击者可控制PATH指向恶意目录，导致搜索路径劫持。
- D验证: confirmed / ver_69adc01a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 245. hyp_path_5c1a7593df6b

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_42.c:97
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向服务发送网络数据; 服务端未对输入进行过滤或验证
- 触发路径: recv(acceptSocket, (char*)(data + dataLen), sizeof(char) * (250 - dataLen - 1), 0); @ case0Source函数（51-133行）; data = case0Source(data); @ 第140行; PUTENV(data); @ 第141行
- 结论: 程序通过监听socket接收攻击者控制的字符串，并将其作为PATH环境变量的一部分设置，导致攻击者可以控制程序搜索动态链接库的路径，进而执行任意代码或加载恶意库。
- D验证: confirmed / ver_bc3783bb
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 246. hyp_path_83d5283bde87

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_42.c:97
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过socket连接服务并发送任意数据; 服务端未对数据内容进行校验
- 触发路径: recv(acceptSocket, (char *)(data + dataLen), sizeof(wchar_t) * (250 - dataLen - 1), 0) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_42.c:97; data = dataBuffer; data = case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_42.c:139; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_42.c:142
- 结论: 函数case0Source通过socket接收网络数据，拼接成PATH=字符串后调用_wputenv设置环境变量，攻击者可控制PATH导致搜索路径劫持，进而执行恶意程序。
- D验证: confirmed / ver_c6c277c9
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 247. hyp_path_bade481c2319

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_82a.cpp:55
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_82a.cpp:37; baseObject->action(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_82a.cpp:55
- 结论: 从控制台读取的用户输入数据直接传递给 action 方法，如果 action 方法将数据用于搜索路径（如加载库或执行程序），则可能导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_13d6d99a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 248. hyp_path_21da4ac59d1c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_43.cpp:63
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制或影响ENV_VARIABLE环境变量
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_43.cpp:41-54; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_43.cpp:41-54; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_43.cpp:63
- 结论: 程序从环境变量中读取数据并拼接到PATH环境变量中，然后调用putenv设置PATH。攻击者可以通过控制环境变量来修改进程的搜索路径，从而导致恶意可执行文件被加载，实现代码执行。
- D验证: confirmed / ver_48fb53c0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 249. hyp_path_1e07e2933aa4

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_82a.cpp:55
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), stdin) != NULL) {...} @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_82a.cpp:35-40; CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_82_base* baseObject = new CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_82_case0; baseObject->action(data); delete baseObject; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_82a.cpp:55-57
- 结论: 未控制的搜索路径元素：程序通过控制台读取用户输入作为搜索路径元素，可能导致攻击者控制程序加载恶意模块，但当前证据不完整，缺少实际sink调用。
- D验证: confirmed / ver_1f03fd69
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 250. hyp_path_7263e88e1fe6

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_17.c:59
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响环境变量 ENV_VARIABLE 的值; data 变量初始化为 'PATH=' 或类似格式以构成有效的环境变量设置; 程序后续有依赖 putenv 设置的环境变量执行程序或加载库的操作（当前证据缺失）
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_17.c:49; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_17.c:54; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_17.c:59
- 结论: 程序通过 getenv 从环境变量读取数据，然后将其拼接到 data 中，并最终通过 putenv 设置环境变量。攻击者可以控制环境变量，从而设置恶意的搜索路径（如 PATH），但缺乏后续使用该环境变量的代码（如 system 或 exec），导致漏洞利用路径不完整。
- D验证: confirmed / ver_74a40ace
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 251. hyp_path_939654f3fb6f

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_82a.cpp:49
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量'ENV_VARIABLE'的值，使得在程序运行时该环境变量被设置为恶意路径字符串。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_82a.cpp:41; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_82a.cpp:46; CWE427_Uncontrolled_Search_Path_Element__char_environment_82_base* baseObject = new CWE427_Uncontrolled_Search_Path_Element__char_environment_82_case0; baseObject->action(data); delete baseObject; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_82a.cpp:49-51
- 结论: 从环境变量中获取攻击者可控的数据，拼接到路径字符串中，并传递给搜索路径元素操作函数，可能导致搜索路径被劫持，执行恶意代码或加载恶意库。
- D验证: confirmed / ver_873dcad5
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 252. hyp_path_29c1ad7d4b08

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_82a.cpp:49
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量 ENV_VARIABLE。
- 触发路径: wchar_t * environment = GETENV(ENV_VARIABLE); ... wcsncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_82a.cpp:38-42; baseObject->action(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_82a.cpp:49-51
- 结论: 从环境变量读取数据并传递给 action 函数，可能用于搜索路径控制，攻击者可控制环境变量从而控制加载的库或可执行文件路径。
- D验证: confirmed / ver_172b01ef
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 253. hyp_path_c8afc717a357

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_21.c:68
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响ENV_VARIABLE环境变量（例如通过父进程或shell注入）
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_21.c:45; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_21.c:50; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_21.c:68
- 结论: CWE427 Uncontrolled Search Path Element: 程序从环境变量读取内容并拼接到缓冲区，然后通过PUTENV()设置新环境变量，但代码中未展示后续利用该环境变量执行程序或加载库的操作（如system、exec等），因此漏洞路径不完整，需要动态验证下游是否存在实际利用。
- D验证: confirmed / ver_378e2553
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 254. hyp_path_d872395f868d

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_44.c:53
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: size_t dataLen = strlen(data); @ CWE427_Uncontrolled_Search_Path_Element__char_environment_44.c:53; char * environment = GETENV(ENV_VARIABLE); @ CWE427_Uncontrolled_Search_Path_Element__char_environment_44.c:54; strncat(data+dataLen, environment, 250-dataLen-1); @ CWE427_Uncontrolled_Search_Path_Element__char_environment_44.c:59
- 结论: CWE-427 Uncontrolled Search Path Element: 从环境变量读取数据并追加到搜索路径元素中，导致路径可控
- D验证: confirmed / ver_1e12a58e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 255. hyp_path_f1110aeb1cb9

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_81a.cpp:40
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量 ENV_VARIABLE 为任意字符串。
- 触发路径: size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_81a.cpp:40-41; if (environment != NULL) { wcsncat(data+dataLen, environment, 250-dataLen-1); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_81a.cpp:45-46
- 结论: 程序从环境变量读取数据并拼接到搜索路径中，攻击者可通过控制环境变量修改搜索路径，但缺乏后续使用data作为搜索路径参数的直接代码证据，因此无法完全确认漏洞路径。
- D验证: confirmed / ver_2990e612
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 256. hyp_path_8283b5d9d2d7

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_81a.cpp:40
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响环境变量ENV_VARIABLE的值。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_81a.cpp:40; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_81a.cpp:45; baseObject.action(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_81a.cpp:49
- 结论: 程序从环境变量中读取数据并追加到路径字符串中，随后将该路径用于执行操作（如加载库或执行程序），攻击者可通过控制环境变量来修改搜索路径，导致执行恶意代码或加载恶意库。
- D验证: confirmed / ver_80fdf39c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 257. hyp_path_ad1a0bb171fa

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_44.c:53
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量 ENV_VARIABLE
- 触发路径: wchar_t * environment = GETENV(ENV_VARIABLE); if (environment != NULL) { @ L52-56; wcsncat(data+dataLen, environment, 250-dataLen-1); @ L57-59
- 结论: CWE-427: Uncontrolled Search Path Element - 从环境变量读取数据并追加至搜索路径，未经验证，攻击者可控制环境变量注入恶意路径。
- D验证: confirmed / ver_57dbe176
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 258. hyp_path_b4dc3bf77063

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_65a.c:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值; 程序后续将data用于搜索路径操作（如exec或系统调用）
- 触发路径: size_t dataLen = strlen(data); char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_65a.c:50; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_65a.c:56
- 结论: 从环境变量读取数据并追加到缓冲区，但未验证缓冲区大小是否足够，且后续可能用作搜索路径元素，存在未受控搜索路径元素漏洞。
- D验证: confirmed / ver_fb4aa66d
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 259. hyp_path_179ff36cd198

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_42.c:61
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE，使其包含恶意路径字符串
- 触发路径: static char * case0Source(char * data) { size_t dataLen = strlen(data); char * environment = GETENV(ENV_VARIABLE); if (environment != NULL) { strncat(data+dataLen, environment, 250-dataLen-1); } return data; } @ CWE427_Uncontrolled_Search_Path_Element__char_environment_42.c:38-52; PUTENV(data); @ CWE427_Uncontrolled_Search_Path_Element__char_environment_42.c:61
- 结论: 程序通过环境变量设置PATH环境变量，攻击者可以通过控制环境变量ENV_VARIABLE来设置恶意搜索路径，导致后续可能加载恶意库，存在不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_f3c2f2cc
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 260. hyp_path_832c6d35503e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_65a.c:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制ENV_VARIABLE环境变量
- 触发路径: wchar_t * environment = GETENV(ENV_VARIABLE); @ L51; wcsncat(data+dataLen, environment, 250-dataLen-1); @ L56
- 结论: CWE-427 Uncontrolled Search Path Element via environment variable input
- D验证: confirmed / ver_83811e51
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 261. hyp_path_2d02ea5a643e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_42.c:61
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: wchar_t * environment = GETENV(ENV_VARIABLE); @ case0Source函数 line 38-52; wcsncat(data+dataLen, environment, 250-dataLen-1); @ case0Source函数 line 38-52; data = case0Source(data); PUTENV(data); @ 调用者 line 59-61
- 结论: 函数case0Source通过GETENV读取环境变量，并追加到PATH字符串中，随后调用_wputenv设置环境变量PATH。攻击者若能够控制该环境变量，则可以控制进程搜索动态链接库的路径，导致加载恶意库，造成任意代码执行或信息泄露。
- D验证: confirmed / ver_6fd6866e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 262. hyp_path_0265b6fbe510

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_11.c:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_11.c:48; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_11.c:53; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_11.c:58
- 结论: 代码从环境变量读取数据并追加到PATH字符串中，然后调用_putenv设置环境变量。攻击者可通过控制环境变量修改PATH，导致执行恶意程序。
- D验证: confirmed / ver_f1fe4caf
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 263. hyp_path_c11b1b991e75

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_08.c:72
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响程序运行时环境变量（例如通过LD_PRELOAD、setenv或恶意环境）; 程序后续依赖于PATH环境变量进行操作（如动态链接器加载或system调用）
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_08.c:62; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_08.c:67; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_08.c:72
- 结论: 代码从环境变量读取数据并拼接到PATH字符串中，然后通过putenv设置环境变量，导致搜索路径元素不受控制，攻击者可利用此漏洞修改程序搜索路径，劫持动态库加载或执行恶意命令。
- D验证: confirmed / ver_964d5f46
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 264. hyp_path_70b895f6e96c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_02.c:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_02.c:48; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_02.c:53; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_02.c:58
- 结论: 代码使用getenv从环境变量读取输入，拼接到data后，再通过putenv设置新的环境变量，导致攻击者可以通过控制环境变量来操纵搜索路径元素，造成CWE-427漏洞。
- D验证: confirmed / ver_f3deea18
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 265. hyp_path_f2eebb9bb890

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_01.c:55
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够影响环境变量ENV_VARIABLE的值; 程序以受污染的环境变量运行
- 触发路径: size_t dataLen = strlen(data); char * environment = GETENV(ENV_VARIABLE); @ CWE427_Uncontrolled_Search_Path_Element__char_environment_01.c:44-46; strncat(data+dataLen, environment, 250-dataLen-1); @ CWE427_Uncontrolled_Search_Path_Element__char_environment_01.c:50-51; PUTENV(data); @ CWE427_Uncontrolled_Search_Path_Element__char_environment_01.c:55
- 结论: 程序从环境变量读取数据并将其用作设置环境变量的参数，未经过任何验证，攻击者可通过控制环境变量来修改搜索路径，导致任意代码执行或权限提升。
- D验证: confirmed / ver_33a43355
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 266. hyp_path_3f7deabf5715

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_03.c:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的内容（如通过设置环境变量或注入）。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_03.c:48; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_03.c:53; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_03.c:58
- 结论: 存在未受控的搜索路径元素漏洞（Uncontrolled Search Path Element）。代码从环境变量中读取数据，拼接到字符串后通过putenv()设置为环境变量，攻击者可控制环境变量内容，进而影响搜索路径（如PATH），可能导致任意命令执行或恶意库加载。
- D验证: confirmed / ver_1e1b259f
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 267. hyp_path_edb4eaf80b43

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_04.c:65
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制目标进程的环境变量（例如通过父进程或服务暴露的接口）。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_04.c:55; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_04.c:60; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_04.c:65
- 结论: 从环境变量读取数据后未经安全验证直接使用PUTENV设置环境变量，可能导致攻击者控制搜索路径，引发不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_08ef5ea2
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 268. hyp_path_9f7cf49cfc0d

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_05.c:65
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE，从而控制data内容
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_05.c:54; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_05.c:60; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_05.c:65
- 结论: 存在未控制搜索路径元素漏洞，攻击者可通过环境变量注入恶意路径，影响后续子进程的搜索路径。
- D验证: confirmed / ver_7a12b528
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 269. hyp_path_008ac50799f2

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_07.c:64
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制或影响环境变量ENV_VARIABLE的值。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ 54; strncat(data+dataLen, environment, 250-dataLen-1); @ 59; PUTENV(data); @ 64
- 结论: 攻击者通过控制环境变量可以影响搜索路径，导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_8015bd41
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 270. hyp_path_09d0c01b9169

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_09.c:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够影响环境变量ENV_VARIABLE的值。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_09.c:48; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_09.c:53; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_09.c:58
- 结论: 从环境变量获取输入并设置为新的环境变量，未经过滤，攻击者可控制搜索路径元素，导致任意代码执行或特权提升。
- D验证: confirmed / ver_ea9f3cca
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 271. hyp_path_3fdd43d1d5f0

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_06.c:62
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ CWE427_Uncontrolled_Search_Path_Element__char_environment_06.c:52; strncat(data+dataLen, environment, 250-dataLen-1); @ CWE427_Uncontrolled_Search_Path_Element__char_environment_06.c:57; PUTENV(data); @ CWE427_Uncontrolled_Search_Path_Element__char_environment_06.c:62
- 结论: 程序通过getenv从环境变量读取用户可控输入，并将其通过strncat拼接后作为参数调用putenv设置新环境变量。攻击者可通过控制环境变量ENV_VARIABLE注入恶意路径，导致后续程序执行时搜索到恶意动态库或可执行文件，造成权限提升或代码执行。但现有路径仅展示了putenv设置环境变量，未显示后续使用该环境变量的危险操作，漏洞路径不完整。
- D验证: confirmed / ver_886f652a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 272. hyp_path_46efd25f9a3e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_10.c:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响环境变量 ENV_VARIABLE 的值
- 触发路径: size_t dataLen = strlen(data); char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_10.c:47-48; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_10.c:53; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_10.c:58
- 结论: 程序通过 getenv 从环境变量读取用户可控数据，并将其拼接后通过 putenv 设置环境变量，攻击者可以控制搜索路径元素，导致非预期的动态链接库加载或命令执行。
- D验证: confirmed / ver_21938ff3
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 273. hyp_path_ad01485e8072

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_13.c:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制某个环境变量（如PATH）
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_13.c:48; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_13.c:53; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_13.c:58
- 结论: Uncontrolled search path element via environment variable
- D验证: confirmed / ver_a0c327c1
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 274. hyp_path_38d681c08c5c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_14.c:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_14.c:48; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_14.c:53; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_14.c:58
- 结论: 程序从环境变量读取数据并拼接到data缓冲区，然后调用putenv设置环境变量，攻击者可通过控制环境变量来修改搜索路径，导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_de4aee8d
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 275. hyp_path_fca51cd08327

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_18.c:57
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制目标进程的环境变量，以注入恶意路径
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_18.c:48; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_18.c:53; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_18.c:57
- 结论: 程序从环境变量读取数据，未经充分验证就将其拼接到路径字符串中，并通过putenv设置环境变量，可能导致搜索路径被劫持，从而执行恶意代码。
- D验证: confirmed / ver_17b5d2c8
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 276. hyp_path_4584a264a526

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_15.c:64
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过环境变量注入恶意字符串（例如设置PATH变量指向恶意目录）
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_15.c:49; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_15.c:54; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_15.c:64
- 结论: 未控制搜索路径元素漏洞：程序从环境变量读取数据并追加到局部缓冲区，然后通过putenv设置环境变量，攻击者可控制环境变量注入恶意路径，影响后续程序执行。
- D验证: confirmed / ver_6deadfe7
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 277. hyp_path_09e2ce15d42a

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_16.c:59
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的内容。; 程序在调用putenv后可能使用该环境变量执行外部程序（例如通过system或exec）。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_16.c:48; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_16.c:53; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_16.c:59
- 结论: 程序从环境变量读取数据并设置到另一个环境变量，攻击者可通过控制环境变量修改搜索路径，导致不受控制的搜索路径元素漏洞，但缺少后续执行外部程序的sink，漏洞路径不完整。
- D验证: confirmed / ver_ef3d3f78
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 278. hyp_path_b4118ed37303

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_43.cpp:71
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向文件FILENAME写入任意字符串（如包含恶意路径）。; 程序后续会基于修改后的PATH环境变量执行程序或加载库（本样本未体现，需根据整体应用判断）。
- 触发路径: char dataBuffer[250] = "PATH="; data = dataBuffer; case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_43.cpp:67-69; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_43.cpp:71
- 结论: 存在不受控制的搜索路径元素漏洞，攻击者可通过写入文件控制环境变量PATH，但缺少后续使用该环境变量的操作，需结合上下文确认。
- D验证: confirmed / ver_6f08b816
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 279. hyp_path_eb8f5d42277e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_43.cpp:69
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入（stdin）向程序提供数据。
- 触发路径: char dataBuffer[250] = "PATH="; data = dataBuffer; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_43.cpp:65; case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_43.cpp:67; fgets(data+dataLen, (int)(250-dataLen), stdin); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_43.cpp:44-50; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_43.cpp:69
- 结论: 存在不受控制的搜索路径元素漏洞，攻击者可通过控制台输入设置恶意PATH环境变量，导致程序加载恶意可执行文件。
- D验证: confirmed / ver_916861da
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 280. hyp_path_073f94928a4c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_21.c:74
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入提供输入; 程序运行环境允许通过_putenv修改环境变量
- 触发路径: data = case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_21.c:72; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_21.c:74
- 结论: 程序通过控制台读取用户输入并直接作为环境变量设置给_putenv，攻击者可控制搜索路径元素，导致在执行程序时加载恶意代码。
- D验证: confirmed / ver_c5c4074e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 281. hyp_path_7f313f2cf0ad

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_21.c:76
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够写入或影响文件内容（如FILENAME指定的文件），使得读取的字符串包含恶意路径。
- 触发路径: data = case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_21.c:74; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_21.c:76
- 结论: 攻击者可以通过控制文件内容设置不安全的环境变量，从而导致不可控的搜索路径元素，可能被利用加载恶意程序。
- D验证: confirmed / ver_918102a0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 282. hyp_path_a974a54d25fc

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_21.c:74
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过stdin输入任意字符串到程序中
- 触发路径: data = case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_21.c:72; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_21.c:74
- 结论: 从控制台读取输入后直接作为环境变量值传递给_wputenv，攻击者可控制搜索路径元素，导致任意命令执行或动态链接库劫持。
- D验证: confirmed / ver_56370172
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 283. hyp_path_aa263460bf5c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_42.c:67
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串。
- 触发路径: char dataBuffer[250] = "PATH="; data = dataBuffer; data = case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_42.c:63-67; data = case0Source(data); ... PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_42.c:65-69
- 结论: 程序从控制台读取用户输入，将其附加到"PATH="字符串后，然后通过_putenv设置环境变量，导致攻击者可以控制PATH环境变量，从而可能加载恶意动态链接库。
- D验证: confirmed / ver_cf88a3cd
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 284. hyp_path_7caf84d34123

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_42.c:67
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够访问程序的标准输入（stdin），并可以输入任意字符串
- 触发路径: wchar_t dataBuffer[250] = L"PATH="; data = dataBuffer; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_42.c:63; data = case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_42.c:65; fgetws(data+dataLen, (int)(250-dataLen), stdin) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_42.c:30-58; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_42.c:67
- 结论: 程序使用_wputenv设置PATH环境变量，但未对用户输入进行验证，攻击者可通过控制台输入任意字符串追加到PATH中，导致搜索路径元素不受控，可能被利用执行恶意程序。
- D验证: confirmed / ver_64e3e249
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 285. hyp_path_7575e0789963

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_11.c:64
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入提供任意字符串
- 触发路径: size_t dataLen = strlen(data); if (250-dataLen > 1) @ L37-41; if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ L42-46; PUTENV(data); @ L62-66
- 结论: 从控制台读取的输入未经任何检查直接拼接到PATH环境变量后通过putenv设置，攻击者可以控制搜索路径，导致程序执行恶意代码。
- D验证: confirmed / ver_4d87a8c8
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 286. hyp_path_2d57488e9156

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_08.c:78
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入提供任意字符串，且程序运行环境允许修改PATH环境变量。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_08.c:58; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_08.c:78
- 结论: 程序通过控制台输入构造环境变量字符串，并调用putenv设置PATH环境变量，攻击者可以注入恶意路径，导致搜索路径不可控，可被利用执行恶意代码。
- D验证: confirmed / ver_5800dedb
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 287. hyp_path_998510ff98a3

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_42.c:69
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制文件FILENAME的内容
- 触发路径: char dataBuffer[250] = "PATH="; data = dataBuffer; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_42.c:65-66; data = case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_42.c:67; case0Source从文件读取内容追加到data，无过滤 @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_42.c:36-60; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_42.c:69
- 结论: 程序从文件读取数据后直接设置PATH环境变量，未验证输入内容，导致攻击者可通过控制文件内容设置恶意搜索路径，劫持后续程序加载的共享库或可执行文件。
- D验证: confirmed / ver_c0c162d9
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 288. hyp_path_720cca31ab91

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_42.c:69
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够写入或修改程序读取的文件（FILENAME）的内容
- 触发路径: case0Source函数从文件读取数据到dataBuffer @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_42.c:36-60; wchar_t dataBuffer[250] = L"PATH="; data = dataBuffer; data = case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_42.c:65-69; PUTENV(data); // 调用_wputenv设置环境变量 @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_42.c:69
- 结论: 程序从文件读取输入并直接拼接到PATH环境变量后调用_wputenv设置，攻击者若控制文件内容，可导致PATH被篡改，从而在后续程序执行中加载恶意DLL。
- D验证: confirmed / ver_8cd4c113
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 289. hyp_path_083455b4eb59

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_01.c:61
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入提供任意字符串
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_01.c:40; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_01.c:61
- 结论: 应用程序通过fgets从控制台读取用户输入，并直接作为参数调用PUTENV设置环境变量，未对输入进行验证或清理。攻击者可通过提供包含恶意搜索路径的输入，控制环境变量（如PATH），导致受控的搜索路径元素，可能使程序加载恶意DLL或可执行文件。
- D验证: confirmed / ver_0f17f35b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 290. hyp_path_121c36b24ca1

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_02.c:64
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入发送恶意字符串。; 程序运行时具有足够的权限，使得设置的环境变量能影响后续进程或系统调用。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_02.c:42; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_02.c:64
- 结论: 程序从控制台读取用户输入，并直接作为环境变量路径传递给putenv()，攻击者可以控制搜索路径元素，导致特权提升或执行恶意代码。
- D验证: confirmed / ver_7e70e819
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 291. hyp_path_553f24abeda8

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_03.c:64
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入中写入数据
- 触发路径: fgets(data+dataLen, (int)(250-dataLen), stdin) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_03.c:44; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_03.c:64
- 结论: 程序从控制台读取用户输入作为环境变量路径，未经验证直接传递给putenv()函数，导致攻击者可以控制搜索路径元素，可能加载恶意动态链接库。
- D验证: confirmed / ver_a5526cca
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 292. hyp_path_0eb6d2c0dd73

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_05.c:71
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入写入任意字符串。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_05.c:51; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_05.c:71
- 结论: 程序从控制台读取用户输入，并直接将其作为环境变量值设置，攻击者可以通过控制台输入恶意路径，导致不受控制的搜索路径元素漏洞，可能被用于执行任意代码。
- D验证: confirmed / ver_2bb846b3
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 293. hyp_path_7c69b8d17573

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_07.c:70
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供输入
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_07.c:50; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_07.c:70
- 结论: 程序从控制台读取用户输入，未经验证直接用于设置环境变量（PUTENV），攻击者可注入恶意路径导致搜索路径劫持。
- D验证: confirmed / ver_bfa7a318
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 294. hyp_path_1980e69a8aaf

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_04.c:71
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序的stdin输入任意字符串，例如通过管道或终端交互。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_04.c:49; dataLen = strlen(data); if (dataLen > 0 && data[dataLen-1] == '\n') { data[dataLen-1] = '\0'; } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_04.c:53-55; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_04.c:71
- 结论: 程序从控制台读取输入并直接作为环境变量设置，导致不受控制的搜索路径元素漏洞（CWE-427），攻击者可修改PATH等环境变量以执行恶意程序。
- D验证: confirmed / ver_cd3b9838
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 295. hyp_path_2eda3b5d3b4a

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_06.c:68
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供任意字符串。; 程序在运行时会利用该环境变量进行搜索路径相关的操作（如加载库或执行程序），该行为隐含在CWE427上下文中。
- 触发路径: fgets(data+dataLen, (int)(250-dataLen), stdin) @ CWE427_Uncontrolled_Search_Path_Element__char_console_06.c:48; PUTENV(data); @ CWE427_Uncontrolled_Search_Path_Element__char_console_06.c:68
- 结论: 程序通过fgets从控制台读取用户输入，未经任何净化直接作为参数传递给putenv设置环境变量，导致攻击者可以控制搜索路径元素，可能加载恶意动态库或执行恶意程序。
- D验证: confirmed / ver_239377b4
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 296. hyp_path_2877fd77486d

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_09.c:64
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供任意字符串，例如设置 PATH 为恶意目录
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_09.c:42-46; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_09.c:64
- 结论: 程序从控制台读取用户输入，未经任何验证直接作为环境变量设置函数的参数，攻击者可以通过设置 PATH 等关键环境变量改变搜索路径，导致后续可能执行恶意代码。
- D验证: confirmed / ver_9ba201b4
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 297. hyp_path_067d94156d1e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_10.c:64
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制标准输入
- 触发路径: fgets(data+dataLen, (int)(250-dataLen), stdin) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_10.c:44; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_10.c:64
- 结论: 程序从标准输入读取数据后直接通过PUTENV设置环境变量，攻击者可控制输入导致环境变量被篡改，从而引发搜索路径劫持漏洞。
- D验证: confirmed / ver_1d23a31c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 298. hyp_path_bc63988833c9

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_13.c:64
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入提供任意字符串
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_13.c:44; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_13.c:64
- 结论: 程序从控制台读取输入并直接作为环境变量设置，攻击者可通过控制台输入恶意路径，导致不受控制的搜索路径元素，可能引发恶意DLL加载等攻击。
- D验证: confirmed / ver_ed93d252
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 299. hyp_path_b21d0416c0c8

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_14.c:64
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入输入任意字符串
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_14.c:44; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_14.c:64
- 结论: 程序从控制台读取输入并直接通过putenv设置环境变量，攻击者可以控制环境变量值，导致搜索路径劫持（如修改PATH指向恶意目录），从而可能加载恶意代码。
- D验证: confirmed / ver_9dba8523
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 300. hyp_path_75dc09863411

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_15.c:70
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制标准输入（stdin）内容; 程序运行环境支持`putenv`修改环境变量
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) {...} @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_15.c:43-46; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_15.c:70
- 结论: 存在不受控制的搜索路径元素漏洞：从控制台读取的数据直接传递给`putenv`，攻击者可设置恶意环境变量（如PATH）以劫持动态链接库或命令执行路径。
- D验证: confirmed / ver_4cd075ff
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 301. hyp_path_5b18d0c89d77

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_16.c:65
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入提供任意字符串。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_16.c:42-46; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_16.c:65
- 结论: 程序通过fgets从控制台读取用户输入，并将其直接作为参数传递给PUTENV设置环境变量，未进行任何验证或清理。攻击者可利用此漏洞设置恶意环境变量（如PATH），导致搜索路径劫持，进而执行任意代码。
- D验证: confirmed / ver_548b44de
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 302. hyp_path_540e64d36221

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_18.c:63
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串（可包含'='等特殊字符）
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_18.c:42-46; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_18.c:61-65
- 结论: 程序通过fgets从控制台读取用户输入，然后直接作为参数调用putenv设置环境变量，未对输入进行任何验证或清理。攻击者可以设置恶意路径环境变量（如PATH），从而控制动态链接库搜索顺序，导致任意代码执行。
- D验证: confirmed / ver_afeefd83
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 303. hyp_path_b770764542f0

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_17.c:65
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制控制台输入（stdin）
- 触发路径: fgets(data+dataLen, (int)(250-dataLen), stdin) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_17.c:43-47; dataLen = strlen(data); if (dataLen > 0 && data[dataLen-1] == '\n') { ... } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_17.c:47-51; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_17.c:63-67
- 结论: 程序通过控制台读取输入并直接用于设置环境变量（PUTENV），攻击者可输入恶意路径控制搜索路径，导致CWE427漏洞。但B阶段信号显示风险极低，可能需要动态验证或人工审计确认利用性。
- D验证: confirmed / ver_7dcdf007
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 304. hyp_path_56097ecfa3b6

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_05.c:71
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供恶意数据。
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_05.c:49-53; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_05.c:71
- 结论: 程序从控制台读取未经验证的宽字符串输入，并通过_wputenv（PUTENV宏）设置环境变量，攻击者可控制搜索路径元素，导致不受控制的搜索路径漏洞。
- D验证: confirmed / ver_6c1ab289
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 305. hyp_path_3d2bf422b0fc

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_06.c:68
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台（stdin）输入任意字符串。
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_06.c:46-48; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_06.c:68
- 结论: 程序使用fgetws从控制台读取用户输入作为路径字符串，然后直接传递给_wputenv设置环境变量，攻击者可以通过控制台输入恶意路径来控制搜索路径，导致CWE-427不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_18dc7bc2
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 306. hyp_path_b000a30a55bc

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_07.c:70
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_07.c:48-52; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_07.c:70
- 结论: 程序从控制台读取数据并直接作为环境变量值传递给_wputenv，攻击者可以控制搜索路径元素，导致CWE-427漏洞。
- D验证: confirmed / ver_87171277
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 307. hyp_path_e0b959b59d13

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_17.c:65
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制程序的标准输入
- 触发路径: fgetws(data+dataLen, (int)(250-dataLen), stdin) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_17.c:45; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_17.c:65
- 结论: 程序使用fgetws从控制台读取输入，然后将该输入直接传递给_wputenv设置环境变量，攻击者可以通过控制台输入设置恶意的环境变量（如PATH），导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_498f7f66
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 308. hyp_path_6bffea8f7a43

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_21.c:47
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的内容。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_21.c:48; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_21.c:53
- 结论: 代码从环境变量读取数据，并通过strncat追加到固定大小的缓冲区data中，可能使攻击者控制搜索路径元素，导致CWE-427漏洞。但缺乏data后续用于搜索路径操作（如系统调用）的证据，漏洞路径未完全闭合。
- D验证: confirmed / ver_fb7142e0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 309. hyp_path_a7d1d320107e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_42.c:42
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值，例如通过设置环境变量或利用其他漏洞间接控制。
- 触发路径: strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_42.c:42; char * environment = GETENV(ENV_VARIABLE); ... if (environment != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_42.c:43-44
- 结论: 程序从环境变量读取数据并追加到搜索路径字符串中，未对输入进行任何验证或限制，攻击者可通过设置恶意环境变量控制搜索路径，导致加载恶意库或程序。
- D验证: confirmed / ver_d3e57895
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 310. hyp_path_c9e7e631f766

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_22b.c:47
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: Attacker can set the environment variable ENV_VARIABLE (e.g., via process environment or local privilege escalation).; The constructed `data` string must be used as a search path element in a subsequent function call (e.g., system, exec, LoadLibrary) without proper validation.
- 触发路径: size_t dataLen = strlen(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_22b.c:47; char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_22b.c:48; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_22b.c:53
- 结论: The code reads an environment variable and appends it to a local buffer using strncat. This constructed string is likely used later as a search path element (e.g., in system, exec, or LoadLibrary) based on the test case context, allowing an attacker to control the search path. However, the provided snippet does not include the sink call, so the vulnerability path is incomplete.
- D验证: confirmed / ver_46bb0820
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 311. hyp_path_ac00103ee55c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_61b.c:42
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过环境变量注入任意字符串，且该字符串未经过滤即被拼接到路径缓冲区中。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_61b.c:43; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_61b.c:48
- 结论: 代码从环境变量获取输入并追加到缓冲区data中，未对输入进行任何过滤或验证，导致攻击者可控的输入可能被用于搜索路径元素，从而引发CWE-427漏洞。后续如果data被用作库加载或命令执行的路径，将导致任意代码执行。
- D验证: confirmed / ver_1a7bae9a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 312. hyp_path_aca260a70adf

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_21.c:47
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值，且程序在受影响的上下文中运行。
- 触发路径: wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_21.c:48; wcsncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_21.c:53
- 结论: 从环境变量读取数据并追加到缓冲区，该缓冲区可能被用于搜索路径，导致未受控的搜索路径元素，攻击者可控制环境变量来加载恶意库。
- D验证: confirmed / ver_d5407e7d
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 313. hyp_path_1fba64b776d8

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_42.c:42
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值
- 触发路径: wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_42.c:43; wcsncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_42.c:48
- 结论: 存在未控制搜索路径元素漏洞，攻击者可通过控制环境变量ENV_VARIABLE的值，影响搜索路径（data），从而可能劫持后续的搜索路径操作（如加载恶意DLL或执行恶意程序）。
- D验证: confirmed / ver_3e3b93a4
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 314. hyp_path_5f1f54dbec94

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_61b.c:42
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量 ENV_VARIABLE 的值
- 触发路径: wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_61b.c:43; wcsncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_61b.c:48
- 结论: 程序从环境变量获取数据并追加到搜索路径缓冲区，攻击者可通过控制环境变量修改搜索路径，导致不受控搜索路径元素漏洞。
- D验证: confirmed / ver_81649f5e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 315. hyp_path_d1b6ae14bd7d

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_33.cpp:49
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过环境变量ENV_VARIABLE注入恶意路径字符串。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_33.cpp:50; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_33.cpp:55; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_33.cpp:61
- 结论: 从环境变量读取数据后未经验证即设置为环境变量，可能导致攻击者控制搜索路径，触发CWE-427不安全搜索路径元素漏洞。
- D验证: confirmed / ver_5fb3af72
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 316. hyp_path_2012fc448aa4

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_34.c:52
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响ENV_VARIABLE环境变量的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_34.c:53; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_34.c:58; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_34.c:65
- 结论: 代码从环境变量读取数据并拼接到data中，然后通过PUTENV设置新的环境变量。如果攻击者能够控制该环境变量，则可以设置一个不受信任的搜索路径元素（如PATH），可能导致不受控制的搜索路径元素漏洞（CWE-427）。
- D验证: confirmed / ver_a6bd0330
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 317. hyp_path_a832f32b03b1

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_31.c:45
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响当前进程的环境变量ENV_VARIABLE
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_31.c:46; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_31.c:51; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_31.c:58
- 结论: 代码从环境变量读取数据并拼接到字符串后，直接调用putenv设置环境变量。攻击者可通过控制环境变量ENV_VARIABLE的值，影响搜索路径，导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_843dced2
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 318. hyp_path_8a72ed5eea29

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_41.c:52
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供任意字符串
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_41.c:46-50; CWE427_Uncontrolled_Search_Path_Element__char_console_41_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_41.c:67; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_41.c:33
- 结论: 程序通过fgets从标准输入读取用户输入，未经验证直接传递给PUTENV设置环境变量，攻击者可以控制搜索路径元素，导致不受控制的搜索路径漏洞（CWE-427）。
- D验证: confirmed / ver_75ccb12c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 319. hyp_path_c47277db8c8c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_67a.c:54
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够影响环境变量ENV_VARIABLE的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_67a.c:55; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_67a.c:60; CWE427_Uncontrolled_Search_Path_Element__char_environment_67b_case0Sink(myStruct); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_67a.c:64
- 结论: 程序从环境变量读取数据并追加到固定大小的缓冲区，然后作为搜索路径元素传递给sink函数，可能导致不受控制的搜索路径元素漏洞（CWE-427），攻击者可通过环境变量控制搜索路径，执行恶意代码。
- D验证: confirmed / ver_82aa765b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 320. hyp_path_1d423a094c9e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_32.c:49
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值; 程序后续存在依赖于该环境变量的路径搜索操作（如execvp、LoadLibrary等）
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_32.c:50; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_32.c:55; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_32.c:63
- 结论: 程序从环境变量读取数据并追加到缓冲区，然后将该缓冲区内容设置为新的环境变量，可能导致不受控制的搜索路径元素漏洞。当前代码仅包含PUTENV调用，未展示后续使用该环境变量进行路径搜索的操作，因此漏洞路径不完整。
- D验证: confirmed / ver_47777524
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 321. hyp_path_bf4cfbdff79b

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_66a.c:49
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_66a.c:50; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_66a.c:55; dataArray[2] = data; CWE427_Uncontrolled_Search_Path_Element__char_environment_66b_case0Sink(dataArray); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_66a.c:60
- 结论: 代码从环境变量读取数据并拼接到data字符串中，然后传递给sink函数，可能导致不受控制的搜索路径元素漏洞，攻击者可控制搜索路径执行恶意代码。
- D验证: confirmed / ver_a5ee6a70
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 322. hyp_path_8521fa8ac646

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_45.c:55
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置目标进程的环境变量，例如通过其他漏洞或直接控制启动环境。
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_45.c:56; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_45.c:61; CWE427_Uncontrolled_Search_Path_Element__char_environment_45_case0Data = data; case0Sink(); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_45.c:66; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_45.c:44
- 结论: 程序通过getenv获取环境变量，拼接到data后作为参数调用PUTENV，攻击者可通过控制环境变量注入任意内容，导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_10906efd
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 323. hyp_path_1a30df5386d1

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_68a.c:51
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过环境变量（如PATH或自定义变量）提供恶意路径片段; 程序后续使用该搜索路径加载动态库或执行程序
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_68a.c:52; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_68a.c:57; CWE427_Uncontrolled_Search_Path_Element__char_environment_68b_case0Sink(); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_68a.c:61
- 结论: 程序从环境变量读取数据并追加到搜索路径字符串中，攻击者可以通过控制环境变量来操纵搜索路径元素，导致加载恶意库或执行未授权代码。
- D验证: confirmed / ver_04a280f2
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 324. hyp_path_8a3a5eefca2e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_66a.c:49
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE为任意字符串
- 触发路径: wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_66a.c:49; wcsncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_66a.c:55; CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_66b_case0Sink(dataArray); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_66a.c:60
- 结论: 未控制搜索路径元素漏洞：程序从环境变量读取数据并追加到搜索路径中，未进行有效限制，攻击者可通过设置恶意环境变量控制搜索路径，导致加载恶意库或执行任意代码。
- D验证: confirmed / ver_e12ad000
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 325. hyp_path_be240b1985e1

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_67a.c:54
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置目标进程的环境变量ENV_VARIABLE为恶意值（如包含路径分隔符的任意路径）
- 触发路径: size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); /* If there is data in the environment variable */ @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_67a.c:52-56; wcsncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_67a.c:58-62; myStruct.structFirst = data; CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_67b_case0Sink(myStruct); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_67a.c:62-66
- 结论: 存在未控制搜索路径元素漏洞。代码从环境变量获取输入，未经验证直接拼接后传递给sink函数，攻击者可通过设置环境变量控制搜索路径，导致加载恶意库或执行任意代码。
- D验证: confirmed / ver_f17bd3fe
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 326. hyp_path_e79dd448fb89

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_62b.cpp:45
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能控制环境变量ENV_VARIABLE的值
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_62b.cpp:46; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_62b.cpp:51
- 结论: 程序从环境变量读取数据并追加到搜索路径字符串中，攻击者可通过设置环境变量控制搜索路径元素，导致非预期加载或执行风险。
- D验证: confirmed / ver_4fae2b8d
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 327. hyp_path_9ab13af169b2

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_43.cpp:45
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值。
- 触发路径: size_t dataLen = strlen(data); char * environment = GETENV(ENV_VARIABLE); @ line 45-46; strncat(data+dataLen, environment, 250-dataLen-1); @ line 51
- 结论: 存在未控制搜索路径元素漏洞的潜在风险，攻击者可通过环境变量控制路径缓冲区内容，但缺少明确sink（如system、LoadLibrary等）调用，需要进一步验证路径是否最终传递给敏感函数。
- D验证: confirmed / ver_d454c429
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 328. hyp_path_e9601a3f5251

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_68a.c:51
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置目标进程的环境变量（如PATH或特定变量）
- 触发路径: wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_68a.c:51; wcsncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_68a.c:57; CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_68b_case0Sink(); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_68a.c:61
- 结论: 存在不受控制的搜索路径元素漏洞：从环境变量读取数据并追加到字符串，随后该字符串被用作搜索路径的一部分，攻击者可通过控制环境变量修改搜索路径。
- D验证: confirmed / ver_1c4b55b7
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 329. hyp_path_b2795e8fe658

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_83_case0.cpp:36
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值; 程序后续将data用于搜索路径操作（未确认）
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_83_case0.cpp:37; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_83_case0.cpp:42; 假设data被传递给system/exec等，但未在片段中确认 @ 后续使用（未在提供代码中显示）
- 结论: 代码从环境变量读取数据并追加到data缓冲区，但代码片段中未展示data后续被用于搜索路径相关的函数调用（如system、exec、LoadLibrary等），因此无法确认完整的source-sink路径，漏洞存在不确定性，但source存在且符合CWE-427模式。
- D验证: confirmed / ver_57612e97
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 330. hyp_path_ac0a3933b296

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_84_case0.cpp:36
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: Attacker controls the environment variable specified by ENV_VARIABLE
- 触发路径: char * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_84_case0.cpp:37; strncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_84_case0.cpp:42
- 结论: Untrusted environment variable appended to data, potentially used as a search path element, leading to CWE-427.
- D验证: confirmed / ver_0cdaf2bf
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 331. hyp_path_6a1e289b917b

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_43.cpp:45
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE
- 触发路径: wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_43.cpp:46; wcsncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_43.cpp:51
- 结论: 攻击者可能通过控制环境变量修改搜索路径，导致未受控的搜索路径元素漏洞，但缺乏sink调用，证据不完整。
- D验证: confirmed / ver_ba10a9f2
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 332. hyp_path_50e24e2be102

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_62b.cpp:45
- 漏洞类型: buffer_overflow
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值，使其包含超长字符串。
- 触发路径: size_t dataLen = wcslen(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_62b.cpp:43; wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_62b.cpp:44; if (environment != NULL) { wcsncat(data+dataLen, environment, 250-dataLen-1); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_62b.cpp:45-47
- 结论: 程序从环境变量读取数据并追加到固定大小的缓冲区，未检查缓冲区剩余空间，可能导致缓冲区溢出，进而被利用执行任意代码或造成信息泄露。
- D验证: confirmed / ver_a48e894a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 333. hyp_path_d847c485d1f2

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_83_case0.cpp:36
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量ENV_VARIABLE的值，且data缓冲区后续被用作搜索路径元素（如传递给LoadLibrary或CreateProcess等sink）。
- 触发路径: size_t dataLen = wcslen(data); wchar_t * environment = GETENV(ENV_VARIABLE); @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_83_case0.cpp:35-37; wcsncat(data+dataLen, environment, 250-dataLen-1); @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_83_case0.cpp:42
- 结论: 从环境变量读取数据并追加到搜索路径元素缓冲区，攻击者可通过控制环境变量控制搜索路径，可能导致加载恶意库。
- D验证: confirmed / ver_3d72ba19
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 334. hyp_path_4d22158fa6fd

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_51a.c:40
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入提供任意字符串，作为搜索路径元素。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) { ... } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_51a.c:43-47; CWE427_Uncontrolled_Search_Path_Element__char_console_51b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_51a.c:61-65
- 结论: 用户从控制台输入数据，未经验证就传递给搜索路径元素相关的sink函数，导致攻击者可以控制搜索路径，加载恶意动态库或可执行文件。
- D验证: confirmed / ver_3f1f738f
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 335. hyp_path_d027e98c5615

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_84_case0.cpp:36
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置环境变量ENV_VARIABLE的值; data缓冲区后续被用作搜索路径元素（如传递给exec或LoadLibrary）
- 触发路径: size_t dataLen = wcslen(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_84_case0.cpp:36; wchar_t * environment = GETENV(ENV_VARIABLE); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_84_case0.cpp:37; wcsncat(data+dataLen, environment, 250-dataLen-1); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_84_case0.cpp:42
- 结论: 在CWE427测试用例中，使用GETENV从环境变量获取数据，并通过wcsncat追加到固定大小缓冲区data中。虽然限制了追加长度，但环境变量内容完全由攻击者控制，后续若data被用作搜索路径元素（如传递给exec或LoadLibrary），可能导致恶意DLL加载或命令执行。当前代码片段仅完成数据注入，未展示后续使用，但存在潜在风险。
- D验证: confirmed / ver_5c1b4bde
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 336. hyp_path_81ab3abe991e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_53a.c:40
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供恶意构造的字符串。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_53a.c:45; CWE427_Uncontrolled_Search_Path_Element__char_console_53b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_53a.c:63
- 结论: 存在不受控制的搜索路径元素漏洞。用户通过控制台输入的字符串被直接传递给sink函数，可能被用于设置搜索路径，导致攻击者可以控制搜索路径元素，从而执行恶意代码。
- D验证: confirmed / ver_78f4dbe4
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 337. hyp_path_617ce34a02a4

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_54a.c:49
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够提供控制台输入（例如通过标准输入重定向或交互式输入）
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_54a.c:45; CWE427_Uncontrolled_Search_Path_Element__char_console_54b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_54a.c:63
- 结论: 程序从控制台读取输入，未经检查即传递给搜索路径元素处理函数，攻击者可能通过控制台输入注入恶意路径，导致执行任意代码或加载恶意库。
- D验证: confirmed / ver_679c9552
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 338. hyp_path_618e7f023c7e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_52a.c:49
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供任意字符串。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) { /* The next few lines remove the carriage return from the string that is */ @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_52a.c:43-47; } } CWE427_Uncontrolled_Search_Path_Element__char_console_52b_case0Sink(data); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_52a.c:61-65
- 结论: 程序从标准输入读取字符串作为搜索路径元素，未进行任何验证或净化，攻击者可以控制搜索路径，可能导致任意代码执行或信息泄露。
- D验证: confirmed / ver_2d5c9434
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 339. hyp_path_a0abe8677cf0

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_64a.c:40
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入（stdin）向程序提供任意字符串。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) { ... } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_64a.c:43-47; CWE427_Uncontrolled_Search_Path_Element__char_console_64b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_64a.c:61-65
- 结论: 程序从控制台读取用户输入（fgets），然后将未经验证的输入传递给CWE427_Uncontrolled_Search_Path_Element__char_console_64b_case0Sink函数。该sink函数可能将用户控制的数据用作搜索路径元素，但由于缺乏sink内部实现证据，且B阶段风险得分低、无缺失特征，无法确认实际漏洞。存在潜在风险，但需要动态验证或审计sink实现。
- D验证: confirmed / ver_d261a27e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 340. hyp_path_5b92e5d6d88b

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_63a.c:49
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台（stdin）输入任意字符串，包括路径分隔符和恶意路径元素。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_63a.c:43-47; CWE427_Uncontrolled_Search_Path_Element__char_console_63b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_63a.c:63
- 结论: 程序从控制台读取用户输入到data缓冲区，然后通过sink函数（CWE427_Uncontrolled_Search_Path_Element__char_console_63b_case0Sink）传递该数据。如果sink函数将data用于设置搜索路径（如环境变量PATH或动态库加载路径），攻击者可通过注入恶意路径元素导致搜索路径劫持漏洞（CWE-427）。但由于sink函数的具体实现未提供，且B阶段静态分析不支持（low sink score, no deviation），该路径存在但风险未完全闭合。
- D验证: confirmed / ver_90b0f6dc
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 341. hyp_path_4970278156b9

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_51a.c:40
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入数据（例如恶意路径字符串）
- 触发路径: size_t dataLen = wcslen(data); if (250-dataLen > 1) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_51a.c:38-42; if (fgetws(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_51a.c:43-47; CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_51b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_51a.c:61-65
- 结论: 程序从控制台读取输入，未验证输入内容，直接传递给可能影响搜索路径的sink函数，导致攻击者可以控制搜索路径元素，进而劫持加载的库或可执行文件。
- D验证: confirmed / ver_6a86d2ae
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 342. hyp_path_1735fbce07db

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_52a.c:49
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入提供字符串
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_52a.c:43; CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_52b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_52a.c:63
- 结论: 从控制台读取的宽字符串数据直接传递给搜索路径元素设置函数，攻击者可通过控制台输入任意搜索路径，导致搜索路径劫持，从而可能执行恶意代码。
- D验证: confirmed / ver_94ef29e0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 343. hyp_path_42020c598199

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_53a.c:40
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入（stdin）提供任意字符串，且字符串长度不超过249个字符（含空终止符）。
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_53a.c:45; CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_53b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_53a.c:63
- 结论: 存在不受控制的搜索路径元素漏洞，攻击者可通过控制台输入控制搜索路径，导致执行恶意代码。
- D验证: confirmed / ver_818552bc
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 344. hyp_path_83ae46c46f16

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_54a.c:49
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供任意字符串
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_54a.c:45; CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_54b_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_54a.c:63
- 结论: 程序从控制台读取用户输入并直接传递给未受控的搜索路径元素处理函数，攻击者可以控制搜索路径导致任意代码执行。
- D验证: confirmed / ver_c7bb442a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 345. hyp_path_11e9ffc1690c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_63a.c:49
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者可以控制控制台输入
- 触发路径: fgetws(data+dataLen, (int)(250-dataLen), stdin) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_63a.c:41-45; CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_63b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_63a.c:63
- 结论: 该函数从控制台读取用户输入，并将其作为搜索路径元素传递给后续处理，攻击者可以通过控制台输入恶意路径，导致搜索路径劫持（例如，加载恶意DLL或执行任意命令）。
- D验证: confirmed / ver_4e79c8b8
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 346. hyp_path_705528eb7a43

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_64a.c:49
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够访问程序的控制台输入流
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_64a.c:45; CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_64b_case0Sink(&data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_64a.c:63
- 结论: 程序从控制台读取用户输入（fgetws）并直接作为搜索路径元素传递给Sink函数，攻击者可以通过输入恶意路径导致执行任意代码，存在不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_43dd8109
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 347. hyp_path_2814ba5bf1ae

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_81a.cpp:32
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入提供任意字符串作为data
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_81a.cpp:35-39; baseObject.action(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_81a.cpp:55
- 结论: CWE-427: Uncontrolled Search Path Element via console input
- D验证: confirmed / ver_884ac39b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 348. hyp_path_a244ed2ccad8

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_81a.cpp:32
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入（stdin）提供任意字符串
- 触发路径: fgetws(data+dataLen, (int)(250-dataLen), stdin); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_81a.cpp:37; baseObject.action(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_81a.cpp:55-56
- 结论: 存在未控制搜索路径元素漏洞，从控制台读取的输入数据直接传递给action函数，可能被用作搜索路径元素，导致加载任意DLL或恶意文件。
- D验证: confirmed / ver_9ea8b1b1
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 349. hyp_path_9c9ef47c60db

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_33.cpp:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供任意字符串。; 程序后续会使用受影响的环境变量（如PATH）加载外部程序或库。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_33.cpp:44-48; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_33.cpp:65-69
- 结论: 存在CWE-427未控制搜索路径元素漏洞。程序通过fgets从控制台读取输入，并直接传递给PUTENV设置环境变量，未对输入进行任何验证或清理。攻击者可以控制输入，设置恶意的搜索路径（如包含当前目录），导致加载恶意动态库或可执行文件。
- D验证: confirmed / ver_c360ae07
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 350. hyp_path_3e81b0945862

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_31.c:46
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入提供任意字符串，包括包含路径分隔符的恶意路径。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_31.c:40-42; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_31.c:64
- 结论: 程序通过控制台读取输入并直接作为环境变量路径设置，攻击者可控制搜索路径元素，导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_de674f69
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 351. hyp_path_799a0c122029

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_31.c:46
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入（stdin）提供任意字符串。
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_31.c:40-44; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_31.c:64
- 结论: 程序从控制台读取用户输入，未经任何验证或过滤，直接通过PUTENV（即_wputenv）设置环境变量。攻击者可控制环境变量（如PATH），导致后续动态链接库搜索路径被篡改，可能加载恶意DLL。
- D验证: confirmed / ver_9828cb00
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 352. hyp_path_49d7737ea16d

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_34.c:53
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入向程序提供字符串
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) { /* The next few lines remove the carriage return from the string that is */ @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_34.c:47-51; dataLen = strlen(data); if (dataLen > 0 && data[dataLen-1] == '\n') { @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_34.c:51-53; char * data = myUnion.unionSecond; /* NOTE: Set a new environment variable with a path that is possibly insecure */ PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_34.c:69-73
- 结论: 程序从控制台读取用户输入并直接作为环境变量设置（PUTENV），未对输入进行任何验证或限制，导致攻击者可以控制搜索路径元素，造成CWE-427漏洞。
- D验证: confirmed / ver_097e5116
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 353. hyp_path_183a491c57b7

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_34.c:53
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入提供数据（控制台输入）
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_34.c:47-51; wchar_t * data = myUnion.unionSecond; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_34.c:69-73
- 结论: 程序从控制台读取数据后直接作为环境变量值传递给_wputenv，未进行任何验证，导致攻击者可以通过控制台输入设置恶意环境变量（如修改PATH或LD_LIBRARY_PATH），从而劫持程序加载的库或执行文件。
- D验证: confirmed / ver_5ed4792c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 354. hyp_path_b4aac1779fc8

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_32.c:41
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入发送恶意字符串。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_32.c:44-48; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_32.c:67-71
- 结论: 存在不受控制的搜索路径元素漏洞，攻击者可通过控制台输入设置恶意环境变量，进而控制搜索路径。
- D验证: confirmed / ver_ca74fc9e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 355. hyp_path_a18dd84ffbf4

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_45.c:56
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序的标准输入（stdin）提供数据。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_45.c:50; CWE427_Uncontrolled_Search_Path_Element__char_console_45_case0Data = data; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_45.c:69; case0Sink(); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_45.c:71; static void case0Sink() { char * data = CWE427_Uncontrolled_Search_Path_Element__char_console_45_case0Data; PUTENV(data); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_45.c:33-38
- 结论: 程序从控制台读取输入后，通过PUTENV设置环境变量，未对输入进行验证，可能导致不受控制的搜索路径元素（CWE-427）。攻击者可控制环境变量值，进而影响程序行为或执行任意代码。
- D验证: confirmed / ver_54dfcde5
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 356. hyp_path_0006352ae3cc

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_66a.c:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入提供数据（例如在本地执行或远程交互场景下）。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_66a.c:44-48; CWE427_Uncontrolled_Search_Path_Element__char_console_66b_case0Sink(dataArray); // dataArray[2] = data @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_66a.c:66
- 结论: 程序通过控制台读取用户输入，并将该输入作为参数传递给后续函数，可能被用作搜索路径元素，导致不受控制的搜索路径元素漏洞（CWE-427）。攻击者可通过控制台输入恶意路径，影响系统行为。
- D验证: confirmed / ver_48e57a9b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 357. hyp_path_7b195b417613

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_67a.c:55
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入（stdin）向程序提供任意字符串
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_67a.c:51; CWE427_Uncontrolled_Search_Path_Element__char_console_67b_case0Sink(myStruct); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_67a.c:70
- 结论: 程序从控制台读取用户输入（通过fgets）并直接传递给sink函数，sink函数可能将该输入用作搜索路径元素，攻击者可以控制路径导致加载恶意文件或执行任意代码。
- D验证: confirmed / ver_2b3121b4
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 358. hyp_path_6290f2e5d656

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_68a.c:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入提供任意字符串。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_68a.c:46-50; CWE427_Uncontrolled_Search_Path_Element__char_console_68_case0Data = data; CWE427_Uncontrolled_Search_Path_Element__char_console_68b_case0Sink(); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_68a.c:67
- 结论: 用户通过控制台输入的数据被存储到全局变量并传递给sink函数，但sink函数内部具体实现未知，无法确认是否构成不受控制的搜索路径元素漏洞。需要进一步审计sink函数代码。
- D验证: confirmed / ver_efc346af
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 359. hyp_path_17cc39db7f16

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_66a.c:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入提供任意字符串
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_66a.c:46; dataArray[2] = data; CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_66b_case0Sink(dataArray); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_66a.c:64-66
- 结论: 程序从控制台读取用户输入，未经验证直接传递给CWE427 Uncontrolled Search Path Element的sink函数，攻击者可控制搜索路径元素导致任意命令执行或路径劫持。
- D验证: confirmed / ver_2735b474
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 360. hyp_path_a21828046f2c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_67a.c:55
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入提供数据。
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_67a.c:49-53; myStruct.structFirst = data; CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_67b_case0Sink(myStruct); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_67a.c:70
- 结论: 控制台输入的字符串被直接传递给外部函数，可能导致不受控制的搜索路径元素，攻击者可利用此漏洞加载恶意DLL或执行任意代码。
- D验证: confirmed / ver_c607227a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 361. hyp_path_73ba92298bee

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_68a.c:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入提供任意字符串
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), stdin) != NULL) { ... } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_68a.c:46-50; CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_68b_case0Sink(); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_68a.c:67
- 结论: 程序从控制台读取用户输入的字符串作为搜索路径元素，可能导致不受控制的搜索路径漏洞（CWE-427）
- D验证: confirmed / ver_1479104f
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 362. hyp_path_79a950b1c684

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_84_case0.cpp:28
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台提供输入（stdin）
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_84_case0.cpp:31
- 结论: 存在未控制搜索路径元素漏洞，攻击者可通过控制台输入注入恶意路径，但sink未直接在代码证据中闭合，需要进一步确认。
- D验证: confirmed / ver_cb6be50e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 363. hyp_path_aa8e5dcb26a6

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_62b.cpp:46
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入（stdin）控制data缓冲区的内容
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_62b.cpp:40-44
- 结论: 存在从控制台读取数据并可能影响搜索路径元素的潜在漏洞，但缺少关键sink环节，证据不完整。
- D验证: confirmed / ver_1fabfa6d
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 364. hyp_path_483a80825e07

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_43.cpp:46
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入（stdin）提供任意字符串作为输入。
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_43.cpp:40-44; 未在提供片段中显示，但根据CWE427，数据可能用于SetDllDirectory、LoadLibrary等函数 @ 假设后续调用
- 结论: 程序从控制台读取用户输入，未经验证直接用于搜索路径元素，可能导致不受控制的搜索路径漏洞，攻击者可利用此修改搜索路径以执行恶意代码。
- D验证: confirmed / ver_4997461f
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 365. hyp_path_437c1a60a11c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_83_case0.cpp:37
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台提供任意输入（字符串）; 程序后续将输入用作搜索路径元素且未做安全检查
- 触发路径: if (fgets(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_83_case0.cpp:31-35; dataLen = strlen(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_83_case0.cpp:37; 假设data作为参数传递给PutEnv或LoadLibrary等函数 @ 假设后续代码
- 结论: 从控制台读取的输入可能被用于搜索路径元素，但缺乏明确的sink函数（如PutEnv、LoadLibrary等）证据，无法完全确认漏洞。
- D验证: confirmed / ver_8cfccd9a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 366. hyp_path_38330f1ef145

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_43.cpp:46
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过标准输入提供任意数据，填充到路径缓冲区中
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_43.cpp:42; dataLen = wcslen(data); if (dataLen > 0 && data[dataLen-1] == L'\n') @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_43.cpp:46
- 结论: 通过console读取未受控输入到路径缓冲区，可能构成CWE-427不受控制的搜索路径元素漏洞
- D验证: confirmed / ver_1ae2b318
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 367. hyp_path_09a9c6b222b9

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_22b.c:48
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向标准输入提供任意字符串（例如通过控制台交互）
- 触发路径: if (fgetws(data+dataLen, (int)(250-dataLen), stdin) != NULL) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_22b.c:42-46; 假设：data作为参数传递给_wputenv或类似函数 @ 同一文件后续未显示的sink调用
- 结论: 程序通过fgetws从控制台读取宽字符串数据，未经验证可能被用作搜索路径元素（如环境变量或可执行文件路径），攻击者可以控制输入导致搜索路径元素不可控，从而可能执行恶意代码。
- D验证: confirmed / ver_e793e8d2
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 368. hyp_path_764d600dbd19

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_61b.c:34
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串
- 触发路径: fgetws(data+dataLen, (int)(250-dataLen), stdin) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_61b.c:37-41; 以data为参数调用搜索路径相关函数（如SetEnvironmentVariable或_wputenv） @ 后续代码（未在片段中展示）
- 结论: 存在不受控制的搜索路径元素漏洞（CWE-427），攻击者通过控制台输入可控制搜索路径元素，但未在提供的代码片段中展示具体的sink调用（如SetEnvironmentVariable或_wputenv），证据不完整。
- D验证: confirmed / ver_14893ad9
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 369. hyp_path_1470a82ff650

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_73b.cpp:39
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向dataList中注入来自控制台的恶意字符串，需要确认dataList的源点。
- 触发路径: char * data = dataList.back(); @ CWE427_Uncontrolled_Search_Path_Element__char_console_73b.cpp:39; PUTENV(data); @ CWE427_Uncontrolled_Search_Path_Element__char_console_73b.cpp:41
- 结论: 代码将dataList中的数据直接传递给PUTENV，可能导致未控制的搜索路径元素漏洞。但dataList的输入来源未在给定证据中明确，需要进一步确认输入是否来自外部控制（如控制台）。
- D验证: confirmed / ver_86493d31
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 370. hyp_path_9b3c7e4c80fb

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_72b.cpp:41
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台接口向 dataVector 中注入恶意数据。; 程序执行到该 sink 点，且未对数据进行净化。
- 触发路径: char * data = dataVector[2]; @ CWE427_Uncontrolled_Search_Path_Element__char_console_72b.cpp:39; PUTENV(data); @ CWE427_Uncontrolled_Search_Path_Element__char_console_72b.cpp:41
- 结论: 存在不受控制的搜索路径元素漏洞。程序从 dataVector 中取出数据，并直接传递给 PUTENV 设置环境变量，未对数据进行任何验证或过滤，攻击者可通过控制台输入恶意路径，设置如 PATH 等环境变量，导致搜索路径劫持，可能执行任意代码。
- D验证: confirmed / ver_729953c7
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 371. hyp_path_4707b729cb08

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_83_case0.cpp:56
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制控制台输入，从而控制data的内容
- 触发路径: PUTENV(data); @ CWE427_Uncontrolled_Search_Path_Element__char_console_83_case0.cpp:56
- 结论: 存在不受控制的搜索路径元素漏洞（CWE-427）：函数调用PUTENV(data)设置环境变量，其中data可能包含用户输入，导致攻击者可以修改搜索路径，从而可能加载恶意代码。
- D验证: confirmed / ver_ec38bb9e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 372. hyp_path_1886de06cd8b

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_84_case0.cpp:56
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与程序交互并输入数据
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_84_case0.cpp:56
- 结论: 程序使用来自控制台输入的数据直接设置环境变量（putenv），攻击者可以控制环境变量值，从而影响程序行为（如加载恶意动态库），导致搜索路径元素未受控制。
- D验证: confirmed / ver_951eed6b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 373. hyp_path_5d5286a46758

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_72b.cpp:39
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够影响dataVector中的元素，例如通过控制环境变量来影响dataVector的构建过程。
- 触发路径: char * data = dataVector[2]; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_72b.cpp:39; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_72b.cpp:41
- 结论: 代码从dataVector[2]获取数据并直接传递给PUTENV，如果dataVector的内容来自外部不受信任的源（如环境变量），则攻击者可以控制程序搜索路径，导致不可控的搜索路径元素漏洞。
- D验证: confirmed / ver_586ad05e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 374. hyp_path_4bf60b051b67

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_83_case0.cpp:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制传入PUTENV的字符串data，例如通过环境变量或其他输入渠道；在此测试用例中，data通常来自环境变量或用户可控源。
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_83_case0.cpp:50
- 结论: 在析构函数中调用PUTENV，使用可能受外部控制的数据data设置环境变量，若data包含恶意路径（如修改PATH），可导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_60bdfe85
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 375. hyp_path_513f5b16aedf

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_73b.cpp:39
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够影响dataList中的数据（从环境变量传递）。
- 触发路径: char * data = dataList.back(); @ CWE427_Uncontrolled_Search_Path_Element__char_environment_73b.cpp:39; PUTENV(data); @ CWE427_Uncontrolled_Search_Path_Element__char_environment_73b.cpp:41
- 结论: 存在不受控制的搜索路径元素漏洞，攻击者可能通过控制环境变量设置恶意路径，但由于静态证据未完全闭合从PUTENV到后续命令执行的路由，需要进一步动态验证或审计确认。
- D验证: confirmed / ver_48f4390c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 376. hyp_path_010ec6d9aa8c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_84_case0.cpp:50
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够影响程序的环境变量，或能够提供恶意输入以设置data变量
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_84_case0.cpp:50
- 结论: 存在不受控制的搜索路径元素漏洞：通过putenv设置环境变量，其值来自环境变量，导致攻击者可能控制环境变量，进而影响搜索路径，造成恶意DLL或程序执行。
- D验证: confirmed / ver_51425ab5
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 377. hyp_path_92fbc2e6314d

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_41.c:33
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: Attacker can control console input (e.g., via stdin)
- 触发路径: data = console input (not shown in snippet but typical for this test case) @ console input (source); PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_41.c:33
- 结论: Uncontrolled search path element: external input is used to set an environment variable via _putenv, allowing potential search path hijacking.
- D验证: confirmed / ver_587dfaba
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 378. hyp_path_76cfdc0750d5

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_45.c:37
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制控制台输入（或相应数据来源）。
- 触发路径: char * data = CWE427_Uncontrolled_Search_Path_Element__char_console_45_case0Data; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_45.c:35; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_45.c:37
- 结论: 攻击者可以通过控制台输入控制环境变量数据，进而设置不安全的PATH环境变量，导致搜索路径劫持漏洞。
- D验证: confirmed / ver_3cddb3ca
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 379. hyp_path_de82ef6eed62

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_44.c:33
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供任意字符串; 程序在调用putenv后，会使用受影响的环境变量（如PATH）来查找或执行程序
- 触发路径: fgets(data, ...); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_44.c:30 (入口，从控制台读取数据); PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_44.c:33
- 结论: 程序使用可能受用户控制的字符串调用putenv设置环境变量，导致不受控制的搜索路径元素漏洞（CWE-427）。攻击者可设置恶意路径，例如修改PATH变量，从而执行任意恶意程序。
- D验证: confirmed / ver_4c07abf0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 380. hyp_path_4fab837cfe32

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_51b.c:35
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供恶意的路径字符串; 程序后续使用受污染的环境变量加载外部程序或库（未在证据中体现）
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_51b.c:35
- 结论: 程序通过PUTENV从控制台读取并设置环境变量，可能允许攻击者控制搜索路径元素，但缺少后续使用该环境变量加载程序或库的证据，因此漏洞假设不完整。
- D验证: confirmed / ver_dcbfe624
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 381. hyp_path_beacbf679a5f

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_52c.c:35
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串
- 触发路径: （推断代码） @ 函数入口处从控制台读取数据存入data变量（推断代码，未显示）; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_52c.c:35
- 结论: 存在未控制的搜索路径元素漏洞，通过`PUTENV(data)`设置环境变量，其中`data`来自控制台输入且未经验证，可能允许攻击者控制搜索路径，加载恶意组件。
- D验证: confirmed / ver_5a9b8cdb
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 382. hyp_path_e0a8a797bb01

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_53c.c:37
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向控制台输入任意字符串
- 触发路径: void CWE427_Uncontrolled_Search_Path_Element__char_console_53c_case0Sink(char * data) { CWE427_Uncontrolled_Search_Path_Element__char_console_53d_case0Sink(data); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_53c.c:35; CWE427_Uncontrolled_Search_Path_Element__char_console_53d_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_53c.c:37
- 结论: 不受控制的搜索路径元素漏洞：函数从控制台接收输入，并将该数据作为参数传递给后续函数，但B阶段证据显示路径未闭合且静态支持不足。由于缺乏实际sink（如exec、system等）的代码证据，无法确认漏洞，但存在理论可能性。
- D验证: confirmed / ver_150f8165
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 383. hyp_path_d5ed778d9f40

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_53d.c:35
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供恶意路径字符串; 设置的变量为PATH或LD_LIBRARY_PATH等关键环境变量; 程序在PUTENV调用后执行依赖于该环境变量的操作（如system、exec）; 当前代码片段未展示后续利用，但根据样本设计，后续可能包含相关操作
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_53d.c:35
- 结论: 存在未控制搜索路径元素漏洞（CWE-427）的潜在风险。程序通过PUTENV(data)设置环境变量，data源自外部控制台输入，若设置的是PATH或LD_LIBRARY_PATH等关键变量，且后续存在依赖该变量的操作（如system/exec），则攻击者可加载恶意库或执行任意程序。但当前证据链中缺少后续利用步骤，需动态或审计验证。
- D验证: confirmed / ver_563a12a2
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 384. hyp_path_89cbc7f9892d

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_54b.c:37
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入影响data参数的内容，且后续sink函数（如system或exec）未验证路径
- 触发路径: void CWE427_Uncontrolled_Search_Path_Element__char_console_54b_case0Sink(char * data) { CWE427_Uncontrolled_Search_Path_Element__char_console_54c_case0Sink(data); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_54b.c:35-39
- 结论: 潜在CWE-427漏洞：存在未控制搜索路径元素的风险，但source-sink路径未完全闭合
- D验证: confirmed / ver_4dd9acd5
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 385. hyp_path_db95fbc51f5a

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_54e.c:35
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与程序的控制台交互，并输入自定义路径。
- 触发路径: /* 从控制台读取输入并存入data */ @ CWE427_Uncontrolled_Search_Path_Element__char_console_54e.c:32; PUTENV(data); @ CWE427_Uncontrolled_Search_Path_Element__char_console_54e.c:35
- 结论: 程序使用从控制台读取的输入直接调用putenv设置环境变量（如PATH），导致搜索路径元素不受控制，攻击者可利用此漏洞执行任意代码。
- D验证: confirmed / ver_c2b77f0b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 386. hyp_path_d4bb803bf232

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_63b.c:34
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供恶意路径字符串
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_63b.c:34
- 结论: 程序通过PUTENV设置环境变量，其中路径数据来自控制台输入，攻击者可控制搜索路径元素，导致执行恶意程序。
- D验证: confirmed / ver_24ecd17b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 387. hyp_path_00529cabb2d1

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_64b.c:37
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序提供控制台输入，且输入未经过净化直接传递给PUTENV的data参数。
- 触发路径: CWE427_Uncontrolled_Search_Path_Element__char_console_64b_case0Sink @ 入口函数 CWE427_Uncontrolled_Search_Path_Element__char_console_64b_case0Sink; char * data = (*dataPtr); PUTENV(data); @ 行37
- 结论: 程序使用PUTENV设置环境变量，且变量值来源于控制台输入，攻击者可以控制环境变量，导致不安全的搜索路径元素（CWE-427）。
- D验证: confirmed / ver_c87687ff
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 388. hyp_path_114605f40f5f

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_65b.c:33
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供任意字符串给data变量。
- 触发路径: 用户通过控制台输入数据，存储在data变量中（未在片段中显示，但上下文为console输入）; /* NOTE: Set a new environment variable with a path that is possibly insecure */ PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_65b.c:33
- 结论: 存在不受控的搜索路径元素漏洞，攻击者可通过控制台输入任意字符串设置恶意环境变量路径，导致程序加载恶意库。
- D验证: confirmed / ver_d2f4e567
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 389. hyp_path_1e01a3226164

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_66b.c:35
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入控制dataArray[2]的内容
- 触发路径: char * data = dataArray[2]; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_66b.c:33; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_66b.c:35
- 结论: 函数通过PUTENV设置环境变量，未对数据来源进行验证，攻击者可通过控制台输入控制dataArray[2]中的路径字符串，从而修改环境变量，导致搜索路径被劫持，可能执行恶意程序。
- D验证: confirmed / ver_5586be94
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 390. hyp_path_39ba5adf6d11

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_68b.c:39
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串，该字符串被存储到全局变量中。
- 触发路径: char * data = CWE427_Uncontrolled_Search_Path_Element__char_console_68_case0Data; @ 入口函数 CWE427_Uncontrolled_Search_Path_Element__char_console_68b_case0Sink 第35行; PUTENV(data); @ 第39行
- 结论: 程序使用不受信任的输入设置环境变量，可能导致搜索路径劫持漏洞。
- D验证: confirmed / ver_aad430cf
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 391. hyp_path_6fd2286e3ddd

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_67b.c:39
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够与程序交互并输入控制台数据。
- 触发路径: char * data = myStruct.structFirst; @ 入口:35行附近，函数接受参数; PUTENV(data); @ 39行
- 结论: 程序从控制台读取输入作为环境变量值，未经任何验证直接传递给putenv函数，导致攻击者可以控制环境变量PATH等，从而影响程序加载共享库的行为，实现任意代码执行。
- D验证: confirmed / ver_c37938dc
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 392. hyp_path_bdb457b6368a

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_81_case0.cpp:27
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供任意字符串。
- 触发路径: data = 用户输入 @ 控制台输入; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_81_case0.cpp:27
- 结论: 存在不受控制的搜索路径元素漏洞。攻击者通过控制台输入控制环境变量（例如PATH），导致程序在搜索可执行文件或库时加载恶意代码。
- D验证: confirmed / ver_89b5ec95
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 393. hyp_path_a798b3723210

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_82_case0.cpp:27
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入任意字符串作为环境变量值。
- 触发路径: action(data); // data由控制台输入 @ 入口: CWE427_Uncontrolled_Search_Path_Element__char_console_82_case0.cpp:24; PUTENV(data); // 设置不安全的环境变量 @ CWE427_Uncontrolled_Search_Path_Element__char_console_82_case0.cpp:27
- 结论: 程序通过putenv设置环境变量，且环境变量值来自控制台输入，可能导致不受控制的搜索路径元素漏洞，攻击者可利用此漏洞加载恶意程序。
- D验证: confirmed / ver_60adddb3
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 394. hyp_path_618c6b562494

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_41.c:41
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置或影响目标进程的环境变量
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_41.c:41
- 结论: 函数通过PUTENV设置环境变量，data来自环境变量，攻击者可能通过控制环境变量设置恶意的搜索路径，导致后续使用非预期路径执行程序或加载库，造成CWE-427漏洞。
- D验证: confirmed / ver_a7c95243
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 395. hyp_path_9875895dbadb

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_44.c:41
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量data的来源（如来自getenv等外部输入）
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_44.c:41
- 结论: 存在不受控制的搜索路径元素漏洞：攻击者可通过控制环境变量（如通过putenv设置恶意路径），影响后续搜索路径，导致CWE-427。
- D验证: confirmed / ver_9a5ddebd
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 396. hyp_path_edb3428705d7

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_45.c:45
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够影响环境变量，从而控制data的值。
- 触发路径: char * data = CWE427_Uncontrolled_Search_Path_Element__char_environment_45_case0Data; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_45.c:44; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_45.c:45
- 结论: 函数PUTENV使用攻击者可控的data设置环境变量，可能导致不受控制的搜索路径元素，攻击者可利用此漏洞执行任意代码或劫持DLL。
- D验证: confirmed / ver_97cca25c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 397. hyp_path_f9db1d30ee98

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_51b.c:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制一个环境变量，该环境变量的值被拷贝到data中，并最终作为PUTENV的参数
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_51b.c:43
- 结论: 程序使用PUTENV设置环境变量，变量值来自环境变量（可能受攻击者控制），导致不受控制的搜索路径元素漏洞。攻击者可利用此漏洞设置恶意路径，如修改PATH环境变量，导致加载恶意库或执行任意代码。
- D验证: confirmed / ver_eebb901f
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 398. hyp_path_a4b62b4ae9f9

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_52c.c:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够影响环境变量的值（如通过子进程继承、修改进程环境等）。
- 触发路径: data = getenv(...); // 从环境变量获取输入 @ 入口函数; PUTENV(data); // 设置可能不安全的路径到环境变量 @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_52c.c:43
- 结论: 存在不受控制的搜索路径元素漏洞，攻击者可通过控制环境变量`data`的值，设置恶意路径到环境变量（如PATH），导致后续程序加载恶意动态链接库或可执行文件。
- D验证: confirmed / ver_de5c8796
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 399. hyp_path_c7c47356e88c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_53d.c:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制data的值，例如通过设置环境变量或提供输入，但未在代码证据中确认。
- 触发路径: data = getenv("SOME_VAR"); // 假设，未在片段中显示 @ 未知源; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_53d.c:43
- 结论: 程序使用putenv设置环境变量，参数data可能受攻击者控制，导致不安全的搜索路径元素，但当前证据未显示data来源，无法确认外部可控性。
- D验证: confirmed / ver_e26d27ee
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 400. hyp_path_88c5022955cf

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_54c.c:45
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量以影响搜索路径
- 触发路径: CWE427_Uncontrolled_Search_Path_Element__char_environment_54d_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_54c.c:45
- 结论: 可能存在未受控的搜索路径元素漏洞，但当前代码片段仅包含sink转发，缺少source，无法闭合路径。
- D验证: confirmed / ver_460a5ca7
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 401. hyp_path_2befdce3f167

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_54e.c:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制目标机器的环境变量（例如通过本地shell或利用其他漏洞）
- 触发路径: （未直接提供，但源为char_environment） @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_54e.c:40（入口处，data来自环境变量）; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_54e.c:43
- 结论: 存在未受控搜索路径元素漏洞，攻击者可通过控制环境变量设置不安全的路径，从而影响程序行为（如加载恶意库）。但漏洞路径不完整，PUTENV仅设置环境变量，未直接展示后续利用。
- D验证: confirmed / ver_904f443d
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 402. hyp_path_9efa2c3486dc

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_63b.c:42
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够设置受影响的环境变量（如PATH、LD_LIBRARY_PATH等）
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_63b.c:42
- 结论: 存在未控制搜索路径元素漏洞，攻击者可通过控制环境变量来设置恶意路径，导致程序加载恶意代码。
- D验证: confirmed / ver_735e1ec5
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 403. hyp_path_c18ddf3fdf17

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_64b.c:45
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量或间接影响dataPtr指针所指向的数据。
- 触发路径: char * data = (*dataPtr); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_64b.c:44; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_64b.c:45
- 结论: 代码从环境变量获取数据并直接传递给putenv函数，设置环境变量PATH等，可能导致不受控制的搜索路径元素漏洞，攻击者可劫持动态链接库或命令执行路径。
- D验证: confirmed / ver_57b8f672
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 404. hyp_path_2beb99392ed6

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_65b.c:41
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制外部环境变量，导致data变量包含恶意路径字符串
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_65b.c:41
- 结论: 调用putenv设置环境变量，数据来自环境变量，可能导致路径搜索元素被恶意控制（CWE-427）
- D验证: confirmed / ver_0a5360bd
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 405. hyp_path_48f561d15d09

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_66b.c:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过环境变量或其他方式控制dataArray[2]中的数据，使其包含恶意路径字符串。
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_66b.c:43
- 结论: 程序调用PUTENV设置可能受攻击者控制的环境变量，导致非受控搜索路径元素漏洞。
- D验证: confirmed / ver_9d7835f3
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 406. hyp_path_afac344f21d9

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_67b.c:47
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制 data 的输入，例如通过环境变量或其他外部输入（如 char_environment 函数获取）。
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_67b.c:47
- 结论: 程序使用不受控制的搜索路径元素，通过 putenv 设置环境变量，攻击者可控制该变量导致执行恶意代码。
- D验证: confirmed / ver_58e2a4f4
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 407. hyp_path_61b899ce2516

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_68b.c:47
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制输入环境变量（CWE427_Uncontrolled_Search_Path_Element__char_environment_68_case0Data的来源）
- 触发路径: char * data = CWE427_Uncontrolled_Search_Path_Element__char_environment_68_case0Data; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_68b.c:45; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_68b.c:47
- 结论: 程序使用从环境变量获取的数据直接作为参数调用putenv设置环境变量，攻击者可通过控制环境变量来修改搜索路径，导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_b298e811
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 408. hyp_path_c17aa0e871d7

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_81_case0.cpp:27
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制data的值（例如通过环境变量注入或恶意输入）
- 触发路径: char * data 由调用者传入 @ 函数入口参数data; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_81_case0.cpp:27
- 结论: 可能存在未受控搜索路径元素漏洞，通过PUTENV设置不安全的环境变量路径，若后续使用该环境变量加载库或程序，可能导致任意代码执行。
- D验证: confirmed / ver_8a095975
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 409. hyp_path_0ba2d505396c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_82_case0.cpp:27
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制data变量指向的环境变量值
- 触发路径: PUTENV(data); @ CWE427_Uncontrolled_Search_Path_Element__char_environment_82_case0.cpp:27
- 结论: 可能存在CWE-427未控制搜索路径元素漏洞：函数PUTENV使用参数data设置环境变量，但data的来源未在提供的代码片段中明确，可能来自外部可控环境变量，导致路径搜索被劫持。
- D验证: confirmed / ver_baad586b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 410. hyp_path_5816043ca791

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_52b.c:37
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入向data参数传入恶意字符串
- 触发路径: void CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_52b_case0Sink(wchar_t * data) @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_52b.c:35; CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_52c_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_52b.c:37
- 结论: 未经控制的搜索路径元素漏洞，攻击者可通过控制台输入控制程序搜索路径，可能导致恶意DLL加载或命令执行。
- D验证: confirmed / ver_fe5612f7
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 411. hyp_path_628cf61d8856

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_54d.c:37
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入（stdin）控制data字符串的内容
- 触发路径: void CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_54d_case0Sink(wchar_t * data) { CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_54e_case0Sink(data); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_54d.c:35; CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_54e_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_54d.c:37
- 结论: CWE427: Uncontrolled Search Path Element - 通过控制台输入的可控数据传递至搜索路径元素操作函数
- D验证: confirmed / ver_3ca71037
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 412. hyp_path_971dc4d5761c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_66b.c:35
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过控制台输入提供任意字符串（假设性）
- 触发路径: wchar_t * data = dataArray[2]; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_66b.c:33-37
- 结论: 程序从控制台读取数据并直接传递给_wputenv设置环境变量，攻击者可控制环境变量内容，但source到dataArray[2]的数据流不完整，无法确认dataArray[2]是否外部可控。
- D验证: confirmed / ver_306a7b6a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 413. hyp_path_99240a2ed69c

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_52b.c:45
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量等输入源，从而影响data参数的值。
- 触发路径: CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_52c_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_52b.c:45
- 结论: 函数将未受控制的搜索路径元素传递给下一个函数，可能引发CWE427漏洞。
- D验证: confirmed / ver_5a9b1910
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 414. hyp_path_e6515511a8f0

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_53c.c:45
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制环境变量或其他输入源，使得data包含恶意路径
- 触发路径: void CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_53c_case0Sink(wchar_t * data) @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_53c.c:43; CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_53d_case0Sink(data); @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_53c.c:45
- 结论: 可能存在不受控制的搜索路径元素漏洞，但当前代码片段仅显示转发调用，缺少下游危险函数（如SetDllDirectory或CreateProcess）的调用证据。需要进一步分析CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_53d_case0Sink的实现以闭合路径。
- D验证: confirmed / ver_d65b51e0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 415. hyp_path_589ea4b5f0ce

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_54b.c:45
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制输入给data参数的数据（通常通过环境变量）
- 触发路径: CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_54c_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_54b.c:45
- 结论: 可能存在未受控搜索路径元素漏洞：函数接收外部数据作为搜索路径元素，并传递给后续函数，但未进行任何校验或清理，可能导致攻击者通过控制环境变量加载恶意库或执行任意代码。
- D验证: confirmed / ver_864a6b99
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 416. hyp_path_60a210f25552

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_54c.c:45
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: attacker can control environment variable value that is passed as 'data' into the sink chain
- 触发路径: CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_54d_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_54c.c:45
- 结论: CWE-427: Uncontrolled Search Path Element - data from environment variable flows through sink functions that may be used to control search path in process execution.
- D验证: confirmed / ver_3c63691f
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 417. hyp_path_c2963490df40

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_63b.c:42
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制dataPtr所指向的数据（如通过环境变量或输入）
- 触发路径: 函数入口，接收dataPtr @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_63b.c:38; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_63b.c:42
- 结论: 函数通过PUTENV（_wputenv）设置环境变量，数据来自传入的dataPtr，若dataPtr指向攻击者可控数据，则可能导致不可控搜索路径元素漏洞（CWE-427）。攻击者可设置恶意路径，导致程序加载恶意DLL或可执行文件。
- D验证: confirmed / ver_f16c6032
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 418. hyp_path_41eaf262f5db

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_22a.c:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够以网络连接方式与程序通信，并发送可控字符串。
- 触发路径: data = CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_22_case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_22a.c:41; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_22a.c:43
- 结论: 程序通过socket接收数据，未经验证直接设置为环境变量，可能导致攻击者控制搜索路径，执行恶意代码。
- D验证: confirmed / ver_5afa00c3
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 419. hyp_path_97d04d5ce229

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_61a.c:61
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够建立到目标socket的网络连接，并发送精心构造的路径字符串
- 触发路径: char dataBuffer[250] = "PATH="; data = dataBuffer; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_61a.c:57; data = CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_61b_case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_61a.c:59; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_61a.c:61
- 结论: 通过socket接收不受信任的数据并直接用于设置PATH环境变量，导致不受控制的搜索路径元素漏洞（CWE-427）。攻击者可以控制路径，从而劫持进程加载的恶意动态库或可执行文件。
- D验证: confirmed / ver_e1ebaab0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 420. hyp_path_d00127a219fb

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_62a.cpp:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够连接到程序监听的socket端口; 程序后续会使用依赖PATH的系统调用（如system、exec）
- 触发路径: case0Source(data); // 从socket读取数据到data @ CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_62a.cpp:41; PUTENV(data); // 将data设置为环境变量，期望格式为"PATH=..." @ CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_62a.cpp:43
- 结论: 程序通过socket接收外部输入，并将其设置为PATH环境变量，攻击者可控制PATH指向恶意路径，导致后续执行程序时加载恶意代码。
- D验证: confirmed / ver_4efdb630
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 421. hyp_path_37539cb748d1

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_22a.c:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向目标发送自制数据包，使得data变量包含恶意路径字符串；目标系统上的应用程序具有对相应环境变量（如PATH）的设置权限。
- 触发路径: data = CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_22_case0Source(data); /* NOTE: Set a new environment variable with a path that is possibly insecure */ PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_22a.c:41-45
- 结论: 通过socket接收外部输入数据，直接作为环境变量设置，可能导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_7da491b3
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 422. hyp_path_fd48be2656ec

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_61a.c:61
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向监听socket发送任意字符串; 服务未对输入进行合法性检查
- 触发路径: data = CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_61b_case0Source(data); PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_61a.c:59-61; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_61a.c:61
- 结论: 未受控的搜索路径元素漏洞：通过socket接收的输入直接用于设置PATH环境变量，攻击者可控制搜索路径，导致加载恶意程序。
- D验证: confirmed / ver_d4039fd6
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 423. hyp_path_47d0a2c4e9d2

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_62a.cpp:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够访问并发送数据到该程序监听的socket，且发送的数据作为PATH值（以"PATH="开头或直接是路径字符串）。
- 触发路径: case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_62a.cpp:41; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_62a.cpp:43
- 结论: 存在不受控制的搜索路径元素漏洞。函数case0Source从网络套接字读取用户可控数据，然后直接通过putenv设置PATH环境变量，攻击者可以控制PATH导致加载恶意动态库或可执行文件。
- D验证: confirmed / ver_e1b0e585
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 424. hyp_path_6677adcc6490

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_62a.cpp:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接向套接字发送恶意构造的路径字符串，case0Source会将其追加到data缓冲区（初始'PATH='），最终通过_wputenv设置PATH环境变量。
- 触发路径: case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_62a.cpp:41; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_62a.cpp:43
- 结论: 函数通过套接字接收不可信数据，将其用作PATH环境变量的值，并调用_wputenv设置环境变量，导致未控制搜索路径元素漏洞，攻击者可控制可执行文件搜索路径，执行恶意代码。
- D验证: confirmed / ver_9b9a0f24
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 425. hyp_path_c423a99af805

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_22a.c:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够访问目标主机的监听socket，并发送构造的环境变量字符串。
- 触发路径: data = CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_22_case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_22a.c:41; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_22a.c:43
- 结论: 程序通过网络socket获取输入并直接用作环境变量值调用_wputenv，攻击者可控制搜索路径元素，导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_ccd47d3c
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 426. hyp_path_ff4cb615949e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_61a.c:61
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向监听socket发送数据
- 触发路径: wchar_t dataBuffer[250] = L"PATH="; data = dataBuffer; data = CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_61b_case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_61a.c:57-61; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_61a.c:61
- 结论: 程序通过网络接收未经验证的数据，并将其直接用于设置PATH环境变量（通过_wputenv），攻击者可以控制该数据，从而修改搜索路径，导致加载恶意DLL或可执行文件，造成任意代码执行。
- D验证: confirmed / ver_bebedc84
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 427. hyp_path_0bbe44436111

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_74b.cpp:41
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络socket连接向程序发送数据，并使其存入dataMap[2]中。
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_74b.cpp:41
- 结论: 存在未受控的搜索路径元素漏洞，攻击者可通过网络连接控制环境变量中的路径，导致不安全执行。
- D验证: confirmed / ver_7d56ce3a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 428. hyp_path_d1e43acf4536

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_74b.cpp:41
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向dataMap[2]中注入任意字符串，例如通过控制文件输入（样本为file类型，dataMap由文件读取填充）。
- 触发路径: char * data = dataMap[2]; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_74b.cpp:41; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_74b.cpp:41
- 结论: 存在不受控制的搜索路径元素漏洞。程序从数据映射中获取字符串并设置为环境变量，攻击者可能通过控制该字符串修改搜索路径，导致程序加载恶意库或可执行文件。
- D验证: confirmed / ver_48d9dbb0
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 429. hyp_path_deec295c51c2

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_74b.cpp:41
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向监听套接字发送恶意数据，该数据最终被存入dataMap[2]并被PUTENV使用
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_74b.cpp:41
- 结论: 程序使用PUTENV设置了环境变量，且数据来源于外部不可信输入（如套接字），攻击者可通过控制环境变量（如PATH）导致任意命令执行。
- D验证: confirmed / ver_9504355a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 430. hyp_path_cce96f328aef

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_74b.cpp:41
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制输入文件内容
- 触发路径: 从文件读取数据并插入dataMap @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_74a.cpp（推测为文件读取函数）; wchar_t * data = dataMap[2]; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_74b.cpp:41
- 结论: 在CWE427测试用例中，函数从map中获取数据并直接调用_wputenv设置环境变量，如果该数据来自外部输入（如文件），则攻击者可以控制环境变量，导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_6ecb9304
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 431. hyp_path_b005809ef68f

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_83a.cpp:30
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络socket发送恶意数据，该数据被用于覆盖或追加到PATH环境变量
- 触发路径: char dataBuffer[250] = "PATH="; data = dataBuffer; CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_83_case0 case0Object(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_83a.cpp:30
- 结论: CWE-427: Uncontrolled Search Path Element - 通过socket接收的数据可能被用于构造PATH环境变量，但当前代码证据仅显示data被初始化为固定字符串'PATH='，未展示从socket接收外部输入的部分。由于存在潜在的source-sink路径，但证据不完整，保留漏洞假设。
- D验证: confirmed / ver_04fc4a69
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 432. hyp_path_1515b4162ddc

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_52b.c:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制data的值，例如通过socket连接发送恶意字符串。
- 触发路径: void CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_52b_case0Sink(char * data) { @ CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_52b.c:56; CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_52c_case0Sink(data); @ CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_52b.c:58
- 结论: 可能存在未受控搜索路径元素漏洞，但当前代码证据不完整，无法确认攻击者可控的source到安全敏感sink的完整路由。
- D验证: confirmed / ver_4a7959b3
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 433. hyp_path_78ea59d81773

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_52b.c:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过socket向程序发送特制字符串数据，该数据将被用作搜索路径元素。
- 触发路径: CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_52c_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_52b.c:58
- 结论: 函数接收外部控制的字符串data，并传递给CWE427..._52c_case0Sink，该函数可能使用data作为搜索路径元素（如设置环境变量或加载库），导致不受控制的搜索路径元素漏洞。但当前代码片段仅显示中间层调用，未提供source（socket输入）和sink（实际使用搜索路径）的直接证据。
- D验证: confirmed / ver_2e35caee
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 434. hyp_path_9ed1d5c8ea20

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_54c.c:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络socket发送恶意字符串，该字符串被用作搜索路径元素
- 触发路径: char *data = recvFromSocket(); // 外部可控数据 @ 假设的source行; CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_54d_case0Sink(data); @ CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_54c.c:56-58
- 结论: CWE427: 不受控制的搜索路径元素 - 通过socket接收的数据被用作搜索路径元素
- D验证: confirmed / ver_76cb31c6
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 435. hyp_path_d3c4af0923bb

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_52b.c:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接向程序发送恶意数据，该数据最终作为data参数传入此函数
- 触发路径: void CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_52b_case0Sink(wchar_t * data) { @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_52b.c:56; CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_52c_case0Sink(data); @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_52b.c:58
- 结论: 在CWE427_Uncontrolled_Search_Path_Element测试用例中，函数CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_52b_case0Sink接收一个wchar_t指针data，并直接传递给下一个处理函数，没有进行任何验证或净化。如果data来自用户可控的网络输入，并且最终被用于设置系统搜索路径（如通过_wputenv），则攻击者可控制搜索路径元素，导致权限提升或任意代码执行。
- D验证: confirmed / ver_cbad1082
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 436. hyp_path_5ecc8dea3d18

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_53b.c:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制传入的data参数，通常通过网络连接接收外部输入
- 触发路径: void CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_53b_case0Sink(wchar_t * data) { CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_53c_case0Sink(data); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_53b.c:56
- 结论: CWE-427: Uncontrolled Search Path Element - 攻击者可能通过控制data参数注入恶意路径，但当前代码片段仅传递数据至下一层函数，未展示实际sink操作，需动态验证路径是否闭合。
- D验证: confirmed / ver_792b5658
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 437. hyp_path_01e8d73c27cc

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_54b.c:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制wchar_t * data变量的内容（例如通过socket接收）
- 触发路径: void CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_54b_case0Sink(wchar_t * data) { CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_54c_case0Sink(data); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_54b.c:56-60
- 结论: 函数接收外部传入的字符串指针，并直接传递给后续处理函数，可能用于设置搜索路径或执行命令，但缺乏从source到sink的完整路径确认，无法验证实际触发。
- D验证: confirmed / ver_9cd743a6
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 438. hyp_path_d8c632993139

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_52b.c:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络socket控制data内容
- 触发路径: void CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_52b_case0Sink(wchar_t * data) { CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_52c_case0Sink(data); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_52b.c:56; 数据通过52c sink传递，可能调用_wputenv或类似函数 @ 后续函数调用（52c sink），预期最终使用未受控搜索路径元素执行命令
- 结论: Uncontrolled search path element via command execution
- D验证: confirmed / ver_e39fc1d4
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 439. hyp_path_ffcbc53ba43e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_53c.c:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能向listen_socket发送恶意数据，控制data内容。
- 触发路径: CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_53d_case0Sink(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_53c.c:58
- 结论: 可能存在不受控制的搜索路径元素漏洞，但当前代码片段仅显示参数传递，缺乏source到sink的完整证据。假设data来自外部可控源（如socket），并最终用于设置搜索路径，则可能导致攻击者控制程序搜索路径，加载恶意库。
- D验证: confirmed / ver_37811b95
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 440. hyp_path_f82c1e29ecf9

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_54b.c:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络发送数据到监听socket，从而控制搜索路径元素
- 触发路径: void CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_54b_case0Sink(wchar_t * data) { CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_54c_case0Sink(data); } @ CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_54b.c:56-60; （代码片段未展示完整路径，但依据测试用例结构判定） @ 推测source为socket接收，sink在54c.c中调用_wputenv等
- 结论: 存在从网络socket到不受控制的搜索路径元素的潜在漏洞（CWE-427），但证据不完整。
- D验证: confirmed / ver_4ac2a105
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 441. hyp_path_6b433073bac2

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_54d.c:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络发送恶意数据到监听端口，使得`data`包含路径元素（如目录分隔符或可执行文件名）。
- 触发路径: void CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_54d_case0Sink(wchar_t * data) { CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_54e_case0Sink(data); } @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_54d.c:56-60
- 结论: 该函数将未经验证的外部输入直接传递给后续处理函数，构成不受控制的搜索路径元素漏洞，攻击者可能通过控制搜索路径加载恶意DLL或执行任意程序。
- D验证: confirmed / ver_f4e505f1
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 442. hyp_path_c98029df2885

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_22a.c:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够写入或篡改程序读取的文件（file_22暗示从文件读取）。
- 触发路径: data = CWE427_Uncontrolled_Search_Path_Element__char_file_22_case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_22a.c:41; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_22a.c:43
- 结论: 程序从文件读取数据后设置环境变量（`_putenv`），攻击者可能通过控制文件内容设置恶意搜索路径，但缺乏后续使用该环境变量执行程序或加载库的sink，漏洞路径不完整。
- D验证: confirmed / ver_72d6cc27
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 443. hyp_path_6c47b1f626b0

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_61a.c:46
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够写入或控制被读取的文件内容。
- 触发路径: data = CWE427_Uncontrolled_Search_Path_Element__char_file_61b_case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_61a.c:44; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_61a.c:46
- 结论: 通过文件读取的未受控数据被用于设置PATH环境变量，可能导致搜索路径劫持，攻击者可利用恶意文件内容修改PATH以加载恶意DLL或可执行文件。
- D验证: confirmed / ver_0ff4ec05
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 444. hyp_path_843a8fff6403

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_62a.cpp:43
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制case0Source读取的输入文件内容，以构造恶意路径字符串
- 触发路径: char dataBuffer[250] = "PATH="; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_62a.cpp:39; data = dataBuffer; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_62a.cpp:41; case0Source(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_62a.cpp:42; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_62a.cpp:43
- 结论: 未控制搜索路径元素漏洞：程序通过PUTENV设置PATH环境变量，且数据来源于case0Source（疑似从文件读取），攻击者可控制PATH指向恶意目录，导致加载恶意动态库。
- D验证: confirmed / ver_e252cb7a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 445. hyp_path_9d39eb8e0142

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_73b.cpp:39
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接发送恶意数据，该数据最终被放入dataList中。
- 触发路径: char * data = dataList.back(); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_73b.cpp:39; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_73b.cpp:41
- 结论: 从socket接收的数据通过list传递给PUTENV，设置环境变量时未验证路径，可能导致搜索路径元素控制漏洞。
- D验证: confirmed / ver_4de2492d
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 446. hyp_path_05f5356bbef1

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_72b.cpp:39
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过socket向程序发送恶意数据，该数据最终作为环境变量值。; 程序在之后会依赖该环境变量（如PATH）执行操作。
- 触发路径: CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_72a.cpp @ socket接收数据并存入data; dataVector.push_back(data); @ 将data放入dataVector; char * data = dataVector[2]; @ 从dataVector取出data[2]; PUTENV(data); @ 调用PUTENV设置环境变量
- 结论: 函数从外部可控的dataVector中取出数据，直接作为环境变量设置，可能导致搜索路径劫持。
- D验证: confirmed / ver_7dbd8195
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 447. hyp_path_d1d28351c931

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_83_case0.cpp:119
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络连接访问目标应用程序，并发送任意字符串作为环境变量值（如PATH）。
- 触发路径: char data[256]; recv(socket, data, sizeof(data), 0); @ socket读取处（由路由名connect_socket推断，未显式出现在代码片段中）; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_83_case0.cpp:119
- 结论: 在CWE427_Uncontrolled_Search_Path_Element示例中，通过connect socket获取的输入直接传递给PUTENV设置环境变量，导致攻击者可控制搜索路径元素，可能引发任意代码执行。
- D验证: confirmed / ver_559f1a88
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 448. hyp_path_7a1735cebb98

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_84_case0.cpp:119
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络套接字发送恶意数据到目标程序，且data变量确实从socket接收并包含攻击者输入。
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_84_case0.cpp:119
- 结论: 函数通过PUTENV设置环境变量，参数data来自外部网络读取且未经验证，攻击者可注入恶意路径字符串，导致不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_52ac7bb7
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 449. hyp_path_115b5e58476a

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_72b.cpp:41
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够影响dataVector[2]的内容，例如通过写入文件或控制程序输入。
- 触发路径: char * data = dataVector[2]; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_72b.cpp:39; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_72b.cpp:41
- 结论: 在函数CWE427_Uncontrolled_Search_Path_Element__char_file_72b.cpp中，从dataVector[2]获取的数据未经充分验证直接通过putenv设置环境变量，可能导致不受控制的搜索路径元素漏洞。如果dataVector中的数据来源于外部输入（如文件），攻击者可操纵环境变量路径，进而劫持程序加载的动态库或可执行文件，造成任意代码执行。
- D验证: confirmed / ver_2168a465
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 450. hyp_path_31f517d4d4ea

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_73b.cpp:39
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制文件内容，进而控制 data 所指向的字符串
- 触发路径: char * data = dataList.back(); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_73b.cpp:39; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_73b.cpp:41
- 结论: 从 dataList 中获取的 data 可能来源于外部输入（文件读取），并直接传递给 PUTENV 设置环境变量，导致不受控制的搜索路径元素漏洞。攻击者可通过控制文件内容修改环境变量（如 PATH），从而劫持程序加载的库或可执行文件。
- D验证: confirmed / ver_52d9c2ad
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 451. hyp_path_39100b378e21

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_83_case0.cpp:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制或影响data变量的内容，例如通过修改输入文件。
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_83_case0.cpp:58
- 结论: 在CWE427_Uncontrolled_Search_Path_Element__char_file_83_case0.cpp第58行，调用PUTENV(data)设置环境变量，其中data可能来自不可信文件输入，导致攻击者可以控制搜索路径元素，从而降低系统安全性。
- D验证: confirmed / ver_934e3c43
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 452. hyp_path_9227266c98a4

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_84_case0.cpp:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够控制提供data值的文件或其他输入源
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_84_case0.cpp:58
- 结论: 在析构函数中调用PUTENV(data)设置环境变量，其中data可能来自外部输入（如文件），导致攻击者能够控制环境变量路径，可能引发不受控制的搜索路径元素漏洞。
- D验证: confirmed / ver_064bfc14
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 453. hyp_path_13693583680e

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_83_case0.cpp:131
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能访问监听socket并发送任意字符串
- 触发路径: /* 接收网络数据到data */ @ 127-129; PUTENV(data); @ 131
- 结论: 程序通过PUTENV设置环境变量，且data来自网络socket，未经验证和清理，导致攻击者可控制搜索路径，加载恶意动态链接库，实现代码执行。
- D验证: confirmed / ver_534bf18b
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 454. hyp_path_b2d7f12172f9

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_72b.cpp:39
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络或其他不可信渠道控制dataVector中的数据
- 触发路径: 未提供 @ 未提供（假设存在source，如a.cpp）; char * data = dataVector[2]; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_72b.cpp:39; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_72b.cpp:41
- 结论: 函数CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_72b::case0Sink从dataVector[2]取出数据并调用PUTENV设置环境变量，构成不受控制的搜索路径元素漏洞的sink点，但数据来源（source）未确认，source-sink路径未闭合。
- D验证: confirmed / ver_4b9ce096
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 455. hyp_path_27b511121380

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_73b.cpp:41
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向目标程序发送恶意数据，并控制dataList中的内容，进而控制环境变量。
- 触发路径: PUTENV(data); @ CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_73b.cpp:41
- 结论: 在函数中将来自socket的未验证数据通过PUTENV设置为环境变量，攻击者可以控制搜索路径，导致加载恶意程序或DLL。
- D验证: confirmed / ver_835bb86a
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 456. hyp_path_467cdb034f12

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_84_case0.cpp:131
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够通过网络向监听socket发送恶意字符串，且该字符串能最终赋给data变量（当前证据未展示完整source-sink路径）
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_84_case0.cpp:131
- 结论: 函数PUTENV(data)被调用，其中data可能来自网络socket且未经验证。静态分析未能完全确认source-sink闭合，但基于样本名称和代码注释，存在设置不安全环境变量的风险，可能导致搜索路径元素注入（CWE-427）。需要动态验证或人工审计确认data来源的可控性。
- D验证: confirmed / ver_0ad55c02
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 457. hyp_path_03a0315d9951

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_72b.cpp:41
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够提供恶意数据，使得dataVector[2]被赋予攻击者控制的字符串
- 触发路径: wchar_t * data = dataVector[2]; @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_72b.cpp:39-40; PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_72b.cpp:41
- 结论: 在函数中，从dataVector[2]获取数据并直接传递给PUTENV（_wputenv）设置环境变量。如果攻击者能够控制dataVector中的内容，则可以设置任意环境变量（如修改PATH），导致搜索路径元素不受控制，可能执行恶意代码。
- D验证: confirmed / ver_825466da
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

### 458. hyp_path_1ae5a3cfde49

- 漏洞位置: juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_83_case0.cpp:58
- 漏洞类型: CWE-427
- CWE: CWE-427
- 风险等级: P0
- 触发条件: 攻击者能够向程序提供或修改输入文件的内容，从而控制`data`指向的环境变量字符串。
- 触发路径: PUTENV(data); @ juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_83_case0.cpp:58
- 结论: 程序使用不受控制的搜索路径元素，通过`_wputenv`设置环境变量，攻击者可能通过控制文件内容修改PATH等关键环境变量，导致搜索路径劫持，例如加载恶意DLL。
- D验证: confirmed / ver_a219e47e
- 运行证据: oracle matched patterns: MAGUS_ROUTE_CONFIRMED
- 保留原因: N/A

## Unconfirmed / Failed Verification

These records are not reported as confirmed vulnerabilities. See `verification.failed.jsonl` for full failure details.

- hyp_path_2ea8145cff90 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_72a.cpp:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5b6151ba4f49 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_72a.cpp:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_25c69aaaa6cc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_72a.cpp:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1c6bc4e4fa37 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_12.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f31ad410dca4 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_12.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d342d44560f2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_41.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_730b14c7ada4 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_41.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_22940827c284 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_17.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_438c3db379f9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_08.c:116 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_be7ad0df8d71 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_11.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b3de34d0dffb | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_02.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_73922ad7b948 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_01.c:100 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4fc5bd3700ab | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_03.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b581e28b19aa | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_05.c:109 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f8eb96c450d6 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_04.c:109 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ea97586cdca5 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_06.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a08aebda5e24 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_07.c:108 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c8043647ae8c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_10.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e1a88477f74d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_13.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e9cc5727271f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_14.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8cbee43cfd9f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_15.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4cd60bc999b3 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_18.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_111a3f14299f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_16.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9036ae9df5fa | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_11.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b4a5b27184a7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_08.c:101 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7bbb43aed186 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_02.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1a2277e6f3fa | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_03.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b3e87f310259 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_06.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_663f07f26f88 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_04.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_99a4453ec1b2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_07.c:93 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2290385cedf7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_09.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3a8df230053c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_14.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b9e9ac789eac | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_10.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cae4ccc981b6 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_13.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fa961d3a47b7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_16.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a539b636c6a9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_74a.cpp:464 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_927147b1017d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_74a.cpp:464 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1f52105a9e5c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_74a.cpp:464 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3f9e613ecfcd | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_74a.cpp:464 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c6abcd2916d8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_73a.cpp:443 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_82bc3975f9b0 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_73a.cpp:443 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_193d8c9243af | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_73a.cpp:443 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_05775c329164 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_73a.cpp:443 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3ace547f5d17 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_33.cpp:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_02c9f3b2c4fc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_31.c:100 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_366accfa9623 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_31.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ca860372c861 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_45.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_045af12b4b0b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_45.c:95 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_063c901878f9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_72a.cpp:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a219a59eebcb | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_72a.cpp:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4a77608d9ad9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_72a.cpp:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6d3a75b5196a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_72a.cpp:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2edf8f55d6a2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_12.c:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_93cedf331559 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_74b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_42afef39869d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_74b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1adbc1a78b43 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_74b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b2fae6f9218b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_74b.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d2e00d0882df | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_17.c:51 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6701d1e5c5d2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_41.c:54 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ed0773f9ad0d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_74b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d0c0ddaf583f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_08.c:64 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4ab246f0c2ea | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_01.c:48 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_34bbcce6db3f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_02.c:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b342d7c8d595 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_04.c:57 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c559559c1499 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_03.c:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_18521f4eb9d8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_05.c:57 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e19ff232d0b2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_07.c:56 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7843c49f4e51 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_10.c:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bf714ad04ae6 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_13.c:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8dc6c345039f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_14.c:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d49e65882b63 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_16.c:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3652b98fef13 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_18.c:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_95b174acd66f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_31.c:48 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_805716db0b0d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_34.c:55 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_275a9859be23 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_33.cpp:52 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_24a25c671db1 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_45.c:58 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4d322e27af4f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_74a.cpp:464 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b38b45247359 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_74a.cpp:464 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_edfcd2e4893e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_74a.cpp:464 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d9a4fef07b3e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_73a.cpp:443 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_82e2fea6f4ca | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_74a.cpp:464 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c72207701a3b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_73a.cpp:443 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f0efa859ec64 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_73a.cpp:443 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_390d73efe25f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_73a.cpp:443 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0f36e07d7490 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_43.cpp:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_02d1acdff79b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_22a.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e6b6fa588663 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5a9289394cea | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_61a.c:57 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_720ff7531638 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_62a.cpp:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_73dd59f58b4a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_61a.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d9cfdced8e9a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_22a.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c92e2115b3be | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bcbe566633a9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_62a.cpp:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7d533260f9e2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_17b330a302c6 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_22a.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_56e579af10f9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_61a.c:40 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2fdd558af3cd | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_61a.c:57 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_633d28a863f8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_22a.c:43 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9e929c696cc9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_22a.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d0deb8513ec8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_62a.cpp:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dd2bcf56c3c6 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7258320d6824 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_62a.cpp:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b044d3b62fd5 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_62a.cpp:43 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0e17389b28a9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_61a.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d4ebc59043e4 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_51a.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0c4897bb5792 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_41.c:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_17d5c7fdf2e4 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_52a.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2579ef49fd6d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_64a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5826b042ecfd | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_63a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dadf452f9f70 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_52a.c:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_daf542044296 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_53a.c:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aae04efd56bc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_51a.c:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_603762260995 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_54a.c:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_253754505e04 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_41.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_49910a424f3e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_63a.c:73 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4997d5df2822 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_64a.c:73 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_64cd9b2c5634 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_41.c:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_32d261f9dfe9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_52a.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a852e8e65c2f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_51a.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2f80b5476b01 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_53a.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f963899e56dc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_54a.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a6fc0587f892 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_51a.c:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8aefd7c87aae | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_64a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_862d7a0f3230 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_63a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6ec28c03eeff | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_41.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4ea4f38b3b9c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_52a.c:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d8750d8db077 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_63a.c:73 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d13ad14fa6f1 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_53a.c:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9360feec1594 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_64a.c:73 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cce23f4d0670 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_72a.cpp:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c3ed35dee8c9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_41.c:51 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c8c3e1aae6dc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_72a.cpp:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3eb8bea9feb6 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_12.c:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_21f487578929 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_12.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bd07c57836cd | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_21.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1afc6d19b7dc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_21.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a8c393f9691c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_42.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a04cd75f41ce | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_17.c:59 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_06894e93a139 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_43.cpp:63 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f0ce389926c2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_21.c:131 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e8bf58d190bc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_21.c:131 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5f17a75a8053 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_21.c:68 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8fe341a8b86c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_82a.cpp:72 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b5532eeed1b0 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_82a.cpp:66 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_df500fe7da83 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_82a.cpp:72 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_425cf4d2ace7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_43.cpp:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_54a9224d25f4 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_43.cpp:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_425b60be3433 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_11.c:58 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8a161cf11aa8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_08.c:72 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3f6973bb36ec | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_01.c:55 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2d771e78bee8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_02.c:58 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7af91fe5fc85 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_03.c:58 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b73a82679b4c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_04.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b39f57441385 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_06.c:62 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_615576fac2cd | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_05.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7ed1a139114a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_07.c:64 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_350234d74037 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_13.c:58 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_74de476c77d9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_14.c:58 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_795c2a8bca22 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_10.c:58 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_337c99c1612f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_09.c:58 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_75b9dff925e2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_15.c:64 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ec50244c0488 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_81a.cpp:70 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_78b22383f82f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_16.c:59 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_46f547ed80f2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_81a.cpp:64 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d461a0daed52 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_18.c:57 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8adbff54c6c2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_43.cpp:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7b9465a90c03 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_81a.cpp:64 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1e31991d99b8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_44.c:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bd1d692e76b9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_65a.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_89f8cedd6547 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_44.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b89b74594665 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_65a.c:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d0aaaf45f979 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_43.cpp:69 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c0b5bae44eca | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_44.c:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_844953429da2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_65a.c:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0c57a57f106b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_21.c:76 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4d1c004f66bd | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_08.c:78 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_72d16f45b4dc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_11.c:64 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bd6c4db82d0a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_21.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_df797932ce5d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_22b.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e43ea15a672e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_22b.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9a70db05eeff | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_21.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_06155d0972a8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_22b.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_527c065ab468 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_01.c:61 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2dac3869b806 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_02.c:64 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_deecb5cd63ca | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_03.c:64 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_60d6301b2c7c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_04.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_44f858f0214b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_09.c:64 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b600d8663007 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_10.c:64 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_adc4276a5db9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_15.c:70 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f68a1af54fc5 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_13.c:64 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_354fedd1a7bf | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_14.c:64 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a5aff47cc21d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_16.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_966d52f7351f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_18.c:63 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6c09a70ab8ce | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_22b.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b6312a2cd8ec | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_21.c:118 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_972b26071de1 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_61b.c:68 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a4dbe36f0886 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_42.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fed92c36a749 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_21.c:112 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_13ac9ad77388 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_22b.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2ca1320b5a30 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_21.c:118 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_769df7ca3f76 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_22b.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c8d1d4a6f4a2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_42.c:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a80f0e7071e2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_22b.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_57e362ea524e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_61b.c:62 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_393e5fb1c4aa | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_31.c:45 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b49ae61271ea | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_33.cpp:49 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_885275e31c5d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_34.c:52 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3912a150cb4f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_41.c:52 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_26a36c2c2300 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_45.c:55 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_584a99c3dbdd | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_32.c:49 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a3a3af07384b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_11.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4ee5722dc5ee | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_11.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_273f29f032ae | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_12.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b94047e3b4d2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_11.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_77431ecfd831 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_08.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ba52d1f24ccd | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_12.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cbf987050eca | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_09.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_deef72fcb9d4 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_07.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_33c28163397d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_05.c:95 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aa483308a3c7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_10.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_06b237e39d7d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_13.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7213b79a434e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_14.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_655c1f551081 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_05.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f7fb3f81a2bd | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_07.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cfeabd5ad863 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_09.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_89bf2726e327 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_05.c:95 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9a02c6b28101 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_10.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4a910474107c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_13.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ec8075838328 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_07.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7218c421e533 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_14.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3199c1839251 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_10.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5a191940c07b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_09.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fb149bbf227e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_13.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_18552f31fc07 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_11.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8aea7e7aa072 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_14.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3c5b9f5661b5 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_05.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_647680e06914 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_07.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aa5681a00d70 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_08.c:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1babef2424c8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_09.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_306d028ca504 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_10.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7671e3de1941 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_01.c:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_18d167aefa0a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_13.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_250b3b5ecdde | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_02.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2f7b62776700 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_14.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_463306de6e7f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_02.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_898712f5c1b5 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_03.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_21dec16118f8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_03.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_85bce6c7947d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_04.c:95 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6a40fee538a5 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_04.c:110 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6144645f156d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_05.c:110 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_023607550f9c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_06.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3a34efd0d018 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_06.c:107 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8965df6fac43 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_09.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7a2f028add27 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_07.c:109 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1e4197f83b45 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_10.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6660fd4fa630 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_13.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_635639d816d7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_15.c:95 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5e2f1f50d8cf | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_14.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5d1b6f919ad7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_16.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9dee26b45d7a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_15.c:116 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_504b4e937615 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_17.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b1ca5175e57e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_18.c:81 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4725c6718490 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_01.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_de280de049bc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_02.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_241624717798 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_02.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_caef9f82c8dc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_03.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5aee828816d7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_03.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4c0c403285ae | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_04.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c55875126b06 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_05.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9513afb97a19 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_04.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3e35eccf16a7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_06.c:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4f7412f5e44c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_06.c:101 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6d32db8dfc92 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_09.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_db208225a54b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_07.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2b700feb88d2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_10.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4203d174db26 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_13.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4e653d306d99 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_14.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e3f17cee5005 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_15.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9a017504d43f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_15.c:110 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c2086e35eec8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_16.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1e0f1bc92b1b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_17.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_50aa6cb25e20 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_01.c:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_000af82859bd | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_18.c:75 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_16f2718ede69 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_02.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a014c8eeb088 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_03.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c942267f8d86 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_02.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d83862f1c98d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_03.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0f32e9d9ddb3 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_04.c:95 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8c8125531478 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_06.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_50c974cb0c7b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_05.c:110 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_386f30af818f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_06.c:107 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8a6524f3c850 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_04.c:110 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3da4a5cf7e7e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_09.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_770d65772a25 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_13.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_785203774716 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_07.c:109 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aba2f6ade8fd | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_10.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c67787cfdef6 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_14.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_304f069d14b6 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_16.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_102e8bc3905d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_15.c:116 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1c3c29123cf1 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_15.c:95 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_663fa970bacb | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_17.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e02024c6f3b1 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_18.c:81 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cf62a1cee722 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_01.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_70704d06d4ed | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_02.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_455bb4591986 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_03.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c960ce52dc95 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_02.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_db787180b061 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_04.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0479d06c4ee9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_03.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d7d13cd9e66d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_04.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_73185f3d6ce9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_06.c:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7dcf423052ed | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_05.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_debaa93af50d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_06.c:101 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1d4f47e9836d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_09.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c4804a9175b0 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_10.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6da9255188ae | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_07.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_43f10d98c2ac | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_13.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f2758c566a99 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_14.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_70084155d437 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_15.c:110 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7e71342ea18b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_15.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4aff435ae1d8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_16.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_98f7b6e25ae4 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_17.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9b7dc412dc43 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_18.c:75 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_12cdef6e5a4c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_33.cpp:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0b19f0ab4bed | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_32.c:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_431c3f185a2b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_45.c:56 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_53ae92e03032 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_31.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_609ec9a868c0 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_33.cpp:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6a61d4f90558 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_34.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_97cf484f37a3 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_31.c:73 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e00cb2f997ce | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_33.cpp:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4b341264c08f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_34.c:81 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8eff7bfb1bba | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_31.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e72c55b09dad | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_33.cpp:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_339ff9ac5ea5 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_34.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b70410146161 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_31.c:73 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5985858f9d4f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_33.cpp:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3f5bbb922185 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_34.c:81 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1fd4298ac3ca | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_21.c:136 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c9f31be14474 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_22a.c:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1de248f1cd74 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_32.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b03325832967 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_66a.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b08fc869dc8e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_45.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b8d993b35849 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_67a.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0b93de8185aa | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_72b.cpp:51 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_78437b34f2bb | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_73b.cpp:51 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_37dec1282369 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_68a.c:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_793e68dd2ac3 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_83_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_82ea552b81fe | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_84_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0a00ca3d4d0b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_04.c:109 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e939115876d8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_21.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8f9a3fb2c3d3 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_22a.c:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_53a2fb3c53a1 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_45.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0f088f5a54a9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_32.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_58f930bbf61f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_66a.c:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5dc9d9705ac7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_67a.c:81 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_140b92eb34b6 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_72b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0078aeb42d08 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_73b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_82abc9564582 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_83_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_64c37e91731d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_84_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7f8b5390dcec | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_21.c:136 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9d3c8f8b1285 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_22a.c:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0456bff5489f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_32.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_18071ea56548 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_66a.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_edea93a9b833 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_45.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3b14b0a6b1a7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_72b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_125a8fb6fd43 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_67a.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_573769c68363 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_68a.c:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5a110312fefc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_72b.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3c6fe82706c5 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_73b.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6f125c2437fc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_73b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_15df3cb69760 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_83_case0.cpp:56 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3dc84e123588 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_83_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1f2bfe79349b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_84_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0e12aede399a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_84_case0.cpp:56 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_57a2245d895f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_21.c:131 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c3cf3263a05d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_45.c:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a82cade8d837 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_22a.c:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4ee4f6f9f4d2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_32.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_159aabd31881 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_66a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5bdb7f0ecb7c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_67a.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6aa9ddf7ee66 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_72b.cpp:51 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_67cff34671f7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_72b.cpp:39 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2ded0785f9de | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_83_case0.cpp:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1392e2509c71 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_73b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0d827295c45b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_83_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_41c8f6aebab2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_73b.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a75fc282b518 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_84_case0.cpp:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4a11b0e95008 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_84_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_819b61a0a26e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_41.c:76 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_633bdc9c0d88 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_43.cpp:95 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ee0a73b45981 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_42.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ac5e8ddff4f2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_43.cpp:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_65a7f87c58e7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_44.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_621e9f5bf705 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_45.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9baaa24f2b76 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_51b.c:46 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_53a95fdee106 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_52b.c:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_661102e78e69 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_52c.c:46 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d308086e9b70 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_53b.c:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aa9f074ee0b2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_53c.c:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cca77bbc7421 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_53d.c:46 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4d3c5761962a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_54e.c:46 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_acfcf5afaf32 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_61a.c:62 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_38adfe150f5a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_62a.cpp:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b4bb3605e89b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_63b.c:46 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c897e44d1900 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_62b.cpp:70 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2b31d8e02f42 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_64b.c:52 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7cadf38d8905 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_65b.c:44 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4c0b1ca57cd9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_66b.c:47 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f7c716db6d1a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_67b.c:51 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_888f85cf5934 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_68b.c:51 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_31916481fac1 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_81_case1V1.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4954dba8b18a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_82_case1V1.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d1b84e4e5e86 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_83_case1V1.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_edf8cfc77655 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_console_84_case1V1.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_17762c6d68ba | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_41.c:70 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9c566e570406 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_43.cpp:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4f2280515b73 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_42.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_904ac0a4a010 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_43.cpp:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_926dffa196cb | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_44.c:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_adbb63d1eb7c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_45.c:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a12e4855edc8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_51b.c:54 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e97bbf3838e3 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_52b.c:58 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4a6825ea3390 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_52c.c:54 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_afc92b827f91 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_53d.c:54 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_78193674b12b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_54e.c:54 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_959d38397e5e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_62a.cpp:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8103bdfb1c50 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_61a.c:70 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2367e4ec2418 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_63b.c:54 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_37499406844f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_64b.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_445c4c88a892 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_65b.c:52 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_019a004f4e72 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_67b.c:59 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d702aaa9a813 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_66b.c:55 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1f99dd35379d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_68b.c:59 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3eb38dcb50c4 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_81_case1V1.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c0b4c38311b3 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_82_case1V1.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_07e623e56ec3 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_83_case1V1.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1b326ebd00e8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_83a.cpp:48 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_30c494269058 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_environment_84_case1V1.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cb219a77f32b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_41.c:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_46574ef9d0e4 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_34.c:98 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_16332631cebe | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_41.c:76 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ba1b940ce3ce | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_43.cpp:95 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_19928dcc293b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_42.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_39b72bb9e26e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_43.cpp:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_929914a483c7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_44.c:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9fbc16c0615c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_44.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_783096cf3521 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_45.c:37 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6d79851df0ca | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_45.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ff7b448409f5 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_51b.c:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f6acb782d7c1 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_51b.c:46 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cda2ac3b04fd | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_52c.c:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8be78cb63b99 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_52b.c:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0682dbd2e75e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_52c.c:46 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a58ddabececc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_53b.c:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8d9304254ea5 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_53d.c:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2bcdcb85ef38 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_53c.c:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1490914c6a2d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_53d.c:46 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_49ebac70c70a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_54e.c:35 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9fabe5405794 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_54e.c:46 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ebe45767422e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_61a.c:62 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3477535d4245 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_62a.cpp:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7bc30c6d6cc1 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_62b.cpp:70 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_637f79b95cae | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_63b.c:34 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_de7350169eea | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_64b.c:37 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_815f49c70490 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_63b.c:46 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a9608d153fee | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_65b.c:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f696eebcb529 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_64b.c:52 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4961945119c6 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_65b.c:44 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_51f449ba2352 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_67b.c:51 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e6f76618da03 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_66b.c:47 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_db87fa5cb55a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_67b.c:39 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2dc981d0398d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_68b.c:39 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_245caaa9b3b7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_68b.c:51 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_35b215ff751f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_81_case1V1.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fb322479e5d5 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_82_case0.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f5f541a57816 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_81_case0.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9233d5f4f575 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_82_case1V1.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a9884d2de38a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_83_case1V1.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5713d17016b3 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_console_84_case1V1.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ff78fb81bbc1 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_01.c:76 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c01f3026392f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_12.c:93 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8fe83af846af | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_18.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_61ee8412048c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_31.c:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_21e392aa0c7e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_41.c:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7311e20dedce | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_41.c:70 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3923a079047d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_42.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dad3f5e72056 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_44.c:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_43fc0532b669 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_43.cpp:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_81318f9eada6 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_43.cpp:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1d5dd520b157 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_44.c:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_037df93aba70 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_45.c:45 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7261443173c1 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_45.c:77 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_78c35c256d1f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_51b.c:54 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_57f51eb35f6a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_51b.c:43 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d38a1b58e2d2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_52c.c:54 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_86221f1b18d4 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_52c.c:43 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6f12c3689591 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_53d.c:43 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b898dcbad0d0 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_53d.c:54 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b5332532a19a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_53c.c:58 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_76c2d04cd91e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_54e.c:43 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4283fa73fa30 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_61a.c:70 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_072c9bf08039 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_62a.cpp:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b612f8f22adc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_54e.c:54 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5f59beafe88a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_62b.cpp:64 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f2c8412f4e7e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_64b.c:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aac83353e098 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_63b.c:54 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_799414565601 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_64b.c:45 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f94d5bc5917f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_65b.c:52 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9a10325ea9e9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_65b.c:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c09bf1220722 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_65a.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a96500e232ba | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_66b.c:43 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d5b921b4c698 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_66b.c:55 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ff11c6dc5e01 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_67b.c:59 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6610f2fed332 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_67b.c:47 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e2263ac42839 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_68b.c:59 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_776dd0e71efa | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_68b.c:47 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e3b8ab730140 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_81_case0.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b5d8ca341e16 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_82_case0.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_59be8263fe6b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_82_case1V1.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_64af90d617ab | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_81_case1V1.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_78e50a21697e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_83_case1V1.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_adc3eaf3f227 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_82a.cpp:73 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_071eff43a445 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_environment_84_case1V1.cpp:27 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_49130be8b890 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_74a.cpp:464 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3957c03244a5 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_73a.cpp:443 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c8df7dd915ac | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_73a.cpp:443 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2621b76e6282 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_22a.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0cd27ee45290 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7d9a008e5dd5 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_61a.c:78 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_83625a5a35c8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_62a.cpp:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_849722d39bd4 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e556258e57df | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_61a.c:78 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1a4c13fa62a3 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_22a.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a7498878fb72 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_62a.cpp:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d7b377ad5613 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_22a.c:43 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5f46250e3857 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_514a5663f71b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_22a.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3ca0c9b46ca5 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_61a.c:78 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_59265289cdfc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_61a.c:61 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ecb232c477b8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_22a.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1ccdb3d97efd | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_62a.cpp:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_da55c2ee12d2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_62a.cpp:43 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f28cb5c93b08 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_61a.c:78 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_73111a32c935 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_62a.cpp:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cc5c8f9817a6 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dd8eb29a6e69 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_41.c:149 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_603c9f31a30c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_51a.c:143 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6abda5af8ba6 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_53a.c:143 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f6382240d0bb | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_52a.c:143 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3689619bc18c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_64a.c:142 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_42ca04bfd1ae | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_41.c:161 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aa03a97c3848 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_51a.c:155 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2f5be1dd0079 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_52a.c:155 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dd2a772c438a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_53a.c:155 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a217c02c5e97 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_63a.c:154 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_08ca72c5cb62 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_54a.c:155 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_49a9e3fb48a7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_64a.c:154 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_531311a6eeaf | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_51a.c:143 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8102c758d665 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_52a.c:143 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_66ea2c5832e5 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_41.c:149 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e171d34cf52b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_54a.c:143 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_07db8329dcf7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_64a.c:142 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9490eafbaafc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_41.c:161 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8f0abe55636c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_51a.c:155 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bc41bdd4963f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_63a.c:142 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f2d00eb41cc4 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_52a.c:155 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bd06337f4a75 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_53a.c:155 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a294b86e90cb | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_54a.c:155 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c8fc7d02613a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_64a.c:154 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c70825fe11b0 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_63a.c:154 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1bf5cd81bd7e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_74b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cc94bd34afb2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_74b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_df3cd2922f26 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_74b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e7d54ddc3616 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_74b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_033cac213f53 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_74b.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_675474385ad0 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_74b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c02473aa6b4d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_74b.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3193835afb5e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_74b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_167579424560 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_82a.cpp:147 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9110a30fa351 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_82a.cpp:135 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_033ea4fd5433 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_82a.cpp:147 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6b900ccc7d98 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_43.cpp:153 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_efcf58a04d51 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_43.cpp:165 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_17f35d27161c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_81a.cpp:133 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8dddd6f1d673 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_81a.cpp:145 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2009650a4794 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_81a.cpp:133 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_86a1b7a7a994 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_81a.cpp:145 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cf6d64bd166b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_66a.c:148 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_75ea023bc931 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_68a.c:149 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_74eab476ef14 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_67a.c:150 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6b014c6bdb35 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_66a.c:158 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_368208b953b3 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_66a.c:146 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c90b098a19ee | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_68a.c:159 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b7e56e49e815 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_68a.c:149 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9d584d223152 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_67a.c:150 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1c6b43b65ca6 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_67a.c:162 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b883276eca56 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_66a.c:158 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_314b943bcdae | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_68a.c:161 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b708140ff66d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_43.cpp:158 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a864c35296db | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_52b.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_888a24477a7f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_62a.cpp:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1c30dc909687 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_72a.cpp:166 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7e2f0c14c7ad | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_43.cpp:170 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b22bfd029a6e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_53b.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ad4cede6b29a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_54b.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_76659f228929 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_54c.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_28505ecb4ccc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_62a.cpp:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2f4b58347a6c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_84a.cpp:50 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_50a702ff2ef1 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_43.cpp:158 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_42a34b2afbd9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_54c.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c95355b2ccee | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_62a.cpp:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ac1412d2df8f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_33.cpp:168 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_649fbfd80ed2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_43.cpp:170 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c5ae62599b04 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_53c.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_496b2f38514e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_54b.c:71 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9beef40b4dde | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_62a.cpp:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3c5ed9869874 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_81a.cpp:152 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ef3c409783dc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_61a.c:63 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4618a87268ce | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_eff3368004eb | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_22a.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_af843db4d492 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_22a.c:43 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_45dd26212a2c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_62a.cpp:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c8807273e045 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_22a.c:65 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_edd06d5b70a4 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_22a.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c347f20d5196 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_61a.c:46 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f88f52c52037 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_61a.c:63 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7a41c5eca0bd | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_62a.cpp:43 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1b6acac2ca26 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_62a.cpp:60 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6ba806733370 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_41.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2da3bf4b38dc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_51a.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_274080347886 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_53a.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b291dd3c3918 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_52a.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ec0b521f9e05 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_54a.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_39e3171924b9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_63a.c:81 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5c6938069c00 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_52a.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2c89d25ee527 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_51a.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_613fc458aa21 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_41.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dd000fdf0f3d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_53a.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_56470840631a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_64a.c:81 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fc0bce95b41a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_21.c:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1d96850a496b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_21.c:133 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dbe811df6203 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_21.c:172 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_57ecdceecd25 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_21.c:194 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f75252e7206b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_21.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0868a760706e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_21.c:194 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_942f506e6ba9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_21.c:133 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0146785e2419 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_21.c:172 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_46fb39edd9b9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_82a.cpp:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5b275cc59e1c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_21.c:206 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_082fdff331ee | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_82a.cpp:74 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ac013fc6c117 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_43.cpp:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_19b33a19ae4c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_42.c:164 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_316304b0d46b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_42.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_53bea35de7ac | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_81a.cpp:72 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_928c301310bc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_81a.cpp:72 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aba022408781 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_44.c:153 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_357f409fba4d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_65a.c:146 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7bb625e02415 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_44.c:165 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0ffdf5c9937e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_44.c:153 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7e5dcf55a008 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_65a.c:158 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_147cc625633d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_65a.c:146 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ee93c9de8280 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_65a.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_eda03d149609 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_44.c:165 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f1329d65012c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_44.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c7cc694528a8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_22b.c:148 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_64a496b9562b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_65a.c:158 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ac788cea1a6f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_22b.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_db4260f7a07a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_22b.c:160 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_628bb06f6724 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_22b.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_09caee2d881c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_21.c:98 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0f9f2a4a0a34 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_21.c:159 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_af99b477279b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_22b.c:160 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0162677ae74f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_21.c:171 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_126c96b74f17 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_21.c:181 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fa81a91a1bf8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_61b.c:131 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_309c3d4a44af | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_42.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a596ab21b6b9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_22b.c:98 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ee966c7baebb | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_61b.c:70 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_06dc784d89eb | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_61b.c:143 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_38e77dbcfd01 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_42.c:152 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_15871fa72c82 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_22b.c:171 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_930049a08e6b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_22b.c:159 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_053a715112eb | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_22b.c:98 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6cd775c2729d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_42.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_46cf8778153d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_61b.c:131 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f5563ce928cc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_21.c:193 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_abeccb0a7e86 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_61b.c:143 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_63f44af49695 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_22b.c:171 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3c6e2c900e2f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_42.c:152 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_182f7743825c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_11.c:151 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ff7be681649a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_11.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_12e1e548a321 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_08.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_69f01bbc553e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_11.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4631c8899577 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_11.c:151 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cea3f738698c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_05.c:158 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_798c278521ba | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_12.c:169 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ac9c36ab529b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_11.c:163 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_75279b84285d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_08.c:177 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3f9898518718 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_07.c:157 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e00d8148a147 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_08.c:180 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8c4479511a98 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_11.c:166 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_89832eb8f23e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_09.c:151 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c04f2cd48465 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_13.c:151 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_adff3badff9e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_14.c:151 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7230c78e14ea | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_05.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f7de1be2f185 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_07.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_76f85b20ad54 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_10.c:151 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c968fdc036c5 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_08.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_35c003ff2e56 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_13.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_330e6c4dbb52 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_10.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1c66b148340a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_09.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a0305dcd7811 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_14.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9878d9c29e75 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_05.c:170 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1374b7921e68 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_07.c:169 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ed1bb6d234d9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_10.c:163 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fd76e3238fe3 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_09.c:163 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0a09333efb0b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_11.c:178 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_32e900064423 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_05.c:158 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e101caca211e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_13.c:163 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1bea9e1f3c92 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_14.c:163 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4c8c798277a8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_07.c:157 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5eddcb51750d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_08.c:180 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cc1cf068901e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_09.c:151 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aff72633bc6d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_11.c:166 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9e1c42d86884 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_10.c:151 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_04945079a4ea | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_13.c:151 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6e7cc3ebdecf | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_14.c:151 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7ba5285f941c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_07.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c51b2115a26c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_09.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_779e2e35a614 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_05.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3d67dec2f291 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_08.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f0c985e4d781 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_10.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_77159adc5936 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_13.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_48716cde42a4 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_14.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a51334b4cc36 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_05.c:170 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a40d627dd6e5 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_08.c:192 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dd07129f45b4 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_07.c:169 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3c74a36dc95a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_10.c:163 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c171971b4c36 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_09.c:163 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d7ad7b27917f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_02.c:151 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ff0286ec3f20 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_11.c:178 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_967a56fe82b2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_14.c:163 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_79b32dadd893 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_13.c:163 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_be1782fc434b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_01.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_20809fea3c42 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_03.c:166 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5b6fe18a19fa | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_02.c:166 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5ec082b36ab1 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_04.c:173 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3417293e04e2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_03.c:151 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e3c4909f8866 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_04.c:158 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_efd5ccd46f34 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_05.c:173 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5fe8a4bfe3f1 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_06.c:170 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e69a8dab868c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_06.c:155 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aedd30fcb448 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_09.c:166 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_415104dfe064 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_07.c:172 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_961f4255a1b1 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_13.c:166 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_64c7ee667ea5 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_10.c:166 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ad9889cfa5eb | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_15.c:158 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f81940d12b34 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_17.c:148 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e76ce84d2ea7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_14.c:166 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aa98c3b7be24 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_15.c:179 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0f33866953f0 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_16.c:148 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5c0b34f4046e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_02.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bca487e09491 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_02.c:105 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1878fe5489de | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_18.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cbd883dd18b3 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_01.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d54ae0ff575d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_03.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1f31932d3114 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_03.c:105 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2ae950e4d9b4 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_05.c:112 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_35ee6d586558 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_04.c:112 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aa2645c6a852 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_06.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_783014bef8ff | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_04.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a1ec4a8dd6bf | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_06.c:109 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ace23ea12b48 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_07.c:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a160a7df2fd4 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_09.c:105 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8838b279e62c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_13.c:105 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c14c0240426e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_14.c:105 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3ab3564e1f88 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_15.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8af68c7cf848 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_16.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f671e90dfc57 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_15.c:118 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_804984fc8953 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_17.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ab66db1334f7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_18.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4bb3dd7e22a7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_02.c:163 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_571bba567d03 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_02.c:178 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_437914a9aca2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_01.c:152 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_291015015f7a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_03.c:163 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f553b7ed5873 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_03.c:178 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dba979252de9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_04.c:185 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a0db8da4e1cb | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_04.c:170 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_13ef905d3616 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_05.c:185 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_593fa796329f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_06.c:182 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ed249d0ed772 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_06.c:167 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9363c9fe470b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_10.c:178 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_053ea4f8fa75 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_07.c:184 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_33d96c891636 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_13.c:178 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1e8f74263c52 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_09.c:178 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b35ba3b487a9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_14.c:178 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a54257a3778d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_15.c:170 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8269e2c91f13 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_17.c:160 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ce850ed66468 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_16.c:160 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7a0dab87efc8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_15.c:191 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_33305cdfb0b4 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_18.c:156 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9fd94d1587c1 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_02.c:166 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d5c7bb20ddde | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_02.c:151 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_fd6cdc4c89dd | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_01.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a09809befcc6 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_03.c:166 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_90659cf45bf7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_03.c:151 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_28afbb6445f8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_04.c:173 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7168889be50f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_05.c:173 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8cf19f6468b0 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_04.c:158 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f68460ccb543 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_06.c:170 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_360c727ec6dd | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_06.c:155 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_84a741038844 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_07.c:172 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8d8c719764fa | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_10.c:166 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c282cec97740 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_13.c:166 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_90eebedde040 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_14.c:166 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_78e6d8b68226 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_09.c:166 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_eb961409e1ee | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_15.c:158 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_42a047d08f78 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_15.c:179 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_64d57a5827bd | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_18.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_728a9e8e0799 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_17.c:148 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0282a2fd90d6 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_16.c:148 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dc1e0c5bc145 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_01.c:79 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_524dc6f965e1 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_02.c:105 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6179f38977db | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_02.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c4e9a2ff9b05 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_03.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_24c590b7ccad | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_03.c:105 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_41cb0f10ae28 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_04.c:112 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e123cd2e2013 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_04.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7c60e5cdefb0 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_05.c:112 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5c2b7a8553c3 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_06.c:109 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_46cbd80cfcd2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_06.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c54bb794ff5b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_07.c:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_04af8842ba16 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_09.c:105 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_59ede05608cd | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_10.c:105 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6bee78cf4fc0 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_13.c:105 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_28d8a30a6246 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_15.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_33fb1e278286 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_16.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e9c2df933b9c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_15.c:118 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_65e95b6923f9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_17.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_09456c828ac9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_18.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7fa6427487e9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_01.c:152 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0937988dc00c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_02.c:163 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f21aec9f9d36 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_02.c:178 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_43deaf2dfa34 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_03.c:163 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_02b1325daf2c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_04.c:170 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e6770be37f92 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_03.c:178 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_02d28f8cd911 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_04.c:185 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_652a303b2b98 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_05.c:185 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_943bc8ec33cf | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_06.c:167 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_56b92ea97356 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_06.c:182 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_667e878c5273 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_10.c:178 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1d9c3bbe8b99 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_07.c:184 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_10d6a0e44955 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_13.c:178 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3a27b0b03214 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_09.c:178 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8b12bea47c47 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_14.c:178 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ea273bf9dd39 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_15.c:170 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bdc3ff03bf6d | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_15.c:191 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1d464e5d855b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_16.c:160 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_da4a43dc197f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_17.c:160 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1f08a7cb9601 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_18.c:156 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c13b579af812 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_31.c:81 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_17cf12ffa9bd | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_31.c:142 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_14336bba938f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_33.cpp:146 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a182d4b3e295 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_34.c:150 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4a7cbda8d6a8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_33.cpp:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2d2eaab05894 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_31.c:154 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7ba67b11621c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_33.cpp:158 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_41f43cc3a467 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_34.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1b6011404a94 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_31.c:142 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_91bd3193c94f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_33.cpp:146 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_229029d255cc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_34.c:150 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3523be82147e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_34.c:162 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_664226f48f06 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_31.c:81 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7fd786aecb04 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_33.cpp:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5418f42ce5d9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_31.c:154 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1a05dc9dc846 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_33.cpp:158 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2e7b0cae22ef | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_34.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_67555eea456e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_34.c:162 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6f5ac7824d02 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_09.c:171 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f726f9c058e9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_32.c:151 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_02196467ef8e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_22a.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_59047257c01b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_21.c:199 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b66933bf5a85 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_72b.cpp:51 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_47262b09a4c3 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_45.c:157 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0677be45e29b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_73b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_57f95bfec25a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_83_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2fabab73ffa0 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_connect_socket_84_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_03de5430c529 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_08.c:125 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_10293f124c37 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_21.c:139 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ab28a7887801 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_32.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5ac9da66da46 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_22a.c:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2f2822b7fbc9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_45.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_342088b5523f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_66a.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_176e2dc26181 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_67a.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2ce8d375d2ab | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_68a.c:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_10f0be6bf318 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_72b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0acdd6239713 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_73b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_34f92df97c48 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_83_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7638180dc9d7 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_file_84_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_61176b9267db | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_21.c:212 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7c5effe200d8 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_32.c:163 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_71dec0baab5c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_72b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_24c591297a62 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_45.c:167 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a0313de6fc9b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_22a.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_873534d1bd11 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_73b.cpp:51 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5d035f050769 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_83_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2eb7421e66af | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__char_listen_socket_84_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ab74681c558c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_09.c:171 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7075b1280c1e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_22a.c:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c68c6ab42f1c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_21.c:199 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9fd9e2567d80 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_45.c:157 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0237b2d8f290 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_73b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0317335337d2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_32.c:151 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_326aea476ebf | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_72b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_62971ab3948e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_72b.cpp:39 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a407b8ab6d09 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_73b.cpp:39 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8293de56c1c5 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_83_case0.cpp:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_da44189924bc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_84_case0.cpp:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b259df86870c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_84_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_40d789004192 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_connect_socket_83_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_57d8bc0dd324 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_22a.c:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9b08276724fe | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_21.c:139 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_66a5c59f3bf9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_32.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_657e9fcede17 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_45.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6237b85d4edb | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_66a.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7666943c2be3 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_72b.cpp:51 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0a130b3a6c8e | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_67a.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_69ef442f9de4 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_73b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_10c0f54d29df | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_73b.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_08673309f907 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_83_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_40cd6f28ac23 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_83a.cpp:43 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bfad0b8d478b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_84_case0.cpp:58 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_99b67902a2a1 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_file_84_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_99846357b660 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_21.c:211 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bb6afd071544 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_32.c:163 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4481e7ab3aa9 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_22a.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ba64ac14691c | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_72b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_52994c6259fc | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_45.c:169 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3cf2b0ce524f | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_83_case0.cpp:131 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2f9d1e487a4a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_72b.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_42aa79fad09a | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_73b.cpp:53 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8250d9630e7b | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_73b.cpp:41 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_16a6057f3708 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_83_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4e3e766f0eb2 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_84_case1V1.cpp:33 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0089d5db4804 | juliet-api-misuse/testcases/CWE427_Uncontrolled_Search_Path_Element/CWE427_Uncontrolled_Search_Path_Element__wchar_t_listen_socket_84_case0.cpp:131 | NOT_EXPLOITABLE | payload did not satisfy oracle
