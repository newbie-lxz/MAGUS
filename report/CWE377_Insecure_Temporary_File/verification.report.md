# MAGUS Final Vulnerability Report

- generated_at: 2026-05-22T11:42:35Z
- confirmed_vulnerabilities: 186
- failed_verifications: 277
- source_confirmed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE377_Insecure_Temporary_File/verification.jsonl
- source_failed: /home/sq_hu/MAGUS/d/memberD_verifier/02_run_with_C/output/CWE377_Insecure_Temporary_File/verification.failed.jsonl

## Confirmed Vulnerabilities

### 1. hyp_path_059be0e83e29

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_12.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够对临时文件目录进行文件创建或符号链接操作。
- 触发路径: wchar_t * filename; filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_12.c:50-55; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_12.c:72-73
- 结论: 使用tempnam生成临时文件名，然后以O_CREAT标志（无O_EXCL）打开文件，导致竞态条件漏洞，攻击者可预测或控制临时文件名并创建符号链接，从而覆盖或窃取文件内容。
- D验证: confirmed / ver_1be21b26
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 2. hyp_path_42b975f1d129

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_12.c:90
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够提前创建与tempnam生成的文件名相同的符号链接
- 触发路径: filename = TEMPNAM(NULL, NULL); @ 第68行; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); // 无O_EXCL @ 第90行
- 结论: 代码中使用tempnam生成临时文件名，随后使用open()创建文件。在一处分之没有使用O_EXCL标志，导致竞争条件漏洞。攻击者可以预测文件名并在程序创建之前创建符号链接，导致任意文件写入或覆盖。
- D验证: confirmed / ver_7e8622b7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 3. hyp_path_0c0916a67098

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_12.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在的目录; 攻击者能够在文件名创建与文件打开之间的时间窗口内执行文件系统操作（如创建符号链接）
- 触发路径: printLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); if (fileDesc != -1) { @ L48-52; { printLine("Temporary file was opened...now closing file"); CLOSE(fileDesc); } } @ L52-56
- 结论: 函数GetTempFileNameA与_open结合使用，在第一个分支（uUnique=0）中未采用安全的临时文件创建方式（O_EXCL），导致TOCTOU竞争条件漏洞，攻击者可能通过替换临时文件实现权限提升或信息泄露。
- D验证: confirmed / ver_ad573d5a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 4. hyp_path_508bbb1dbcee

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_12.c:69
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在目录（通常为操作系统临时目录或当前工作目录）并具有写入权限。; 攻击者能够预测或监听临时文件名（模板'fnXXXXXX'，随机性不足，但mktemp基于时间，可预测）。
- 触发路径: char tmpl[] = "fnXXXXXX"; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_12.c:58; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_12.c:64-65
- 结论: 使用mktemp生成临时文件名，然后以O_RDWR|O_CREAT（无O_EXCL）打开，存在竞态条件漏洞，攻击者可能通过提前创建同名文件进行符号链接攻击或文件内容篡改。
- D验证: confirmed / ver_c866a1d8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 5. hyp_path_7468433211f9

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_12.c:68
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录（如 /tmp）。; 攻击者具有在该目录下创建文件的权限。
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_12.c:55-58; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_12.c:62-63
- 结论: 程序使用 tmpnam 生成临时文件名，然后使用 open 调用 O_RDWR|O_CREAT 标志（不含 O_EXCL）创建文件，存在 TOCTOU 竞争条件漏洞，可能导致攻击者抢占创建符号链接或恶意文件。
- D验证: confirmed / ver_e80c8647
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 6. hyp_path_2da4aba0632e

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_12.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够预测或观察临时文件名; 攻击者能够在适当的时间窗口内执行文件替换操作
- 触发路径: 进入case0 @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_12.c:35; GetTempFileNameW生成文件名 @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_12.c:48; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_12.c:54或77
- 结论: 程序使用GetTempFileNameW生成临时文件名，然后以O_RDWR|O_CREAT标志打开文件，未使用O_EXCL标志，导致存在TOCTOU竞争条件，攻击者可在文件名生成后、文件打开前替换文件为符号链接，从而覆盖任意文件或获得意外权限。
- D验证: confirmed / ver_4a528fdc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 7. hyp_path_16b7f74fd846

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_12.c:81
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够与程序在同一主机上运行，并有权限访问临时文件目录（通常为/tmp或当前工作目录）
- 触发路径: wchar_t tmpl[] = L"fnXXXXXX"; filename = MKTEMP(tmpl); @ CWE377_Insecure_Temporary_File__wchar_t_mktemp_12.c:43-44; printWLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ CWE377_Insecure_Temporary_File__wchar_t_mktemp_12.c:51-55
- 结论: 在临时文件创建过程中，程序使用mktemp生成基于可预测模板"fnXXXXXX"的文件名，并在随后使用open()函数以O_CREAT标志（未使用O_EXCL）创建文件，存在竞态条件漏洞。攻击者可以在文件创建前预创建同名文件，导致程序操作攻击者控制的文件，可能造成信息泄露或权限提升。
- D验证: confirmed / ver_e7e154a3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 8. hyp_path_0a5442d0777c

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_12.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录（通常为/tmp）; 攻击者能够预测或推测tmpnam生成的临时文件名; 攻击者能够提前创建同名文件或符号链接
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_12.c:50; printWLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_12.c:52-53
- 结论: 使用tmpnam生成临时文件名，然后使用open()以O_RDWR|O_CREAT标志（未使用O_EXCL）创建文件，存在TOCTOU竞争条件漏洞，攻击者可能通过预测文件名创建符号链接或恶意文件，导致权限提升或数据篡改。
- D验证: confirmed / ver_c3698abd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 9. hyp_path_3e1f76da9897

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_11.c:68
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在目录，并能够预判tempnam生成的临时文件名；攻击者能够在临时文件创建前或创建过程中，在同一目录下创建同名符号链接指向目标文件。
- 触发路径: filename = TEMPNAM(NULL, NULL); @ CWE377_Insecure_Temporary_File__char_tempnam_11.c:58; printLine(filename); @ CWE377_Insecure_Temporary_File__char_tempnam_11.c:62; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ CWE377_Insecure_Temporary_File__char_tempnam_11.c:63
- 结论: 使用tempnam生成临时文件名，然后以O_RDWR|O_CREAT标志打开文件，未使用O_EXCL标志，存在竞争条件漏洞，攻击者可能通过预判文件名创建符号链接，导致信息泄露或任意文件覆盖。
- D验证: confirmed / ver_f9eb104f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 10. hyp_path_bb0a7996489c

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_08.c:81
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在的目录（如/tmp），并具有在该目录下创建文件的权限。; 攻击者能够预测或通过文件系统监听得知tempnam返回的文件名（由于tempnam使用L_tmpnam长度的随机字符，但攻击者仍可通过轮询或inotify等机制猜测）。
- 触发路径: filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_08.c:70; printLine(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_08.c:75; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_08.c:77; if (fileDesc != -1) { printLine("Temporary file was opened...now closing file"); CLOSE(fileDesc); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_08.c:79-81
- 结论: 使用tempnam生成临时文件名，然后使用open()以O_RDWR|O_CREAT标志打开文件，但未使用O_EXCL标志，导致存在TOCTOU竞争条件。攻击者可以在tempnam返回文件名和open创建文件之间创建同名文件，从而可能导致信息泄露、数据篡改或权限提升。
- D验证: confirmed / ver_5fd70309
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 11. hyp_path_76bb4dc2e4eb

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_08.c:71
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录，并能够预测临时文件名（TEMPNAM生成的名称可预测或受限于实现）
- 触发路径: filename = TEMPNAM(NULL, NULL); if (filename == NULL) { @ CWE377_Insecure_Temporary_File__wchar_t_tempnam_08.c:58-60; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ CWE377_Insecure_Temporary_File__wchar_t_tempnam_08.c:65-66
- 结论: 程序使用不安全的临时文件创建方式，未使用O_EXCL标志，存在竞态条件漏洞，攻击者可能通过预测或提前创建同名文件导致安全风险。
- D验证: confirmed / ver_f09cd6bb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 12. hyp_path_2e1ab64dff86

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_11.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够在本地系统上对临时目录进行文件操作; 攻击者能够通过观察或猜测获取tempnam生成的文件名
- 触发路径: filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_11.c:47; printWLine(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_11.c:52; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_11.c:55
- 结论: 不安全的临时文件创建：使用tempnam生成文件名，然后使用open()以O_CREAT标志创建文件，但未使用O_EXCL标志，导致TOCTOU竞争条件，攻击者可能在open()调用前创建同名的恶意文件或符号链接，造成信息泄露或任意文件覆盖。
- D验证: confirmed / ver_455e601d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 13. hyp_path_ec2611ba7f99

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_01.c:66
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够与目标程序并发运行; 攻击者能够访问临时文件目录并创建符号链接
- 触发路径: filename = TEMPNAM(NULL, NULL); @ 53-57; printLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ @ 60-61; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ 63
- 结论: 代码使用tempnam生成临时文件名，然后以O_RDWR|O_CREAT打开，存在TOCTOU竞争条件漏洞，攻击者可能通过预测或抢占创建符号链接等方式导致安全风险。
- D验证: confirmed / ver_9f42269e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 14. hyp_path_4a08e823cc2b

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_17.c:69
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时目录并能预测文件名
- 触发路径: filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_17.c:58; printLine(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_17.c:63; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_17.c:65
- 结论: 使用tempnam生成临时文件名，随后使用open()以O_RDWR|O_CREAT标志创建文件，但未使用O_EXCL标志，导致存在竞态条件漏洞。攻击者可能通过预测或嗅探文件名，在文件创建前创建符号链接，从而覆盖或篡改目标文件。
- D验证: confirmed / ver_73a7f7b9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 15. hyp_path_e498045faeab

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_02.c:68
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录（通常为/tmp）; 攻击者能够预测或影响filename的值
- 触发路径: char * filename; int fileDesc; filename = TEMPNAM(NULL, NULL); if (filename == NULL) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_02.c:55-59; printLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); if (fileDesc != -1) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_02.c:62-66
- 结论: 程序使用tempnam()生成临时文件名，然后使用open()以O_RDWR|O_CREAT标志创建文件，未指定O_EXCL标志，存在TOCTOU竞态条件漏洞。攻击者可能通过预测文件名并创建符号链接，导致敏感文件被覆盖或访问权限提升。
- D验证: confirmed / ver_6708958b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 16. hyp_path_91cb635f93ae

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_04.c:74
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者对临时文件目录有写入权限; 攻击者能够猜测或抢占tempnam()生成的文件名
- 触发路径: filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_04.c:63; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_04.c:70-71
- 结论: 使用tempnam()生成临时文件名，然后以O_RDWR|O_CREAT打开文件，未使用O_EXCL标志，存在TOCTOU竞态条件，攻击者可以预创建或替换临时文件，导致信息泄露或权限提升。
- D验证: confirmed / ver_32d1c209
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 17. hyp_path_624df79c60d0

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_05.c:74
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者具有对同一目录的写权限（或通过其他方式创建符号链接）; 攻击者能够获取或猜测临时文件名
- 触发路径: filename = TEMPNAM(NULL, NULL); @ 61-65; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ 68-72
- 结论: 使用tempnam创建临时文件名，并以O_RDWR|O_CREAT标志打开文件，未使用O_EXCL标志，存在TOCTOU竞态条件漏洞，攻击者可能通过符号链接攻击导致任意文件写入或读取。
- D验证: confirmed / ver_48dff879
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 18. hyp_path_69a88f5a2ead

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_06.c:73
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够预测或知道 tempnam 生成的临时文件名（例如通过观察或文件系统监控）。; 攻击者能够在文件创建前在临时目录中创建符号链接指向目标文件。
- 触发路径: filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_06.c:60-64; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_06.c:67-71; CLOSE(fileDesc); } free(filename); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_06.c:73-77
- 结论: 代码使用 tempnam 生成临时文件名，然后以 O_RDWR|O_CREAT 标志打开文件，未使用 O_EXCL 标志，导致存在 TOCTOU 竞态条件漏洞，攻击者可在文件名生成和文件打开之间创建符号链接指向其他文件，从而造成权限提升或数据损坏。
- D验证: confirmed / ver_b412ed79
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 19. hyp_path_856e79b12749

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_09.c:68
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够在目标系统上创建符号链接（通常需要与程序运行在同一系统，且能够访问临时目录）。
- 触发路径: filename = TEMPNAM(NULL, NULL); @ L55-59; printLine(filename); @ L62; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ L63
- 结论: 使用tempnam()生成临时文件名，并以O_RDWR|O_CREAT方式打开文件，未使用O_EXCL标志，存在竞态条件漏洞（TOCTOU），攻击者可能通过抢先创建符号链接指向敏感文件，导致信息泄露或篡改。
- D验证: confirmed / ver_20231294
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 20. hyp_path_8f269d83d959

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_07.c:73
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录并预测文件名（tempnam生成的名称可预测）。; 攻击者能够在OPEN和后续操作之间执行符号链接攻击（TOCTOU）。
- 触发路径: filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_07.c:60-64; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_07.c:67-71; CLOSE(fileDesc); free(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_07.c:71-75
- 结论: 使用tempnam生成临时文件名，并使用open()以O_RDWR|O_CREAT创建文件，缺少O_EXCL标志，导致竞争条件，使攻击者可以预测文件名并进行符号链接攻击。
- D验证: confirmed / ver_9c801d5a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 21. hyp_path_0248bf8552e9

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_03.c:68
- 漏洞类型: CWE-377, CWE-367
- CWE: CWE-377; CWE-367
- 风险等级: P0
- 触发条件: 攻击者能够写入临时文件所在目录（通常为共享目录如/tmp）。; 攻击者能够预测tempnam生成的临时文件名（由于实现可能基于时间戳等，可预测）。; 攻击者能够在对open()的调用之前迅速替换文件或创建符号链接。
- 触发路径: char * filename; int fileDesc; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_03.c:55-56; filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_03.c:57; printLine(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_03.c:62; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_03.c:63; { printLine("Temporary file was opened...now closing file"); CLOSE(fileDesc); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_03.c:66
- 结论: 函数使用tempnam()生成临时文件名，然后以O_RDWR|O_CREAT模式打开文件，未使用O_EXCL标志，导致存在TOCTOU竞态条件，攻击者可预测文件名并利用时间窗口进行符号链接攻击或文件替换，造成信息泄露或权限提升。
- D验证: confirmed / ver_52afdd1a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 22. hyp_path_bcaf3caf0d89

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_10.c:68
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者具有本地用户权限，能够监控文件系统并创建文件或符号链接。
- 触发路径: filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_10.c:58; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_10.c:63
- 结论: 代码使用tempnam生成临时文件名，随后使用open()以O_RDWR|O_CREAT创建文件，缺少O_EXCL标志，存在TOCTOU竞争条件，攻击者可在文件名生成后、open调用前创建同名的符号链接或文件，导致文件内容被劫持或权限提升。
- D验证: confirmed / ver_9a819788
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 23. hyp_path_3ae361afbb7e

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_14.c:68
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录（如/tmp）; 攻击者具有创建符号链接的权限; 攻击者能够预测tempnam返回的文件名
- 触发路径: filename = TEMPNAM(NULL, NULL); @ CWE377_Insecure_Temporary_File__char_tempnam_14.c:55-59; printLine(filename); @ CWE377_Insecure_Temporary_File__char_tempnam_14.c:62; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ CWE377_Insecure_Temporary_File__char_tempnam_14.c:63-64
- 结论: 使用tempnam生成临时文件名，然后以O_RDWR|O_CREAT打开，未使用O_EXCL，存在TOCTOU竞态条件漏洞，攻击者可预测文件名并创建符号链接，导致任意文件覆盖或信息泄露。
- D验证: confirmed / ver_fda67989
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 24. hyp_path_780ae4c29505

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_16.c:68
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够对文件系统进行写操作（例如创建符号链接），并在 tempnam 和 open 之间的时间窗口内执行操作
- 触发路径: filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_16.c:55-59; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_16.c:62-66
- 结论: 程序使用 tempnam() 生成临时文件名，然后使用 open() 创建文件，但 tempnam 和 open 之间不原子，存在 TOCTOU 竞争条件。攻击者可以通过符号链接攻击导致任意文件写入或信息泄露。
- D验证: confirmed / ver_ec4943dc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 25. hyp_path_01aeb8e7a2ad

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_15.c:69
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能访问临时文件所在的目录（默认为/tmp）; 攻击者能预测tempnam生成的文件名; 攻击者能在时间窗口内创建符号链接
- 触发路径: char * filename; int fileDesc; filename = TEMPNAM(NULL, NULL); if (filename == NULL) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_15.c:56-60; printLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); if (fileDesc != -1) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_15.c:63-67; { printLine("Temporary file was opened...now closing file"); CLOSE(fileDesc); } free(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_15.c:67-71
- 结论: 在临时文件创建过程中存在TOCTOU竞争条件漏洞。使用tempnam生成文件名后，以O_RDWR|O_CREAT且无O_EXCL标志的方式打开文件，攻击者可在文件名生成与文件打开之间的窗口期内用符号链接替换临时文件，导致任意文件写入或覆盖。
- D验证: confirmed / ver_ebdf0ef6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 26. hyp_path_7f59b217068b

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_13.c:68
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够预测tempnam生成的临时文件名（如通过文件系统监控或已知模式）; 攻击者在open调用之前的窗口期内有权限在相同路径创建符号链接
- 触发路径: filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_13.c:57; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_13.c:62-63; CLOSE(fileDesc); free(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_13.c:68-70
- 结论: 程序使用tempnam生成临时文件名，然后以O_RDWR|O_CREAT模式打开，但未指定O_EXCL标志，存在竞态条件漏洞（TOCTOU），攻击者可通过预测文件名创建符号链接导致任意文件覆盖或信息泄露。
- D验证: confirmed / ver_9648c468
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 27. hyp_path_b28a8992ecae

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_18.c:68
- 漏洞类型: CWE-377, CWE-367
- CWE: CWE-377; CWE-367
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在的目录（通常是全局可写的/tmp）。; 攻击者能够预测或发现由tempnam生成的临时文件名。
- 触发路径: filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_18.c:56; printLine(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_18.c:62; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); // 缺少O_EXCL，可被预创建劫持 @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_18.c:63; if (fileDesc != -1) { ... CLOSE(fileDesc); } // 对临时文件进行读写操作 @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_18.c:65
- 结论: 程序使用tempnam生成临时文件名，并以不安全的方式open（缺少O_EXCL），存在TOCTOU竞争条件，攻击者可能预创建恶意文件导致权限提升或数据损坏。
- D验证: confirmed / ver_9940b974
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 28. hyp_path_b1cf70f7e854

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_17.c:59
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录（如 /tmp）并在目标文件创建前创建同名文件或符号链接。
- 触发路径: filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_17.c:46-47; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_17.c:53-55
- 结论: 程序使用 tempnam(NULL, NULL) 生成临时文件名，然后以 O_RDWR|O_CREAT 方式打开文件，但未使用 O_EXCL 标志，导致存在 TOCTOU 竞争条件，攻击者可能通过符号链接攻击或抢先创建文件实现任意文件写或信息泄露。
- D验证: confirmed / ver_37c49d56
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 29. hyp_path_0fdaeab61af4

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_01.c:56
- 漏洞类型: CWE-377, CWE-367
- CWE: CWE-377; CWE-367
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录（通常为系统临时目录），并且能够预测TEMPNAM生成的路径名（例如通过控制环境变量）。; 攻击者能够在文件打开之前创建同名符号链接指向目标文件。
- 触发路径: wchar_t * filename; int fileDesc; filename = TEMPNAM(NULL, NULL); if (filename == NULL) { ... } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_01.c:43-47; printWLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); if (fileDesc != -1) { ... } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_01.c:50-54
- 结论: 使用TEMPNAM生成临时文件名，并使用OPEN创建文件时未指定O_EXCL标志，导致竞态条件（TOCTOU），攻击者可能预测或替换临时文件，从而造成信息泄露或提权。
- D验证: confirmed / ver_9e5dfe9b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 30. hyp_path_6c25062c32d6

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_02.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够预测临时文件名; 攻击者能够在open调用前创建文件/符号链接
- 触发路径: filename = TEMPNAM(NULL, NULL); @ CWE377_Insecure_Temporary_File__wchar_t_tempnam_02.c:48; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ CWE377_Insecure_Temporary_File__wchar_t_tempnam_02.c:52-54
- 结论: 使用tempnam生成临时文件名并用open创建文件，未使用O_EXCL标志，存在竞争条件，攻击者可预测文件名并创建符号链接，导致不安全临时文件漏洞。
- D验证: confirmed / ver_d1b387fc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 31. hyp_path_a69a2ef7a7e8

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_03.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录并创建符号链接; 攻击者可以预测TEMPNAM生成的临时文件名
- 触发路径: wchar_t * filename; int fileDesc; filename = TEMPNAM(NULL, NULL); if (filename == NULL) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_03.c:45-49; printWLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); if (fileDesc != -1) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_03.c:52-56; { printLine("Temporary file was opened...now closing file"); CLOSE(fileDesc); } free(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_03.c:56-60
- 结论: 程序使用不安全的临时文件创建方式，存在竞争条件漏洞。函数TEMPNAM生成可预测的临时文件名，随后使用open()以O_RDWR|O_CREAT标志创建文件，未使用O_EXCL标志，攻击者可通过预测文件名并提前创建符号链接，导致任意文件写入或权限提升。
- D验证: confirmed / ver_e2f3585c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 32. hyp_path_55bd7c4f4e89

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_04.c:64
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问程序运行时的文件系统，并且能够在临时文件创建前创建同名符号链接。
- 触发路径: wchar_t * filename; int fileDesc; filename = TEMPNAM(NULL, NULL); if (filename == NULL) { exit(1); } printWLine(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_04.c:51-55; printWLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); if (fileDesc != -1) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_04.c:58-62
- 结论: 使用tempnam生成临时文件名，然后使用open()以O_RDWR|O_CREAT标志创建文件，存在竞态条件漏洞（TOCTOU），攻击者可以通过预测文件名并创建符号链接或硬链接，导致任意文件写入或覆盖。
- D验证: confirmed / ver_01074bbd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 33. hyp_path_1466359debdd

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_05.c:64
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在的目录（通常为/tmp），并能预测tempnam()的命名模式或通过某种方式提前创建文件。; 攻击者能够在open()调用之前的短暂窗口内完成符号链接创建等操作。
- 触发路径: filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_05.c:53; printWLine(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_05.c:58; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_05.c:61
- 结论: 程序使用tempnam()生成临时文件名，但随后以不安全的标志（O_RDWR|O_CREAT，缺少O_EXCL和O_TRUNC）调用open()创建文件，导致存在TOCTOU竞态条件漏洞。攻击者可以预测临时文件名，在open()之前创建符号链接，从而劫持临时文件，可能导致信息泄露、权限提升或任意文件写入。
- D验证: confirmed / ver_2a43bd0a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 34. hyp_path_e35b01599b1f

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_06.c:63
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够对目标文件系统有写入权限（例如创建符号链接）; 临时文件名可被预测或监控
- 触发路径: filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_06.c:51; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_06.c:57
- 结论: 使用TEMPNAM生成临时文件名，然后以O_RDWR|O_CREAT标志打开，未使用O_EXCL，导致竞态条件（TOCTOU），攻击者可能预测临时文件名并创建符号链接，从而覆盖或读取任意文件。
- D验证: confirmed / ver_9d76bc9c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 35. hyp_path_ab637d6e0a73

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_07.c:63
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够对目标临时目录有写权限; 攻击者能够预测临时文件名或通过竞态窗口操作
- 触发路径: wchar_t * filename; int fileDesc; filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_07.c:50-54; if (filename == NULL) { exit(1); } printWLine(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_07.c:55-59; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_07.c:57-61; CLOSE(fileDesc); free(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_07.c:61-65
- 结论: 程序使用不安全的临时文件创建方式，存在TOCTOU竞态条件漏洞。函数TEMPNAM生成临时文件名后，使用OPEN函数以O_RDWR|O_CREAT标志打开文件，但未使用O_EXCL标志，也未进行原子创建，攻击者可以在文件名生成与打开之间创建符号链接等操作，导致安全风险。
- D验证: confirmed / ver_f9db4c11
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 36. hyp_path_ff50a7853348

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_09.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够在目标系统上执行任意文件操作（如创建符号链接）
- 触发路径: filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_09.c:45; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_09.c:52-53
- 结论: 程序中使用了不安全的临时文件创建方式：先调用tempnam生成临时文件名，再以O_RDWR|O_CREAT（无O_EXCL）打开文件，存在TOCTOU竞态条件漏洞。攻击者可在文件创建前预测文件名并创建恶意文件，导致程序打开攻击者控制的文件，可能被用于权限提升或数据篡改。
- D验证: confirmed / ver_e285fe20
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 37. hyp_path_f8ae6506dcf8

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_10.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录（如/tmp）并监控文件系统事件; 攻击者能够预测由tempnam生成的临时文件名（通常基于进程PID和时间戳，可预测）; 攻击者拥有对临时目录的写权限或可创建符号链接
- 触发路径: filename = TEMPNAM(NULL, NULL); @ CWE377_Insecure_Temporary_File__wchar_t_tempnam_10.c:48; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); // 缺少O_EXCL标志 @ CWE377_Insecure_Temporary_File__wchar_t_tempnam_10.c:53-54
- 结论: 临时文件创建存在竞态条件（TOCTOU）漏洞，攻击者可能通过预测临时文件名并在文件创建前替换为符号链接或恶意文件，导致权限提升或信息泄露。
- D验证: confirmed / ver_72d7bfdc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 38. hyp_path_a8c5603446c2

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_13.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在目录，并具备创建符号链接或重命名文件的权限；攻击者能够预判或监听TEMPNAM生成的随机文件名，并在竞态窗口内完成攻击。
- 触发路径: wchar_t * filename; int fileDesc; filename = TEMPNAM(NULL, NULL); if (filename == NULL) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_13.c:45-49; printWLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_13.c:52-56
- 结论: 程序使用不安全的临时文件创建方式：先使用TEMPNAM生成文件名，再使用OPEN打开文件，两者之间存在竞态条件，攻击者可能通过替换文件或创建符号链接导致意外文件打开或覆盖，符合CWE-377。
- D验证: confirmed / ver_ae9d2bfc
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 39. hyp_path_885bf655667a

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_14.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在的目录; 攻击者能够预测或监听临时文件名（例如通过多次观察或利用tempnam的随机性弱点）; 攻击者具有在目标目录下创建符号链接的权限
- 触发路径: wchar_t * filename; int fileDesc; filename = TEMPNAM(NULL, NULL); if (filename == NULL) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_14.c:45-49; printWLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); if (fileDesc != -1) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_14.c:52-56; CLOSE(fileDesc); } free(filename); } } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_14.c:58-62
- 结论: 程序使用不安全的临时文件创建方式，存在竞态条件漏洞。函数tempnam生成临时文件名后，open函数未使用O_EXCL和O_CREAT组合，攻击者可以通过预测文件名并进行符号链接攻击，导致覆盖或读取任意文件。
- D验证: confirmed / ver_a9df273d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 40. hyp_path_f810cc6164c3

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_15.c:59
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问系统临时文件目录（如/tmp）并具有文件创建权限。; 攻击者能够预测或监测TEMPNAM生成的临时文件名。
- 触发路径: filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_15.c:46-48; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_15.c:53-55
- 结论: 程序使用不安全的临时文件创建方式，存在TOCTOU竞态条件，攻击者可能通过预测或替换临时文件导致权限提升或数据损坏。
- D验证: confirmed / ver_63d06753
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 41. hyp_path_24160c1096cc

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_16.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够与受害者同时访问共享临时目录（如/tmp或/temp），并能够预测或枚举临时文件名
- 触发路径: wchar_t * filename; int fileDesc; filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_16.c:45-47; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_16.c:50-54
- 结论: 使用不安全的临时文件创建方法，存在TOCTOU竞态条件漏洞。攻击者可预测临时文件名并在open()调用前创建符号链接，导致以提升权限写入或读取任意文件。
- D验证: confirmed / ver_71bfc08f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 42. hyp_path_20dd3e430e49

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_18.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时目录（如/tmp）并能创建符号链接。
- 触发路径: filename = TEMPNAM(NULL, NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_18.c:47; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_18.c:53
- 结论: 代码使用TEMPNAM生成临时文件名，然后使用OPEN以O_RDWR|O_CREAT标志打开，存在TOCTOU竞态条件漏洞，攻击者可以在文件名生成后、文件打开前替换为符号链接，导致不安全临时文件创建。
- D验证: confirmed / ver_922b911b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 43. hyp_path_510670e672d8

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_17.c:69
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够与目标程序并行运行，具有对/tmp目录的读写权限，并能推测或监控tmpnam生成的临时文件名。
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_17.c:58; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_17.c:69
- 结论: 使用tmpnam生成临时文件名，然后以O_CREAT标志打开文件但未使用O_EXCL标志，导致存在TOCTOU竞争条件，攻击者可利用此漏洞创建或覆盖预期外的文件，属于不安全临时文件漏洞。
- D验证: confirmed / ver_4cfb45c7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 44. hyp_path_9ff5aeb9f0e9

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_17.c:70
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问程序运行的临时文件目录。; 攻击者能够预测或获取mktemp生成的文件名（例如通过/proc或名称模式）。; 攻击者能够在open()调用之前的竞态窗口内执行文件操作（如创建符号链接）。
- 触发路径: char tmpl[] = "fnXXXXXX"; filename = MKTEMP(tmpl); @ 第57-61行; printLine(filename); @ 第64行; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ 第65行
- 结论: 代码使用mktemp生成临时文件名，然后使用open()以O_RDWR|O_CREAT标志创建文件，未指定O_EXCL标志，导致竞态条件漏洞（TOCTOU）。攻击者可预测临时文件名并在open()调用前创建符号链接，从而操纵或读取临时文件内容。
- D验证: confirmed / ver_227967b9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 45. hyp_path_abca85f8ccf1

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_17.c:55
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问当前目录，并能够预测GetTempFileNameA生成的文件名（由于uUnique=0），且在文件创建后、打开前的时间窗口内具有写入权限。
- 触发路径: if (GetTempFileNameA(".", "case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_17.c:43; printLine(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_17.c:49; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_17.c:50
- 结论: 存在不安全的临时文件创建漏洞，攻击者可能利用竞争条件在临时文件创建后、打开前替换文件，导致权限提升或信息泄露。
- D验证: confirmed / ver_28165326
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 46. hyp_path_d365ea39bbf9

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_08.c:67
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够预测临时文件名（由于uUnique=0，文件名基于系统时间或计数器，但易被预测）; 攻击者能够在GetTempFileNameA返回后、open调用前在临时目录创建同名符号链接
- 触发路径: if (GetTempFileNameA(".", "case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_08.c:55-58; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); if (fileDesc != -1) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_08.c:61-67
- 结论: 使用GetTempFileNameA(uUnique=0)创建临时文件后立即关闭，随后以O_RDWR|O_CREAT打开，未使用O_EXCL或安全创建方式，导致竞态条件，攻击者可预测文件名并创建符号链接，导致任意文件写入或信息泄露。
- D验证: confirmed / ver_8222c90c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 47. hyp_path_009556da1422

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_11.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在的目录，并且能够在文件创建后、打开前进行替换操作
- 触发路径: if (GetTempFileNameA(".", "case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_11.c:42-46; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); if (fileDesc != -1) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_11.c:48-52
- 结论: 存在不安全的临时文件创建漏洞，GetTempFileNameA 使用 uUnique=0 导致先创建并关闭文件，然后使用 open 重新打开，期间存在 TOCTOU 竞态条件，攻击者可以替换文件进行符号链接攻击。
- D验证: confirmed / ver_68c84004
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 48. hyp_path_781281c08313

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_01.c:52
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录，并具有创建文件或符号链接的权限
- 触发路径: if (GetTempFileNameA(".", "case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_01.c:40; printLine(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_01.c:46; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_01.c:47
- 结论: 使用GetTempFileNameA创建临时文件时，uUnique参数为0导致文件被创建并立即关闭，随后使用open()打开文件且未采取防止竞态条件的措施（如O_EXCL），攻击者可在文件创建后、打开前替换文件，造成权限提升或数据篡改。
- D验证: confirmed / ver_db503a95
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 49. hyp_path_c18f726872cc

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_02.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够对临时文件所在目录具有写权限或控制符号链接创建。; 攻击者能够预测或观察到临时文件名（GetTempFileNameA生成的文件名容易猜测）。
- 触发路径: if (GetTempFileNameA(".", "case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_02.c:42-46; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_02.c:48-52
- 结论: 程序使用GetTempFileNameA创建临时文件时传入uUnique=0，该函数创建文件后立即关闭，导致后续使用open重新打开时存在竞态条件（TOCTOU），攻击者可能替换临时文件，造成不安全临时文件漏洞。
- D验证: confirmed / ver_8ed77431
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 50. hyp_path_435cc833fa32

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_03.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问同一目录并具有创建符号链接的权限; 攻击者能够在GetTempFileNameA返回后、open()执行前的时间窗口内进行符号链接替换
- 触发路径: if (GetTempFileNameA(".", "case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_03.c:42-46; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_03.c:48-52
- 结论: 使用GetTempFileNameA创建临时文件时，uUnique参数为0导致文件被创建后立即关闭，随后使用open()以O_CREAT标志重新打开，未使用O_EXCL，存在TOCTOU竞态条件，攻击者可在文件创建后打开前替换文件为符号链接，导致权限提升或数据泄露。
- D验证: confirmed / ver_435c2c84
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 51. hyp_path_83a95fbc8437

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_04.c:60
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在的目录（当前目录'.'），并能预测文件名（由GetTempFileNameA生成的格式为'case0XXXX'，其中XXXX为随机数字）。; 攻击者能够在GetTempFileNameA创建文件之后、open()打开文件之前的极短时间窗口内，删除或替换该文件（例如创建符号链接指向目标文件）。
- 触发路径: if (GetTempFileNameA(".", "case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_04.c:48-52; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_04.c:54-58
- 结论: 使用GetTempFileNameA时传入uUnique=0，导致先创建并关闭临时文件，随后再次打开同一文件，存在TOCTOU竞争条件，可能被攻击者利用创建符号链接等导致文件内容被篡改或敏感信息泄露。
- D验证: confirmed / ver_206f6f01
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 52. hyp_path_0523d8dd757e

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_05.c:60
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者具有对临时文件所在目录的写入权限（当前工作目录）
- 触发路径: if (GetTempFileNameA(".", "case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_05.c:48-52; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_05.c:54-58
- 结论: 存在不安全的临时文件漏洞，攻击者可能利用竞态条件替换临时文件，导致权限提升或信息泄露。
- D验证: confirmed / ver_81342693
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 53. hyp_path_f1a2c5c27aa5

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_06.c:59
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录（当前目录）; 攻击者能够与目标程序同时运行以竞态操作文件
- 触发路径: if (GetTempFileNameA(".", "case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_06.c:47-50; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_06.c:55-57
- 结论: 代码使用GetTempFileNameA时传入uUnique=0，导致函数创建并关闭临时文件，随后程序再次打开该文件，存在TOCTOU竞态条件漏洞。攻击者可在文件创建后、程序打开前替换为恶意文件，造成信息泄露或权限提升。
- D验证: confirmed / ver_28e5e2cd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 54. hyp_path_d1472014641d

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_07.c:59
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者与目标程序在同一系统上运行; 攻击者能够监控文件系统事件并快速创建文件
- 触发路径: if (GetTempFileNameA(".", "case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_07.c:47-50; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_07.c:53-57
- 结论: 程序使用GetTempFileNameA创建临时文件时，将uUnique参数设为0，导致函数创建文件后立即关闭，产生竞态条件。随后使用open()以O_RDWR|O_CREAT标志打开文件，但未指定O_EXCL，攻击者可在文件创建与打开之间创建同名文件，从而使程序打开恶意文件或覆盖敏感数据。
- D验证: confirmed / ver_f7dac367
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 55. hyp_path_faea17a4646c

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_10.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者与程序在同一系统上，可以观察文件系统事件或预测临时文件名（GetTempFileNameA生成的名称符合模式，可预测）。
- 触发路径: if (GetTempFileNameA(".", "case0", 0, filename) == 0) { exit(1); } printLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_10.c:46-50; if (fileDesc != -1) { printLine("Temporary file was opened...now closing file"); CLOSE(fileDesc); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_10.c:52-56
- 结论: 程序使用GetTempFileNameA创建临时文件时，将uUnique参数设置为0，导致函数在创建文件后立即关闭，随后程序再次使用open()以O_CREAT标志打开同一文件，这引入了竞态条件（TOCTOU），攻击者可能在文件创建后、打开前替换文件内容或链接，导致安全风险。
- D验证: confirmed / ver_990d14b7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 56. hyp_path_5c13e1fbb1b9

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_09.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够对临时文件所在目录进行写入操作（例如通过其他用户账户或进程），并能够预测文件名或监听文件系统事件。
- 触发路径: if (GetTempFileNameA(".", "case0", 0, filename) == 0) { exit(1); } @ CWE377_Insecure_Temporary_File__char_w32GetTempFileName_09.c:42; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ CWE377_Insecure_Temporary_File__char_w32GetTempFileName_09.c:48; if (fileDesc != -1) { printLine("Temporary file was opened...now closing file"); CLOSE(fileDesc); } @ CWE377_Insecure_Temporary_File__char_w32GetTempFileName_09.c:52
- 结论: 使用GetTempFileNameA创建临时文件时uUnique参数为0，导致文件创建后立即关闭，随后又以不安全的方式重新打开，存在TOCTOU竞争条件，攻击者可在文件创建后、重新打开前替换文件，导致不安全的临时文件漏洞。
- D验证: confirmed / ver_9f858013
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 57. hyp_path_b0c6b4fd2fce

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_13.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在目录（当前目录），并具有创建文件或符号链接的权限。
- 触发路径: if (GetTempFileNameA(".", "case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_13.c:42-46; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_13.c:48-52
- 结论: 使用GetTempFileNameA创建临时文件时，将uUnique参数设为0，导致函数创建并关闭文件，随后重新打开文件时存在TOCTOU竞争条件，攻击者可在文件创建后替换或修改文件内容，导致信息泄露或权限提升。
- D验证: confirmed / ver_3a481c6b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 58. hyp_path_5b556037043f

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_14.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在的目录，并在竞态窗口内替换文件。
- 触发路径: if (GetTempFileNameA(".", "case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_14.c:42-46; printLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_14.c:48-52
- 结论: 使用GetTempFileNameA创建临时文件时uUnique参数设为0，导致函数内部创建并关闭文件，后续使用open()以O_RDWR|O_CREAT重新打开，未使用O_EXCL标志，存在TOCTOU竞态条件，攻击者可能替换临时文件导致安全风险。
- D验证: confirmed / ver_3c0fec94
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 59. hyp_path_8d45ed5948fb

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_16.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在目录（当前工作目录），并能够在竞态窗口内创建符号链接或替换文件。
- 触发路径: if (GetTempFileNameA(".", "case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_16.c:42-46; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_16.c:48-50
- 结论: 程序使用GetTempFileNameA创建临时文件，但传入uUnique=0导致函数创建并立即关闭文件，随后使用open()以O_CREAT打开，未使用O_EXCL标志，存在竞态条件和符号链接攻击，可被攻击者利用以创建或覆盖任意文件。
- D验证: confirmed / ver_bada9337
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 60. hyp_path_f83d28b34b74

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_15.c:55
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问当前工作目录（"."）。; 攻击者能够预测临时文件名或利用竞争窗口。
- 触发路径: if (GetTempFileNameA(".", "case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_15.c:43; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_15.c:50
- 结论: 程序使用不安全的临时文件创建方式，存在TOCTOU竞争条件漏洞。GetTempFileNameA创建临时文件后立即关闭，然后使用OPEN重新打开，攻击者可在窗口期间替换文件，导致权限提升或文件内容被篡改。
- D验证: confirmed / ver_dfd96b19
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 61. hyp_path_969d6adea11f

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_18.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够在应用程序当前工作目录下创建文件或符号链接，并在GetTempFileNameA执行后、open执行前完成替换动作
- 触发路径: if (GetTempFileNameA(".", "case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_18.c:42-46; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_18.c:48-52
- 结论: 存在不安全的临时文件创建漏洞，使用GetTempFileNameA时传入uUnique=0，导致文件创建后立即关闭，后续open调用存在TOCTOU竞争条件，攻击者可能替换临时文件为恶意文件。
- D验证: confirmed / ver_fc49ddc2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 62. hyp_path_26eae56b6d71

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_08.c:82
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问目标文件系统，并能预测或观测mktemp生成的临时文件名。
- 触发路径: char tmpl[] = "fnXXXXXX"; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_08.c:69-71; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_08.c:76-80
- 结论: 代码使用mktemp()生成临时文件名并随后以O_RDWR|O_CREAT打开，未使用O_EXCL，存在TOCTOU竞争条件漏洞，可导致攻击者预测或替换临时文件，造成信息泄露或权限提升。
- D验证: confirmed / ver_ffbff11d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 63. hyp_path_0b5d79060cd0

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_08.c:81
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能通过网络或本地访问预测文件路径，并在文件创建前执行文件创建操作
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_08.c:69; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_08.c:77
- 结论: 函数使用 tmpnam() 生成临时文件名，然后以 O_RDWR|O_CREAT 打开，未使用 O_EXCL 或安全替代方案，导致 TOCTOU 竞态条件漏洞，攻击者可预测文件名并在 open 前创建恶意文件，造成信息泄露或权限提升。
- D验证: confirmed / ver_d0d8221d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 64. hyp_path_d9e02486709d

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_11.c:69
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录并具有创建符号链接的权限
- 触发路径: filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_11.c:59; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_11.c:64-65
- 结论: 使用mktemp生成临时文件名，然后使用open()以O_RDWR|O_CREAT创建文件，存在TOCTOU竞争条件漏洞，攻击者可能预测文件名并创建符号链接，导致覆盖或访问任意文件。
- D验证: confirmed / ver_6ac870ff
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 65. hyp_path_4d9798a1f807

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_11.c:68
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录并有权限创建符号链接
- 触发路径: filename = TMPNAM(NULL); @ line 55-59; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ line 62-66
- 结论: 使用不安全的临时文件函数tmpnam()，没有使用O_EXCL标志，可能导致竞争条件，攻击者可预测文件名并创建符号链接攻击。
- D验证: confirmed / ver_5b5df820
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 66. hyp_path_5f4488114422

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_01.c:67
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者具有文件系统访问权限，能够监控或预测临时文件名，并在竞态窗口内创建恶意文件或符号链接
- 触发路径: char tmpl[] = "fnXXXXXX"; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_01.c:54-56; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_01.c:61-63
- 结论: 代码使用mktemp生成临时文件名，然后调用open()创建文件时未使用O_EXCL标志，导致存在TOCTOU竞态条件，攻击者可在文件名创建和打开之间替换文件，造成信息泄露或权限提升。
- D验证: confirmed / ver_0212bdce
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 67. hyp_path_e9ee651d7b89

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_02.c:69
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够枚举或预测临时文件名; 攻击者在open调用前创建同名符号链接
- 触发路径: char tmpl[] = "fnXXXXXX"; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_02.c:56; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_02.c:58; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_02.c:69
- 结论: 使用mktemp生成临时文件名，然后以O_RDWR|O_CREAT打开文件，未使用O_EXCL标志，导致存在TOCTOU竞争条件，攻击者可能预测文件名并创建符号链接，造成敏感信息泄露或任意文件写入。
- D验证: confirmed / ver_5d3736c2
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 68. hyp_path_647fdf6265f0

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_03.c:69
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录，并可预测或观察到文件创建时间，在竞争窗口内替换文件。
- 触发路径: char tmpl[] = "fnXXXXXX"; int fileDesc; filename = MKTEMP(tmpl); if (filename == NULL) { ... } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_03.c:56-60; printLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); if (fileDesc != -1) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_03.c:63-67
- 结论: 使用mktemp创建临时文件后，在open调用之前存在TOCTOU竞争条件，攻击者可能替换临时文件，导致安全漏洞。
- D验证: confirmed / ver_8c865f97
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 69. hyp_path_adacb85c296d

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_05.c:75
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够按路径写入或创建符号链接、文件
- 触发路径: char tmpl[] = "fnXXXXXX"; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_05.c:62-63; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_05.c:73-74
- 结论: 使用 mktemp 生成临时文件名后，通过 open() 以 O_CREAT 标志创建文件，但未使用 O_EXCL，存在 TOCTOU 竞态条件，攻击者可能利用符号链接替换临时文件或创建已存在文件，导致信息泄露或权限提升。
- D验证: confirmed / ver_cd180fc1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 70. hyp_path_9d79c5a5ce95

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_04.c:75
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够与目标程序运行在同一系统上，并拥有写入临时文件目录的权限。
- 触发路径: char tmpl[] = "fnXXXXXX"; filename = MKTEMP(tmpl); if (filename == NULL) { @ line 62-66; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ line 69-73; printLine("Temporary file was opened...now closing file"); CLOSE(fileDesc);} @ line 73-77
- 结论: 代码使用mktemp生成临时文件名，随后使用open()创建文件，存在TOCTOU竞争条件。攻击者可能在mktemp返回文件名和open创建文件之间替换文件为符号链接，导致安全风险。
- D验证: confirmed / ver_dcd2f5b4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 71. hyp_path_583d9f1da811

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_06.c:74
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够对目标文件系统有写入和符号链接创建权限; 攻击者能够触发该代码路径（如通过某种方式调用该函数）
- 触发路径: char tmpl[] = "fnXXXXXX"; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_06.c:63-64; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_06.c:69-70
- 结论: 使用mktemp生成临时文件名后调用open()创建文件，存在TOCTOU竞争条件，可能导致攻击者利用符号链接攻击，属于不安全的临时文件处理漏洞。
- D验证: confirmed / ver_dd8086dd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 72. hyp_path_3e6aef06ca9b

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_07.c:74
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在目录并创建文件或符号链接。; 攻击者能够预测或观察到文件名时隙。
- 触发路径: char tmpl[] = "fnXXXXXX"; int fileDesc; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_07.c:61-64; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_07.c:68-72
- 结论: 程序使用mktemp生成临时文件名，随后使用open()创建文件，但未指定O_EXCL标志，导致存在TOCTOU竞态条件，可能被攻击者利用进行文件劫持或符号链接攻击。
- D验证: confirmed / ver_923b7b11
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 73. hyp_path_07aad2660562

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_09.c:69
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够对临时文件所在目录有写入权限，并能执行符号链接攻击
- 触发路径: char tmpl[] = "fnXXXXXX";\nfilename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_09.c:56-57; printLine(filename);\nfileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_09.c:63-64; printLine("Temporary file was opened...now closing file");\nCLOSE(fileDesc); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_09.c:68-70
- 结论: 存在不安全临时文件漏洞（条件竞争）。程序使用mktemp生成临时文件名，然后使用open()并设置O_CREAT和O_RDWR标志，但没有使用O_EXCL或O_NOFOLLOW等防止条件竞争的标志。攻击者可以在mktemp返回文件名后、open创建文件前，通过符号链接劫持文件，导致任意文件写入或信息泄露。
- D验证: confirmed / ver_910c1432
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 74. hyp_path_93b970c5e515

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_10.c:69
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够写入临时文件目录; 攻击者能够预测mktemp输出的文件名
- 触发路径: char tmpl[] = "fnXXXXXX"; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_10.c:57; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_10.c:63
- 结论: 使用mktemp创建临时文件，然后用open()打开，但未使用O_EXCL标志，导致存在TOCTOU竞态条件，攻击者可能通过符号链接攻击替换临时文件，造成信息泄露或任意文件写入。
- D验证: confirmed / ver_cd80a93a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 75. hyp_path_62db92f25c89

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_13.c:69
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够与目标程序在同一系统上运行，并有权限在临时目录创建符号链接。
- 触发路径: filename = MKTEMP(tmpl); @ L59; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ L63-64
- 结论: 代码使用mktemp生成临时文件名，然后使用open()并指定O_RDWR|O_CREAT，但未使用O_EXCL标志，存在竞态条件（TOCTOU），攻击者可能创建符号链接指向其他文件，导致不安全临时文件漏洞。
- D验证: confirmed / ver_4e673c6c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 76. hyp_path_d4876f9bc82f

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_14.c:69
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问本地文件系统并具有创建符号链接的权限
- 触发路径: char tmpl[] = "fnXXXXXX"; int fileDesc; filename = MKTEMP(tmpl); if (filename == NULL) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_14.c:56-60; printLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); if (fileDesc != -1) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_14.c:63-67
- 结论: 使用mktemp生成临时文件名后，以O_RDWR|O_CREAT标志打开文件，未使用O_EXCL标志，存在TOCTOU竞态条件，攻击者可能预测文件名并在时间窗口内创建符号链接，导致权限提升或文件内容覆盖。
- D验证: confirmed / ver_6c6f1295
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 77. hyp_path_1a98a483ed9e

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_15.c:70
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录（通常是/tmp或当前目录）; 攻击者能够在目标文件名上执行文件操作（符号链接、创建等）
- 触发路径: char tmpl[] = "fnXXXXXX"; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_15.c:57-61; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_15.c:64-68
- 结论: 代码使用mktemp生成临时文件名，然后调用open()并使用O_CREAT标志，但没有使用O_EXCL标志，导致存在TOCTOU竞态条件漏洞。攻击者可以在文件名预测后、文件打开前创建符号链接或文件，从而可能导致权限提升或文件内容被篡改。
- D验证: confirmed / ver_c608bffb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 78. hyp_path_7b68a10e5a98

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_16.c:69
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者具有对临时文件目录的写权限或能够创建符号链接; 攻击者能够侦测文件名生成时机（如通过文件系统事件或竞争）
- 触发路径: char tmpl[] = "fnXXXXXX"; int fileDesc; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_16.c:56; printLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_16.c:63-64
- 结论: 使用mktemp生成临时文件名后，以O_RDWR|O_CREAT标志打开文件，未使用O_EXCL防止竞态条件，可能导致攻击者在创建文件前替换为符号链接等，造成安全漏洞。
- D验证: confirmed / ver_ba4f79f7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 79. hyp_path_d72bb14bdf1a

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_18.c:69
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够对目标临时文件目录（如/tmp）具有写入权限; 攻击者能够预测或观察到生成的临时文件名
- 触发路径: char tmpl[] = "fnXXXXXX"; int fileDesc; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_18.c:56-58; printLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_18.c:63-64
- 结论: 使用mktemp生成临时文件名后，调用open()以O_RDWR|O_CREAT标志创建文件，未指定O_EXCL，导致竞态条件：攻击者可在mktemp和open之间创建同名文件或符号链接，从而覆盖文件或劫持文件描述符。
- D验证: confirmed / ver_1bf49d1b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 80. hyp_path_af293b38e6f6

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_01.c:66
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者具有本地用户权限，能够在目标文件系统上创建文件/符号链接。; 攻击者能够获取或预测tmpnam()输出的文件名。
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_01.c:54-56; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_01.c:60-63
- 结论: 使用tmpnam()生成临时文件名，随后以O_CREAT打开文件，存在TOCTOU竞争条件漏洞，攻击者可能在文件名生成后、文件打开前创建同名文件或符号链接，导致数据泄露或权限提升。
- D验证: confirmed / ver_249472be
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 81. hyp_path_e7e2e9affca4

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_02.c:68
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问文件系统并预测tmpnam产生的文件名; 攻击者能够在open调用前对目标路径进行操作
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_02.c:58; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_02.c:68
- 结论: 使用tmpnam生成临时文件名，然后以O_RDWR|O_CREAT打开文件，存在竞争条件漏洞，攻击者可预测文件名并创建符号链接，导致任意文件写入或覆盖。
- D验证: confirmed / ver_dbca6bcb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 82. hyp_path_1549b7908e3c

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_03.c:68
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问文件系统并创建符号链接; 攻击者能够观察到打印输出的临时文件名（通过printLine）
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_03.c:58; printLine(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_03.c:62; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_03.c:63
- 结论: 使用 tmpnam() 生成临时文件名，然后以 O_RDWR|O_CREAT 打开，没有使用 O_EXCL 标志，存在 TOCTOU 竞争条件漏洞，攻击者可能通过预测文件名并创建符号链接指向其他文件，导致安全风险。
- D验证: confirmed / ver_f93f447a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 83. hyp_path_cb030c11d895

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_04.c:74
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问运行程序的系统的文件系统，并且在临时目录具有写权限。; 攻击者能够预测tmpnam()生成的临时文件名。
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_04.c:63; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_04.c:70
- 结论: 程序使用tmpnam()生成临时文件名，然后调用open()使用O_RDWR|O_CREAT标志创建文件，但没有使用O_EXCL标志，导致存在TOCTOU竞态条件漏洞。攻击者可以预测文件名并在open()调用前创建符号链接，从而打开或覆盖任意文件。
- D验证: confirmed / ver_80b7470f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 84. hyp_path_c802a4c09453

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_06.c:73
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够预测或捕获tmpnam()生成的文件名; 攻击者能够在open()调用之前在目标目录下创建文件（例如符号链接）
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_06.c:63; printLine(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_06.c:67; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_06.c:68
- 结论: 使用tmpnam()生成临时文件名，然后使用open()并带有O_RDWR|O_CREAT标志打开文件，但没有指定O_EXCL，也没有进行原子创建，导致存在TOCTOU竞态条件，攻击者可以预测或提前创建该临时文件，造成符号链接攻击或文件内容篡改。
- D验证: confirmed / ver_372dd6da
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 85. hyp_path_af185014b8d4

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_05.c:74
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够在 tmpnam() 返回文件名之后、open() 调用之前的时间窗口内，以相同文件名创建符号链接指向目标文件。
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_05.c:63; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_05.c:71
- 结论: 使用 tmpnam() 生成临时文件名后，以 O_RDWR|O_CREAT 标志调用 open() 创建文件，存在 TOCTOU 竞争条件漏洞。攻击者可预测或抢先创建符号链接，导致任意文件写入或信息泄露。
- D验证: confirmed / ver_b8765007
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 86. hyp_path_a1baec0df9fc

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_07.c:73
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问运行该程序的系统，并且能够监控或预测tmpnam()生成的临时文件名。; 攻击者能够在同一目录下创建符号链接。
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_07.c:62; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_07.c:68-69
- 结论: 使用tmpnam()生成可预测的临时文件名，然后以不安全的方式打开文件，存在TOCTOU竞态条件漏洞，攻击者可能通过预先创建符号链接导致任意文件写入或覆盖。
- D验证: confirmed / ver_1e4d5d49
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 87. hyp_path_f2463cf2d8a8

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_09.c:68
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够预测临时文件名（tmpnam生成可预测的文件名）; 攻击者能够在文件名生成后、文件打开前的窗口期内创建符号链接或文件
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_09.c:57; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_09.c:65
- 结论: 使用tmpnam生成临时文件名，然后使用open()创建文件，未使用O_EXCL标志，存在竞态条件，可能导致攻击者创建符号链接或覆盖文件。
- D验证: confirmed / ver_5c5b6479
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 88. hyp_path_3d2fa67d532d

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_14.c:68
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问程序运行的临时目录; 攻击者能够预测tmpnam()生成的临时文件名
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_14.c:55-59; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_14.c:62-66
- 结论: 使用tmpnam()生成临时文件名，然后以O_RDWR|O_CREAT打开文件，未使用O_EXCL标志，存在竞态条件漏洞，攻击者可预测文件名并创建符号链接，导致任意文件写入或信息泄露。
- D验证: confirmed / ver_a2258458
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 89. hyp_path_6ccb751804b3

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_15.c:69
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问目标目录并创建符号链接; 攻击者能够预测临时文件名或通过竞态窗口操作
- 触发路径: filename = TMPNAM(NULL); @ 56-60; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ 63-67
- 结论: 使用tmpnam()生成临时文件名，并通过open() O_RDWR|O_CREAT创建文件，未使用O_EXCL标志，存在TOCTOU竞态条件，攻击者可能创建符号链接覆盖任意文件。
- D验证: confirmed / ver_8a0422ae
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 90. hyp_path_d3f449d7f825

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_10.c:68
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够与目标程序在同一文件系统上操作；攻击者能够预测tmpnam()的输出或具有文件名猜测能力；攻击者能够在文件名生成后、open()前创建符号链接。
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_10.c:55-58; printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_10.c:62-63
- 结论: 使用不安全的临时文件创建方式，存在竞态条件漏洞：tmpnam()生成可预测文件名，且open()使用O_RDWR|O_CREAT标志未防止竞态，攻击者可预测文件名并在open()前创建符号链接，导致授权或数据篡改。
- D验证: confirmed / ver_5dfcc8bb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 91. hyp_path_aa84de1691fb

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_13.c:68
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者具有本地用户权限，能够对临时目录进行读写操作；; 攻击者能够预测或观察到临时文件名；; 攻击者能够在竞争窗口内执行文件系统操作。
- 触发路径: filename = TMPNAM(NULL); @ 55-59; printLine(filename); @ 62-64; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ 64-67
- 结论: 不安全的临时文件创建：使用tmpnam()生成临时文件名，然后使用open()带O_RDWR|O_CREAT标志创建文件，未指定O_EXCL标志，存在TOCTOU竞争条件。攻击者可在文件名生成与文件打开之间创建符号链接，导致任意文件覆盖或信息泄露。
- D验证: confirmed / ver_a545430e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 92. hyp_path_a6bffe9ad2b5

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_16.c:68
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者具有对临时文件目录的写入权限（如/tmp），并能预测或影响tmpnam()生成的名称。
- 触发路径: filename = TMPNAM(NULL); @ CWE377_Insecure_Temporary_File__char_tmpnam_16.c:55-59; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ CWE377_Insecure_Temporary_File__char_tmpnam_16.c:62-66
- 结论: 使用tmpnam()生成临时文件名，随后使用open()创建文件，但未使用O_EXCL标志，存在TOCTOU竞争条件漏洞，攻击者可能通过预创建符号链接覆盖或访问敏感文件。
- D验证: confirmed / ver_b8f6493b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 93. hyp_path_7fe8682811cc

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_17.c:60
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在目录，并能够在mktemp调用后、open调用前创建符号链接。
- 触发路径: wchar_t tmpl[] = L"fnXXXXXX"; int fileDesc; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_17.c:48-50; printWLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_17.c:54-56
- 结论: 使用mktemp生成临时文件名，然后以O_RDWR|O_CREAT标志打开文件，未使用O_EXCL标志，存在TOCTOU竞争条件漏洞，可能导致攻击者预测文件名并创建符号链接，从而获得未授权访问或覆盖文件。
- D验证: confirmed / ver_7de9b6ec
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 94. hyp_path_f263fcdd67ce

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_18.c:68
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录; 攻击者能够预测tmpnam返回的文件名; 攻击者能在open之前执行文件操作
- 触发路径: char * filename; int fileDesc; filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_18.c:55-59; exit(1); } printLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_18.c:60-64
- 结论: 使用tmpnam生成临时文件名，然后以不安全的方式打开，存在TOCTOU竞态条件漏洞，攻击者可预测文件名并创建符号链接，导致敏感文件被覆写或访问。
- D验证: confirmed / ver_192e8f94
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 95. hyp_path_0fe35016f92b

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_17.c:59
- 漏洞类型: CWE-377, CWE-367
- CWE: CWE-377; CWE-367
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录，并具备预测或获取 tmpnam 输出的能力。
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_17.c:46-48; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_17.c:53-55
- 结论: 使用 tmpnam 生成临时文件名，并以 O_RDWR|O_CREAT 标志打开文件，未使用 O_EXCL 标志，存在竞态条件漏洞（TOCTOU），攻击者可预测文件名并创建符号链接，导致不安全临时文件。
- D验证: confirmed / ver_ceece383
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 96. hyp_path_a510a085c319

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_17.c:55
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者具有对当前目录的写权限; 攻击者能够预测或实时观察临时文件名
- 触发路径: if (GetTempFileNameW(L".", L"case0", 0, filename) == 0) { exit(1); } @ 43-47; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ 49-51
- 结论: 程序使用GetTempFileNameW创建临时文件时，将uUnique参数设为0，导致文件名可预测且文件立即关闭，随后使用open()以O_RDWR|O_CREAT打开同一文件，未使用O_EXCL标志，存在竞态条件漏洞。攻击者可在文件创建后、打开前替换文件，导致权限提升或信息泄露。
- D验证: confirmed / ver_9a07d2bb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 97. hyp_path_4316d7213271

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_08.c:67
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在目录（当前目录）; 攻击者能够执行符号链接操作
- 触发路径: if (GetTempFileNameW(L".", L"case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_08.c:55; printWLine(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_08.c:61; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_08.c:63
- 结论: 程序使用GetTempFileNameW创建临时文件后立即以不安全的方式重新打开，存在竞争条件漏洞，攻击者可能通过符号链接攻击导致文件内容被篡改或访问任意文件。
- D验证: confirmed / ver_35803b77
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 98. hyp_path_0575faa0e966

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_11.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问当前目录并具有写入权限或创建符号链接的能力，能够在GetTempFileNameW返回后、open()调用前的时间窗口内执行文件操作。
- 触发路径: if (GetTempFileNameW(L".", L"case0", 0, filename) == 0) { exit(1); } @ 42-46; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ 48-52
- 结论: 使用GetTempFileNameW创建临时文件时，uUnique参数设为0，导致文件被创建并立即关闭，随后使用open()打开，存在TOCTOU竞争条件，攻击者可在窗口期间替换文件，导致不安全临时文件漏洞。
- D验证: confirmed / ver_4dce1fce
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 99. hyp_path_1f0a5b499b28

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_01.c:52
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在目录，并在GetTempFileNameW返回后、OPEN调用前替换该文件。
- 触发路径: if (GetTempFileNameW(L".", L"case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_01.c:40-43; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_01.c:46-48
- 结论: 程序使用GetTempFileNameW创建临时文件时指定uUnique为0，导致函数创建并立即关闭文件，随后使用OPEN以O_RDWR|O_CREAT打开同一文件，中间存在时间窗口，攻击者可以替换文件或修改文件内容，引发TOCTOU竞态条件，导致不安全临时文件漏洞。
- D验证: confirmed / ver_62f61f1d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 100. hyp_path_1cedf859cf03

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_02.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者具有对临时文件目录的写入权限（通常是本地用户）。
- 触发路径: if (GetTempFileNameW(L".", L"case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_02.c:42-46; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_02.c:48-52
- 结论: 程序使用GetTempFileNameW创建临时文件时，uUnique参数为0，导致系统自动创建并关闭文件，随后使用open()以O_CREAT|O_RDWR打开同一文件，未使用O_EXCL标志，存在TOCTOU竞态条件，攻击者可替换临时文件，导致信息泄露或任意文件写入。
- D验证: confirmed / ver_de9894a3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 101. hyp_path_346609383a92

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_04.c:60
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在的目录（当前目录'.'）; 攻击者能够在GetTempFileNameW创建文件后到open()打开文件之间的时间窗口内执行文件替换操作（如符号链接攻击）
- 触发路径: if (GetTempFileNameW(L".", L"case0", 0, filename) == 0) { exit(1); } @ 48-52; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ 54-58
- 结论: 程序使用GetTempFileNameW创建临时文件时传递uUnique=0，导致函数创建并立即关闭文件，随后程序再次打开该文件，存在TOCTOU竞争条件漏洞，攻击者可利用该窗口替换临时文件，造成权限提升或信息泄露。
- D验证: confirmed / ver_64b48c25
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 102. hyp_path_11487687f53b

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_03.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问当前工作目录（"."）并预测临时文件名（前缀"case0"，由GetTempFileNameW生成的文件名可预测）
- 触发路径: if (GetTempFileNameW(L".", L"case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_03.c:42-46; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_03.c:48-52
- 结论: 程序使用GetTempFileNameW创建临时文件时传入uUnique=0，导致文件被创建后立即关闭，然后使用open()以O_RDWR|O_CREAT打开，未使用O_EXCL标志，存在TOCTOU竞态条件，攻击者可能替换临时文件，造成不安全临时文件漏洞。
- D验证: confirmed / ver_671c73c9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 103. hyp_path_78cd944cf643

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_05.c:60
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在的目录; 攻击者能够预测临时文件名; 攻击者能够在创建和打开之间存在的时间窗口内执行文件系统操作
- 触发路径: if (GetTempFileNameW(L".", L"case0", 0, filename) == 0) { exit(1); } @ 48-51; printWLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ 54-55; if (fileDesc != -1) { printLine("Temporary file was opened...now closing file"); CLOSE(fileDesc); } @ 58-62
- 结论: 程序使用GetTempFileNameW函数创建临时文件时，传递uUnique参数为0，该参数导致函数创建并立即关闭文件，留下可预测的文件名。随后程序使用open()函数以O_RDWR|O_CREAT标志重新打开该文件，但未采取任何竞争条件防护措施。攻击者可在文件创建后、重新打开前替换或修改该文件，导致TOCTOU（time-of-check time-of-use）漏洞，可能造成信息泄露或权限提升。
- D验证: confirmed / ver_2328cfe4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 104. hyp_path_7a8d558ab920

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_06.c:59
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在的目录（当前目录），并在GetTempFileNameW创建文件后、open重新打开前进行竞态操作。
- 触发路径: if (GetTempFileNameW(L".", L"case0", 0, filename) == 0) @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_06.c:47-48; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_06.c:53-55
- 结论: 使用GetTempFileNameW时传入uUnique=0，导致临时文件被创建后立即关闭，随后再次打开时存在TOCTOU竞态条件，攻击者可在间隙期间替换或修改临时文件，导致不安全临时文件漏洞。
- D验证: confirmed / ver_c67449a0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 105. hyp_path_2a40d164a3cf

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_07.c:59
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在的目录（本例中为当前目录），并具有写入权限以替换文件。; 攻击者能够准确预判或监视GetTempFileNameW生成的文件名（由于传参固定，文件名可预测）。
- 触发路径: if (GetTempFileNameW(L".", L"case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_07.c:47; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_07.c:53-55
- 结论: 程序使用GetTempFileNameW函数并传入0作为uUnique参数，导致创建临时文件后立即关闭，随后使用OPEN函数打开该文件，但未使用O_EXCL标志，存在TOCTOU竞争条件漏洞，攻击者可在文件创建后打开前替换为符号链接，从而造成任意文件读写或权限提升。
- D验证: confirmed / ver_9bdd2fb9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 106. hyp_path_cbcd3a508fb1

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_09.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够对程序当前工作目录具有写访问权限，或能够预测临时文件路径并快速替换文件。
- 触发路径: if (GetTempFileNameW(L".", L"case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_09.c:42-46; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_09.c:48-50
- 结论: 使用GetTempFileNameW时传入uUnique=0，导致临时文件创建后立即关闭，随后使用open()重新打开，存在TOCTOU竞争条件，攻击者可利用符号链接或文件替换劫持临时文件，导致信息泄露或任意文件写入。
- D验证: confirmed / ver_8211dc9e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 107. hyp_path_1896eec16f63

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_10.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: The attacker must have write access to the directory where the temporary file is created (here, the current directory ".").; The attacker must be able to perform a race condition attack by replacing the file between the close by GetTempFileNameW and the open by OPEN.
- 触发路径: if (GetTempFileNameW(L".", L"case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_10.c:42-46; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_10.c:48-52
- 结论: Insecure temporary file creation due to TOCTOU race condition. The program uses GetTempFileNameW with uUnique=0, which creates and immediately closes the temporary file, then opens it again using O_RDWR|O_CREAT without proper precautions, allowing an attacker to replace the file between creation and open.
- D验证: confirmed / ver_c7bdf6e1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 108. hyp_path_a07d443f9365

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_14.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在的目录（当前工作目录）并且能够在竞态窗口内替换或修改文件
- 触发路径: if (GetTempFileNameW(L".", L"case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_14.c:42-46; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_14.c:48-50
- 结论: 代码使用GetTempFileNameW创建临时文件时，uUnique参数设为0，导致文件被创建后立即关闭，随后再次打开时存在竞态条件，攻击者可能替换临时文件，造成权限提升或信息泄露。
- D验证: confirmed / ver_5569a791
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 109. hyp_path_0dff709511f9

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_13.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者具有与程序相同的用户权限，能够访问程序运行时的当前目录。; 攻击者能够执行本地代码或通过其他手段在目标文件系统上创建符号链接。
- 触发路径: if (GetTempFileNameW(L".", L"case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_13.c:44; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_13.c:48; { printLine("Temporary file was opened...now closing file"); CLOSE(fileDesc); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_13.c:52-55
- 结论: 使用GetTempFileNameW函数时，uUnique参数设置为0，导致函数创建临时文件后立即关闭，随后程序再次打开该文件时存在竞态条件，攻击者可利用此窗口进行符号链接攻击，导致任意文件写入或读取，属于不安全的临时文件漏洞。
- D验证: confirmed / ver_bd3f8af5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 110. hyp_path_c38098695389

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_15.c:55
- 漏洞类型: CWE-377, CWE-367
- CWE: CWE-377; CWE-367
- 风险等级: P0
- 触发条件: 攻击者具有对当前目录的写权限; 攻击者能提前获知或将预测GetTempFileNameW生成的临时文件名（由于uUnique=0，文件名是确定性的）; 攻击者可在极短时间窗口内完成符号链接替换
- 触发路径: if (GetTempFileNameW(L".", L"case0", 0, filename) == 0) { exit(1); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_15.c:43-47; N/A（外部操作） @ 攻击者在GetTempFileNameW返回后、open调用前创建符号链接指向目标文件; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_15.c:49-53
- 结论: 存在不安全的临时文件创建导致TOCTOU竞态条件漏洞。GetTempFileNameW使用uUnique=0创建临时文件后立即关闭，随后使用open()且未指定O_EXCL标志重新打开文件，攻击者可在文件创建后、打开前替换为符号链接，从而操纵程序打开任意文件。
- D验证: confirmed / ver_8a42d318
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 111. hyp_path_210332e2ce3b

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_18.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在的目录（当前目录）; 攻击者能够在GetTempFileNameW创建文件后、OPEN打开前的时间窗口内执行文件操作
- 触发路径: if (GetTempFileNameW(L".", L"case0", 0, filename) == 0) @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_18.c:42; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_18.c:49-50
- 结论: 使用GetTempFileNameW创建临时文件时，参数uUnique为0，导致文件创建后立即关闭，然后再次以O_RDWR|O_CREAT打开，存在TOCTOU竞态条件，攻击者可能在文件创建后和打开前替换文件，导致权限提升或数据泄露。
- D验证: confirmed / ver_74c9ca6d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 112. hyp_path_50421acd65ac

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_16.c:54
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够在GetTempFileNameW返回后和open()调用前这段时间内访问文件系统并替换临时文件。
- 触发路径: if (GetTempFileNameW(L".", L"case0", 0, filename) == 0) @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_16.c:42-43; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_16.c:48-49; printLine("Temporary file was opened...now closing file"); CLOSE(fileDesc); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_16.c:52-56
- 结论: 使用GetTempFileNameW创建临时文件时，uUnique参数为0，导致系统创建并关闭文件，之后再次使用open()以O_RDWR|O_CREAT打开，未使用O_EXCL标志，存在竞态条件漏洞，攻击者可在文件创建后打开前替换为恶意文件，导致权限提升或信息泄露。
- D验证: confirmed / ver_4e125492
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 113. hyp_path_7c05c0c74499

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_08.c:72
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录，并能预测或获取临时文件名，且在竞态窗口内进行文件操作。
- 触发路径: wchar_t tmpl[] = L"fnXXXXXX"; int fileDesc; filename = MKTEMP(tmpl); if (filename == NULL) { @ 59-63; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); if (fileDesc != -1) { @ 66-69
- 结论: 存在不安全的临时文件创建漏洞，使用 mktemp 生成文件名后，在 open 之前存在竞态条件，攻击者可能通过预测或替换文件导致安全问题。
- D验证: confirmed / ver_37ed199f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 114. hyp_path_133a5e908df2

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_11.c:59
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录（例如/tmp），并能与目标程序并发运行。; 攻击者能够预测或快速猜测由mktemp生成的临时文件名（模板为'fnXXXXXX'）。
- 触发路径: filename = MKTEMP(tmpl); @ CWE377_Insecure_Temporary_File__wchar_t_mktemp_11.c:48; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ CWE377_Insecure_Temporary_File__wchar_t_mktemp_11.c:54-55; 使用fileDesc进行文件操作后关闭 @ CWE377_Insecure_Temporary_File__wchar_t_mktemp_11.c:57-61
- 结论: 使用mktemp生成临时文件名后，使用open()以O_RDWR|O_CREAT标志创建文件，未使用O_EXCL标志，导致竞态条件，攻击者可利用时间窗口创建符号链接等恶意文件，造成信息泄露或权限提升。
- D验证: confirmed / ver_d0cea452
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 115. hyp_path_20fa80431139

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_08.c:71
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问程序运行时的文件系统，并且能够预测tmpnam()生成的临时文件名。
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_08.c:58-62; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_08.c:65-69
- 结论: 代码使用tmpnam()生成临时文件名，然后以O_RDWR|O_CREAT打开，存在TOCTOU竞争条件漏洞（CWE-377），攻击者可能通过预测文件名并创建符号链接等方式导致任意文件写入或权限提升。
- D验证: confirmed / ver_583604b5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 116. hyp_path_3e30742bac58

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_11.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问文件系统，并能够创建符号链接或文件。; 攻击者知道或能够猜测临时文件名。
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_11.c:45-49; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_11.c:52-56
- 结论: 程序使用TMPNAM生成临时文件名，然后以O_RDWR|O_CREAT标志打开文件，未指定O_EXCL，导致竞态条件，攻击者可能通过抢占创建符号链接或文件，造成信息泄露或任意文件写入。
- D验证: confirmed / ver_7e9c3afb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 117. hyp_path_10af1ae8b672

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_01.c:57
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够对目标文件系统具有写入权限，并能在文件名生成后、打开前创建同名文件或符号链接
- 触发路径: wchar_t tmpl[] = L"fnXXXXXX"; int fileDesc; filename = MKTEMP(tmpl); if (filename == NULL) { ... } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_01.c:44-48; printWLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_01.c:51-55
- 结论: 使用mktemp生成临时文件名后，未使用O_EXCL标志调用open()，导致存在TOCTOU竞争条件，攻击者可能创建符号链接或抢占创建文件，造成权限提升或信息泄露。
- D验证: confirmed / ver_b55a8e76
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 118. hyp_path_2e1e317b99e5

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_02.c:59
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够对临时文件目录（例如/tmp）进行写入操作，且能够在mktemp和open之间替换文件。
- 触发路径: wchar_t tmpl[] = L"fnXXXXXX"; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_02.c:46; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_02.c:49; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_02.c:53-55
- 结论: 使用不安全的临时文件创建方式，存在TOCTOU竞争条件漏洞，攻击者可能通过预测或替换临时文件进行攻击。
- D验证: confirmed / ver_a79f8239
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 119. hyp_path_0c5c27abf174

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_03.c:59
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够与程序运行在同一系统上，并具有对临时目录的写入权限
- 触发路径: wchar_t tmpl[] = L"fnXXXXXX"; int fileDesc; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_03.c:46-49; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_03.c:53-56; if (fileDesc != -1) { printLine("Temporary file was opened...now closing file"); CLOSE(fileDesc); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_03.c:57-60
- 结论: 使用mktemp生成临时文件名后，使用open()以O_RDWR|O_CREAT标志创建文件，未使用O_EXCL标志，导致竞态条件漏洞，攻击者可预测文件名并创建符号链接指向重要文件，造成文件覆盖或权限提升。
- D验证: confirmed / ver_1120aa23
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 120. hyp_path_0b548be2b284

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_04.c:65
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够在目标系统上执行任意代码（或具有文件系统写入权限）以创建符号链接或文件。; 攻击者能够控制临时文件名或预测mktemp的输出（例如通过固定前缀或竞争窗口）。
- 触发路径: wchar_t tmpl[] = L"fnXXXXXX"; int fileDesc; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_04.c:52-53; if (filename == NULL) { exit(1); } printWLine(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_04.c:57-59; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_04.c:60-61; if (fileDesc != -1) { printLine("Temporary file was opened...now closing file"); CLOSE(fileDesc); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_04.c:63-66
- 结论: 程序使用mktemp生成临时文件名，然后以O_RDWR|O_CREAT标志打开文件，未使用O_EXCL，导致TOCTOU竞争条件漏洞，攻击者可在检查与打开之间替换文件，造成信息泄露或权限提升。
- D验证: confirmed / ver_5d90dcc7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 121. hyp_path_0b772fea1242

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_05.c:65
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够写入临时文件目录（通常为共享临时目录，如/tmp）; 攻击者能够在MKTEMP返回后、open调用前快速替换文件
- 触发路径: wchar_t tmpl[] = L"fnXXXXXX"; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_05.c:52; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_05.c:65
- 结论: 使用mktemp生成临时文件名后，以O_RDWR|O_CREAT标志打开文件而未使用O_EXCL，存在TOCTOU竞态条件，攻击者可在检查与打开之间替换文件为符号链接，导致打开恶意文件或覆盖重要文件。
- D验证: confirmed / ver_8c2f929f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 122. hyp_path_0cf209240cfc

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_06.c:64
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者具有对临时文件所在目录的写权限（能够创建符号链接）
- 触发路径: wchar_t tmpl[] = L"fnXXXXXX"; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_06.c:51-53; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_06.c:58-60
- 结论: 使用mktemp生成临时文件名，然后使用open创建文件，但mktemp存在TOCTOU竞争条件，可能导致符号链接攻击，属于不安全的临时文件创建。
- D验证: confirmed / ver_b9aee8fb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 123. hyp_path_0c5c00b866f4

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_07.c:64
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够执行本地或远程代码以创建符号链接或文件，或能够影响文件系统状态。
- 触发路径: wchar_t tmpl[] = L"fnXXXXXX"; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_07.c:51; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_07.c:52; printWLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_07.c:58-60
- 结论: 使用可预测的临时文件名（mktemp）并以不安全的方式打开文件（未使用O_EXCL标志），导致竞态条件漏洞，攻击者可能通过预测文件名进行符号链接攻击或文件覆盖。
- D验证: confirmed / ver_fa15b52d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 124. hyp_path_06f7beed731e

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_10.c:59
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者具有对临时文件所在目录的写入权限，能够创建文件或符号链接
- 触发路径: wchar_t tmpl[] = L"fnXXXXXX"; int fileDesc; filename = MKTEMP(tmpl); if (filename == NULL) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_10.c:46-50; printWLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_10.c:53-57; { printLine("Temporary file was opened...now closing file"); CLOSE(fileDesc); } } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_10.c:57-61
- 结论: 使用不安全的临时文件创建方式，存在竞争条件漏洞。mktemp()生成临时文件名后，在open()调用之前存在时间窗口，攻击者可创建同名文件或符号链接，导致权限提升或信息泄露。
- D验证: confirmed / ver_ed810956
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 125. hyp_path_52fd4c0863f6

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_09.c:59
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够对临时文件所在目录具有写入权限; 攻击者能够预测或观察到临时文件名，并在mktemp调用之后、open调用之前创建符号链接指向目标文件
- 触发路径: wchar_t tmpl[] = L"fnXXXXXX"; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_09.c:46; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_09.c:47-48; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_09.c:53-56
- 结论: 代码使用mktemp生成临时文件名，然后使用open()创建文件时未指定O_EXCL标志，导致竞争条件漏洞，攻击者可能在文件创建前替换为恶意符号链接，从而造成任意文件写入或信息泄露。
- D验证: confirmed / ver_694d3557
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 126. hyp_path_17db518ece3d

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_14.c:59
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够预测临时文件名; 攻击者在目标路径有写入权限（创建符号链接）
- 触发路径: wchar_t tmpl[] = L"fnXXXXXX"; filename = MKTEMP(tmpl); @ 46-50; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ 53-55
- 结论: 使用mktemp生成临时文件名，然后以O_RDWR|O_CREAT打开但未使用O_EXCL标志，存在竞态条件漏洞，攻击者可预测文件名并创建符号链接，导致任意文件写入或覆盖。
- D验证: confirmed / ver_0b746f2f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 127. hyp_path_2e2f8f9b569e

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_13.c:59
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者具有对临时目录的写入权限; 攻击者能够预测或枚举mktemp生成的临时文件名; 攻击者能够在mktemp()返回后、open()调用前创建同名文件或符号链接
- 触发路径: wchar_t tmpl[] = L"fnXXXXXX"; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_13.c:48; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_13.c:49; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_13.c:53-55
- 结论: 使用不安全的临时文件创建方式：mktemp()生成的临时文件名可被预测，且open()未使用O_EXCL标志，存在TOCTOU竞争条件漏洞，攻击者可能通过预创建文件或符号链接导致文件内容被篡改或敏感信息泄露。
- D验证: confirmed / ver_caf47ba6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 128. hyp_path_08996c6fda8f

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_15.c:60
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够在临时文件生成目录中创建符号链接，并在open()调用前完成替换
- 触发路径: wchar_t tmpl[] = L"fnXXXXXX"; int fileDesc; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File__wchar_t_mktemp_15.c:47; printWLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File__wchar_t_mktemp_15.c:54-55
- 结论: 使用mktemp生成临时文件名，随后以O_CREAT和O_RDWR标志打开文件，未使用O_EXCL标志，导致存在TOCTOU竞争条件，攻击者可在文件创建前替换为符号链接，从而造成权限提升或数据篡改。
- D验证: confirmed / ver_c77c2c05
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 129. hyp_path_6f1f7b8ebdc0

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_16.c:59
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在目录并进行符号链接攻击。
- 触发路径: wchar_t tmpl[] = L"fnXXXXXX"; int fileDesc; filename = MKTEMP(tmpl); if (filename == NULL) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_16.c:46-50; printWLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); if (fileDesc != -1) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_16.c:53-57; { printLine("Temporary file was opened...now closing file"); CLOSE(fileDesc); } } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_16.c:57-61
- 结论: 使用mktemp生成可预测的临时文件名，然后在检查与打开之间存在竞态条件，可能导致攻击者创建符号链接指向敏感文件，造成信息泄露或任意文件写入。
- D验证: confirmed / ver_ec83172f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 130. hyp_path_374d6fb88506

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_18.c:59
- 漏洞类型: CWE-377, CWE-367
- CWE: CWE-377; CWE-367
- 风险等级: P0
- 触发条件: 攻击者能够访问应用程序创建临时文件的目录（通常为共享目录如/tmp）并具有写入权限。; 攻击者能够在mktemp和open之间的时间窗口内执行操作，例如通过并发进程或提前放置文件。
- 触发路径: wchar_t tmpl[] = L"fnXXXXXX"; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_18.c:46; filename = MKTEMP(tmpl); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_18.c:50; printWLine(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_18.c:53; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_18.c:54
- 结论: 程序使用mktemp生成临时文件名，然后使用open()以O_RDWR|O_CREAT模式创建文件，未使用O_EXCL标志，存在TOCTOU竞争条件漏洞。攻击者可在mktemp和open之间创建或替换文件，导致访问非预期的文件，构成不安全临时文件漏洞。
- D验证: confirmed / ver_521c3a88
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 131. hyp_path_47d98e44dbf4

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_01.c:56
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件所在目录，并能写入或创建符号链接。
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_01.c:44; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_01.c:52
- 结论: 程序使用tmpnam生成临时文件名后，直接以O_RDWR|O_CREAT打开，未使用O_EXCL标志，存在竞态条件（TOCTOU）漏洞，攻击者可预测文件名并在打开前创建符号链接或文件，导致安全风险。
- D验证: confirmed / ver_80c61986
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 132. hyp_path_79990895213f

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_02.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问运行程序的系统，并且能够预测或获取tmpnam生成的临时文件名
- 触发路径: filename = TMPNAM(NULL); if (filename == NULL) { ... } @ CWE377_Insecure_Temporary_File__wchar_t_tmpnam_02.c:51-52; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ CWE377_Insecure_Temporary_File__wchar_t_tmpnam_02.c:55-56
- 结论: 代码使用tmpnam()生成临时文件名，然后使用open()创建文件，但未使用O_EXCL标志，存在TOCTOU竞态条件，攻击者可以预测文件名并创建符号链接，导致任意文件覆盖或信息泄露。
- D验证: confirmed / ver_21c11ecb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 133. hyp_path_25b1252cb183

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_03.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问目标系统，并能够在该进程的工作目录或临时目录中创建文件或符号链接
- 触发路径: wchar_t * filename; int fileDesc; filename = TMPNAM(NULL); if (filename == NULL) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_03.c:45-48; printWLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); if (fileDesc != -1) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_03.c:52-56
- 结论: 代码使用tmpnam()生成临时文件名，然后以O_RDWR|O_CREAT模式打开文件，未使用O_EXCL标志，导致存在竞态条件（TOCTOU），攻击者可在文件名生成与文件打开之间创建或链接恶意文件，造成信息泄露或权限提升。
- D验证: confirmed / ver_ef7ca913
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 134. hyp_path_21884ecb4124

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_04.c:64
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够在文件系统上对目标目录（通常为/tmp）有写权限，并能预测或截获tmpnam生成的临时文件名。
- 触发路径: wchar_t * filename; int fileDesc; filename = TMPNAM(NULL); if (filename == NULL) { @ CWE377_Insecure_Temporary_File__wchar_t_tmpnam_04.c:51-55; printWLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); if (fileDesc != -1) { @ CWE377_Insecure_Temporary_File__wchar_t_tmpnam_04.c:58-62; { printLine("Temporary file was opened...now closing file"); CLOSE(fileDesc); } @ CWE377_Insecure_Temporary_File__wchar_t_tmpnam_04.c:62-66
- 结论: 使用tmpnam生成临时文件名后，以O_RDWR|O_CREAT打开，存在TOCTOU竞争条件漏洞，可能导致攻击者在创建文件前替换文件，造成信息泄露或写入恶意内容。
- D验证: confirmed / ver_85168240
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 135. hyp_path_505e93322c45

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_05.c:64
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者具有本地文件系统写权限; 攻击者能够预测tmpnam的返回值（或通过竞争窗口多次尝试）
- 触发路径: wchar_t * filename; int fileDesc; filename = TMPNAM(NULL); if (filename == NULL) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_05.c:51-55; printWLine(filename); /* NOTE: Open a temporary file using open() and flags that do not prevent a race condition */ fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); if (fileDesc != -1) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_05.c:58-62
- 结论: 程序使用tmpnam生成临时文件名，然后使用open()以O_RDWR|O_CREAT标志（未指定O_EXCL）创建文件，存在TOCTOU竞争条件漏洞，攻击者可在tmpnam返回与open调用之间创建同名文件，导致使用不安全的临时文件。
- D验证: confirmed / ver_2654bedb
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 136. hyp_path_7c59d8720ba9

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_06.c:63
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者具有本地用户权限，能够访问/tmp目录（或默认临时目录）并能够创建文件或符号链接
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_06.c:50-52; printWLine(filename); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_06.c:57; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_06.c:58
- 结论: 代码使用tmpnam生成临时文件名，然后打印文件名并打开创建文件，存在TOCTOU竞争条件漏洞，攻击者可通过预测或观察文件名创建符号链接，导致不安全临时文件。
- D验证: confirmed / ver_22628c45
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 137. hyp_path_3c85160dc06b

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_07.c:63
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录; 攻击者能够预测或侦测临时文件名; 攻击者在文件创建前能够创建竞争条件
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_07.c:54; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_07.c:59
- 结论: 程序使用tmpnam生成临时文件名，并使用open()函数以O_RDWR|O_CREAT标志创建文件，未使用O_EXCL标志，导致存在竞态条件漏洞，攻击者可能通过预测或侦测文件名，在文件创建前创建符号链接，从而覆盖或读取敏感文件。
- D验证: confirmed / ver_59dca6f1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 138. hyp_path_11af94f5bae4

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_09.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够预测或影响 tmpnam 生成的临时文件名（常见于共享临时目录），并能在 open 调用前创建同名的符号链接或文件。
- 触发路径: filename = TMPNAM(NULL); @ L45-49; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ L52-56; CLOSE(fileDesc); @ L56-60
- 结论: 使用 tmpnam 生成临时文件名后，以 O_RDWR|O_CREAT 打开文件，未使用 O_EXCL，存在 TOCTOU 竞争条件漏洞，攻击者可能通过预测文件名创建符号链接或覆盖文件，导致特权提升或数据损坏。
- D验证: confirmed / ver_7cec5dd7
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 139. hyp_path_7ef0bc61eebc

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_10.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够预测 tmpnam() 生成的临时文件名（例如基于进程ID和时间等可预测因素）; 攻击者能够在 tmpnam() 和 open() 之间的时间窗口内在相同路径创建符号链接指向目标文件
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_10.c:46; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_10.c:52-54
- 结论: 使用不安全的临时文件生成函数 tmpnam() 和 open() 且未使用 O_EXCL 标志，存在竞态条件漏洞，攻击者可能通过预测文件名并创建符号链接导致任意文件覆盖或信息泄露。
- D验证: confirmed / ver_a658bea5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 140. hyp_path_2c28e9e104e2

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_13.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者需要能够访问目标系统的文件系统，并有写入临时目录的权限
- 触发路径: filename = TMPNAM(NULL); if (filename == NULL) { ... } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_13.c:45-49; printWLine(filename); fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_13.c:52-56
- 结论: 程序使用tmpnam生成临时文件名，然后使用open()创建并打开文件，但未采取防止竞态条件的措施，导致存在不安全的临时文件创建漏洞（TOCTOU竞态）。攻击者可在tmpnam返回文件名到open打开文件之间创建同名文件，从而造成文件内容被篡改或信息泄露。
- D验证: confirmed / ver_9384cfba
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 141. hyp_path_86b6baf59073

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_14.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够预测临时文件名; 攻击者在open调用前具备对临时目录的写权限
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_14.c:47; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_14.c:54
- 结论: 程序使用不安全的临时文件生成函数tmpnam()，并在创建文件时未使用O_EXCL标志，导致存在TOCTOU竞态条件漏洞，攻击者可能通过预测文件名并提前创建符号链接来劫持临时文件。
- D验证: confirmed / ver_bb0a616d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 142. hyp_path_595ec0c24ec1

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_15.c:59
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够预测临时文件名或通过观察得到文件名; 攻击者在文件名生成与文件打开之间有时间窗口创建符号链接
- 触发路径: filename = TMPNAM(NULL); @ CWE377_Insecure_Temporary_File__wchar_t_tmpnam_15.c:46; printWLine(filename); @ CWE377_Insecure_Temporary_File__wchar_t_tmpnam_15.c:53; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ CWE377_Insecure_Temporary_File__wchar_t_tmpnam_15.c:54
- 结论: 使用不安全的临时文件创建，存在TOCTOU竞态条件漏洞。tmpnam()生成的文件名可预测，且open()未使用O_EXCL标志，攻击者可通过符号链接攻击覆盖或创建任意文件。
- D验证: confirmed / ver_de562139
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 143. hyp_path_83bfd36783f8

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_16.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录并预测文件名。
- 触发路径: filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_16.c:47; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_16.c:52-53
- 结论: 程序使用tmpnam生成临时文件名，并使用open()创建文件，但未使用O_EXCL标志，存在TOCTOU竞争条件，攻击者可能通过预测文件名并创建符号链接导致安全漏洞。
- D验证: confirmed / ver_a18a4d41
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 144. hyp_path_752a4b41d08b

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_18.c:58
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者与程序运行在同一文件系统上，且对临时目录有写入权限（可创建符号链接）。
- 触发路径: wchar_t * filename; int fileDesc; filename = TMPNAM(NULL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_18.c:45-49; fileDesc = OPEN(filename, O_RDWR|O_CREAT, S_IREAD|S_IWRITE); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_18.c:52-56
- 结论: 使用不安全的临时文件创建函数tmpnam和open，存在TOCTOU竞争条件漏洞，攻击者可能通过符号链接攻击覆盖或篡改文件。
- D验证: confirmed / ver_b302e86f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 145. hyp_path_841ec7dd75ab

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_04.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够控制_mkstemp函数的输入参数t的内容和长度
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_04.c:30; char s[50]; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_04.c:31-32; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_04.c:33
- 结论: 在_mkstemp函数中，用户提供的模板字符串t被strncpy复制到固定大小缓冲区s[50]中，复制长度由strlen(t)+1决定。如果t的长度超过49，则strncpy会写入超过缓冲区大小的数据，导致栈缓冲区溢出。
- D验证: confirmed / ver_0a734382
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 146. hyp_path_3a53dc1986a8

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_03.c:33
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够控制或影响临时文件模板t的内容，或者现网的模板不够随机；攻击者能够预测mktemp_s生成的临时文件名；攻击者在时间窗口内具有创建文件的权限。
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_03.c:30; char s[50]; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_03.c:31; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_03.c:32
- 结论: 在_mkstemp函数中，使用mktemp_s生成临时文件名后立即调用open，但mktemp_s生成的名称可能可预测（取决于模板），且在mktemp_s和open之间存在时间窗口，攻击者有可能预测文件名并创建同名文件，导致open失败（O_CREAT|O_EXCL失败）或打开攻击者控制的文件，造成不安全临时文件漏洞。
- D验证: confirmed / ver_ca9f38d0
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 147. hyp_path_62b2d91f3f81

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_06.c:33
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时目录并能预测_mktemp_s生成的临时文件名（例如，若随机数生成可预测或种子弱）; 在_mktemp_s返回后到_open调用之间，存在时间窗口允许攻击者创建同名文件
- 触发路径: size_t l = strlen(t) + 1; char s[50]; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_06.c:29-30; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_06.c:33
- 结论: 代码使用_mktemp_s生成临时文件名后立即以O_CREAT|O_EXCL模式打开，但可能存在TOCTOU竞态条件，攻击者可在文件名生成后到文件打开前预测或创建同名文件，导致不安全临时文件漏洞。
- D验证: confirmed / ver_7c3df760
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 148. hyp_path_8d6539234e09

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_05.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够向_mkstemp函数传递一个长度>=50的字符串
- 触发路径: int _mkstemp(const char * t) { @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_05.c:29; size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_05.c:30; char s[50]; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_05.c:31; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_05.c:32
- 结论: 函数_mkstemp中，strncpy复制长度l可能大于目标缓冲区s的大小（50字节），导致栈缓冲区溢出。
- D验证: confirmed / ver_3184f51b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 149. hyp_path_78f49155a142

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_10.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够控制传入_mkstemp的字符串t的内容和长度，且长度至少为50。
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_10.c:30; char s[50]; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_10.c:32
- 结论: 在函数_mkstemp中，strncpy复制长度由传入参数t的长度决定，若t长度大于等于50，则复制操作会超出栈上缓冲区s的大小（50字节），导致缓冲区溢出。
- D验证: confirmed / ver_c31c8bcd
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 150. hyp_path_09918c0a3236

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_08.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够控制_mkstemp函数的参数t，且t长度大于等于50
- 触发路径: strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_08.c:32
- 结论: 函数_mkstemp中，strncpy使用长度l = strlen(t)+1复制到固定大小缓冲区s[50]，当t长度大于等于50时导致栈缓冲区溢出。
- D验证: confirmed / ver_9506f577
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 151. hyp_path_2a5596952ad6

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_13.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够控制输入参数t（如通过外部传入的文件名模板）
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_13.c:30; char s[50]; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_13.c:31; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_13.c:32
- 结论: 在_mkstemp函数中，strncpy将长度l（strlen(t)+1）复制到大小为50的栈缓冲区s，如果输入字符串t的长度大于等于49，会导致栈缓冲区溢出（CWE-121）。
- D验证: confirmed / ver_1506cf9e
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 152. hyp_path_484a21f4e3bf

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_11.c:33
- 漏洞类型: CWE-367
- CWE: CWE-367
- 风险等级: P0
- 触发条件: 攻击者能够对临时文件目录有写入和创建文件的权限; 攻击者能够预测或观察到_mktemp_s生成的临时文件名
- 触发路径: _mkstemp函数入口 @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_11.c:29; char s[50]; strncpy(s, t, l); return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_11.c:31-33
- 结论: 使用_mktemp_s和_open创建临时文件时存在TOCTOU竞争条件，攻击者可在文件名生成后、文件创建前创建同名文件，导致_open失败（拒绝服务），但无法覆盖其他文件。
- D验证: confirmed / ver_99246984
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 153. hyp_path_b07ccab13de5

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_15.c:33
- 漏洞类型: CWE-377, CWE-367
- CWE: CWE-377; CWE-367
- 风险等级: P0
- 触发条件: 攻击者具有对临时文件目录的写权限; 攻击者能够预测或探测临时文件名
- 触发路径: static int _mkstemp(const char * t) @ 函数入口; size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_15.c:30; char s[50]; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_15.c:31-32; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_15.c:33
- 结论: 在临时文件创建过程中，使用了_mktemp_s生成文件名后单独调用_open，存在TOCTOU竞态条件，可能导致攻击者提前创建文件，造成不安全临时文件漏洞。
- D验证: confirmed / ver_d2ebfb7c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 154. hyp_path_2a2f35f77aa6

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_17.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够控制传入_mkstemp的参数t的内容和长度
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_17.c:30; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_17.c:32
- 结论: 栈缓冲区溢出漏洞：在函数_mkstemp中，strncpy(s, t, l)使用从strlen(t)+1计算的长度l作为最大复制字节数，但目标缓冲区s大小固定为50字节。若输入字符串t长度超过49（含空字符），则导致栈缓冲区溢出。
- D验证: confirmed / ver_ee6499c5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 155. hyp_path_7fa23f6a2c85

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_14.c:33
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够预测_mktemp_s生成的临时文件名（例如通过进程ID和当前时间）或通过文件系统监听在创建前放置同名文件
- 触发路径: strncpy(s, t, l); return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_14.c:32; _open(s, _O_CREAT|_O_EXCL) @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_14.c:33
- 结论: 使用_mktemp_s生成临时文件名后立即调用_open创建文件，存在TOCTOU竞态条件，可能导致不安全临时文件漏洞
- D验证: confirmed / ver_33210504
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 156. hyp_path_b2c415cfc766

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_01.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够控制_mkstemp函数的输入参数t，使其长度大于等于50字节
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_01.c:29; char s[50]; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_01.c:32; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_01.c:33
- 结论: 栈缓冲区溢出漏洞。函数_mkstemp中，strncpy(s, t, l)使用长度l = strlen(t)+1，但目标缓冲区s只有50字节。当输入t的长度大于等于50时，strncpy会复制超出缓冲区边界的数据，导致栈上缓冲区溢出，可能覆盖返回地址或其他局部变量。
- D验证: confirmed / ver_5864e4e8
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 157. hyp_path_a38d861477a9

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_05.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够提供或影响`_mkstemp`函数的第一个参数`t`的值，且该值长度大于等于50个字符。
- 触发路径: size_t l = strlen(t) + 1; char s[50]; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_05.c:30-31; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_05.c:32
- 结论: 栈缓冲区溢出漏洞：在`_mkstemp`函数中，通过`strncpy(s, t, l)`复制模板字符串时，如果`t`的长度大于等于50，则`l`超过目标缓冲区大小`char s[50]`，导致栈溢出。
- D验证: confirmed / ver_57426c68
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 158. hyp_path_1c8e1a0d9086

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_02.c:33
- 漏洞类型: command_injection
- CWE: CWE-121; CWE-787
- 风险等级: P0
- 触发条件: 攻击者能够控制传入_mkstemp的外部输入t，使得strlen(t) >= 50
- 触发路径: static int _mkstemp(const char * t){ @ _mkstemp入口; size_t l = strlen(t) + 1; @ CWE377_Insecure_Temporary_File__char_tempnam_02.c:30; char s[50]; @ CWE377_Insecure_Temporary_File__char_tempnam_02.c:31; strncpy(s, t, l); @ CWE377_Insecure_Temporary_File__char_tempnam_02.c:32; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ CWE377_Insecure_Temporary_File__char_tempnam_02.c:33
- 结论: 在函数_mkstemp中，strncpy拷贝长度l由外部可控参数t决定，当t长度大于等于50时，导致栈上数组s[50]缓冲区溢出（CWE-121），并可能因_mktemp_s第二个参数错误传递l（非缓冲区大小）引发越界写（CWE-787）。
- D验证: confirmed / ver_2eed2b27
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 159. hyp_path_be08f52ac232

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_04.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121; CWE-119
- 风险等级: P0
- 触发条件: 攻击者能够控制模板字符串t的长度超过49字节。
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_04.c:30; char s[50]; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_04.c:31; strncpy(s, t, l); // 若l>50则溢出 @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_04.c:32
- 结论: 函数_mkstemp中，当传入的模板字符串t长度超过49时，strncpy复制strlen(t)+1个字符到大小为50的栈缓冲区s，导致缓冲区溢出。
- D验证: confirmed / ver_a69c6818
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 160. hyp_path_a1ed436ebde7

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_07.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够控制_mkstemp函数的参数t，使其长度大于等于50。但t的实际来源未在本代码片段中给出，可能受限于源文件中的固定路径，需进一步验证外部可控性。
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_07.c:30; char s[50]; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_07.c:32
- 结论: 在_mkstemp函数中，使用strncpy将参数t复制到固定大小（50）的栈缓冲区s时，若t长度大于等于50，则复制长度l = strlen(t)+1会超过缓冲区大小，导致栈缓冲区溢出。
- D验证: confirmed / ver_3700743d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 161. hyp_path_71cf94abc910

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_06.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121; CWE-119
- 风险等级: P0
- 触发条件: 攻击者能够控制传入_mkstemp的参数t（例如通过tempnam生成可预测文件名或直接控制输入），且t的长度大于等于50。
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_06.c:31; char s[50]; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_06.c:32; strncpy(s, t, l); // 当l > 50时溢出 @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_06.c:32
- 结论: 在_mkstemp函数中，strncpy(s, t, l)使用从strlen(t)+1计算的长度l，但目标缓冲区s固定为50字节。当t的长度大于等于50时，l大于50，strncpy会写入超出s边界，导致栈缓冲区溢出。
- D验证: confirmed / ver_242db2c6
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 162. hyp_path_59e65283696f

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_10.c:33
- 漏洞类型: command_injection
- CWE: CWE-121; CWE-787
- 风险等级: P0
- 触发条件: 攻击者能够提供长度超过49的字符串作为参数t
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_10.c:30; char s[50]; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_10.c:32; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_10.c:33
- 结论: 存在缓冲区溢出漏洞：在_mkstemp函数中，strncpy使用strlen(t)+1作为复制长度，当t的长度超过49时，strncpy会向仅有50字节的栈缓冲区s写入超过50字节的数据，导致栈缓冲区溢出。
- D验证: confirmed / ver_1dd13d09
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 163. hyp_path_653df06f55e9

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_08.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121; CWE-122
- 风险等级: P0
- 触发条件: 攻击者能够控制 _mkstemp 的参数 t，使其长度大于等于 50。但实际测试用例中 t 可能来自 tempnam()，长度通常受限，可控性存疑。
- 触发路径: static int _mkstemp(const char * t){ @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_08.c:29; size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_08.c:30; char s[50]; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_08.c:31; strncpy(s, t, l); // 若 l > 50，则溢出 @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_08.c:32
- 结论: 栈缓冲区溢出：strncpy 复制长度可能超过目标缓冲区大小，导致栈上缓冲区溢出，可能覆盖返回地址或局部变量。但输入 t 的可控性未经验证，实际测试用例中 t 可能来自 tempnam()，长度受限，因此漏洞可能不可触发。
- D验证: confirmed / ver_dccc093c
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 164. hyp_path_e9dca70dfd10

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_09.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121; CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够通过程序入口（如文件输入、环境变量等）向_mkstemp函数的参数t提供长度超过48的字符串。
- 触发路径: #define MKSTEMP _mkstemp static int _mkstemp(const char * t){ size_t l = strlen(t) + 1; char s[50]; strncpy(s, t, l); return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); } @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_09.c:28-35; size_t l = strlen(t) + 1; // l可能大于50 @ line 30; char s[50]; // 栈缓冲区大小50 @ line 31; strncpy(s, t, l); // 最多复制50字符，可能不添加null终止 @ line 32; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); // 写入s时使用l作为size，可能溢出 @ line 33
- 结论: 存在栈缓冲区溢出漏洞。函数_mkstemp中，当传入的模板字符串t长度大于48时，strncpy复制最多50个字符到栈数组s[50]，但后续调用_mktemp_s(s, l)时传入的size参数l为strlen(t)+1，该值可能大于50，导致_mktemp_s在s中写入临时文件名时超出缓冲区边界，造成栈溢出。
- D验证: confirmed / ver_11585434
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 165. hyp_path_f883a4b189e7

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_11.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够控制传递给_mkstemp的字符串t，例如通过环境变量或命令行参数，使其长度超过49个字符（不含null终止符）。
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_11.c:30; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_11.c:32; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_11.c:33
- 结论: 在_mkstemp函数中，使用strncpy复制字符串时，目标缓冲区s大小为50字节，但复制长度l由strlen(t)+1决定，如果t的长度大于等于50，则会导致栈缓冲区溢出。
- D验证: confirmed / ver_b8e5b66f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 166. hyp_path_0f034ae25888

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_12.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121; CWE-119
- 风险等级: P0
- 触发条件: 攻击者能够控制传入_mkstemp的参数t，使其长度大于等于50字节。
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_12.c:30; char s[50]; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_12.c:31-32; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_12.c:33
- 结论: 函数_mkstemp中，strncpy(s, t, l)在t长度≥50时可能导致栈缓冲区溢出，但t的来源未知，无法确认外部可控。
- D验证: confirmed / ver_d8dddc25
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 167. hyp_path_d424711fe3c4

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_15.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121; CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够向函数_mkstemp传递一个长度>=50的可控字符串参数t
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_15.c:30; char s[50]; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_15.c:32
- 结论: 缓冲区溢出漏洞：在函数_mkstemp中，使用strncpy将输入字符串t复制到固定大小（50字节）的栈缓冲区s时，复制长度l = strlen(t)+1，如果t的长度大于等于50，则会导致缓冲区溢出。
- D验证: confirmed / ver_c9d4c90f
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 168. hyp_path_f692ca76a384

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_14.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够向 _mkstemp 函数提供长度 >= 50 的字符串 t，且该输入来自外部可控源
- 触发路径: char s[50]; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_14.c:31; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_14.c:32
- 结论: 缓冲区溢出：strncpy 将过长字符串复制到固定大小缓冲区，可能导致栈溢出。
- D验证: confirmed / ver_a15419d9
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 169. hyp_path_6fc45bdbd40f

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_16.c:33
- 漏洞类型: command_injection
- CWE: CWE-121; CWE-787
- 风险等级: P0
- 触发条件: 攻击者能够控制`_mkstemp`函数的参数`t`，或通过调用链将攻击者可控数据传入该函数。
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_16.c:30; char s[50]; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_16.c:32
- 结论: 在`_mkstemp`函数中，使用`strncpy`将字符串复制到固定大小的栈缓冲区`s[50]`时，若输入字符串`t`的长度大于等于50，会导致栈缓冲区溢出。
- D验证: confirmed / ver_5b20e896
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 170. hyp_path_1fa1d5b82623

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_17.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够控制_mkstemp的参数t（如通过调用处传入长字符串）
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_17.c:30; char s[50]; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_17.c:31; strncpy(s, t, l); // 如果l>50，则溢出 @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_17.c:32
- 结论: 在函数_mkstemp中，使用strncpy将字符串t复制到固定大小的栈缓冲区s（大小50）时，未检查源字符串长度，可能导致栈缓冲区溢出。当t的长度大于等于50时，strncpy会复制超过缓冲区大小的数据，造成溢出。
- D验证: confirmed / ver_35937bb3
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 171. hyp_path_0da89aa2809a

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_01.c:33
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录并预测文件名; 攻击者能够在竞态窗口内创建文件
- 触发路径: char s[50]; strncpy(s, t, l); return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_01.c:31-35
- 结论: 函数_mkstemp使用tmpnam生成的可预测临时文件名，并在调用_mktemp_s和_open之间可能存在竞态条件，攻击者可以预测文件名并抢先创建同名的临时文件，导致_open失败（由于_O_EXCL标志），从而造成拒绝服务或信息泄露。
- D验证: confirmed / ver_c027c77d
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 172. hyp_path_21bd2d6dd176

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_13.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-120; CWE-170
- 风险等级: P0
- 触发条件: 攻击者能够控制传入_mkstemp的模板字符串t
- 触发路径: 传入长字符串t @ 函数入口_mkstemp(const char * t); strncpy(s, t, l); // l = strlen(t)+1，若t长度>=50，则s不空终止且溢出 @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_13.c:32; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); // s未空终止导致_mktemp_s越界读取 @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_13.c:33
- 结论: 在_mkstemp函数中，当输入的模板字符串t长度大于等于50时，strncpy无法保证空终止，导致s数组未null终止，随后传递给_mktemp_s可能造成缓冲区溢出或未初始化读取。
- D验证: confirmed / ver_5f1033d5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 173. hyp_path_00446f3cbbaf

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_18.c:33
- 漏洞类型: command_injection
- CWE: CWE-121; CWE-787
- 风险等级: P0
- 触发条件: 攻击者能够控制_mkstemp函数的参数t（例如通过文件名输入）
- 触发路径: size_t l = strlen(t) + 1; // l可能大于50 @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_18.c:30; char s[50]; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_18.c:31; strncpy(s, t, l); // 若l>50则越界写入 @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_18.c:32; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_18.c:33
- 结论: 缓冲区溢出漏洞：函数_mkstemp中，参数t的长度未经验证直接复制到固定大小(50字节)的局部数组s中，当t的长度大于等于50时，strncpy会写入超出数组边界的内存，导致栈缓冲区溢出。
- D验证: confirmed / ver_b0e350e4
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 174. hyp_path_a1645822c5af

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_04.c:33
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够预测tmpnam生成的临时文件名，并在文件创建前进行符号链接攻击。
- 触发路径: char s[50]; strncpy(s, t, l); return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_04.c:31-35
- 结论: 使用tmpnam生成临时文件名，导致不可预测的临时文件名，存在不安全临时文件漏洞（CWE-377）。
- D验证: confirmed / ver_e29eb9f1
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 175. hyp_path_0706b42ac6e1

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_02.c:33
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够在临时文件目录中创建符号链接; 临时文件名模板可预测（来自`tmpnam`等不安全函数）
- 触发路径: char* filename = tmpnam(NULL); @ 未在提供代码片段中显示（假设调用处）; static int _mkstemp(const char * t){ @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_02.c:29; char s[50]; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_02.c:32; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_02.c:33
- 结论: 代码中使用`_mkstemp`函数创建临时文件，但传入的文件名模板可能来源于不安全的`tmpnam`调用，导致临时文件名可预测。攻击者可在临时文件创建前创建符号链接，实现任意文件写入或信息泄露，存在CWE-377不安全临时文件漏洞。
- D验证: confirmed / ver_eae21165
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 176. hyp_path_621dd14c86e1

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_03.c:33
- 漏洞类型: CWE-377, CWE-367
- CWE: CWE-377; CWE-367
- 风险等级: P0
- 触发条件: 攻击者能够监听或预测tmpnam生成的临时文件名（例如通过观察文件系统或预测算法）
- 触发路径: #define MKSTEMP _mkstemp static int _mkstemp(const char * t){ @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_03.c:29; size_t l = strlen(t) + 1; char s[50]; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_03.c:31; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_03.c:33
- 结论: 在临时文件创建过程中存在TOCTOU（条件竞争）漏洞，使用tmpnam生成可预测的文件名，即使后续使用_O_EXCL标志，也无法原子地创建文件，攻击者可提前创建符号链接导致任意文件写入。
- D验证: confirmed / ver_9c8b2173
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 177. hyp_path_4fe4c6fa9c69

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_05.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121; CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够控制传入 `_mkstemp` 的字符串 `t` 的长度，使其大于等于50字节。
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_05.c:30; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_05.c:32; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_05.c:33
- 结论: 在 `_mkstemp` 函数中，`strncpy` 使用 `strlen(t)+1` 作为复制长度，当输入字符串 `t` 长度超过49时，会导致栈缓冲区溢出。同时 `_mktemp_s` 也使用了相同的长度参数，可能加剧越界。
- D验证: confirmed / ver_ebd278ea
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 178. hyp_path_4f4ae17949f1

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_07.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够向_mkstemp函数提供任意长度的字符串t，且该字符串长度超过49字节。
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_07.c:29; char s[50]; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_07.c:32; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_07.c:33
- 结论: 在_mkstemp函数中，当从参数t复制的字符串长度超过49字节时，strncpy可能导致栈缓冲区溢出，因为目标缓冲区s只有50字节，但复制长度l（strlen(t)+1）可能大于50。
- D验证: confirmed / ver_a79e50af
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 179. hyp_path_d2476c2c4551

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_08.c:33
- 漏洞类型: CWE-377
- CWE: CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够控制传入_mkstemp的模板字符串t，或能够影响模板字符串的生成过程。
- 触发路径: static int _mkstemp(const char * t){ @ CWE377_Insecure_Temporary_File__char_tmpnam_08.c:29; size_t l = strlen(t) + 1; char s[50]; strncpy(s, t, l); @ CWE377_Insecure_Temporary_File__char_tmpnam_08.c:30-32; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ CWE377_Insecure_Temporary_File__char_tmpnam_08.c:33
- 结论: 函数_mkstemp使用了_mktemp_s生成临时文件名，但模板参数t的来源未明确，可能来自外部输入或不可信源，存在不安全的临时文件创建漏洞（CWE-377）。当前代码证据未展示t的实际来源和调用上下文，无法确认攻击者能否控制t，因此漏洞路径不完整。
- D验证: confirmed / ver_f7a2ed60
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 180. hyp_path_0f46208ab258

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_06.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够控制_mkstemp的参数t，使其长度大于等于50。
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_06.c:30; strncpy(s, t, l); // s大小50，l可能大于50，导致缓冲区溢出 @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_06.c:32; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_06.c:33
- 结论: 函数_mkstemp中，strncpy拷贝时，若输入字符串t长度大于等于50，则目标缓冲区s（大小50）可能被溢出，因为strncpy会复制l=strlen(t)+1个字符，导致栈缓冲区溢出。但实际调用中t通常来自tmpnam，长度固定且小于20，不可控制，因此该路径的实际可利用性较低。
- D验证: confirmed / ver_97472349
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 181. hyp_path_7b7fbddf5837

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_09.c:33
- 漏洞类型: CWE-377, CWE-367
- CWE: CWE-377; CWE-367
- 风险等级: P0
- 触发条件: 攻击者能够访问临时文件目录并预测文件名; 目标程序使用 tmpnam 且未使用 O_EXCL 以外的保护
- 触发路径: size_t l = strlen(t) + 1; char s[50]; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_09.c:29-30; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_09.c:33
- 结论: 使用 tmpnam 生成临时文件名后，未在创建文件前对文件存在性进行原子检查，存在 TOCTOU 竞争条件，攻击者可提前创建恶意符号链接或文件，导致信息泄露或权限提升。
- D验证: confirmed / ver_82fbb01b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 182. hyp_path_de1b55a8adf6

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_13.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121; CWE-377
- 风险等级: P0
- 触发条件: 攻击者能够控制传入_mkstemp函数的字符串参数t，且t的长度至少为50。
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_13.c:31; char s[50]; strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_13.c:32
- 结论: 栈缓冲区溢出漏洞：函数_mkstemp使用固定大小的栈缓冲区char s[50]，并通过strncpy从输入参数t复制数据，复制长度为strlen(t)+1，如果t的长度大于等于50，则strncpy会写入超过s容量的数据，导致栈缓冲区溢出。
- D验证: confirmed / ver_ecb85193
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 183. hyp_path_a1eaabf14b23

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_11.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够控制传递给_mkstemp函数的字符串t的长度和内容
- 触发路径: strncpy(s, t, l); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_11.c:32
- 结论: 栈缓冲区溢出漏洞：在_mkstemp函数中，strncpy(s, t, l)将长度l（等于strlen(t)+1）的输入t复制到固定大小栈数组s[50]，若t长度≥50则溢出。但缺乏攻击者控制t的上下文证据，且B阶段风险评分低，无法确认漏洞可利用性。
- D验证: confirmed / ver_7ebcfc30
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 184. hyp_path_7ad7a2ff76d1

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_12.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够控制传入_mkstemp的参数t，使其长度大于等于50。
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_12.c:30; char s[50]; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_12.c:31; strncpy(s, t, l); return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_12.c:32-33
- 结论: 函数_mkstemp中，strncpy的第三个参数l由strlen(t)+1计算得出，若t的长度大于等于50，则拷贝的字符数会超过目标缓冲区s（大小为50）的边界，导致栈缓冲区溢出。此外，_mktemp_s的第二个参数l也被错误地用作缓冲区大小，可能引发额外溢出。但攻击者能否控制参数t尚不明确，证据不完整。
- D验证: confirmed / ver_b706ebb5
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 185. hyp_path_18bb0450be6e

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_14.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121
- 风险等级: P0
- 触发条件: 攻击者能够向_mkstemp函数提供任意长度（超过49）的字符串作为参数t。
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_14.c:30; char s[50]; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_14.c:31; strncpy(s, t, l); // 当l > 50时，写入越界 @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_14.c:32
- 结论: 栈缓冲区溢出：在函数_mkstemp中，使用strncpy将模板字符串t复制到固定大小（50字节）的栈缓冲区s时，未检查t的长度，若t长度超过49（包括null终止符），则strncpy会复制超出s边界的数据，导致缓冲区溢出。
- D验证: confirmed / ver_0044092a
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

### 186. hyp_path_70dc1656d3ee

- 漏洞位置: juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_18.c:33
- 漏洞类型: buffer_overflow
- CWE: CWE-121; CWE-119
- 风险等级: P0
- 触发条件: 攻击者能够控制传递给_mkstemp的参数t的长度（使其大于等于50）
- 触发路径: size_t l = strlen(t) + 1; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_18.c:30; char s[50]; @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_18.c:31; strncpy(s, t, l); // 当t长度>=50时，只复制49字符，但l仍为原始长度 @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_18.c:32; return _mktemp_s(s, l) ? -1 : _open(s, _O_CREAT|_O_EXCL); // l大于50，_mktemp_s可能越界写入 @ juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_18.c:33
- 结论: 在_mkstemp函数中，缓冲区s大小为50，但调用_mktemp_s时传入的长度l为strlen(t)+1，如果t的长度大于等于50，则实际缓冲区大小小于l，导致_mktemp_s可能写入超过s边界，引发栈缓冲区溢出。
- D验证: confirmed / ver_d9a6694b
- 运行证据: oracle matched patterns: MAGUS_JULIET_ROUTE_CONFIRMED

## Unconfirmed / Failed Verification

These records are not reported as confirmed vulnerabilities. See `verification.failed.jsonl` for full failure details.

- hyp_path_5c557f0460be | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_12.c:111 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9fbe3442d357 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_12.c:109 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_058d3274c363 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_12.c:134 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4326c3842b8b | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_12.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_051bd50897d1 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_12.c:132 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0314e94bafd4 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_07.c:99 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cdebf3191b8d | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_08.c:107 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1bf55c99389c | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_11.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a67872501b18 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_09.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_17f130387db5 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_08.c:134 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_17078b50ef8d | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_10.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4d64bd58a8ce | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_13.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8b52a7ad9c44 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_11.c:121 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_88498a368edc | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_14.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_46c490b5b6db | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_12.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bca178466776 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_05.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_406c93d3a32b | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_11.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6d8644e37cdf | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_08.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_63d784ea84cf | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_07.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cab715aa8a7f | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_08.c:132 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d41dc360d4ac | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_09.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c8669f5b93d0 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_11.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d809877c9eb3 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_10.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9fe4908905e1 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_13.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1d174b9f5613 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_14.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_dc9fa3c7ba7d | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_01.c:83 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_804ba89ff17d | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_17.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1fe0f46a831d | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_03.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1573e8f9cc58 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_02.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2a8a3201d21d | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_02.c:121 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5104e476486f | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_03.c:121 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d19beef13a5c | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_04.c:127 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_661282b31e3f | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_04.c:100 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1ae0504f70fe | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_05.c:127 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_37905ac87621 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_06.c:99 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0e60fdd82fd2 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_07.c:126 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_935fad44a37d | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_10.c:121 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_558b5993c87d | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_09.c:121 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b4c4f34fce22 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_14.c:121 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2c678be51f5c | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_13.c:121 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7298f71643b2 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_15.c:129 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_607860b80bdb | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_15.c:100 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5c1490c5d079 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_16.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d35b8e3924bf | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_18.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_19eeab8680a4 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_05.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8f92906c1627 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_08.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_38dc05c45dfd | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_07.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cb3bbfe5b84e | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_08.c:132 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3766d7a929a1 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_11.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_500592dc5b0d | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_13.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8732ed93f804 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_11.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4641cac4ae65 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_09.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_131de12ab881 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_11.c:95 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1aad854e6ff0 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_14.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0f653f427a1c | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_08.c:106 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0fb609ad959e | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_08.c:108 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_682f8733b341 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_11.c:93 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ab2077f38bfb | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_17.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ca917799574f | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_17.c:95 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f2f599d11093 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_02.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b6b49fa1b547 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_02.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3d836aa7b47d | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_01.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5057d55d1ef3 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_03.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2e1a7233d208 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_03.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_56d50cf0926b | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_04.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_125279e4d7ba | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_06.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d09d62bffc3c | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_05.c:125 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ffd8f43fe075 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_07.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7838b48d6c37 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_06.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3d53b183ba2a | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_04.c:125 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_91c71fbaffe8 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_09.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_14d0dc268dcd | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_10.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e23afd88c7b5 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_13.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0a3862088622 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_14.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cd29db03ab20 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_16.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e2eada57e6bc | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_15.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6f42033737c1 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_15.c:127 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5aa8ef430991 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_18.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ed0db82c2262 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_11.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_686e2395f7bb | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_08.c:131 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a9212624c54f | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_09.c:98 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8b000a001ebc | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_11.c:118 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4e8dfd0fb983 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_09.c:98 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4117f2f79bcc | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_11.c:118 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_96a30bbaf13f | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_05.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_df141074813c | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_11.c:117 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_543b6b1ab9e7 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_02.c:98 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d57ffa771c12 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_01.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8e3f365f890b | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_03.c:118 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f8454a08dfa7 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_04.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c638d8efa353 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_06.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bfa1c1578852 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_07.c:123 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bb8d71069e2d | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_15.c:104 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_89cc9ee2d862 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_14.c:118 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a16710f2600d | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_18.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a0dbc1411a4b | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_02.c:98 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aebe21f5b79b | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_07.c:123 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9e5060333882 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_05.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_36559869e2db | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_06.c:123 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b951f7bc4390 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_06.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_51ea3be805c9 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_14.c:118 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6d03c65e43f6 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_18.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7d11533054d6 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_16.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_958d284d5583 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_01.c:86 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8dbe4f0ce0b4 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_02.c:117 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b81e33651053 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_02.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_225b99e5f296 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_04.c:103 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_576bd4459ceb | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_04.c:123 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_63ac68ffa6a7 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_05.c:123 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1dcb39db6fcd | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_09.c:117 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_cf10fa9e6d38 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_14.c:117 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_018aeead5d81 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_10.c:117 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_a93ed6d4155d | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_16.c:93 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5097ff707dd2 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_17.c:88 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5bd06b47f159 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_17.c:90 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4fc2fa286360 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_17.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2c28c7cd3a9c | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_03.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_969cc1c7e552 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_02.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_36340545d6f8 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_03.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6831bf579e03 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_02.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_534e20787281 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_04.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_11744a326d08 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_01.c:80 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_321215fbf5ae | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_04.c:125 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_43f2e029602f | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_05.c:125 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2018dc31dba7 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_07.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7b7c32260018 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_06.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_310234e6fd14 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_06.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4262d76f949c | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_09.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_10e460ce38b8 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_14.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_75e09fecf826 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_13.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_857055a2e8b6 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_10.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5c6a8d0c2be6 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_15.c:97 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ccc444a6a8ca | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_18.c:85 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_09490f9dbea1 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_16.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b2f3bda7f3b1 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_15.c:127 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0160f466eede | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_05.c:101 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_48ce81332d7c | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_10.c:95 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1706ea5ffb65 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_08.c:135 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_02febbb7e824 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_09.c:95 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_53158f4d59f9 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_11.c:122 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c118054fc9fa | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_13.c:95 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_046e71d6135a | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_05.c:99 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_17b11d6becbb | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_07.c:98 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_36a4ef94a825 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_14.c:95 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6827d4ce65e8 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_08.c:132 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2ada2e9715ee | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_10.c:93 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_869e72025395 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_11.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_90bd789937d8 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_13.c:93 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1392bc169229 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_09.c:93 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_41e528801aac | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_14.c:93 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_65fa12f84426 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_02.c:95 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3ff2292ca464 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_01.c:84 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_554388d4da38 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_03.c:95 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_15aefd05176b | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_02.c:122 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_78548a6c5532 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_03.c:122 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4d159972e01c | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_04.c:128 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2830f7137231 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_04.c:101 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1fd442c570eb | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_05.c:128 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_26c9d968367f | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_06.c:100 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_96b7b135164e | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_07.c:127 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_11d29c5f0f21 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_06.c:127 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c4355d1221cf | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_09.c:122 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_64d97cdacbfc | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_13.c:122 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_27258aa84d9e | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_10.c:122 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_529a1e42bdd7 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_15.c:101 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_60ef57eb02b7 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_14.c:122 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7e4b4d478b0f | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_15.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0cf3a7e0a049 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_18.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_aee74c3eee85 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_01.c:82 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_24c57e09c9d8 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_16.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_571e56338f16 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_02.c:93 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9ee5e1867e8f | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_02.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_52706e767f39 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_03.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1f70d986a51a | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_04.c:99 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9f4429f974a0 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_04.c:125 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_01206d897c74 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_06.c:98 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_171c1a6ef3a2 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_06.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_87a01d3c9164 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_05.c:125 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0c7cfb9fb5a0 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_07.c:124 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_234e3f23312b | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_10.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_53efb9ea7448 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_09.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0c80c4720fd0 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_13.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_075506b1373f | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_14.c:119 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_805630bc4af9 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_15.c:99 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_725f5e38413d | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_18.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_133408f04e41 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_16.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_188fd2a19ab7 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_11.c:127 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_112d80a69c2a | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_07.c:132 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3fd9b26d8ace | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tempnam_15.c:139 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_46bcef050a8b | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_02.c:127 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_ade69b97a427 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_05.c:134 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0fb3fc59ad67 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_06.c:133 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_12cc2375b045 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_04.c:134 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0f2848c0414f | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_09.c:128 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3b5ac6fd961a | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_10.c:127 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5291dbe14c27 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_08.c:141 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_729dc9436bc7 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_11.c:128 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_525fffd352da | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_13.c:128 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5ce1d24089e0 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_03.c:131 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0c21a2a955de | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_15.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0b4b1149764f | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_14.c:127 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3dd2a652a3d7 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_02.c:131 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3c935083a573 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_04.c:137 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_081e9f549a05 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_06.c:135 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9ff874288d0d | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_05.c:137 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5030de47e3c0 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_07.c:136 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f060157d4961 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_10.c:131 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4ec92db8a9e3 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_13.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4af298e5af70 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_11.c:131 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2d3ced21cfb3 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_09.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1f23c3f7d26e | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_14.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_7f6a005f0a97 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_03.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5e2b8135e58d | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_15.c:143 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_29f0d477f77f | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_05.c:136 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6cf5e292b5e2 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_02.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4820c95a7386 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_04.c:136 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f3a0d96f484c | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_06.c:135 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_254b9d20f981 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_07.c:135 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4945fa0138ac | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_08.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bd18c4aa7ede | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_13.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3ceae858a7b6 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_09.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0679514de11b | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_11.c:131 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_20a02fb98cb7 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_02.c:128 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_23825151817b | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_10.c:130 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_65946154c730 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_15.c:144 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_d25cf9064c6a | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_05.c:133 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_487d8cbda228 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_14.c:131 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9cc1e899a3af | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_03.c:128 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_62d20f349a34 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_06.c:132 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5b7340706421 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_04.c:134 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2cf3a7c96367 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_07.c:132 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1ae67e59bc66 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_08.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0389dfdb929c | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_09.c:127 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3b71c201aa8e | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_10.c:128 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_0e98b82a00bb | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_14.c:127 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6d98e986b6cf | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_15.c:141 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_90c12536ecc0 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_11.c:128 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_15882db2ed3c | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_03.c:127 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8fe754af4b0c | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_04.c:134 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_03d7f5474864 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_02.c:127 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_2a7d9936c72e | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_07.c:133 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8c66b2cc8641 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_09.c:127 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_52bdbfeb1a45 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_08.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_29a04acbd5fb | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_06.c:133 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_23c3bd5e637a | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_14.c:127 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_16e5fc3cbe9e | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_13.c:127 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3324a3f06711 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_15.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_3769a6c5551b | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_10.c:128 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_520b819a1e93 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_01.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_e473d11e4ab4 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_mktemp_18.c:99 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_25c79870e778 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_tmpnam_16.c:102 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_42c09a0765da | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_12.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f4ef3587b642 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_16.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8a2b7b5b4cdb | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_01.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_4cfd8d856569 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_17.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_749720e2c285 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_16.c:100 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_f4f85289cc87 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_17.c:100 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8e29ce832156 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_01.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_bbb66a599dd9 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_12.c:142 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8f3ddb926f47 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__char_w32GetTempFileName_18.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_729eaea4c5c2 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_mktemp_18.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_79acfa513802 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_12.c:142 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_40ee446fcca8 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_01.c:91 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_6e52aacaebce | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_17.c:100 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b1ff94e773c5 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_12.c:138 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b1b56b96baec | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_18.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_b8035e999628 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_01.c:89 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_1d61e70b3754 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_16.c:98 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_c4e96b56c82c | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_17.c:98 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_476c39538b16 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tempnam_16.c:100 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8f2419382472 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_tmpnam_18.c:94 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_8064cdfd8255 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_01.c:87 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_895d431fb7e8 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_12.c:140 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_5c3a11662839 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_16.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_9eccef389ffc | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_17.c:96 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_da6860419e1a | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/CWE377_Insecure_Temporary_File__wchar_t_w32GetTempFileName_18.c:92 | NOT_EXPLOITABLE | payload did not satisfy oracle
- hyp_path_073452443df8 | juliet-api-misuse/testcases/CWE377_Insecure_Temporary_File/main_linux.cpp:237 | ENV_MISSING | payload did not satisfy oracle
