# Lazy Juliet Runs

These commands mirror `test/README.md`: run MAGUS on `srcs_sanitized`, and let the evaluation script map sanitized report paths back to the original Juliet tree under `srcs` for ground truth.

Run the one-time setup first:

```bash
export LLVM_HOME=/usr/lib/llvm-20
export PATH="$LLVM_HOME/bin:$PATH"

python3 tools/sanitize_juliet_tree.py \
  --input srcs \
  --output srcs_sanitized \
  --force

(cd d/memberD_verifier/01_demo_test && ./01_setup_linux.sh)
```

Stage C calls the configured OpenAI-compatible LLM client, so set the required API credentials in the same shell before running a folder command.

Load this helper once in the shell:

```bash
run_juliet_folder() {
  local cwe_dir="$1"
  local cwe_id="$2"

  python3 tools/gen_srcs_compile_commands.py \
    --repo-path srcs_sanitized \
    --output "srcs_sanitized/compile_commands.${cwe_id}.json" \
    --source-glob "juliet-api-misuse/testcases/${cwe_dir}/**/*.c" \
    --source-glob "juliet-api-misuse/testcases/${cwe_dir}/**/*.cc" \
    --source-glob "juliet-api-misuse/testcases/${cwe_dir}/**/*.cpp" \
    --source-glob "juliet-api-misuse/testcases/${cwe_dir}/**/*.cxx" \
    --include-dir ../tools/juliet_win_shim \
    --include-dir juliet-api-misuse/testcasesupport \
    --force

  python3 pipeline.py gen-input \
    --repo-path srcs_sanitized \
    --compile-commands "srcs_sanitized/compile_commands.${cwe_id}.json" \
    --output "a/input/srcs.${cwe_id}.in.jsonl" \
    --project-id "${cwe_id}" \
    --force

  python3 test/evaluate_juliet_report.py \
    --run-command "python3 pipeline.py abcd --a-input a/input/srcs.${cwe_id}.in.jsonl --a-output a/out/srcs.${cwe_id}.raw.jsonl --b-output-dir b/b_output_${cwe_id} --c-output c/out/${cwe_id}.hypotheses.jsonl" \
    --scope-compile-commands "srcs_sanitized/compile_commands.${cwe_id}.json"
}
```

## CWE114_Process_Control

```bash
run_juliet_folder 'CWE114_Process_Control' 'cwe114'
```

## CWE121_Stack_Based_Buffer_Overflow

```bash
run_juliet_folder 'CWE121_Stack_Based_Buffer_Overflow' 'cwe121'
```

## CWE122_Heap_Based_Buffer_Overflow

```bash
run_juliet_folder 'CWE122_Heap_Based_Buffer_Overflow' 'cwe122'
```

## CWE124_Buffer_Underwrite

```bash
run_juliet_folder 'CWE124_Buffer_Underwrite' 'cwe124'
```

## CWE126_Buffer_Overread

```bash
run_juliet_folder 'CWE126_Buffer_Overread' 'cwe126'
```

## CWE127_Buffer_Underread

```bash
run_juliet_folder 'CWE127_Buffer_Underread' 'cwe127'
```

## CWE134_Uncontrolled_Format_String

```bash
run_juliet_folder 'CWE134_Uncontrolled_Format_String' 'cwe134'
```

## CWE15_External_Control_of_System_or_Configuration_Setting

```bash
run_juliet_folder 'CWE15_External_Control_of_System_or_Configuration_Setting' 'cwe15'
```

## CWE226_Sensitive_Information_Uncleared_Before_Release

```bash
run_juliet_folder 'CWE226_Sensitive_Information_Uncleared_Before_Release' 'cwe226'
```

## CWE23_Relative_Path_Traversal

```bash
run_juliet_folder 'CWE23_Relative_Path_Traversal' 'cwe23'
```

## CWE242_Use_of_Inherently_Dangerous_Function

```bash
run_juliet_folder 'CWE242_Use_of_Inherently_Dangerous_Function' 'cwe242'
```

## CWE244_Heap_Inspection

```bash
run_juliet_folder 'CWE244_Heap_Inspection' 'cwe244'
```

## CWE247_Reliance_on_DNS_Lookups_in_Security_Decision

```bash
run_juliet_folder 'CWE247_Reliance_on_DNS_Lookups_in_Security_Decision' 'cwe247'
```

## CWE252_Unchecked_Return_Value

```bash
run_juliet_folder 'CWE252_Unchecked_Return_Value' 'cwe252'
```

## CWE253_Incorrect_Check_of_Function_Return_Value

```bash
run_juliet_folder 'CWE253_Incorrect_Check_of_Function_Return_Value' 'cwe253'
```

## CWE272_Least_Privilege_Violation

```bash
run_juliet_folder 'CWE272_Least_Privilege_Violation' 'cwe272'
```

## CWE273_Improper_Check_for_Dropped_Privileges

```bash
run_juliet_folder 'CWE273_Improper_Check_for_Dropped_Privileges' 'cwe273'
```

## CWE319_Cleartext_Tx_Sensitive_Info

```bash
run_juliet_folder 'CWE319_Cleartext_Tx_Sensitive_Info' 'cwe319'
```

## CWE325_Missing_Required_Cryptographic_Step

```bash
run_juliet_folder 'CWE325_Missing_Required_Cryptographic_Step' 'cwe325'
```

## CWE327_Use_Broken_Crypto

```bash
run_juliet_folder 'CWE327_Use_Broken_Crypto' 'cwe327'
```

## CWE328_Reversible_One_Way_Hash

```bash
run_juliet_folder 'CWE328_Reversible_One_Way_Hash' 'cwe328'
```

## CWE338_Weak_PRNG

```bash
run_juliet_folder 'CWE338_Weak_PRNG' 'cwe338'
```

## CWE367_TOC_TOU

```bash
run_juliet_folder 'CWE367_TOC_TOU' 'cwe367'
```

## CWE36_Absolute_Path_Traversal

```bash
run_juliet_folder 'CWE36_Absolute_Path_Traversal' 'cwe36'
```

## CWE377_Insecure_Temporary_File

```bash
run_juliet_folder 'CWE377_Insecure_Temporary_File' 'cwe377'
```

## CWE390_Error_Without_Action

```bash
run_juliet_folder 'CWE390_Error_Without_Action' 'cwe390'
```

## CWE391_Unchecked_Error_Condition

```bash
run_juliet_folder 'CWE391_Unchecked_Error_Condition' 'cwe391'
```

## CWE401_Memory_Leak

```bash
run_juliet_folder 'CWE401_Memory_Leak' 'cwe401'
```

## CWE404_Improper_Resource_Shutdown

```bash
run_juliet_folder 'CWE404_Improper_Resource_Shutdown' 'cwe404'
```

## CWE415_Double_Free

```bash
run_juliet_folder 'CWE415_Double_Free' 'cwe415'
```

## CWE416_Use_After_Free

```bash
run_juliet_folder 'CWE416_Use_After_Free' 'cwe416'
```

## CWE426_Untrusted_Search_Path

```bash
run_juliet_folder 'CWE426_Untrusted_Search_Path' 'cwe426'
```

## CWE427_Uncontrolled_Search_Path_Element

```bash
run_juliet_folder 'CWE427_Uncontrolled_Search_Path_Element' 'cwe427'
```

## CWE459_Incomplete_Cleanup

```bash
run_juliet_folder 'CWE459_Incomplete_Cleanup' 'cwe459'
```

## CWE475_Undefined_Behavior_for_Input_to_API

```bash
run_juliet_folder 'CWE475_Undefined_Behavior_for_Input_to_API' 'cwe475'
```

## CWE479_Signal_Handler_Use_of_Non_Reentrant_Function

```bash
run_juliet_folder 'CWE479_Signal_Handler_Use_of_Non_Reentrant_Function' 'cwe479'
```

## CWE590_Free_Memory_Not_on_Heap

```bash
run_juliet_folder 'CWE590_Free_Memory_Not_on_Heap' 'cwe590'
```

## CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory

```bash
run_juliet_folder 'CWE591_Sensitive_Data_Storage_in_Improperly_Locked_Memory' 'cwe591'
```

## CWE605_Multiple_Binds_Same_Port

```bash
run_juliet_folder 'CWE605_Multiple_Binds_Same_Port' 'cwe605'
```

## CWE665_Improper_Initialization

```bash
run_juliet_folder 'CWE665_Improper_Initialization' 'cwe665'
```

## CWE666_Operation_on_Resource_in_Wrong_Phase_of_Lifetime

```bash
run_juliet_folder 'CWE666_Operation_on_Resource_in_Wrong_Phase_of_Lifetime' 'cwe666'
```

## CWE667_Improper_Locking

```bash
run_juliet_folder 'CWE667_Improper_Locking' 'cwe667'
```

## CWE672_Operation_on_Resource_After_Expiration_or_Release

```bash
run_juliet_folder 'CWE672_Operation_on_Resource_After_Expiration_or_Release' 'cwe672'
```

## CWE675_Duplicate_Operations_on_Resource

```bash
run_juliet_folder 'CWE675_Duplicate_Operations_on_Resource' 'cwe675'
```

## CWE676_Use_of_Potentially_Dangerous_Function

```bash
run_juliet_folder 'CWE676_Use_of_Potentially_Dangerous_Function' 'cwe676'
```

## CWE680_Integer_Overflow_to_Buffer_Overflow

```bash
run_juliet_folder 'CWE680_Integer_Overflow_to_Buffer_Overflow' 'cwe680'
```

## CWE685_Function_Call_With_Incorrect_Number_of_Arguments

```bash
run_juliet_folder 'CWE685_Function_Call_With_Incorrect_Number_of_Arguments' 'cwe685'
```

## CWE688_Function_Call_With_Incorrect_Variable_or_Reference_as_Argument

```bash
run_juliet_folder 'CWE688_Function_Call_With_Incorrect_Variable_or_Reference_as_Argument' 'cwe688'
```

## CWE690_NULL_Deref_From_Return

```bash
run_juliet_folder 'CWE690_NULL_Deref_From_Return' 'cwe690'
```

## CWE761_Free_Pointer_Not_at_Start_of_Buffer

```bash
run_juliet_folder 'CWE761_Free_Pointer_Not_at_Start_of_Buffer' 'cwe761'
```

## CWE762_Mismatched_Memory_Management_Routines

```bash
run_juliet_folder 'CWE762_Mismatched_Memory_Management_Routines' 'cwe762'
```

## CWE773_Missing_Reference_to_Active_File_Descriptor_or_Handle

```bash
run_juliet_folder 'CWE773_Missing_Reference_to_Active_File_Descriptor_or_Handle' 'cwe773'
```

## CWE775_Missing_Release_of_File_Descriptor_or_Handle

```bash
run_juliet_folder 'CWE775_Missing_Release_of_File_Descriptor_or_Handle' 'cwe775'
```

## CWE780_Use_of_RSA_Algorithm_Without_OAEP

```bash
run_juliet_folder 'CWE780_Use_of_RSA_Algorithm_Without_OAEP' 'cwe780'
```

## CWE785_Path_Manipulation_Function_Without_Max_Sized_Buffer

```bash
run_juliet_folder 'CWE785_Path_Manipulation_Function_Without_Max_Sized_Buffer' 'cwe785'
```

## CWE789_Uncontrolled_Mem_Alloc

```bash
run_juliet_folder 'CWE789_Uncontrolled_Mem_Alloc' 'cwe789'
```

## CWE78_OS_Command_Injection

```bash
run_juliet_folder 'CWE78_OS_Command_Injection' 'cwe78'
```

## CWE832_Unlock_of_Resource_That_is_Not_Locked

```bash
run_juliet_folder 'CWE832_Unlock_of_Resource_That_is_Not_Locked' 'cwe832'
```

## CWE90_LDAP_Injection

```bash
run_juliet_folder 'CWE90_LDAP_Injection' 'cwe90'
```
