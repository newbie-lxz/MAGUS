/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE135_67b.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE135.label.xml
Template File: sources-sinks-67b.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Void pointer to a wchar_t array
 * Case1Source: Void pointer to a char array
 * Sinks:
 *    Case1Sink: Allocate memory using wcslen() and copy data
 *    Case0Sink : Allocate memory using strlen() and copy data
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#define WIDE_STRING L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define CHAR_STRING "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

typedef struct _CWE121_Stack_Based_Buffer_Overflow__CWE135_67_structType
{
    void * structFirst;
} CWE121_Stack_Based_Buffer_Overflow__CWE135_67_structType;

#ifndef OMITCASE0

void CWE121_Stack_Based_Buffer_Overflow__CWE135_67b_case0Sink(CWE121_Stack_Based_Buffer_Overflow__CWE135_67_structType myStruct)
{
    void * data = myStruct.structFirst;
    {
        /* NOTE: treating pointer as a char* when it may point to a wide string */
        size_t dataLen = strlen((char *)data);
        void * dest = (void *)ALLOCA((dataLen+1) * sizeof(wchar_t));
        (void)wcscpy(dest, data);
        printLine((char *)dest);
    }
}

#endif /* OMITCASE0 */

#ifndef OMITCASE1

/* case1V1 uses the Case1Source with the Case0Sink */
void CWE121_Stack_Based_Buffer_Overflow__CWE135_67b_case1V1Sink(CWE121_Stack_Based_Buffer_Overflow__CWE135_67_structType myStruct)
{
    void * data = myStruct.structFirst;
    {
        /* NOTE: treating pointer as a char* when it may point to a wide string */
        size_t dataLen = strlen((char *)data);
        void * dest = (void *)ALLOCA((dataLen+1) * 1);
        (void)strcpy(dest, data);
        printLine((char *)dest);
    }
}

/* case1V2 uses the Case0Source with the Case1Sink */
void CWE121_Stack_Based_Buffer_Overflow__CWE135_67b_case1V2Sink(CWE121_Stack_Based_Buffer_Overflow__CWE135_67_structType myStruct)
{
    void * data = myStruct.structFirst;
    {
        /* ALT: treating pointer like a wchar_t*  */
        size_t dataLen = wcslen((wchar_t *)data);
        void * dest = (void *)ALLOCA((dataLen+1) * sizeof(wchar_t));
        (void)wcscpy(dest, data);
        printWLine((wchar_t *)dest);
    }
}

#endif /* OMITCASE1 */
