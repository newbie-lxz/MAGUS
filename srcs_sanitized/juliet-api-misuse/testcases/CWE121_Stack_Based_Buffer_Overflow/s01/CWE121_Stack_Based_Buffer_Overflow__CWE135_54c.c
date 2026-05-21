/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE135_54c.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE135.label.xml
Template File: sources-sinks-54c.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Void pointer to a wchar_t array
 * Case1Source: Void pointer to a char array
 * Sinks:
 *    Case1Sink: Allocate memory using wcslen() and copy data
 *    Case0Sink : Allocate memory using strlen() and copy data
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#define WIDE_STRING L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define CHAR_STRING "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

#ifndef OMITCASE0

/* case0 function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE135_54d_case0Sink(void * data);

void CWE121_Stack_Based_Buffer_Overflow__CWE135_54c_case0Sink(void * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE135_54d_case0Sink(data);
}

#endif /* OMITCASE0 */

#ifndef OMITCASE1

/* case1V1 uses the Case1Source with the Case0Sink */
void CWE121_Stack_Based_Buffer_Overflow__CWE135_54d_case1V1Sink(void * data);

void CWE121_Stack_Based_Buffer_Overflow__CWE135_54c_case1V1Sink(void * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE135_54d_case1V1Sink(data);
}

/* case1V2 uses the Case0Source with the Case1Sink */
void CWE121_Stack_Based_Buffer_Overflow__CWE135_54d_case1V2Sink(void * data);

void CWE121_Stack_Based_Buffer_Overflow__CWE135_54c_case1V2Sink(void * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE135_54d_case1V2Sink(data);
}

#endif /* OMITCASE1 */
