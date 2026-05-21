/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE135_61b.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE135.label.xml
Template File: sources-sinks-61b.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Void pointer to a wchar_t array
 * Case1Source: Void pointer to a char array
 * Sinks:
 *    Case1Sink: Allocate memory using wcslen() and copy data
 *    Case0Sink : Allocate memory using strlen() and copy data
 * Flow Variant: 61 Data flow: data returned from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#define WIDE_STRING L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define CHAR_STRING "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

#ifndef OMITCASE0

void * CWE121_Stack_Based_Buffer_Overflow__CWE135_61b_case0Source(void * data)
{
    /* NOTE: Set data to point to a wide string */
    data = (void *)WIDE_STRING;
    return data;
}

#endif /* OMITCASE0 */

#ifndef OMITCASE1

/* case1V1() uses the Case1Source with the Case0Sink */
void * CWE121_Stack_Based_Buffer_Overflow__CWE135_61b_case1V1Source(void * data)
{
    /* ALT: Set data to point to a char string */
    data = (void *)CHAR_STRING;
    return data;
}

/* case1V2() uses the Case0Source with the Case1Sink */
void * CWE121_Stack_Based_Buffer_Overflow__CWE135_61b_case1V2Source(void * data)
{
    /* NOTE: Set data to point to a wide string */
    data = (void *)WIDE_STRING;
    return data;
}

#endif /* OMITCASE1 */
