/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncat_54d.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.string.label.xml
Template File: sources-sink-54d.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Set data pointer to the case0 buffer
 * Case1Source: Set data pointer to the case1 buffer
 * Sink: ncat
 *    Case0Sink : Copy string to data using strncat
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITCASE0

/* case0 function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncat_54e_case0Sink(char * data);

void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncat_54d_case0Sink(char * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncat_54e_case0Sink(data);
}

#endif /* OMITCASE0 */

#ifndef OMITCASE1

/* case1 function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncat_54e_case1V1Sink(char * data);

/* case1V1 uses the Case1Source with the Case0Sink */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncat_54d_case1V1Sink(char * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE805_char_alloca_ncat_54e_case1V1Sink(data);
}

#endif /* OMITCASE1 */
