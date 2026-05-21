/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memcpy_54d.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.label.xml
Template File: sources-sink-54d.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Set data pointer to the case0 buffer
 * Case1Source: Set data pointer to the case1 buffer
 * Sink: memcpy
 *    Case0Sink : Copy int array to data using memcpy
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITCASE0

/* case0 function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memcpy_54e_case0Sink(int * data);

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memcpy_54d_case0Sink(int * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memcpy_54e_case0Sink(data);
}

#endif /* OMITCASE0 */

#ifndef OMITCASE1

/* case1 function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memcpy_54e_case1V1Sink(int * data);

/* case1V1 uses the Case1Source with the Case0Sink */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memcpy_54d_case1V1Sink(int * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_memcpy_54e_case1V1Sink(data);
}

#endif /* OMITCASE1 */
