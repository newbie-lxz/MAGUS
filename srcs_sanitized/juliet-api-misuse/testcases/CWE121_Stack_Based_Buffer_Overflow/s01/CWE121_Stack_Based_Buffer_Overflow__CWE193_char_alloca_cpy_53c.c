/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_53c.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE193.label.xml
Template File: sources-sink-53c.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Point data to a buffer that does not have space for a NULL terminator
 * Case1Source: Point data to a buffer that includes space for a NULL terminator
 * Sink: cpy
 *    Case0Sink : Copy string to data using strcpy()
 * Flow Variant: 53 Data flow: data passed as an argument from one function through two others to a fourth; all four functions are in different source files
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

/* MAINTENANCE NOTE: The length of this string should equal the 10 */
#define SRC_STRING "AAAAAAAAAA"

/* all the sinks are the same, we just want to know where the hit originated if a tool flags one */

#ifndef OMITCASE0

/* case0 function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_53d_case0Sink(char * data);

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_53c_case0Sink(char * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_53d_case0Sink(data);
}

#endif /* OMITCASE0 */

#ifndef OMITCASE1

/* case1 function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_53d_case1V1Sink(char * data);

/* case1V1 uses the Case1Source with the Case0Sink */
void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_53c_case1V1Sink(char * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_cpy_53d_case1V1Sink(data);
}

#endif /* OMITCASE1 */
