/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_ncpy_52b.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE193.label.xml
Template File: sources-sink-52b.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Point data to a buffer that does not have space for a NULL terminator
 * Case1Source: Point data to a buffer that includes space for a NULL terminator
 * Sink: ncpy
 *    Case0Sink : Copy string to data using strncpy()
 * Flow Variant: 52 Data flow: data passed as an argument from one function to another to another in three different source files
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
void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_ncpy_52c_case0Sink(char * data);

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_ncpy_52b_case0Sink(char * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_ncpy_52c_case0Sink(data);
}

#endif /* OMITCASE0 */

#ifndef OMITCASE1

/* case1 function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_ncpy_52c_case1V1Sink(char * data);

/* case1V1 uses the Case1Source with the Case0Sink */
void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_ncpy_52b_case1V1Sink(char * data)
{
    CWE121_Stack_Based_Buffer_Overflow__CWE193_char_alloca_ncpy_52c_case1V1Sink(data);
}

#endif /* OMITCASE1 */
