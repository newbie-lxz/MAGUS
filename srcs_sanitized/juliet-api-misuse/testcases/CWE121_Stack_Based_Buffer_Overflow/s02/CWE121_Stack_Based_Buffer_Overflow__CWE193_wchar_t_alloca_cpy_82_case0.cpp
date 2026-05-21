/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_cpy_82_case0.cpp
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE193.label.xml
Template File: sources-sink-82_case0.tmpl.cpp
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Point data to a buffer that does not have space for a NULL terminator
 * Case1Source: Point data to a buffer that includes space for a NULL terminator
 * Sinks: cpy
 *    Case0Sink : Copy string to data using wcscpy()
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */
#ifndef OMITCASE0

#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_cpy_82.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_cpy_82
{

void CWE121_Stack_Based_Buffer_Overflow__CWE193_wchar_t_alloca_cpy_82_case0::action(wchar_t * data)
{
    {
        wchar_t source[10+1] = SRC_STRING;
        /* NOTE: data may not have enough space to hold source */
        wcscpy(data, source);
        printWLine(data);
    }
}

}
#endif /* OMITCASE0 */
