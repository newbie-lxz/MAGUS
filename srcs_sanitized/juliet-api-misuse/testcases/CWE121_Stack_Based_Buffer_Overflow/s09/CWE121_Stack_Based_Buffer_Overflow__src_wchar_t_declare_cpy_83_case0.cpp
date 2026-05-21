/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_declare_cpy_83_case0.cpp
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__src.label.xml
Template File: sources-sink-83_case0.tmpl.cpp
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Initialize data as a large string
 * Case1Source: Initialize data as a small string
 * Sinks: cpy
 *    Case0Sink : Copy data to string using wcscpy
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */
#ifndef OMITCASE0

#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_declare_cpy_83.h"

namespace CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_declare_cpy_83
{
CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_declare_cpy_83_case0::CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_declare_cpy_83_case0(wchar_t * dataCopy)
{
    data = dataCopy;
    /* NOTE: Initialize data as a large buffer that is larger than the small buffer used in the sink */
    wmemset(data, L'A', 100-1); /* fill with L'A's */
    data[100-1] = L'\0'; /* null terminate */
}

CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_declare_cpy_83_case0::~CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_declare_cpy_83_case0()
{
    {
        wchar_t dest[50] = L"";
        /* NOTE: Possible buffer overflow if data is larger than dest */
        wcscpy(dest, data);
        printWLine(data);
    }
}
}
#endif /* OMITCASE0 */
