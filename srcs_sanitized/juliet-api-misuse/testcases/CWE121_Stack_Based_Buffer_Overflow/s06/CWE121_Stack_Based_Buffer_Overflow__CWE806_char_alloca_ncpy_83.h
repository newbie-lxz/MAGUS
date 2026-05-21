/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_83.h
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE806.label.xml
Template File: sources-sink-83.tmpl.h
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Initialize data as a large string
 * Case1Source: Initialize data as a small string
 * Sinks: ncpy
 *    Case0Sink : Copy data to string using strncpy
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_83
{

#ifndef OMITCASE0

class CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_83_case0
{
public:
    CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_83_case0(char * dataCopy);
    ~CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_83_case0();

private:
    char * data;
};

#endif /* OMITCASE0 */

#ifndef OMITCASE1

class CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_83_case1V1
{
public:
    CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_83_case1V1(char * dataCopy);
    ~CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncpy_83_case1V1();

private:
    char * data;
};

#endif /* OMITCASE1 */

}
