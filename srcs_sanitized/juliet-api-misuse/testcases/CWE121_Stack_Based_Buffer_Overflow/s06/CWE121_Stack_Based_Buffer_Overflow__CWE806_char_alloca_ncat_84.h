/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_84.h
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE806.label.xml
Template File: sources-sink-84.tmpl.h
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Initialize data as a large string
 * Case1Source: Initialize data as a small string
 * Sinks: ncat
 *    Case0Sink : Copy data to string using strncat
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_84
{

#ifndef OMITCASE0

class CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_84_case0
{
public:
    CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_84_case0(char * dataCopy);
    ~CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_84_case0();

private:
    char * data;
};

#endif /* OMITCASE0 */

#ifndef OMITCASE1

class CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_84_case1V1
{
public:
    CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_84_case1V1(char * dataCopy);
    ~CWE121_Stack_Based_Buffer_Overflow__CWE806_char_alloca_ncat_84_case1V1();

private:
    char * data;
};

#endif /* OMITCASE1 */

}
