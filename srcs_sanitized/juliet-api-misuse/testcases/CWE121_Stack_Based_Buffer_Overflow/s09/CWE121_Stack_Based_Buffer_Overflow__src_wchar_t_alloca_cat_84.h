/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_alloca_cat_84.h
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__src.label.xml
Template File: sources-sink-84.tmpl.h
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Initialize data as a large string
 * Case1Source: Initialize data as a small string
 * Sinks: cat
 *    Case0Sink : Copy data to string using wcscat
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_alloca_cat_84
{

#ifndef OMITCASE0

class CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_alloca_cat_84_case0
{
public:
    CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_alloca_cat_84_case0(wchar_t * dataCopy);
    ~CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_alloca_cat_84_case0();

private:
    wchar_t * data;
};

#endif /* OMITCASE0 */

#ifndef OMITCASE1

class CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_alloca_cat_84_case1V1
{
public:
    CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_alloca_cat_84_case1V1(wchar_t * dataCopy);
    ~CWE121_Stack_Based_Buffer_Overflow__src_wchar_t_alloca_cat_84_case1V1();

private:
    wchar_t * data;
};

#endif /* OMITCASE1 */

}
