/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE806_wchar_t_declare_memmove_82.h
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE806.label.xml
Template File: sources-sink-82.tmpl.h
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Initialize data as a large string
 * Case1Source: Initialize data as a small string
 *    Case0Sink : Copy data to string using memmove
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE121_Stack_Based_Buffer_Overflow__CWE806_wchar_t_declare_memmove_82
{

class CWE121_Stack_Based_Buffer_Overflow__CWE806_wchar_t_declare_memmove_82_base
{
public:
    /* pure virtual function */
    virtual void action(wchar_t * data) = 0;
};

#ifndef OMITCASE0

class CWE121_Stack_Based_Buffer_Overflow__CWE806_wchar_t_declare_memmove_82_case0 : public CWE121_Stack_Based_Buffer_Overflow__CWE806_wchar_t_declare_memmove_82_base
{
public:
    void action(wchar_t * data);
};

#endif /* OMITCASE0 */

#ifndef OMITCASE1

class CWE121_Stack_Based_Buffer_Overflow__CWE806_wchar_t_declare_memmove_82_case1V1 : public CWE121_Stack_Based_Buffer_Overflow__CWE806_wchar_t_declare_memmove_82_base
{
public:
    void action(wchar_t * data);
};

#endif /* OMITCASE1 */

}
