/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_81.h
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.label.xml
Template File: sources-sink-81.tmpl.h
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Set data pointer to the case0 buffer
 * Case1Source: Set data pointer to the case1 buffer
 * Sinks: memmove
 *    Case0Sink : Copy int64_t array to data using memmove
 * Flow Variant: 81 Data flow: data passed in a parameter to an virtual method called via a reference
 *
 * */

#include "std_testcase.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_81
{

class CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_81_base
{
public:
    /* pure virtual function */
    virtual void action(int64_t * data) const = 0;
};

#ifndef OMITCASE0

class CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_81_case0 : public CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_81_base
{
public:
    void action(int64_t * data) const;
};

#endif /* OMITCASE0 */

#ifndef OMITCASE1

class CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_81_case1V1 : public CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_memmove_81_base
{
public:
    void action(int64_t * data) const;
};

#endif /* OMITCASE1 */

}
