/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__placement_new_alloca_81.h
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__placement_new.label.xml
Template File: sources-sinks-81.tmpl.h
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Initialize data to a small buffer
 * Case1Source: Initialize data to a buffer large enough to hold a TwoIntsClass
 * Sinks:
 *    Case1Sink: Allocate a new class using placement new and a buffer that is large enough to hold the class
 *    Case0Sink : Allocate a new class using placement new and a buffer that is too small
 * Flow Variant: 81 Data flow: data passed in a parameter to an virtual method called via a reference
 *
 * */

#include "std_testcase.h"

namespace CWE121_Stack_Based_Buffer_Overflow__placement_new_alloca_81
{

class CWE121_Stack_Based_Buffer_Overflow__placement_new_alloca_81_base
{
public:
    /* pure virtual function */
    virtual void action(char * data) const = 0;
};

#ifndef OMITCASE0

class CWE121_Stack_Based_Buffer_Overflow__placement_new_alloca_81_case0 : public CWE121_Stack_Based_Buffer_Overflow__placement_new_alloca_81_base
{
public:
    void action(char * data) const;
};

#endif /* OMITCASE0 */

#ifndef OMITCASE1

class CWE121_Stack_Based_Buffer_Overflow__placement_new_alloca_81_case1V1 : public CWE121_Stack_Based_Buffer_Overflow__placement_new_alloca_81_base
{
public:
    void action(char * data) const;
};

class CWE121_Stack_Based_Buffer_Overflow__placement_new_alloca_81_case1V2 : public CWE121_Stack_Based_Buffer_Overflow__placement_new_alloca_81_base
{
public:
    void action(char * data) const;
};

#endif /* OMITCASE1 */

}
