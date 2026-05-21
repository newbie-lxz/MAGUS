/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_82.h
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE129.label.xml
Template File: sources-sinks-82.tmpl.h
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source: fgets Read data from the console using fgets()
 * Case1Source: Larger than zero but less than 10
 * Sinks:
 *    Case1Sink: Ensure the array index is valid
 *    Case0Sink : Improperly check the array index by not checking the upper bound
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */

#include "std_testcase.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_82
{

class CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_82_base
{
public:
    /* pure virtual function */
    virtual void action(int data) = 0;
};

#ifndef OMITCASE0

class CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_82_case0 : public CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_82_base
{
public:
    void action(int data);
};

#endif /* OMITCASE0 */

#ifndef OMITCASE1

class CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_82_case1V1 : public CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_82_base
{
public:
    void action(int data);
};

class CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_82_case1V2 : public CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_82_base
{
public:
    void action(int data);
};

#endif /* OMITCASE1 */

}
