/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE129_large_83_case0.cpp
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE129.label.xml
Template File: sources-sinks-83_case0.tmpl.cpp
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source: large Large index value that is greater than 10-1
 * Case1Source: Larger than zero but less than 10
 * Sinks:
 *    Case1Sink: Ensure the array index is valid
 *    Case0Sink : Improperly check the array index by not checking the upper bound
 * Flow Variant: 83 Data flow: data passed to class constructor and destructor by declaring the class object on the stack
 *
 * */
#ifndef OMITCASE0

#include "std_testcase.h"
#include "CWE121_Stack_Based_Buffer_Overflow__CWE129_large_83.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE129_large_83
{
CWE121_Stack_Based_Buffer_Overflow__CWE129_large_83_case0::CWE121_Stack_Based_Buffer_Overflow__CWE129_large_83_case0(int dataCopy)
{
    data = dataCopy;
    /* NOTE: Use an invalid index */
    data = 10;
}

CWE121_Stack_Based_Buffer_Overflow__CWE129_large_83_case0::~CWE121_Stack_Based_Buffer_Overflow__CWE129_large_83_case0()
{
    {
        int i;
        int buffer[10] = { 0 };
        /* NOTE: Attempt to write to an index of the array that is above the upper bound
        * This code does check to see if the array index is negative */
        if (data >= 0)
        {
            buffer[data] = 1;
            /* Print the array values */
            for(i = 0; i < 10; i++)
            {
                printIntLine(buffer[i]);
            }
        }
        else
        {
            printLine("ERROR: Array index is negative.");
        }
    }
}
}
#endif /* OMITCASE0 */
