/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_33.cpp
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.label.xml
Template File: sources-sink-33.tmpl.cpp
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Set data pointer to the case0 buffer
 * Case1Source: Set data pointer to the case1 buffer
 * Sinks: memcpy
 *    Case0Sink : Copy twoIntsStruct array to data using memcpy
 * Flow Variant: 33 Data flow: use of a C++ reference to data within the same function
 *
 * */

#include "std_testcase.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_33
{

#ifndef OMITCASE0

void case0()
{
    twoIntsStruct * data;
    twoIntsStruct * &dataRef = data;
    twoIntsStruct dataCase0Buffer[50];
    twoIntsStruct dataCase1Buffer[100];
    /* NOTE: Set a pointer to a "small" buffer. This buffer will be used in the sinks as a destination
     * buffer in various memory copying functions using a "large" source buffer. */
    data = dataCase0Buffer;
    {
        twoIntsStruct * data = dataRef;
        {
            twoIntsStruct source[100];
            {
                size_t i;
                /* Initialize array */
                for (i = 0; i < 100; i++)
                {
                    source[i].intOne = 0;
                    source[i].intTwo = 0;
                }
            }
            /* NOTE: Possible buffer overflow if data < 100 */
            memcpy(data, source, 100*sizeof(twoIntsStruct));
            printStructLine(&data[0]);
        }
    }
}

#endif /* OMITCASE0 */

#ifndef OMITCASE1

/* case1V1() uses the Case1Source with the Case0Sink */
static void case1V1()
{
    twoIntsStruct * data;
    twoIntsStruct * &dataRef = data;
    twoIntsStruct dataCase0Buffer[50];
    twoIntsStruct dataCase1Buffer[100];
    /* ALT: Set a pointer to a "large" buffer, thus avoiding buffer overflows in the sinks. */
    data = dataCase1Buffer;
    {
        twoIntsStruct * data = dataRef;
        {
            twoIntsStruct source[100];
            {
                size_t i;
                /* Initialize array */
                for (i = 0; i < 100; i++)
                {
                    source[i].intOne = 0;
                    source[i].intTwo = 0;
                }
            }
            /* NOTE: Possible buffer overflow if data < 100 */
            memcpy(data, source, 100*sizeof(twoIntsStruct));
            printStructLine(&data[0]);
        }
    }
}

void case1()
{
    case1V1();
}

#endif /* OMITCASE1 */

} /* close namespace */

/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */
#ifdef INCLUDEMAIN

using namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_33; /* so that we can use case1 and case0 easily */

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITCASE1
    printLine("Calling case1()...");
    case1();
    printLine("Finished case1()");
#endif /* OMITCASE1 */
#ifndef OMITCASE0
    printLine("Calling case0()...");
    case0();
    printLine("Finished case0()");
#endif /* OMITCASE0 */
    return 0;
}

#endif
