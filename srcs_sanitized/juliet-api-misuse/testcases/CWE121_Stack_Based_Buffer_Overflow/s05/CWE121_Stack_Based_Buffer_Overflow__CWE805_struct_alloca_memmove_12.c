/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memmove_12.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.label.xml
Template File: sources-sink-12.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Set data pointer to the case0 buffer
 * Case1Source: Set data pointer to the case1 buffer
 * Sink: memmove
 *    Case0Sink : Copy twoIntsStruct array to data using memmove
 * Flow Variant: 12 Control flow: if(globalReturnsTrueOrFalse())
 *
 * */

#include "std_testcase.h"

#ifndef OMITCASE0

void CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memmove_12_case0()
{
    twoIntsStruct * data;
    twoIntsStruct * dataCase0Buffer = (twoIntsStruct *)ALLOCA(50*sizeof(twoIntsStruct));
    twoIntsStruct * dataCase1Buffer = (twoIntsStruct *)ALLOCA(100*sizeof(twoIntsStruct));
    if(globalReturnsTrueOrFalse())
    {
        /* NOTE: Set a pointer to a "small" buffer. This buffer will be used in the sinks as a destination
         * buffer in various memory copying functions using a "large" source buffer. */
        data = dataCase0Buffer;
    }
    else
    {
        /* ALT: Set a pointer to a "large" buffer, thus avoiding buffer overflows in the sinks. */
        data = dataCase1Buffer;
    }
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
        memmove(data, source, 100*sizeof(twoIntsStruct));
        printStructLine(&data[0]);
    }
}

#endif /* OMITCASE0 */

#ifndef OMITCASE1

/* case1V1() - use case1source and case0sink by changing the "if" so that
 * both branches use the Case1Source */
static void case1V1()
{
    twoIntsStruct * data;
    twoIntsStruct * dataCase0Buffer = (twoIntsStruct *)ALLOCA(50*sizeof(twoIntsStruct));
    twoIntsStruct * dataCase1Buffer = (twoIntsStruct *)ALLOCA(100*sizeof(twoIntsStruct));
    if(globalReturnsTrueOrFalse())
    {
        /* ALT: Set a pointer to a "large" buffer, thus avoiding buffer overflows in the sinks. */
        data = dataCase1Buffer;
    }
    else
    {
        /* ALT: Set a pointer to a "large" buffer, thus avoiding buffer overflows in the sinks. */
        data = dataCase1Buffer;
    }
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
        memmove(data, source, 100*sizeof(twoIntsStruct));
        printStructLine(&data[0]);
    }
}

void CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memmove_12_case1()
{
    case1V1();
}

#endif /* OMITCASE1 */

/* Below is the main(). It is only used when building this testcase on
 * its own for testing or for building a binary to use in testing binary
 * analysis tools. It is not used when compiling all the testcases as one
 * application, which is how source code analysis tools are tested.
 */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITCASE1
    printLine("Calling case1()...");
    CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memmove_12_case1();
    printLine("Finished case1()");
#endif /* OMITCASE1 */
#ifndef OMITCASE0
    printLine("Calling case0()...");
    CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memmove_12_case0();
    printLine("Finished case0()");
#endif /* OMITCASE0 */
    return 0;
}

#endif
