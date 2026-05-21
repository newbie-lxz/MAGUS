/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_loop_41.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.label.xml
Template File: sources-sink-41.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Set data pointer to the case0 buffer
 * Case1Source: Set data pointer to the case1 buffer
 * Sink: loop
 *    Case0Sink : Copy int64_t array to data using a loop
 * Flow Variant: 41 Data flow: data passed as an argument from one function to another in the same source file
 *
 * */

#include "std_testcase.h"

#ifndef OMITCASE0

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_loop_41_case0Sink(int64_t * data)
{
    {
        int64_t source[100] = {0}; /* fill with 0's */
        {
            size_t i;
            /* NOTE: Possible buffer overflow if data < 100 */
            for (i = 0; i < 100; i++)
            {
                data[i] = source[i];
            }
            printLongLongLine(data[0]);
        }
    }
}

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_loop_41_case0()
{
    int64_t * data;
    int64_t dataCase0Buffer[50];
    int64_t dataCase1Buffer[100];
    /* NOTE: Set a pointer to a "small" buffer. This buffer will be used in the sinks as a destination
     * buffer in various memory copying functions using a "large" source buffer. */
    data = dataCase0Buffer;
    CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_loop_41_case0Sink(data);
}

#endif /* OMITCASE0 */

#ifndef OMITCASE1

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_loop_41_case1V1Sink(int64_t * data)
{
    {
        int64_t source[100] = {0}; /* fill with 0's */
        {
            size_t i;
            /* NOTE: Possible buffer overflow if data < 100 */
            for (i = 0; i < 100; i++)
            {
                data[i] = source[i];
            }
            printLongLongLine(data[0]);
        }
    }
}

/* case1V1 uses the Case1Source with the Case0Sink */
static void case1V1()
{
    int64_t * data;
    int64_t dataCase0Buffer[50];
    int64_t dataCase1Buffer[100];
    /* ALT: Set a pointer to a "large" buffer, thus avoiding buffer overflows in the sinks. */
    data = dataCase1Buffer;
    CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_loop_41_case1V1Sink(data);
}

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_loop_41_case1()
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
    CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_loop_41_case1();
    printLine("Finished case1()");
#endif /* OMITCASE1 */
#ifndef OMITCASE0
    printLine("Calling case0()...");
    CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_declare_loop_41_case0();
    printLine("Finished case0()");
#endif /* OMITCASE0 */
    return 0;
}

#endif
