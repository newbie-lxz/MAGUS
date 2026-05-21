/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_53a.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.label.xml
Template File: sources-sink-53a.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Set data pointer to the case0 buffer
 * Case1Source: Set data pointer to the case1 buffer
 * Sink: memcpy
 *    Case0Sink : Copy int64_t array to data using memcpy
 * Flow Variant: 53 Data flow: data passed as an argument from one function through two others to a fourth; all four functions are in different source files
 *
 * */

#include "std_testcase.h"

#ifndef OMITCASE0

/* case0 function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_53b_case0Sink(int64_t * data);

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_53_case0()
{
    int64_t * data;
    int64_t * dataCase0Buffer = (int64_t *)ALLOCA(50*sizeof(int64_t));
    int64_t * dataCase1Buffer = (int64_t *)ALLOCA(100*sizeof(int64_t));
    /* NOTE: Set a pointer to a "small" buffer. This buffer will be used in the sinks as a destination
     * buffer in various memory copying functions using a "large" source buffer. */
    data = dataCase0Buffer;
    CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_53b_case0Sink(data);
}

#endif /* OMITCASE0 */

#ifndef OMITCASE1

/* case1 function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_53b_case1V1Sink(int64_t * data);

/* case1V1 uses the Case1Source with the Case0Sink */
static void case1V1()
{
    int64_t * data;
    int64_t * dataCase0Buffer = (int64_t *)ALLOCA(50*sizeof(int64_t));
    int64_t * dataCase1Buffer = (int64_t *)ALLOCA(100*sizeof(int64_t));
    /* ALT: Set a pointer to a "large" buffer, thus avoiding buffer overflows in the sinks. */
    data = dataCase1Buffer;
    CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_53b_case1V1Sink(data);
}

void CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_53_case1()
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
    CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_53_case1();
    printLine("Finished case1()");
#endif /* OMITCASE1 */
#ifndef OMITCASE0
    printLine("Calling case0()...");
    CWE121_Stack_Based_Buffer_Overflow__CWE805_int64_t_alloca_memcpy_53_case0();
    printLine("Finished case0()");
#endif /* OMITCASE0 */
    return 0;
}

#endif
