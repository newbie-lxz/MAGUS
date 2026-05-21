/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_67a.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE131.label.xml
Template File: sources-sink-67a.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Allocate memory without using sizeof(int)
 * Case1Source: Allocate memory using sizeof(int)
 * Sinks: memmove
 *    Case0Sink : Copy array to data using memmove()
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

typedef struct _CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_67_structType
{
    int * structFirst;
} CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_67_structType;

#ifndef OMITCASE0

/* case0 function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_67b_case0Sink(CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_67_structType myStruct);

void CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_67_case0()
{
    int * data;
    CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_67_structType myStruct;
    data = NULL;
    /* NOTE: Allocate memory without using sizeof(int) */
    data = (int *)ALLOCA(10);
    myStruct.structFirst = data;
    CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_67b_case0Sink(myStruct);
}

#endif /* OMITCASE0 */

#ifndef OMITCASE1

/* case1V1 uses the Case1Source with the Case0Sink */
void CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_67b_case1V1Sink(CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_67_structType myStruct);

static void case1V1()
{
    int * data;
    CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_67_structType myStruct;
    data = NULL;
    /* ALT: Allocate memory using sizeof(int) */
    data = (int *)ALLOCA(10*sizeof(int));
    myStruct.structFirst = data;
    CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_67b_case1V1Sink(myStruct);
}

void CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_67_case1()
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
    CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_67_case1();
    printLine("Finished case1()");
#endif /* OMITCASE1 */
#ifndef OMITCASE0
    printLine("Calling case0()...");
    CWE121_Stack_Based_Buffer_Overflow__CWE131_memmove_67_case0();
    printLine("Finished case0()");
#endif /* OMITCASE0 */
    return 0;
}

#endif
