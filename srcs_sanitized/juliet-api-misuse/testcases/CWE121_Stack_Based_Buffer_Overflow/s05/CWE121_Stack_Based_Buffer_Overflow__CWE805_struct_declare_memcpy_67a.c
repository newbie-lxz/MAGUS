/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_67a.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.label.xml
Template File: sources-sink-67a.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Set data pointer to the case0 buffer
 * Case1Source: Set data pointer to the case1 buffer
 * Sinks: memcpy
 *    Case0Sink : Copy twoIntsStruct array to data using memcpy
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

typedef struct _CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_67_structType
{
    twoIntsStruct * structFirst;
} CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_67_structType;

#ifndef OMITCASE0

/* case0 function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_67b_case0Sink(CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_67_structType myStruct);

void CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_67_case0()
{
    twoIntsStruct * data;
    CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_67_structType myStruct;
    twoIntsStruct dataCase0Buffer[50];
    twoIntsStruct dataCase1Buffer[100];
    /* NOTE: Set a pointer to a "small" buffer. This buffer will be used in the sinks as a destination
     * buffer in various memory copying functions using a "large" source buffer. */
    data = dataCase0Buffer;
    myStruct.structFirst = data;
    CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_67b_case0Sink(myStruct);
}

#endif /* OMITCASE0 */

#ifndef OMITCASE1

/* case1V1 uses the Case1Source with the Case0Sink */
void CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_67b_case1V1Sink(CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_67_structType myStruct);

static void case1V1()
{
    twoIntsStruct * data;
    CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_67_structType myStruct;
    twoIntsStruct dataCase0Buffer[50];
    twoIntsStruct dataCase1Buffer[100];
    /* ALT: Set a pointer to a "large" buffer, thus avoiding buffer overflows in the sinks. */
    data = dataCase1Buffer;
    myStruct.structFirst = data;
    CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_67b_case1V1Sink(myStruct);
}

void CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_67_case1()
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
    CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_67_case1();
    printLine("Finished case1()");
#endif /* OMITCASE1 */
#ifndef OMITCASE0
    printLine("Calling case0()...");
    CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_declare_memcpy_67_case0();
    printLine("Finished case0()");
#endif /* OMITCASE0 */
    return 0;
}

#endif
