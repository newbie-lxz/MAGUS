/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_64a.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE193.label.xml
Template File: sources-sink-64a.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Point data to a buffer that does not have space for a NULL terminator
 * Case1Source: Point data to a buffer that includes space for a NULL terminator
 * Sinks: cpy
 *    Case0Sink : Copy string to data using strcpy()
 * Flow Variant: 64 Data flow: void pointer to data passed from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

/* MAINTENANCE NOTE: The length of this string should equal the 10 */
#define SRC_STRING "AAAAAAAAAA"

#ifndef OMITCASE0

/* case0 function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_64b_case0Sink(void * dataVoidPtr);

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_64_case0()
{
    char * data;
    char dataCase0Buffer[10];
    char dataCase1Buffer[10+1];
    /* NOTE: Set a pointer to a buffer that does not leave room for a NULL terminator when performing
     * string copies in the sinks  */
    data = dataCase0Buffer;
    data[0] = '\0'; /* null terminate */
    CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_64b_case0Sink(&data);
}

#endif /* OMITCASE0 */

#ifndef OMITCASE1

/* case1V1 uses the Case1Source with the Case0Sink */
void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_64b_case1V1Sink(void * dataVoidPtr);

static void case1V1()
{
    char * data;
    char dataCase0Buffer[10];
    char dataCase1Buffer[10+1];
    /* ALT: Set a pointer to a buffer that leaves room for a NULL terminator when performing
     * string copies in the sinks  */
    data = dataCase1Buffer;
    data[0] = '\0'; /* null terminate */
    CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_64b_case1V1Sink(&data);
}

void CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_64_case1()
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
    CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_64_case1();
    printLine("Finished case1()");
#endif /* OMITCASE1 */
#ifndef OMITCASE0
    printLine("Calling case0()...");
    CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_cpy_64_case0();
    printLine("Finished case0()");
#endif /* OMITCASE0 */
    return 0;
}

#endif
