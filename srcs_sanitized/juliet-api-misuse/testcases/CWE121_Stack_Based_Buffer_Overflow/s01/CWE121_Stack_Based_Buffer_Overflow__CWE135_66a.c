/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE135_66a.c
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE135.label.xml
Template File: sources-sinks-66a.tmpl.c
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Void pointer to a wchar_t array
 * Case1Source: Void pointer to a char array
 * Sinks:
 *    Case1Sink: Allocate memory using wcslen() and copy data
 *    Case0Sink : Allocate memory using strlen() and copy data
 * Flow Variant: 66 Data flow: data passed in an array from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#define WIDE_STRING L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#define CHAR_STRING "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

#ifndef OMITCASE0

/* case0 function declaration */
void CWE121_Stack_Based_Buffer_Overflow__CWE135_66b_case0Sink(void * dataArray[]);

void CWE121_Stack_Based_Buffer_Overflow__CWE135_66_case0()
{
    void * data;
    void * dataArray[5];
    data = NULL;
    /* NOTE: Set data to point to a wide string */
    data = (void *)WIDE_STRING;
    /* put data in array */
    dataArray[2] = data;
    CWE121_Stack_Based_Buffer_Overflow__CWE135_66b_case0Sink(dataArray);
}

#endif /* OMITCASE0 */

#ifndef OMITCASE1

/* case1V1 uses the Case1Source with the Case0Sink */
void CWE121_Stack_Based_Buffer_Overflow__CWE135_66b_case1V1Sink(void * dataArray[]);

static void case1V1()
{
    void * data;
    void * dataArray[5];
    data = NULL;
    /* ALT: Set data to point to a char string */
    data = (void *)CHAR_STRING;
    dataArray[2] = data;
    CWE121_Stack_Based_Buffer_Overflow__CWE135_66b_case1V1Sink(dataArray);
}

/* case1V2 uses the Case0Source with the Case1Sink */
void CWE121_Stack_Based_Buffer_Overflow__CWE135_66b_case1V2Sink(void * dataArray[]);

static void case1V2()
{
    void * data;
    void * dataArray[5];
    data = NULL;
    /* NOTE: Set data to point to a wide string */
    data = (void *)WIDE_STRING;
    dataArray[2] = data;
    CWE121_Stack_Based_Buffer_Overflow__CWE135_66b_case1V2Sink(dataArray);
}

void CWE121_Stack_Based_Buffer_Overflow__CWE135_66_case1()
{
    case1V1();
    case1V2();
}

#endif /* OMITCASE1 */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITCASE1
    printLine("Calling case1()...");
    CWE121_Stack_Based_Buffer_Overflow__CWE135_66_case1();
    printLine("Finished case1()");
#endif /* OMITCASE1 */
#ifndef OMITCASE0
    printLine("Calling case0()...");
    CWE121_Stack_Based_Buffer_Overflow__CWE135_66_case0();
    printLine("Finished case0()");
#endif /* OMITCASE0 */
    return 0;
}

#endif
