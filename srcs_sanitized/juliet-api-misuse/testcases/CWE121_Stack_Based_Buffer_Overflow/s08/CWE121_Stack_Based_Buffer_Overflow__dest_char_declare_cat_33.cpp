/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cat_33.cpp
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__dest.label.xml
Template File: sources-sink-33.tmpl.cpp
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Set data pointer to the case0 buffer
 * Case1Source: Set data pointer to the case1 buffer
 * Sinks: cat
 *    Case0Sink : Copy string to data using strcat
 * Flow Variant: 33 Data flow: use of a C++ reference to data within the same function
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cat_33
{

#ifndef OMITCASE0

void case0()
{
    char * data;
    char * &dataRef = data;
    char dataCase0Buffer[50];
    char dataCase1Buffer[100];
    /* NOTE: Set a pointer to a "small" buffer. This buffer will be used in the sinks as a destination
     * buffer in various memory copying functions using a "large" source buffer. */
    data = dataCase0Buffer;
    data[0] = '\0'; /* null terminate */
    {
        char * data = dataRef;
        {
            char source[100];
            memset(source, 'C', 100-1); /* fill with 'C's */
            source[100-1] = '\0'; /* null terminate */
            /* NOTE: Possible buffer overflow if the sizeof(data)-strlen(data) is less than the length of source */
            strcat(data, source);
            printLine(data);
        }
    }
}

#endif /* OMITCASE0 */

#ifndef OMITCASE1

/* case1V1() uses the Case1Source with the Case0Sink */
static void case1V1()
{
    char * data;
    char * &dataRef = data;
    char dataCase0Buffer[50];
    char dataCase1Buffer[100];
    /* ALT: Set a pointer to a "large" buffer, thus avoiding buffer overflows in the sinks. */
    data = dataCase1Buffer;
    data[0] = '\0'; /* null terminate */
    {
        char * data = dataRef;
        {
            char source[100];
            memset(source, 'C', 100-1); /* fill with 'C's */
            source[100-1] = '\0'; /* null terminate */
            /* NOTE: Possible buffer overflow if the sizeof(data)-strlen(data) is less than the length of source */
            strcat(data, source);
            printLine(data);
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

using namespace CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cat_33; /* so that we can use case1 and case0 easily */

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
