/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_81.h
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE193.label.xml
Template File: sources-sink-81.tmpl.h
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Point data to a buffer that does not have space for a NULL terminator
 * Case1Source: Point data to a buffer that includes space for a NULL terminator
 * Sinks: ncpy
 *    Case0Sink : Copy string to data using strncpy()
 * Flow Variant: 81 Data flow: data passed in a parameter to an virtual method called via a reference
 *
 * */

#include "std_testcase.h"

#ifndef _WIN32
#include <wchar.h>
#endif

/* MAINTENANCE NOTE: The length of this string should equal the 10 */
#define SRC_STRING "AAAAAAAAAA"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_81
{

class CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_81_base
{
public:
    /* pure virtual function */
    virtual void action(char * data) const = 0;
};

#ifndef OMITCASE0

class CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_81_case0 : public CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_81_base
{
public:
    void action(char * data) const;
};

#endif /* OMITCASE0 */

#ifndef OMITCASE1

class CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_81_case1V1 : public CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_ncpy_81_base
{
public:
    void action(char * data) const;
};

#endif /* OMITCASE1 */

}
