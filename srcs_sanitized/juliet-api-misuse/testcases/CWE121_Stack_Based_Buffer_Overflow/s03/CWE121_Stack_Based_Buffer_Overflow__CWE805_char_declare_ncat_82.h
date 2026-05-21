/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_82.h
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE805.string.label.xml
Template File: sources-sink-82.tmpl.h
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Set data pointer to the case0 buffer
 * Case1Source: Set data pointer to the case1 buffer
 *    Case0Sink : Copy string to data using strncat
 * Flow Variant: 82 Data flow: data passed in a parameter to an virtual method called via a pointer
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_82
{

class CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_82_base
{
public:
    /* pure virtual function */
    virtual void action(char * data) = 0;
};

#ifndef OMITCASE0

class CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_82_case0 : public CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_82_base
{
public:
    void action(char * data);
};

#endif /* OMITCASE0 */

#ifndef OMITCASE1

class CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_82_case1V1 : public CWE121_Stack_Based_Buffer_Overflow__CWE805_char_declare_ncat_82_base
{
public:
    void action(char * data);
};

#endif /* OMITCASE1 */

}
