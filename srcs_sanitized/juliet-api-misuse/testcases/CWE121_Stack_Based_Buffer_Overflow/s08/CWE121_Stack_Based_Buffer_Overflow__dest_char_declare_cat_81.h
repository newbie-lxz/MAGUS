/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cat_81.h
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__dest.label.xml
Template File: sources-sink-81.tmpl.h
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source:  Set data pointer to the case0 buffer
 * Case1Source: Set data pointer to the case1 buffer
 * Sinks: cat
 *    Case0Sink : Copy string to data using strcat
 * Flow Variant: 81 Data flow: data passed in a parameter to an virtual method called via a reference
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

namespace CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cat_81
{

class CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cat_81_base
{
public:
    /* pure virtual function */
    virtual void action(char * data) const = 0;
};

#ifndef OMITCASE0

class CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cat_81_case0 : public CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cat_81_base
{
public:
    void action(char * data) const;
};

#endif /* OMITCASE0 */

#ifndef OMITCASE1

class CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cat_81_case1V1 : public CWE121_Stack_Based_Buffer_Overflow__dest_char_declare_cat_81_base
{
public:
    void action(char * data) const;
};

#endif /* OMITCASE1 */

}
