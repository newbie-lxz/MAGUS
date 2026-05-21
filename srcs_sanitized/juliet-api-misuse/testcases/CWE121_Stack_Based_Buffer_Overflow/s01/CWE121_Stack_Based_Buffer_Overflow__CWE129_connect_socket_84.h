/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_84.h
Label Definition File: CWE121_Stack_Based_Buffer_Overflow__CWE129.label.xml
Template File: sources-sinks-84.tmpl.h
*/
/*
 * @description
 * CWE: 121 Stack Based Buffer Overflow
 * Case0Source: connect_socket Read data using a connect socket (client side)
 * Case1Source: Larger than zero but less than 10
 * Sinks:
 *    Case1Sink: Ensure the array index is valid
 *    Case0Sink : Improperly check the array index by not checking the upper bound
 * Flow Variant: 84 Data flow: data passed to class constructor and destructor by declaring the class object on the heap and deleting it after use
 *
 * */

#include "std_testcase.h"

namespace CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_84
{

#ifndef OMITCASE0

class CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_84_case0
{
public:
    CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_84_case0(int dataCopy);
    ~CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_84_case0();

private:
    int data;
};

#endif /* OMITCASE0 */

#ifndef OMITCASE1

class CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_84_case1V1
{
public:
    CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_84_case1V1(int dataCopy);
    ~CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_84_case1V1();

private:
    int data;
};

class CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_84_case1V2
{
public:
    CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_84_case1V2(int dataCopy);
    ~CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_84_case1V2();

private:
    int data;
};

#endif /* OMITCASE1 */

}
