/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_connect_socket_66a.c
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-66a.tmpl.c
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: connect_socket Read data using a connect socket (client side)
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 66 Data flow: data passed in an array from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#pragma comment(lib, "ws2_32") /* include ws2_32.lib when linking */
#define CLOSE_SOCKET closesocket
#else /* NOT _WIN32 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define CLOSE_SOCKET close
#define SOCKET int
#endif

#define TCP_PORT 27015
#define IP_ADDRESS "127.0.0.1"

#include "CWE761_Free_Pointer_Not_at_Start_of_Buffer__sigriscv_connect_socket_helpers.h"

#define SEARCH_CHAR 'S'

#ifndef OMITBAD

/* bad function declaration */
void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_connect_socket_66b_badSink(char * dataArray[]);

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_connect_socket_66_bad()
{
    char * data;
    char * dataArray[5];
    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}
    data[0] = '\0';
    {
        CWE761_sigriscv_char_connect_socket_source(data);
    }
    /* put data in array */
    dataArray[2] = data;
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_connect_socket_66b_badSink(dataArray);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G uses the BadSource with the GoodSink */
void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_connect_socket_66b_goodB2GSink(char * dataArray[]);

static void goodB2G()
{
    char * data;
    char * dataArray[5];
    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}
    data[0] = '\0';
    {
        CWE761_sigriscv_char_connect_socket_source(data);
    }
    dataArray[2] = data;
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_connect_socket_66b_goodB2GSink(dataArray);
}

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_connect_socket_66_good()
{
    goodB2G();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_connect_socket_66_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_connect_socket_66_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
