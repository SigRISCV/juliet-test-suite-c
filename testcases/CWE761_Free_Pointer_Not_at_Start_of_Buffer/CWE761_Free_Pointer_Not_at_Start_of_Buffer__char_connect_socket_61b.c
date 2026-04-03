/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_connect_socket_61b.c
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-61b.tmpl.c
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: connect_socket Read data using a connect socket (client side)
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 61 Data flow: data returned from one function to another in different source files
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

char * CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_connect_socket_61b_badSource(char * data)
{
    {
        CWE761_sigriscv_char_connect_socket_source(data);
    }
    return data;
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G() uses the BadSource with the GoodSink */
char * CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_connect_socket_61b_goodB2GSource(char * data)
{
    {
        CWE761_sigriscv_char_connect_socket_source(data);
    }
    return data;
}

#endif /* OMITGOOD */
