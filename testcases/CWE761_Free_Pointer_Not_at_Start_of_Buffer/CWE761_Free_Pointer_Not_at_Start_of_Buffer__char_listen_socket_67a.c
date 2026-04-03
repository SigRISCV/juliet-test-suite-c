/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_67a.c
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-67a.tmpl.c
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: listen_socket Read data using a listen socket (server side)
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
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
#else
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
#define LISTEN_BACKLOG 5

#include "CWE761_Free_Pointer_Not_at_Start_of_Buffer__sigriscv_listen_socket_helpers.h"

#define SEARCH_CHAR 'S'

typedef struct _CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_67_structType
{
    char * structFirst;
} CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_67_structType;

#ifndef OMITBAD

/* bad function declaration */
void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_67b_badSink(CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_67_structType myStruct);

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_67_bad()
{
    char * data;
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_67_structType myStruct;
    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}
    data[0] = '\0';
    {
        CWE761_sigriscv_char_listen_socket_source(data);
    }
    myStruct.structFirst = data;
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_67b_badSink(myStruct);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G uses the BadSource with the GoodSink */
void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_67b_goodB2GSink(CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_67_structType myStruct);

static void goodB2G()
{
    char * data;
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_67_structType myStruct;
    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}
    data[0] = '\0';
    {
        CWE761_sigriscv_char_listen_socket_source(data);
    }
    myStruct.structFirst = data;
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_67b_goodB2GSink(myStruct);
}

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_67_good()
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
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_67_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_67_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
