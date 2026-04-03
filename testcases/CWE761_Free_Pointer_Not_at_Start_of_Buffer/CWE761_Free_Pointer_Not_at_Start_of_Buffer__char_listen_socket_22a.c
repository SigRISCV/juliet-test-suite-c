/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_22a.c
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-22a.tmpl.c
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: listen_socket Read data using a listen socket (server side)
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 22 Control flow: Flow controlled by value of a global variable. Sink functions are in a separate file from sources.
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


#ifndef OMITBAD

/* The global variable below is used to drive control flow in the sink function */
int CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_22_badGlobal = 0;

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_22_badSink(char * data);

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_22_bad()
{
    char * data;
    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}
    data[0] = '\0';
    {
        CWE761_sigriscv_char_listen_socket_source(data);
    }
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_22_badGlobal = 1; /* true */
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_22_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* The global variables below are used to drive control flow in the sink functions. */
int CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_22_goodB2G1Global = 0;
int CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_22_goodB2G2Global = 0;

/* goodB2G1() - use badsource and goodsink by setting the static variable to false instead of true */
void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_22_goodB2G1Sink(char * data);

static void goodB2G1()
{
    char * data;
    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}
    data[0] = '\0';
    {
        CWE761_sigriscv_char_listen_socket_source(data);
    }
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_22_goodB2G1Global = 0; /* false */
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_22_goodB2G1Sink(data);
}

/* goodB2G2() - use badsource and goodsink by reversing the blocks in the if in the sink function */
void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_22_goodB2G2Sink(char * data);

static void goodB2G2()
{
    char * data;
    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}
    data[0] = '\0';
    {
        CWE761_sigriscv_char_listen_socket_source(data);
    }
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_22_goodB2G2Global = 1; /* true */
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_22_goodB2G2Sink(data);
}

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_22_good()
{
    goodB2G1();
    goodB2G2();
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
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_22_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_listen_socket_22_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
