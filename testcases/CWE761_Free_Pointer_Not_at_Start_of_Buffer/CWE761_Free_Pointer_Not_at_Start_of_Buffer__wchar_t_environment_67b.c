/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_67b.c
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-67b.tmpl.c
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: environment Read input from an environment variable
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 67 Data flow: data passed in a struct from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>
#include "CWE761_Free_Pointer_Not_at_Start_of_Buffer__sigriscv_environment_helpers.h"


#ifdef _WIN32
#define ENV_VARIABLE L"ADD"
#define GETENV _wgetenv
#else
#define ENV_VARIABLE "ADD"
static wchar_t *sigriscv_wchar_getenv(__raw const char *name)
{
    static wchar_t envBuffer[100];
    __raw char *environment = getenv(name);
    if (environment == NULL)
    {
        return NULL;
    }
    if (mbstowcs(envBuffer, environment, 99) == (size_t)-1)
    {
        envBuffer[0] = (wchar_t)0;
    }
    else
    {
        envBuffer[99] = (wchar_t)0;
    }
    return envBuffer;
}
#define GETENV sigriscv_wchar_getenv
#endif

#define SEARCH_CHAR L'S'

typedef struct _CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_67_structType
{
    wchar_t * structFirst;
} CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_67_structType;

#ifndef OMITBAD

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_67b_badSink(CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_67_structType myStruct)
{
    wchar_t * data = myStruct.structFirst;
    CWE761_sigriscv_wchar_environment_bad_sink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G uses the BadSource with the GoodSink */
void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_67b_goodB2GSink(CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_67_structType myStruct)
{
    wchar_t * data = myStruct.structFirst;
    {
        size_t i;
        /* FIX: Use a loop variable to traverse through the string pointed to by data */
        for (i=0; i < wcslen(data); i++)
        {
            if (data[i] == SEARCH_CHAR)
            {
                printLine("We have a match!");
                break;
            }
        }
        free(data);
    }
}

#endif /* OMITGOOD */
