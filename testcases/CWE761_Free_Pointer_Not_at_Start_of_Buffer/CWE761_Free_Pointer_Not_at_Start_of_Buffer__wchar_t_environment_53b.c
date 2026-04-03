/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_53b.c
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-53b.tmpl.c
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: environment Read input from an environment variable
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 53 Data flow: data passed as an argument from one function through two others to a fourth; all four functions are in different source files
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

#ifndef OMITBAD

/* bad function declaration */
void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_53c_badSink(wchar_t * data);

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_53b_badSink(wchar_t * data)
{
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_53c_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G uses the BadSource with the GoodSink */
void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_53c_goodB2GSink(wchar_t * data);

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_53b_goodB2GSink(wchar_t * data)
{
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_53c_goodB2GSink(data);
}

#endif /* OMITGOOD */
