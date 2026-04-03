/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_63a.c
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-63a.tmpl.c
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: environment Read input from an environment variable
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 63 Data flow: pointer to data passed from one function to another in different source files
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
void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_63b_badSink(wchar_t * * dataPtr);

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_63_bad()
{
    wchar_t * data;
    data = (wchar_t *)malloc(100*sizeof(wchar_t));
    if (data == NULL) {exit(-1);}
    data[0] = L'\0';
    {
        CWE761_sigriscv_wchar_environment_source(data);
    }
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_63b_badSink(&data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G uses the BadSource with the GoodSink */
void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_63b_goodB2GSink(wchar_t * * data);

static void goodB2G()
{
    wchar_t * data;
    data = (wchar_t *)malloc(100*sizeof(wchar_t));
    if (data == NULL) {exit(-1);}
    data[0] = L'\0';
    {
        CWE761_sigriscv_wchar_environment_source(data);
    }
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_63b_goodB2GSink(&data);
}

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_63_good()
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
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_63_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_63_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
