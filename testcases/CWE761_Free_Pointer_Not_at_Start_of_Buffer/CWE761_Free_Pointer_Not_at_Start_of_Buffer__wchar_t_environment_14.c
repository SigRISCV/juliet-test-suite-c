/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_14.c
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-14.tmpl.c
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: environment Read input from an environment variable
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 14 Control flow: if(globalFive==5) and if(globalFive!=5)
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

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_14_bad()
{
    wchar_t * data;
    data = (wchar_t *)malloc(100*sizeof(wchar_t));
    if (data == NULL) {exit(-1);}
    data[0] = L'\0';
    {
        CWE761_sigriscv_wchar_environment_source(data);
    }
    if(globalFive==5)
    {
        CWE761_sigriscv_wchar_environment_bad_sink(data);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G1() - use badsource and goodsink by changing globalFive==5 to globalFive!=5 */
static void goodB2G1()
{
    wchar_t * data;
    data = (wchar_t *)malloc(100*sizeof(wchar_t));
    if (data == NULL) {exit(-1);}
    data[0] = L'\0';
    {
        CWE761_sigriscv_wchar_environment_source(data);
    }
    if(globalFive!=5)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
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
}

/* goodB2G2() - use badsource and goodsink by reversing statements in if  */
static void goodB2G2()
{
    wchar_t * data;
    data = (wchar_t *)malloc(100*sizeof(wchar_t));
    if (data == NULL) {exit(-1);}
    data[0] = L'\0';
    {
        CWE761_sigriscv_wchar_environment_source(data);
    }
    if(globalFive==5)
    {
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
}

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_14_good()
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
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_14_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_environment_14_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
