/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_environment_45.c
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-45.tmpl.c
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: environment Read input from an environment variable
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 45 Data flow: data passed as a static global variable from one function to another in the same source file
 *
 * */

#include "std_testcase.h"

#include <wchar.h>
#include "CWE761_Free_Pointer_Not_at_Start_of_Buffer__sigriscv_environment_helpers.h"


#define ENV_VARIABLE "ADD"

#ifdef _WIN32
#define GETENV getenv
#else
#define GETENV getenv
#endif

#define SEARCH_CHAR 'S'

static char * CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_environment_45_badData;
static char * CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_environment_45_goodB2GData;

#ifndef OMITBAD

static void badSink()
{
    char * data = CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_environment_45_badData;
    CWE761_sigriscv_char_environment_bad_sink(data);
}

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_environment_45_bad()
{
    char * data;
    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}
    data[0] = '\0';
    {
        CWE761_sigriscv_char_environment_source(data);
    }
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_environment_45_badData = data;
    badSink();
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G() uses the BadSource with the GoodSink */
static void goodB2GSink()
{
    char * data = CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_environment_45_goodB2GData;
    {
        size_t i;
        /* FIX: Use a loop variable to traverse through the string pointed to by data */
        for (i=0; i < strlen(data); i++)
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

static void goodB2G()
{
    char * data;
    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}
    data[0] = '\0';
    {
        CWE761_sigriscv_char_environment_source(data);
    }
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_environment_45_goodB2GData = data;
    goodB2GSink();
}

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_environment_45_good()
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
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_environment_45_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_environment_45_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
