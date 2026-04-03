/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_file_41.c
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-41.tmpl.c
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: file Read input from a file
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 41 Data flow: data passed as an argument from one function to another in the same source file
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifdef _WIN32
#define FILENAME "C:\\temp\\file.txt"
#else
#define FILENAME "/tmp/file.txt"
#endif

#define SEARCH_CHAR L'S'

#include "CWE761_Free_Pointer_Not_at_Start_of_Buffer__sigriscv_file_helpers.h"

#ifndef OMITBAD

static void badSink(wchar_t * data)
{
    CWE761_sigriscv_wchar_file_bad_sink(data);
}

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_file_41_bad()
{
    wchar_t * data;
    data = (wchar_t *)malloc(100*sizeof(wchar_t));
    if (data == NULL) {exit(-1);}
    data[0] = L'\0';
    {
        CWE761_sigriscv_wchar_file_source(data, FILENAME);
    }
    badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

static void goodB2GSink(wchar_t * data)
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

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2G()
{
    wchar_t * data;
    data = (wchar_t *)malloc(100*sizeof(wchar_t));
    if (data == NULL) {exit(-1);}
    data[0] = L'\0';
    {
        CWE761_sigriscv_wchar_file_source(data, FILENAME);
    }
    goodB2GSink(data);
}

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_file_41_good()
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
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_file_41_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_file_41_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
