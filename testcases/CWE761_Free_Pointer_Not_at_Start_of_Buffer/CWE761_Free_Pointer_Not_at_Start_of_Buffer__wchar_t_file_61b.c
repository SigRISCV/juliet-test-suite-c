/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_file_61b.c
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-61b.tmpl.c
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: file Read input from a file
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 61 Data flow: data returned from one function to another in different source files
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

wchar_t * CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_file_61b_badSource(wchar_t * data)
{
    {
        CWE761_sigriscv_wchar_file_source(data, FILENAME);
    }
    return data;
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G() uses the BadSource with the GoodSink */
wchar_t * CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_file_61b_goodB2GSource(wchar_t * data)
{
    {
        CWE761_sigriscv_wchar_file_source(data, FILENAME);
    }
    return data;
}

#endif /* OMITGOOD */
