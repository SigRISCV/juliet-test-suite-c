/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_file_61b.c
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

#define SEARCH_CHAR 'S'

#include "CWE761_Free_Pointer_Not_at_Start_of_Buffer__sigriscv_file_helpers.h"

#ifndef OMITBAD

char * CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_file_61b_badSource(char * data)
{
    {
        CWE761_sigriscv_char_file_source(data, FILENAME);
    }
    return data;
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G() uses the BadSource with the GoodSink */
char * CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_file_61b_goodB2GSource(char * data)
{
    {
        CWE761_sigriscv_char_file_source(data, FILENAME);
    }
    return data;
}

#endif /* OMITGOOD */
