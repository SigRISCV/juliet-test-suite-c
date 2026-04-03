/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_console_61b.c
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-61b.tmpl.c
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: console Read input from the console
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 61 Data flow: data returned from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#include "CWE761_Free_Pointer_Not_at_Start_of_Buffer__sigriscv_console_helpers.h"

#define SEARCH_CHAR L'S'

#ifndef OMITBAD

wchar_t * CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_console_61b_badSource(wchar_t * data)
{
    {
        CWE761_sigriscv_wchar_console_source(data);
    }
    return data;
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G() uses the BadSource with the GoodSink */
wchar_t * CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_console_61b_goodB2GSource(wchar_t * data)
{
    {
        CWE761_sigriscv_wchar_console_source(data);
    }
    return data;
}

#endif /* OMITGOOD */
