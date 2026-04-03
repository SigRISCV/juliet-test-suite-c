/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE415_Double_Free__malloc_free_char_61b.c
Label Definition File: CWE415_Double_Free__malloc_free.label.xml
Template File: sources-sinks-61b.tmpl.c
*/
/*
 * @description
 * CWE: 415 Double Free
 * BadSource:  Allocate data using malloc() and Deallocate data using free()
 * GoodSource: Allocate data using malloc()
 * Sinks:
 *    GoodSink: do nothing
 *    BadSink : Deallocate data using free()
 * Flow Variant: 61 Data flow: data returned from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#include "CWE415_Double_Free__sigriscv_char_helpers.h"

#ifndef OMITBAD

char ** CWE415_Double_Free__malloc_free_char_61b_badSource(char ** data)
{
    (void)data;
    return CWE415_Double_Free_sigriscv_char_badSource();
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
char ** CWE415_Double_Free__malloc_free_char_61b_goodG2BSource(char ** data)
{
    (void)data;
    return CWE415_Double_Free_sigriscv_char_goodG2BSource();
}

/* goodB2G() uses the BadSource with the GoodSink */
char ** CWE415_Double_Free__malloc_free_char_61b_goodB2GSource(char ** data)
{
    (void)data;
    return CWE415_Double_Free_sigriscv_char_goodB2GSource();
}

#endif /* OMITGOOD */
