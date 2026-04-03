/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE415_Double_Free__malloc_free_wchar_t_61b.c
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

#include "CWE415_Double_Free__sigriscv_wchar_t_helpers.h"

#ifndef OMITBAD

wchar_t ** CWE415_Double_Free__malloc_free_wchar_t_61b_badSource(wchar_t ** data)
{
    (void)data;
    return CWE415_Double_Free_sigriscv_wchar_t_badSource();
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
wchar_t ** CWE415_Double_Free__malloc_free_wchar_t_61b_goodG2BSource(wchar_t ** data)
{
    (void)data;
    return CWE415_Double_Free_sigriscv_wchar_t_goodG2BSource();
}

/* goodB2G() uses the BadSource with the GoodSink */
wchar_t ** CWE415_Double_Free__malloc_free_wchar_t_61b_goodB2GSource(wchar_t ** data)
{
    (void)data;
    return CWE415_Double_Free_sigriscv_wchar_t_goodB2GSource();
}

#endif /* OMITGOOD */
