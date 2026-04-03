/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE415_Double_Free__malloc_free_long_61b.c
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

#include "CWE415_Double_Free__sigriscv_long_helpers.h"

#ifndef OMITBAD

long ** CWE415_Double_Free__malloc_free_long_61b_badSource(long ** data)
{
    (void)data;
    return CWE415_Double_Free_sigriscv_long_badSource();
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
long ** CWE415_Double_Free__malloc_free_long_61b_goodG2BSource(long ** data)
{
    (void)data;
    return CWE415_Double_Free_sigriscv_long_goodG2BSource();
}

/* goodB2G() uses the BadSource with the GoodSink */
long ** CWE415_Double_Free__malloc_free_long_61b_goodB2GSource(long ** data)
{
    (void)data;
    return CWE415_Double_Free_sigriscv_long_goodB2GSource();
}

#endif /* OMITGOOD */
