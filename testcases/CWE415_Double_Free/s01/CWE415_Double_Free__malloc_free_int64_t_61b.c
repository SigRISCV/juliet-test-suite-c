/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE415_Double_Free__malloc_free_int64_t_61b.c
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

#include "CWE415_Double_Free__sigriscv_int64_t_helpers.h"

#ifndef OMITBAD

int64_t ** CWE415_Double_Free__malloc_free_int64_t_61b_badSource(int64_t ** data)
{
    (void)data;
    return CWE415_Double_Free_sigriscv_int64_t_badSource();
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
int64_t ** CWE415_Double_Free__malloc_free_int64_t_61b_goodG2BSource(int64_t ** data)
{
    (void)data;
    return CWE415_Double_Free_sigriscv_int64_t_goodG2BSource();
}

/* goodB2G() uses the BadSource with the GoodSink */
int64_t ** CWE415_Double_Free__malloc_free_int64_t_61b_goodB2GSource(int64_t ** data)
{
    (void)data;
    return CWE415_Double_Free_sigriscv_int64_t_goodB2GSource();
}

#endif /* OMITGOOD */
