/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE415_Double_Free__malloc_free_wchar_t_68b.c
Label Definition File: CWE415_Double_Free__malloc_free.label.xml
Template File: sources-sinks-68b.tmpl.c
*/
/*
 * @description
 * CWE: 415 Double Free
 * BadSource:  Allocate data using malloc() and Deallocate data using free()
 * GoodSource: Allocate data using malloc()
 * Sinks:
 *    GoodSink: do nothing
 *    BadSink : Deallocate data using free()
 * Flow Variant: 68 Data flow: data passed as a global variable from one function to another in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#include "CWE415_Double_Free__sigriscv_wchar_t_helpers.h"

extern wchar_t ** CWE415_Double_Free__malloc_free_wchar_t_68_badData;
extern wchar_t ** CWE415_Double_Free__malloc_free_wchar_t_68_goodG2BData;
extern wchar_t ** CWE415_Double_Free__malloc_free_wchar_t_68_goodB2GData;

#ifndef OMITBAD

void CWE415_Double_Free__malloc_free_wchar_t_68b_badSink()
{
    wchar_t ** data = CWE415_Double_Free__malloc_free_wchar_t_68_badData;
    CWE415_Double_Free_sigriscv_wchar_t_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE415_Double_Free__malloc_free_wchar_t_68b_goodG2BSink()
{
    wchar_t ** data = CWE415_Double_Free__malloc_free_wchar_t_68_goodG2BData;
    CWE415_Double_Free_sigriscv_wchar_t_goodG2BSink(data);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE415_Double_Free__malloc_free_wchar_t_68b_goodB2GSink()
{
    wchar_t ** data = CWE415_Double_Free__malloc_free_wchar_t_68_goodB2GData;
    /* do nothing */
    /* FIX: Don't attempt to free the memory */
    ; /* empty statement needed for some flow variants */
}

#endif /* OMITGOOD */
