/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE416_Use_After_Free__malloc_free_wchar_t_63b.c
Label Definition File: CWE416_Use_After_Free__malloc_free.label.xml
Template File: sources-sinks-63b.tmpl.c
*/
/*
 * @description
 * CWE: 416 Use After Free
 * BadSource:  Allocate data using malloc(), initialize memory block, and Deallocate data using free()
 * GoodSource: Allocate data using malloc() and initialize memory block
 * Sinks:
 *    GoodSink: Do nothing
 *    BadSink : Use data
 * Flow Variant: 63 Data flow: pointer to data passed from one function to another in different source files
 *
 * SigRISCV Stage 2: dataPtr is now a freed heap block; *dataPtr triggers ls QARMA failure.
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE416_Use_After_Free__malloc_free_wchar_t_63b_badSink(wchar_t * * dataPtr)
{
    /* SigRISCV Stage 2: dataPtr is freed heap block; ls from *dataPtr → QARMA mismatch → SIGILL */
    /* POTENTIAL FLAW: Use of data that may have been freed */
    printWLine(*dataPtr);
    /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE416_Use_After_Free__malloc_free_wchar_t_63b_goodG2BSink(wchar_t * * dataPtr)
{
    /* SigRISCV Stage 2: dataPtr is valid heap block; ls from *dataPtr succeeds */
    /* POTENTIAL FLAW: Use of data that may have been freed */
    printWLine(*dataPtr);
    /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE416_Use_After_Free__malloc_free_wchar_t_63b_goodB2GSink(wchar_t * * dataPtr)
{
    /* FIX: Don't use dataPtr that may have been freed already */
    /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
    /* do nothing */
    ; /* empty statement needed for some flow variants */
}

#endif /* OMITGOOD */
