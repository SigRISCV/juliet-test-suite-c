/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE416_Use_After_Free__malloc_free_int_64b.c
Label Definition File: CWE416_Use_After_Free__malloc_free.label.xml
Template File: sources-sinks-64b.tmpl.c
*/
/*
 * @description
 * CWE: 416 Use After Free
 * BadSource:  Allocate data using malloc(), initialize memory block, and Deallocate data using free()
 * GoodSource: Allocate data using malloc() and initialize memory block
 * Sinks:
 *    GoodSink: Do nothing
 *    BadSink : Use data
 * Flow Variant: 64 Data flow: void pointer to data passed from one function to another in different source files
 *
 * SigRISCV Stage 2: dataVoidPtr is the freed heap block (int**); *((int**)dataVoidPtr) triggers ls QARMA failure.
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE416_Use_After_Free__malloc_free_int_64b_badSink(void * dataVoidPtr)
{
    /* SigRISCV Stage 2: dataVoidPtr is freed heap block (int**); ls from *pp → QARMA mismatch → SIGILL */
    /* cast void pointer to a pointer of the appropriate type */
    int ** pp = (int **)dataVoidPtr;
    /* POTENTIAL FLAW: Use of data that may have been freed - ls from freed heap block */
    printIntLine((*pp)[0]);
    /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE416_Use_After_Free__malloc_free_int_64b_goodG2BSink(void * dataVoidPtr)
{
    /* SigRISCV Stage 2: dataVoidPtr is valid heap block (int**); ls from *pp succeeds */
    /* cast void pointer to a pointer of the appropriate type */
    int ** pp = (int **)dataVoidPtr;
    /* POTENTIAL FLAW: Use of data that may have been freed */
    printIntLine((*pp)[0]);
    /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE416_Use_After_Free__malloc_free_int_64b_goodB2GSink(void * dataVoidPtr)
{
    /* cast void pointer to a pointer of the appropriate type */
    int ** pp = (int **)dataVoidPtr;
    (void)pp; /* suppress unused variable warning */
    /* FIX: Don't use pp that may have been freed already */
    /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
    /* do nothing */
    ; /* empty statement needed for some flow variants */
}

#endif /* OMITGOOD */
