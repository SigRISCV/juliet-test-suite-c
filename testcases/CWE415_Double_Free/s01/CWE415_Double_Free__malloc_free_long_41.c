/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE415_Double_Free__malloc_free_long_41.c
Label Definition File: CWE415_Double_Free__malloc_free.label.xml
Template File: sources-sinks-41.tmpl.c
*/
/*
 * @description
 * CWE: 415 Double Free
 * BadSource:  Allocate data using malloc() and Deallocate data using free()
 * GoodSource: Allocate data using malloc()
 * Sinks:
 *    GoodSink: do nothing
 *    BadSink : Deallocate data using free()
 * Flow Variant: 41 Data flow: data passed as an argument from one function to another in the same source file
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#include "CWE415_Double_Free__sigriscv_long_helpers.h"

#ifndef OMITBAD

static void badSink(long ** data)
{
    CWE415_Double_Free_sigriscv_long_badSink(data);
}

void CWE415_Double_Free__malloc_free_long_41_bad()
{
    long ** data;
    /* Initialize data */
    data = NULL;
    data = CWE415_Double_Free_sigriscv_long_badSource();
    badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2BSink(long ** data)
{
    CWE415_Double_Free_sigriscv_long_goodG2BSink(data);
}

static void goodG2B()
{
    long ** data;
    /* Initialize data */
    data = NULL;
    data = CWE415_Double_Free_sigriscv_long_goodG2BSource();
    goodG2BSink(data);
}

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2GSink(long ** data)
{
    /* do nothing */
    /* FIX: Don't attempt to free the memory */
    ; /* empty statement needed for some flow variants */
}

static void goodB2G()
{
    long ** data;
    /* Initialize data */
    data = NULL;
    data = CWE415_Double_Free_sigriscv_long_goodB2GSource();
    goodB2GSink(data);
}

void CWE415_Double_Free__malloc_free_long_41_good()
{
    goodB2G();
    goodG2B();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */

#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE415_Double_Free__malloc_free_long_41_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE415_Double_Free__malloc_free_long_41_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
