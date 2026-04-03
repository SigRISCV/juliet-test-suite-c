/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE415_Double_Free__malloc_free_char_01.c
Label Definition File: CWE415_Double_Free__malloc_free.label.xml
Template File: sources-sinks-01.tmpl.c
*/
/*
 * @description
 * CWE: 415 Double Free
 * BadSource:  Allocate data using malloc() and Deallocate data using free()
 * GoodSource: Allocate data using malloc()
 * Sinks:
 *    GoodSink: do nothing
 *    BadSink : Deallocate data using free()
 * Flow Variant: 01 Baseline
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE415_Double_Free__malloc_free_char_01_bad()
{
    char **slot1;
    char **slot2;
    char **slot3;
    char *inner;
    /* Initialize data */
    slot1 = NULL;
    slot2 = NULL;
    slot3 = NULL;
    inner = NULL;
    slot1 = (char **)malloc(sizeof(char *));
    if (slot1 == NULL) {exit(-1);}
    inner = (char *)malloc(100*sizeof(char));
    if (inner == NULL) {exit(-1);}
    memset(inner, 'A', 100-1);
    inner[100-1] = '\0';
    /* POTENTIAL FLAW: Double free the same slot so allocator may hand it out twice */
    free((__raw void *)slot1);
    free((__raw void *)slot1);
    slot2 = (char **)malloc(sizeof(char *));
    if (slot2 == NULL) {exit(-1);}
    slot3 = (char **)malloc(sizeof(char *));
    if (slot3 == NULL) {exit(-1);}
    *slot3 = inner;
    /* POTENTIAL FLAW: If double free aliases slot2/slot3 to the same raw address,
     * *slot2 performs ls with a different safe ID than the prior ss(*slot3). */
    printLine(*slot2);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    char **slot1;
    char *inner;
    /* Initialize data */
    slot1 = NULL;
    inner = NULL;
    slot1 = (char **)malloc(sizeof(char *));
    if (slot1 == NULL) {exit(-1);}
    inner = (char *)malloc(100*sizeof(char));
    if (inner == NULL) {exit(-1);}
    memset(inner, 'A', 100-1);
    inner[100-1] = '\0';
    *slot1 = inner;
    /* FIX: No double free, no overlapping aliases */
    printLine(*slot1);
    free((__raw void *)slot1);
    free(inner);
}

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2G()
{
    char **slot1;
    char *inner;
    /* Initialize data */
    slot1 = NULL;
    inner = NULL;
    slot1 = (char **)malloc(sizeof(char *));
    if (slot1 == NULL) {exit(-1);}
    inner = (char *)malloc(100*sizeof(char));
    if (inner == NULL) {exit(-1);}
    memset(inner, 'A', 100-1);
    inner[100-1] = '\0';
    *slot1 = inner;
    /* FIX: Only free once, and do not create a second alias */
    free((__raw void *)slot1);
    free(inner);
    ; /* empty statement needed for some flow variants */
}

void CWE415_Double_Free__malloc_free_char_01_good()
{
    goodG2B();
    goodB2G();
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
    CWE415_Double_Free__malloc_free_char_01_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE415_Double_Free__malloc_free_char_01_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
