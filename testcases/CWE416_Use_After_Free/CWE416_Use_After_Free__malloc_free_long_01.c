/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE416_Use_After_Free__malloc_free_long_01.c
Label Definition File: CWE416_Use_After_Free__malloc_free.label.xml
Template File: sources-sinks-01.tmpl.c
*/
/*
 * @description
 * CWE: 416 Use After Free
 * BadSource:  Allocate data using malloc(), initialize memory block, and Deallocate data using free()
 * GoodSource: Allocate data using malloc() and initialize memory block
 * Sinks:
 *    GoodSink: Do nothing
 *    BadSink : Use data
 * Flow Variant: 01 Baseline
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE416_Use_After_Free__malloc_free_long_01_bad()
{
    long **p1;
    long **p3;
    long *p2;
    p1 = NULL;
    p3 = NULL;
    p2 = NULL;
    p1 = (long **)malloc(sizeof(long *));
    if (p1 == NULL) {exit(-1);}
    p2 = (long *)malloc(100*sizeof(long));
    if (p2 == NULL) {exit(-1);}
    {
        size_t i;
        for(i = 0; i < 100; i++)
        {
            p2[i] = 5L;
        }
    }
    free((__raw void *)p1);
    p3 = (long **)malloc(sizeof(long *));
    if (p3 == NULL) {exit(-1);}
    *p3 = p2;
    /* POTENTIAL FLAW: Use of data that may have been freed */
    printLongLine((*p1)[0]);
    free((__raw void *)p3);
    free(p2);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
static void goodG2B()
{
    long **p1;
    long *p2;
    p1 = NULL;
    p2 = NULL;
    p1 = (long **)malloc(sizeof(long *));
    if (p1 == NULL) {exit(-1);}
    p2 = (long *)malloc(100*sizeof(long));
    if (p2 == NULL) {exit(-1);}
    {
        size_t i;
        for(i = 0; i < 100; i++)
        {
            p2[i] = 5L;
        }
    }
    *p1 = p2;
    /* FIX: Do not free data in the source */
    printLongLine((*p1)[0]);
    free((__raw void *)p1);
    free(p2);
}

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2G()
{
    long **p1;
    long **p3;
    long *p2;
    p1 = NULL;
    p3 = NULL;
    p2 = NULL;
    p1 = (long **)malloc(sizeof(long *));
    if (p1 == NULL) {exit(-1);}
    p2 = (long *)malloc(100*sizeof(long));
    if (p2 == NULL) {exit(-1);}
    {
        size_t i;
        for(i = 0; i < 100; i++)
        {
            p2[i] = 5L;
        }
    }
    free((__raw void *)p1);
    p3 = (long **)malloc(sizeof(long *));
    if (p3 == NULL) {exit(-1);}
    *p3 = p2;
    /* FIX: Don't use data that may have been freed already */
    free((__raw void *)p3);
    free(p2);
}

void CWE416_Use_After_Free__malloc_free_long_01_good()
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

int main(int argc, char * __raw argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE416_Use_After_Free__malloc_free_long_01_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE416_Use_After_Free__malloc_free_long_01_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
