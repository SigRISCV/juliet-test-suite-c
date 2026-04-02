/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE416_Use_After_Free__malloc_free_char_16.c
Label Definition File: CWE416_Use_After_Free__malloc_free.label.xml
Template File: sources-sinks-16.tmpl.c
*/
/*
 * @description
 * CWE: 416 Use After Free
 * BadSource:  Allocate data using malloc(), initialize memory block, and Deallocate data using free()
 * GoodSource: Allocate data using malloc() and initialize memory block
 * Sinks:
 *    GoodSink: Do nothing
 *    BadSink : Use data
 * Flow Variant: 16 Control flow: while(1)
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE416_Use_After_Free__malloc_free_char_16_bad()
{
    /* SigRISCV Stage 2: use char** so freed heap block triggers ls QARMA failure */
    char **pp;
    char **p3;
    char *inner;
    /* Initialize data */
    pp = NULL;
    p3 = NULL;
    inner = NULL;
    while(1)
    {
        pp = (char **)malloc(sizeof(char *));
        if (pp == NULL) {exit(-1);}
        inner = (char *)malloc(100*sizeof(char));
        if (inner == NULL) {exit(-1);}
        memset(inner, 'A', 100-1);
        inner[100-1] = '\0';
        *pp = inner; /* ss: QARMA-encrypt inner stored at heap address pp */
        /* POTENTIAL FLAW: Free data in the source - the bad sink attempts to use data */
        free((__raw void *)pp);
        p3 = (char **)malloc(sizeof(char *));
        if (p3 == NULL) {exit(-1);}
        *p3 = inner;
        break;
    }
    while(1)
    {
        /* POTENTIAL FLAW: Use of data that may have been freed */
        printLine(*pp);
        free((__raw void *)p3);
        free(inner);
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
        break;
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G() - use badsource and goodsink by changing the sinks in the second while statement */
static void goodB2G()
{
    /* SigRISCV Stage 2: use char** so freed heap block triggers ls QARMA failure */
    char **pp;
    char **p3;
    char *inner;
    /* Initialize data */
    pp = NULL;
    p3 = NULL;
    inner = NULL;
    while(1)
    {
        pp = (char **)malloc(sizeof(char *));
        if (pp == NULL) {exit(-1);}
        inner = (char *)malloc(100*sizeof(char));
        if (inner == NULL) {exit(-1);}
        memset(inner, 'A', 100-1);
        inner[100-1] = '\0';
        *pp = inner; /* ss: QARMA-encrypt inner stored at heap address pp */
        /* POTENTIAL FLAW: Free data in the source - the bad sink attempts to use data */
        free((__raw void *)pp);
        p3 = (char **)malloc(sizeof(char *));
        if (p3 == NULL) {exit(-1);}
        *p3 = inner;
        break;
    }
    while(1)
    {
        /* FIX: Don't use data that may have been freed already */
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
        /* do nothing */
        ; /* empty statement needed for some flow variants */
        free((__raw void *)p3);
        free(inner);
        break;
    }
}

/* goodG2B() - use goodsource and badsink by changing the sources in the first while statement */
static void goodG2B()
{
    /* SigRISCV Stage 2: use char** so freed heap block triggers ls QARMA failure */
    char **pp;
    char *inner;
    /* Initialize data */
    pp = NULL;
    inner = NULL;
    while(1)
    {
        pp = (char **)malloc(sizeof(char *));
        if (pp == NULL) {exit(-1);}
        inner = (char *)malloc(100*sizeof(char));
        if (inner == NULL) {exit(-1);}
        memset(inner, 'A', 100-1);
        inner[100-1] = '\0';
        *pp = inner; /* ss: QARMA-encrypt inner stored at heap address pp */
        /* FIX: Do not free data in the source */
        break;
    }
    while(1)
    {
        /* POTENTIAL FLAW: Use of data that may have been freed */
        printLine(*pp);
        free((__raw void *)pp);
        free(inner);
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
        break;
    }
}

void CWE416_Use_After_Free__malloc_free_char_16_good()
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

int main(int argc, char * __raw argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE416_Use_After_Free__malloc_free_char_16_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE416_Use_After_Free__malloc_free_char_16_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
