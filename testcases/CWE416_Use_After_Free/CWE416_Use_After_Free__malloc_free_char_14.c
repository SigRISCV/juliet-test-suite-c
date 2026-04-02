/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE416_Use_After_Free__malloc_free_char_14.c
Label Definition File: CWE416_Use_After_Free__malloc_free.label.xml
Template File: sources-sinks-14.tmpl.c
*/
/*
 * @description
 * CWE: 416 Use After Free
 * BadSource:  Allocate data using malloc(), initialize memory block, and Deallocate data using free()
 * GoodSource: Allocate data using malloc() and initialize memory block
 * Sinks:
 *    GoodSink: Do nothing
 *    BadSink : Use data
 * Flow Variant: 14 Control flow: if(globalFive==5) and if(globalFive!=5)
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE416_Use_After_Free__malloc_free_char_14_bad()
{
    /* SigRISCV Stage 2: use char** so freed heap block triggers ls QARMA failure */
    char **pp;
    char **p3;
    char *inner;
    /* Initialize data */
    pp = NULL;
    p3 = NULL;
    inner = NULL;
    if(globalFive==5)
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
    }
    if(globalFive==5)
    {
        /* POTENTIAL FLAW: Use of data that may have been freed */
        printLine(*pp);
        free((__raw void *)p3);
        free(inner);
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G1() - use badsource and goodsink by changing the second globalFive==5 to globalFive!=5 */
static void goodB2G1()
{
    /* SigRISCV Stage 2: use char** so freed heap block triggers ls QARMA failure */
    char **pp;
    char **p3;
    char *inner;
    /* Initialize data */
    pp = NULL;
    p3 = NULL;
    inner = NULL;
    if(globalFive==5)
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
    }
    if(globalFive!=5)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        /* FIX: Don't use data that may have been freed already */
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
        /* do nothing */
        ; /* empty statement needed for some flow variants */
        free((__raw void *)p3);
        free(inner);
    }
}

/* goodB2G2() - use badsource and goodsink by reversing the blocks in the second if */
static void goodB2G2()
{
    /* SigRISCV Stage 2: use char** so freed heap block triggers ls QARMA failure */
    char **pp;
    char **p3;
    char *inner;
    /* Initialize data */
    pp = NULL;
    p3 = NULL;
    inner = NULL;
    if(globalFive==5)
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
    }
    if(globalFive==5)
    {
        /* FIX: Don't use data that may have been freed already */
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
        /* do nothing */
        ; /* empty statement needed for some flow variants */
        free((__raw void *)p3);
        free(inner);
    }
}

/* goodG2B1() - use goodsource and badsink by changing the first globalFive==5 to globalFive!=5 */
static void goodG2B1()
{
    /* SigRISCV Stage 2: use char** so freed heap block triggers ls QARMA failure */
    char **pp;
    char *inner;
    /* Initialize data */
    pp = NULL;
    inner = NULL;
    if(globalFive!=5)
    {
        /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
        printLine("Benign, fixed string");
    }
    else
    {
        pp = (char **)malloc(sizeof(char *));
        if (pp == NULL) {exit(-1);}
        inner = (char *)malloc(100*sizeof(char));
        if (inner == NULL) {exit(-1);}
        memset(inner, 'A', 100-1);
        inner[100-1] = '\0';
        *pp = inner; /* ss: QARMA-encrypt inner stored at heap address pp */
        /* FIX: Do not free data in the source */
    }
    if(globalFive==5)
    {
        /* POTENTIAL FLAW: Use of data that may have been freed */
        printLine(*pp);
        free((__raw void *)pp);
        free(inner);
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
    }
}

/* goodG2B2() - use goodsource and badsink by reversing the blocks in the first if */
static void goodG2B2()
{
    /* SigRISCV Stage 2: use char** so freed heap block triggers ls QARMA failure */
    char **pp;
    char *inner;
    /* Initialize data */
    pp = NULL;
    inner = NULL;
    if(globalFive==5)
    {
        pp = (char **)malloc(sizeof(char *));
        if (pp == NULL) {exit(-1);}
        inner = (char *)malloc(100*sizeof(char));
        if (inner == NULL) {exit(-1);}
        memset(inner, 'A', 100-1);
        inner[100-1] = '\0';
        *pp = inner; /* ss: QARMA-encrypt inner stored at heap address pp */
        /* FIX: Do not free data in the source */
    }
    if(globalFive==5)
    {
        /* POTENTIAL FLAW: Use of data that may have been freed */
        printLine(*pp);
        free((__raw void *)pp);
        free(inner);
        /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
    }
}

void CWE416_Use_After_Free__malloc_free_char_14_good()
{
    goodB2G1();
    goodB2G2();
    goodG2B1();
    goodG2B2();
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
    CWE416_Use_After_Free__malloc_free_char_14_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE416_Use_After_Free__malloc_free_char_14_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
