/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE416_Use_After_Free__malloc_free_struct_18.c
Label Definition File: CWE416_Use_After_Free__malloc_free.label.xml
Template File: sources-sinks-18.tmpl.c
*/
/*
 * @description
 * CWE: 416 Use After Free
 * BadSource:  Allocate data using malloc(), initialize memory block, and Deallocate data using free()
 * GoodSource: Allocate data using malloc() and initialize memory block
 * Sinks:
 *    GoodSink: Do nothing
 *    BadSink : Use data
 * Flow Variant: 18 Control flow: goto statements
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

void CWE416_Use_After_Free__malloc_free_struct_18_bad()
{
    /* SigRISCV Stage 2: use twoIntsStruct** so freed heap block triggers ls QARMA failure */
    twoIntsStruct **pp;
    twoIntsStruct **p3;
    twoIntsStruct *inner;
    /* Initialize data */
    pp = NULL;
    p3 = NULL;
    inner = NULL;
    goto source;
source:
    pp = (twoIntsStruct **)malloc(sizeof(twoIntsStruct *));
    if (pp == NULL) {exit(-1);}
    inner = (twoIntsStruct *)malloc(100*sizeof(twoIntsStruct));
    if (inner == NULL) {exit(-1);}
    {
        size_t i;
        for(i = 0; i < 100; i++)
        {
            inner[i].intOne = 1;
            inner[i].intTwo = 2;
        }
    }
    *pp = inner; /* ss: QARMA-encrypt inner stored at heap address pp */
    /* POTENTIAL FLAW: Free data in the source - the bad sink attempts to use data */
    free((__raw void *)pp);
    p3 = (twoIntsStruct **)malloc(sizeof(twoIntsStruct *));
    if (p3 == NULL) {exit(-1);}
    *p3 = inner;
    goto sink;
sink:
    /* POTENTIAL FLAW: Use of data that may have been freed */
    printStructLine(&(*pp)[0]);
    free((__raw void *)p3);
    free(inner);
    /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G() - use badsource and goodsink by reversing the blocks on the second goto statement */
static void goodB2G()
{
    /* SigRISCV Stage 2: use twoIntsStruct** so freed heap block triggers ls QARMA failure */
    twoIntsStruct **pp;
    twoIntsStruct **p3;
    twoIntsStruct *inner;
    /* Initialize data */
    pp = NULL;
    p3 = NULL;
    inner = NULL;
    goto source;
source:
    pp = (twoIntsStruct **)malloc(sizeof(twoIntsStruct *));
    if (pp == NULL) {exit(-1);}
    inner = (twoIntsStruct *)malloc(100*sizeof(twoIntsStruct));
    if (inner == NULL) {exit(-1);}
    {
        size_t i;
        for(i = 0; i < 100; i++)
        {
            inner[i].intOne = 1;
            inner[i].intTwo = 2;
        }
    }
    *pp = inner; /* ss: QARMA-encrypt inner stored at heap address pp */
    /* POTENTIAL FLAW: Free data in the source - the bad sink attempts to use data */
    free((__raw void *)pp);
    p3 = (twoIntsStruct **)malloc(sizeof(twoIntsStruct *));
    if (p3 == NULL) {exit(-1);}
    *p3 = inner;
    goto sink;
sink:
    /* FIX: Don't use data that may have been freed already */
    /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
    /* do nothing */
    ; /* empty statement needed for some flow variants */
    free((__raw void *)p3);
    free(inner);
}

/* goodG2B() - use goodsource and badsink by reversing the blocks on the first goto statement */
static void goodG2B()
{
    /* SigRISCV Stage 2: use twoIntsStruct** so freed heap block triggers ls QARMA failure */
    twoIntsStruct **pp;
    twoIntsStruct *inner;
    /* Initialize data */
    pp = NULL;
    inner = NULL;
    goto source;
source:
    pp = (twoIntsStruct **)malloc(sizeof(twoIntsStruct *));
    if (pp == NULL) {exit(-1);}
    inner = (twoIntsStruct *)malloc(100*sizeof(twoIntsStruct));
    if (inner == NULL) {exit(-1);}
    {
        size_t i;
        for(i = 0; i < 100; i++)
        {
            inner[i].intOne = 1;
            inner[i].intTwo = 2;
        }
    }
    *pp = inner; /* ss: QARMA-encrypt inner stored at heap address pp */
    /* FIX: Do not free data in the source */
    goto sink;
sink:
    /* POTENTIAL FLAW: Use of data that may have been freed */
    printStructLine(&(*pp)[0]);
    free((__raw void *)pp);
    free(inner);
    /* POTENTIAL INCIDENTAL - Possible memory leak here if data was not freed */
}

void CWE416_Use_After_Free__malloc_free_struct_18_good()
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
    CWE416_Use_After_Free__malloc_free_struct_18_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE416_Use_After_Free__malloc_free_struct_18_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
