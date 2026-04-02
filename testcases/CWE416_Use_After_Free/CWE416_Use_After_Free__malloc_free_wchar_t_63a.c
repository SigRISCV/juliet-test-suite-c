/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE416_Use_After_Free__malloc_free_wchar_t_63a.c
Label Definition File: CWE416_Use_After_Free__malloc_free.label.xml
Template File: sources-sinks-63a.tmpl.c
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
 * SigRISCV Stage 2: pass pp (freed heap block) directly to sink so *pp triggers ls QARMA failure.
 * */

#include "std_testcase.h"

#include <wchar.h>

#ifndef OMITBAD

/* bad function declaration */
void CWE416_Use_After_Free__malloc_free_wchar_t_63b_badSink(wchar_t * * dataPtr);

void CWE416_Use_After_Free__malloc_free_wchar_t_63_bad()
{
    /* SigRISCV Stage 2: use wchar_t** so freed heap block triggers ls QARMA failure */
    wchar_t **pp;
    wchar_t **p3;
    wchar_t *inner;
    pp = NULL;
    p3 = NULL;
    inner = NULL;
    pp = (wchar_t **)malloc(sizeof(wchar_t *));
    if (pp == NULL) {exit(-1);}
    inner = (wchar_t *)malloc(100*sizeof(wchar_t));
    if (inner == NULL) {exit(-1);}
    wmemset(inner, L'A', 100-1);
    inner[100-1] = L'\0';
    *pp = inner; /* ss: QARMA-encrypt inner stored at heap address pp */
    /* POTENTIAL FLAW: Free pp (outer wrapper) and immediately reallocate the same-size slot */
    free((__raw void *)pp);
    p3 = (wchar_t **)malloc(sizeof(wchar_t *));
    if (p3 == NULL) {exit(-1);}
    *p3 = inner;
    /* Pass stale pp to sink: *pp in sink triggers ls QARMA mismatch */
    CWE416_Use_After_Free__malloc_free_wchar_t_63b_badSink(pp);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B uses the GoodSource with the BadSink */
void CWE416_Use_After_Free__malloc_free_wchar_t_63b_goodG2BSink(wchar_t * * data);

static void goodG2B()
{
    /* SigRISCV Stage 2: use wchar_t** so freed heap block triggers ls QARMA failure */
    wchar_t **pp;
    wchar_t *inner;
    pp = NULL;
    inner = NULL;
    pp = (wchar_t **)malloc(sizeof(wchar_t *));
    if (pp == NULL) {exit(-1);}
    inner = (wchar_t *)malloc(100*sizeof(wchar_t));
    if (inner == NULL) {exit(-1);}
    wmemset(inner, L'A', 100-1);
    inner[100-1] = L'\0';
    *pp = inner; /* ss: QARMA-encrypt inner stored at heap address pp */
    /* FIX: Do not free pp before use - pass valid pp to sink */
    CWE416_Use_After_Free__malloc_free_wchar_t_63b_goodG2BSink(pp);
    free(inner);
    free((__raw void *)pp);
}

/* goodB2G uses the BadSource with the GoodSink */
void CWE416_Use_After_Free__malloc_free_wchar_t_63b_goodB2GSink(wchar_t * * data);

static void goodB2G()
{
    /* SigRISCV Stage 2: use wchar_t** so freed heap block triggers ls QARMA failure */
    wchar_t **pp;
    wchar_t **p3;
    wchar_t *inner;
    pp = NULL;
    p3 = NULL;
    inner = NULL;
    pp = (wchar_t **)malloc(sizeof(wchar_t *));
    if (pp == NULL) {exit(-1);}
    inner = (wchar_t *)malloc(100*sizeof(wchar_t));
    if (inner == NULL) {exit(-1);}
    wmemset(inner, L'A', 100-1);
    inner[100-1] = L'\0';
    *pp = inner; /* ss: QARMA-encrypt inner stored at heap address pp */
    /* POTENTIAL FLAW: Free pp and reallocate the same-size slot */
    free((__raw void *)pp);
    p3 = (wchar_t **)malloc(sizeof(wchar_t *));
    if (p3 == NULL) {exit(-1);}
    *p3 = inner;
    /* Pass stale pp to good sink (which does nothing with it) */
    CWE416_Use_After_Free__malloc_free_wchar_t_63b_goodB2GSink(pp);
    free((__raw void *)p3);
    free(inner);
}

void CWE416_Use_After_Free__malloc_free_wchar_t_63_good()
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
    CWE416_Use_After_Free__malloc_free_wchar_t_63_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE416_Use_After_Free__malloc_free_wchar_t_63_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
