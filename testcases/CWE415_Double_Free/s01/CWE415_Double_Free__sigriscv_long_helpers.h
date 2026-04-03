#ifndef CWE415_DOUBLE_FREE_SIGRISCV_LONG_HELPERS_H
#define CWE415_DOUBLE_FREE_SIGRISCV_LONG_HELPERS_H

#include "std_testcase.h"

static inline long **
CWE415_Double_Free_sigriscv_long_badSource(void)
{
    long **slot1;
    long **slot2;
    long **slot3;
    long *inner;

    slot1 = (long **)malloc(sizeof(long *));
    if (slot1 == NULL) {exit(-1);}
    inner = (long *)malloc(100 * sizeof(long));
    if (inner == NULL) {exit(-1);}
    inner[0] = 5L;

    free((__raw void *)slot1);
    free((__raw void *)slot1);

    slot2 = (long **)malloc(sizeof(long *));
    if (slot2 == NULL) {exit(-1);}
    slot3 = (long **)malloc(sizeof(long *));
    if (slot3 == NULL) {exit(-1);}

    *slot3 = inner;
    return slot2;
}

static inline long **
CWE415_Double_Free_sigriscv_long_goodG2BSource(void)
{
    long **slot1;
    long *inner;

    slot1 = (long **)malloc(sizeof(long *));
    if (slot1 == NULL) {exit(-1);}
    inner = (long *)malloc(100 * sizeof(long));
    if (inner == NULL) {exit(-1);}
    inner[0] = 5L;

    *slot1 = inner;
    return slot1;
}

static inline long **
CWE415_Double_Free_sigriscv_long_goodB2GSource(void)
{
    long **slot1;
    long *inner;

    slot1 = (long **)malloc(sizeof(long *));
    if (slot1 == NULL) {exit(-1);}
    inner = (long *)malloc(100 * sizeof(long));
    if (inner == NULL) {exit(-1);}
    inner[0] = 5L;

    *slot1 = inner;
    free((__raw void *)slot1);
    free(inner);
    return slot1;
}

static inline void
CWE415_Double_Free_sigriscv_long_badSink(long **data)
{
    printLongLine((*data)[0]);
}

static inline void
CWE415_Double_Free_sigriscv_long_goodG2BSink(long **data)
{
    printLongLine((*data)[0]);
    free(*data);
    free((__raw void *)data);
}

static inline void
CWE415_Double_Free_sigriscv_long_goodB2GSink(long **data)
{
    (void)data;
}

#endif
