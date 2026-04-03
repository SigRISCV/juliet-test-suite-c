#ifndef CWE415_DOUBLE_FREE_SIGRISCV_INT_HELPERS_H
#define CWE415_DOUBLE_FREE_SIGRISCV_INT_HELPERS_H

#include "std_testcase.h"

static inline int **
CWE415_Double_Free_sigriscv_int_badSource(void)
{
    int **slot1;
    int **slot2;
    int **slot3;
    int *inner;

    slot1 = (int **)malloc(sizeof(int *));
    if (slot1 == NULL) {exit(-1);}
    inner = (int *)malloc(100 * sizeof(int));
    if (inner == NULL) {exit(-1);}
    inner[0] = 5;

    free((__raw void *)slot1);
    free((__raw void *)slot1);

    slot2 = (int **)malloc(sizeof(int *));
    if (slot2 == NULL) {exit(-1);}
    slot3 = (int **)malloc(sizeof(int *));
    if (slot3 == NULL) {exit(-1);}

    *slot3 = inner;
    return slot2;
}

static inline int **
CWE415_Double_Free_sigriscv_int_goodG2BSource(void)
{
    int **slot1;
    int *inner;

    slot1 = (int **)malloc(sizeof(int *));
    if (slot1 == NULL) {exit(-1);}
    inner = (int *)malloc(100 * sizeof(int));
    if (inner == NULL) {exit(-1);}
    inner[0] = 5;

    *slot1 = inner;
    return slot1;
}

static inline int **
CWE415_Double_Free_sigriscv_int_goodB2GSource(void)
{
    int **slot1;
    int *inner;

    slot1 = (int **)malloc(sizeof(int *));
    if (slot1 == NULL) {exit(-1);}
    inner = (int *)malloc(100 * sizeof(int));
    if (inner == NULL) {exit(-1);}
    inner[0] = 5;

    *slot1 = inner;
    free((__raw void *)slot1);
    free(inner);
    return slot1;
}

static inline void
CWE415_Double_Free_sigriscv_int_badSink(int **data)
{
    printIntLine((*data)[0]);
}

static inline void
CWE415_Double_Free_sigriscv_int_goodG2BSink(int **data)
{
    printIntLine((*data)[0]);
    free(*data);
    free((__raw void *)data);
}

static inline void
CWE415_Double_Free_sigriscv_int_goodB2GSink(int **data)
{
    (void)data;
}

#endif
