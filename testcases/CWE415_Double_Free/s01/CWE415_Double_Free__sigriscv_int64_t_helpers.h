#ifndef CWE415_DOUBLE_FREE_SIGRISCV_INT64_T_HELPERS_H
#define CWE415_DOUBLE_FREE_SIGRISCV_INT64_T_HELPERS_H

#include "std_testcase.h"

static inline int64_t **
CWE415_Double_Free_sigriscv_int64_t_badSource(void)
{
    int64_t **slot1;
    int64_t **slot2;
    int64_t **slot3;
    int64_t *inner;

    slot1 = (int64_t **)malloc(sizeof(int64_t *));
    if (slot1 == NULL) {exit(-1);}
    inner = (int64_t *)malloc(100 * sizeof(int64_t));
    if (inner == NULL) {exit(-1);}
    inner[0] = 5;

    free((__raw void *)slot1);
    free((__raw void *)slot1);

    slot2 = (int64_t **)malloc(sizeof(int64_t *));
    if (slot2 == NULL) {exit(-1);}
    slot3 = (int64_t **)malloc(sizeof(int64_t *));
    if (slot3 == NULL) {exit(-1);}

    *slot3 = inner;
    return slot2;
}

static inline int64_t **
CWE415_Double_Free_sigriscv_int64_t_goodG2BSource(void)
{
    int64_t **slot1;
    int64_t *inner;

    slot1 = (int64_t **)malloc(sizeof(int64_t *));
    if (slot1 == NULL) {exit(-1);}
    inner = (int64_t *)malloc(100 * sizeof(int64_t));
    if (inner == NULL) {exit(-1);}
    inner[0] = 5;

    *slot1 = inner;
    return slot1;
}

static inline int64_t **
CWE415_Double_Free_sigriscv_int64_t_goodB2GSource(void)
{
    int64_t **slot1;
    int64_t *inner;

    slot1 = (int64_t **)malloc(sizeof(int64_t *));
    if (slot1 == NULL) {exit(-1);}
    inner = (int64_t *)malloc(100 * sizeof(int64_t));
    if (inner == NULL) {exit(-1);}
    inner[0] = 5;

    *slot1 = inner;
    free((__raw void *)slot1);
    free(inner);
    return slot1;
}

static inline void
CWE415_Double_Free_sigriscv_int64_t_badSink(int64_t **data)
{
    printLongLongLine((*data)[0]);
}

static inline void
CWE415_Double_Free_sigriscv_int64_t_goodG2BSink(int64_t **data)
{
    printLongLongLine((*data)[0]);
    free(*data);
    free((__raw void *)data);
}

static inline void
CWE415_Double_Free_sigriscv_int64_t_goodB2GSink(int64_t **data)
{
    (void)data;
}

#endif
