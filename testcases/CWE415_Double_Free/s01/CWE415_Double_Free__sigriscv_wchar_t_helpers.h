#ifndef CWE415_DOUBLE_FREE_SIGRISCV_WCHAR_T_HELPERS_H
#define CWE415_DOUBLE_FREE_SIGRISCV_WCHAR_T_HELPERS_H

#include "std_testcase.h"

#include <wchar.h>

static inline wchar_t **
CWE415_Double_Free_sigriscv_wchar_t_badSource(void)
{
    wchar_t **slot1;
    wchar_t **slot2;
    wchar_t **slot3;
    wchar_t *inner;

    slot1 = (wchar_t **)malloc(sizeof(wchar_t *));
    if (slot1 == NULL) {exit(-1);}
    inner = (wchar_t *)malloc(100 * sizeof(wchar_t));
    if (inner == NULL) {exit(-1);}
    wmemset(inner, L'A', 99);
    inner[99] = L'\0';

    free((__raw void *)slot1);
    free((__raw void *)slot1);

    slot2 = (wchar_t **)malloc(sizeof(wchar_t *));
    if (slot2 == NULL) {exit(-1);}
    slot3 = (wchar_t **)malloc(sizeof(wchar_t *));
    if (slot3 == NULL) {exit(-1);}

    *slot3 = inner;
    return slot2;
}

static inline wchar_t **
CWE415_Double_Free_sigriscv_wchar_t_goodG2BSource(void)
{
    wchar_t **slot1;
    wchar_t *inner;

    slot1 = (wchar_t **)malloc(sizeof(wchar_t *));
    if (slot1 == NULL) {exit(-1);}
    inner = (wchar_t *)malloc(100 * sizeof(wchar_t));
    if (inner == NULL) {exit(-1);}
    wmemset(inner, L'A', 99);
    inner[99] = L'\0';

    *slot1 = inner;
    return slot1;
}

static inline wchar_t **
CWE415_Double_Free_sigriscv_wchar_t_goodB2GSource(void)
{
    wchar_t **slot1;
    wchar_t *inner;

    slot1 = (wchar_t **)malloc(sizeof(wchar_t *));
    if (slot1 == NULL) {exit(-1);}
    inner = (wchar_t *)malloc(100 * sizeof(wchar_t));
    if (inner == NULL) {exit(-1);}
    wmemset(inner, L'A', 99);
    inner[99] = L'\0';

    *slot1 = inner;
    free((__raw void *)slot1);
    free(inner);
    return slot1;
}

static inline void
CWE415_Double_Free_sigriscv_wchar_t_badSink(wchar_t **data)
{
    printWLine(*data);
}

static inline void
CWE415_Double_Free_sigriscv_wchar_t_goodG2BSink(wchar_t **data)
{
    printWLine(*data);
    free(*data);
    free((__raw void *)data);
}

static inline void
CWE415_Double_Free_sigriscv_wchar_t_goodB2GSink(wchar_t **data)
{
    (void)data;
}

#endif
