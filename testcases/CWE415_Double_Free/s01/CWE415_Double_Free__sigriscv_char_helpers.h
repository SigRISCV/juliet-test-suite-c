#ifndef CWE415_DOUBLE_FREE_SIGRISCV_CHAR_HELPERS_H
#define CWE415_DOUBLE_FREE_SIGRISCV_CHAR_HELPERS_H

#include "std_testcase.h"

#include <string.h>

static inline char **
CWE415_Double_Free_sigriscv_char_badSource(void)
{
    char **slot1;
    char **slot2;
    char **slot3;
    char *inner;

    slot1 = (char **)malloc(sizeof(char *));
    if (slot1 == NULL) {exit(-1);}
    inner = (char *)malloc(100 * sizeof(char));
    if (inner == NULL) {exit(-1);}
    memset(inner, 'A', 99);
    inner[99] = '\0';

    free((__raw void *)slot1);
    free((__raw void *)slot1);

    slot2 = (char **)malloc(sizeof(char *));
    if (slot2 == NULL) {exit(-1);}
    slot3 = (char **)malloc(sizeof(char *));
    if (slot3 == NULL) {exit(-1);}

    *slot3 = inner;
    return slot2;
}

static inline char **
CWE415_Double_Free_sigriscv_char_goodG2BSource(void)
{
    char **slot1;
    char *inner;

    slot1 = (char **)malloc(sizeof(char *));
    if (slot1 == NULL) {exit(-1);}
    inner = (char *)malloc(100 * sizeof(char));
    if (inner == NULL) {exit(-1);}
    memset(inner, 'A', 99);
    inner[99] = '\0';

    *slot1 = inner;
    return slot1;
}

static inline char **
CWE415_Double_Free_sigriscv_char_goodB2GSource(void)
{
    char **slot1;
    char *inner;

    slot1 = (char **)malloc(sizeof(char *));
    if (slot1 == NULL) {exit(-1);}
    inner = (char *)malloc(100 * sizeof(char));
    if (inner == NULL) {exit(-1);}
    memset(inner, 'A', 99);
    inner[99] = '\0';

    *slot1 = inner;
    free((__raw void *)slot1);
    free(inner);
    return slot1;
}

static inline void
CWE415_Double_Free_sigriscv_char_badSink(char **data)
{
    printLine(*data);
}

static inline void
CWE415_Double_Free_sigriscv_char_goodG2BSink(char **data)
{
    printLine(*data);
    free(*data);
    free((__raw void *)data);
}

static inline void
CWE415_Double_Free_sigriscv_char_goodB2GSink(char **data)
{
    (void)data;
}

#endif
