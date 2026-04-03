#ifndef CWE415_DOUBLE_FREE_SIGRISCV_STRUCT_HELPERS_H
#define CWE415_DOUBLE_FREE_SIGRISCV_STRUCT_HELPERS_H

#include "std_testcase.h"

static inline twoIntsStruct **
CWE415_Double_Free_sigriscv_struct_badSource(void)
{
    twoIntsStruct **slot1;
    twoIntsStruct **slot2;
    twoIntsStruct **slot3;
    twoIntsStruct *inner;

    slot1 = (twoIntsStruct **)malloc(sizeof(twoIntsStruct *));
    if (slot1 == NULL) {exit(-1);}
    inner = (twoIntsStruct *)malloc(100 * sizeof(twoIntsStruct));
    if (inner == NULL) {exit(-1);}
    inner[0].intOne = 1;
    inner[0].intTwo = 2;

    free((__raw void *)slot1);
    free((__raw void *)slot1);

    slot2 = (twoIntsStruct **)malloc(sizeof(twoIntsStruct *));
    if (slot2 == NULL) {exit(-1);}
    slot3 = (twoIntsStruct **)malloc(sizeof(twoIntsStruct *));
    if (slot3 == NULL) {exit(-1);}

    *slot3 = inner;
    return slot2;
}

static inline twoIntsStruct **
CWE415_Double_Free_sigriscv_struct_goodG2BSource(void)
{
    twoIntsStruct **slot1;
    twoIntsStruct *inner;

    slot1 = (twoIntsStruct **)malloc(sizeof(twoIntsStruct *));
    if (slot1 == NULL) {exit(-1);}
    inner = (twoIntsStruct *)malloc(100 * sizeof(twoIntsStruct));
    if (inner == NULL) {exit(-1);}
    inner[0].intOne = 1;
    inner[0].intTwo = 2;

    *slot1 = inner;
    return slot1;
}

static inline twoIntsStruct **
CWE415_Double_Free_sigriscv_struct_goodB2GSource(void)
{
    twoIntsStruct **slot1;
    twoIntsStruct *inner;

    slot1 = (twoIntsStruct **)malloc(sizeof(twoIntsStruct *));
    if (slot1 == NULL) {exit(-1);}
    inner = (twoIntsStruct *)malloc(100 * sizeof(twoIntsStruct));
    if (inner == NULL) {exit(-1);}
    inner[0].intOne = 1;
    inner[0].intTwo = 2;

    *slot1 = inner;
    free((__raw void *)slot1);
    free(inner);
    return slot1;
}

static inline void
CWE415_Double_Free_sigriscv_struct_badSink(twoIntsStruct **data)
{
    printStructLine(*data);
}

static inline void
CWE415_Double_Free_sigriscv_struct_goodG2BSink(twoIntsStruct **data)
{
    printStructLine(*data);
    free(*data);
    free((__raw void *)data);
}

static inline void
CWE415_Double_Free_sigriscv_struct_goodB2GSink(twoIntsStruct **data)
{
    (void)data;
}

#endif
