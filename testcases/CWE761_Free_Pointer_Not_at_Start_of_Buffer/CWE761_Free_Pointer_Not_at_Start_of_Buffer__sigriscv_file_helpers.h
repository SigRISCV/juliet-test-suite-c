#ifndef CWE761_SIGRISCV_FILE_HELPERS_H
#define CWE761_SIGRISCV_FILE_HELPERS_H

#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "CWE761_Free_Pointer_Not_at_Start_of_Buffer__sigriscv_fixed_string_helpers.h"

static inline void
CWE761_sigriscv_char_file_source(char *data, const __raw char *filename)
{
    size_t dataLen = strlen(data);
    __raw FILE *pFile;

    if (100 - dataLen > 1)
    {
        pFile = fopen(filename, "r");
        if (pFile != NULL)
        {
            if (fgets(data + dataLen, (int)(100 - dataLen), pFile) == NULL)
            {
                printLine("fgets() failed");
                data[dataLen] = '\0';
            }
            fclose(pFile);
        }
    }

    /*
     * Preserve the file-read structure, then normalize the local buffer so
     * SEARCH_CHAR lands at a deterministic pointer-aligned offset.
     */
    strcpy(data, CWE761_SIGRISCV_CHAR_FIXED_STRING);
}

static inline void
CWE761_sigriscv_wchar_file_source(wchar_t *data, const __raw char *filename)
{
    size_t dataLen = wcslen(data);
    __raw FILE *pFile;

    if (100 - dataLen > 1)
    {
        pFile = fopen(filename, "r");
        if (pFile != NULL)
        {
            if (fgetws(data + dataLen, (int)(100 - dataLen), pFile) == NULL)
            {
                printLine("fgetws() failed");
                data[dataLen] = L'\0';
            }
            fclose(pFile);
        }
    }

    /*
     * Preserve the file-read structure, then normalize the local buffer so
     * SEARCH_CHAR lands at a deterministic pointer-aligned offset.
     */
    wcscpy(data, CWE761_SIGRISCV_WCHAR_FIXED_STRING);
}

static inline void
CWE761_sigriscv_char_file_bad_sink(char *data)
{
    CWE761_sigriscv_char_fixed_bad_sink(data);
}

static inline void
CWE761_sigriscv_wchar_file_bad_sink(wchar_t *data)
{
    CWE761_sigriscv_wchar_fixed_bad_sink(data);
}

#endif
