#ifndef CWE761_SIGRISCV_CONSOLE_HELPERS_H
#define CWE761_SIGRISCV_CONSOLE_HELPERS_H

#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "CWE761_Free_Pointer_Not_at_Start_of_Buffer__sigriscv_fixed_string_helpers.h"

static inline void
CWE761_sigriscv_char_console_source(char *data)
{
    size_t dataLen = strlen(data);

    if (100 - dataLen > 1)
    {
        if (fgets(data + dataLen, (int)(100 - dataLen), stdin) != NULL)
        {
            dataLen = strlen(data);
            if (dataLen > 0 && data[dataLen - 1] == '\n')
            {
                data[dataLen - 1] = '\0';
            }
        }
        else
        {
            printLine("fgets() failed");
            data[dataLen] = '\0';
        }
    }

    /*
     * Preserve the console-read structure, then normalize the local buffer so
     * SEARCH_CHAR lands at a deterministic pointer-aligned offset.
     */
    strcpy(data, CWE761_SIGRISCV_CHAR_FIXED_STRING);
}

static inline void
CWE761_sigriscv_wchar_console_source(wchar_t *data)
{
    size_t dataLen = wcslen(data);

    if (100 - dataLen > 1)
    {
        if (fgetws(data + dataLen, (int)(100 - dataLen), stdin) != NULL)
        {
            dataLen = wcslen(data);
            if (dataLen > 0 && data[dataLen - 1] == L'\n')
            {
                data[dataLen - 1] = L'\0';
            }
        }
        else
        {
            printLine("fgetws() failed");
            data[dataLen] = L'\0';
        }
    }

    /*
     * Preserve the console-read structure, then normalize the local buffer so
     * SEARCH_CHAR lands at a deterministic pointer-aligned offset.
     */
    wcscpy(data, CWE761_SIGRISCV_WCHAR_FIXED_STRING);
}

static inline void
CWE761_sigriscv_char_console_bad_sink(char *data)
{
    CWE761_sigriscv_char_fixed_bad_sink(data);
}

static inline void
CWE761_sigriscv_wchar_console_bad_sink(wchar_t *data)
{
    CWE761_sigriscv_wchar_fixed_bad_sink(data);
}

#endif
