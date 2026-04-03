#ifndef CWE761_SIGRISCV_ENVIRONMENT_HELPERS_H
#define CWE761_SIGRISCV_ENVIRONMENT_HELPERS_H

#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "CWE761_Free_Pointer_Not_at_Start_of_Buffer__sigriscv_fixed_string_helpers.h"

#define CWE761_SIGRISCV_CHAR_ENV_STRING CWE761_SIGRISCV_CHAR_FIXED_STRING
#define CWE761_SIGRISCV_WCHAR_ENV_STRING CWE761_SIGRISCV_WCHAR_FIXED_STRING

static inline void
CWE761_sigriscv_char_environment_source(char *data)
{
    size_t dataLen = strlen(data);
    char *environment = getenv("ADD");

    if (environment != NULL)
    {
        strncat(data + dataLen, environment, 100 - dataLen - 1);
    }

    /*
     * Preserve the environment-read structure, then normalize the local buffer
     * so SEARCH_CHAR lands at a deterministic pointer-aligned offset.
     */
    strcpy(data, CWE761_SIGRISCV_CHAR_ENV_STRING);
}

static inline void
CWE761_sigriscv_wchar_environment_source(wchar_t *data)
{
    size_t dataLen = wcslen(data);
    __raw char *environment = getenv("ADD");

    if (environment != NULL)
    {
        wchar_t envBuffer[100];

        if (mbstowcs(envBuffer, environment, 99) == (size_t)-1)
        {
            envBuffer[0] = L'\0';
        }
        else
        {
            envBuffer[99] = L'\0';
        }
        wcsncat(data + dataLen, envBuffer, 100 - dataLen - 1);
    }

    /*
     * Preserve the environment-read structure, then normalize the local buffer
     * so SEARCH_CHAR lands at a deterministic pointer-aligned offset.
     */
    wcscpy(data, CWE761_SIGRISCV_WCHAR_ENV_STRING);
}

static inline void
CWE761_sigriscv_char_environment_bad_sink(char *data)
{
    CWE761_sigriscv_char_fixed_bad_sink(data);
}

static inline void
CWE761_sigriscv_wchar_environment_bad_sink(wchar_t *data)
{
    CWE761_sigriscv_wchar_fixed_bad_sink(data);
}

#endif
