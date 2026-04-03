#ifndef CWE761_SIGRISCV_FIXED_STRING_HELPERS_H
#define CWE761_SIGRISCV_FIXED_STRING_HELPERS_H

#include <wchar.h>

#define CWE761_SIGRISCV_CHAR_FIXED_STRING "12345678S"
#define CWE761_SIGRISCV_WCHAR_FIXED_STRING L"12S"

static inline void
CWE761_sigriscv_char_fixed_bad_sink(char *data)
{
    char **reclaimed;
    char *message;

    for (; *data != '\0'; data++)
    {
        if (*data == 'S')
        {
            printLine("We have a match!");
            break;
        }
    }

    free(data);

    reclaimed = (char **)malloc(100 * sizeof(char));
    if (reclaimed == NULL) {exit(-1);}
    message = (char *)malloc(100 * sizeof(char));
    if (message == NULL) {exit(-1);}
    strcpy(message, "Reclaimed pointer string");
    *reclaimed = message;
    printLine(*(char **)data);
}

static inline void
CWE761_sigriscv_wchar_fixed_bad_sink(wchar_t *data)
{
    wchar_t **reclaimed;
    wchar_t *message;

    for (; *data != L'\0'; data++)
    {
        if (*data == L'S')
        {
            printLine("We have a match!");
            break;
        }
    }

    free(data);

    reclaimed = (wchar_t **)malloc(100 * sizeof(wchar_t));
    if (reclaimed == NULL) {exit(-1);}
    message = (wchar_t *)malloc(100 * sizeof(wchar_t));
    if (message == NULL) {exit(-1);}
    wcscpy(message, L"Reclaimed pointer string");
    *reclaimed = message;
    printWLine(*(wchar_t **)data);
}

#endif
