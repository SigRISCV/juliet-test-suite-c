/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_54e.c
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-54e.tmpl.c
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: fixed_string Initialize data to be a fixed string
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>
#include "CWE761_Free_Pointer_Not_at_Start_of_Buffer__sigriscv_fixed_string_helpers.h"


#define BAD_SOURCE_FIXED_STRING CWE761_SIGRISCV_CHAR_FIXED_STRING /* MAINTENANCE NOTE: SEARCH_CHAR is at an aligned offset */

#define SEARCH_CHAR 'S'

#ifndef OMITBAD

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_54e_badSink(char * data)
{
    CWE761_sigriscv_char_fixed_bad_sink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_54e_goodB2GSink(char * data)
{
    {
        size_t i;
        /* FIX: Use a loop variable to traverse through the string pointed to by data */
        for (i=0; i < strlen(data); i++)
        {
            if (data[i] == SEARCH_CHAR)
            {
                printLine("We have a match!");
                break;
            }
        }
        free(data);
    }
}

#endif /* OMITGOOD */
