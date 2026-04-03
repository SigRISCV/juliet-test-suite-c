/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_31.c
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-31.tmpl.c
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: fixed_string Initialize data to be a fixed string
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 31 Data flow using a copy of data within the same function
 *
 * */

#include "std_testcase.h"

#include <wchar.h>
#include "CWE761_Free_Pointer_Not_at_Start_of_Buffer__sigriscv_fixed_string_helpers.h"


#define BAD_SOURCE_FIXED_STRING CWE761_SIGRISCV_CHAR_FIXED_STRING /* MAINTENANCE NOTE: SEARCH_CHAR is at an aligned offset */

#define SEARCH_CHAR 'S'

#ifndef OMITBAD

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_31_bad()
{
    char * data;
    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}
    data[0] = '\0';
    /* POTENTIAL FLAW: Initialize data to be a fixed string that contains the search character in the sinks */
    strcpy(data, BAD_SOURCE_FIXED_STRING);
    {
        char * dataCopy = data;
        char * data = dataCopy;
        CWE761_sigriscv_char_fixed_bad_sink(data);
    }
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodB2G() uses the BadSource with the GoodSink */
static void goodB2G()
{
    char * data;
    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}
    data[0] = '\0';
    /* POTENTIAL FLAW: Initialize data to be a fixed string that contains the search character in the sinks */
    strcpy(data, BAD_SOURCE_FIXED_STRING);
    {
        char * dataCopy = data;
        char * data = dataCopy;
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
}

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_31_good()
{
    goodB2G();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */
#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_31_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_31_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
