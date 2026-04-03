/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_console_54a.c
Label Definition File: CWE761_Free_Pointer_Not_at_Start_of_Buffer.label.xml
Template File: source-sinks-54a.tmpl.c
*/
/*
 * @description
 * CWE: 761 Free Pointer not at Start of Buffer
 * BadSource: console Read input from the console
 * Sinks:
 *    GoodSink: free() memory correctly at the start of the buffer
 *    BadSink : free() memory not at the start of the buffer
 * Flow Variant: 54 Data flow: data passed as an argument from one function through three others to a fifth; all five functions are in different source files
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

#include "CWE761_Free_Pointer_Not_at_Start_of_Buffer__sigriscv_console_helpers.h"

#define SEARCH_CHAR 'S'

#ifndef OMITBAD

/* bad function declaration */
void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_console_54b_badSink(char * data);

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_console_54_bad()
{
    char * data;
    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}
    data[0] = '\0';
    {
        CWE761_sigriscv_char_console_source(data);
    }
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_console_54b_badSink(data);
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* good function declarations */
void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_console_54b_goodB2GSink(char * data);

/* goodB2G uses the BadSource with the GoodSink */
static void goodB2G()
{
    char * data;
    data = (char *)malloc(100*sizeof(char));
    if (data == NULL) {exit(-1);}
    data[0] = '\0';
    {
        CWE761_sigriscv_char_console_source(data);
    }
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_console_54b_goodB2GSink(data);
}

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_console_54_good()
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
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_console_54_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_console_54_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif
