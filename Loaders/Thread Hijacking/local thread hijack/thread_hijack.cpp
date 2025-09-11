#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

/*
Suspend then patch the rip register from a thread to point to the shellcode !
 - use GetThreadConext -> Populate CONTEXT struct (https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context)
 - then setThreadContext -> apply a said CONTEXT to a thread


*/

int main(int argc, char** argv){
    

    return 0;
}