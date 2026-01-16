#include <winternl.h>
#include <windows.h>

#include <stdlib.h>
#include <stdio.h>

/*
- before executing the shellcode setup the return Addr as one instruction of kernel32.dll (for exemple)
- This instruction need to be a JMP to a dereferenced register so that we can set the register value ourselves
- 

*/
typedef struct _STACK_CONFIG {
    PVOID pRopGadget; //PTR to Gadget
    PVOID pEbx; //PTR to EBX
    PVOID pTarget; //PTR to function (MessageBoxA or stv)
    PVOID pArgs; //PTR to the args of the functions
    DWORD dwNumberOfArgs; //Nb of ars of the function
} STACK_CONFIG, *PSTACK_CONFIG;

extern PVOID spoofCall(PSTACK_CONFIG pConfig);

BOOL SetupConfig(PSTACK_CONFIG pConfig, PVOID pRopGadget, PVOID pEbx, PVOID pTarget, PVOID pArgs, DWORD dwNumberOfArgs) {


}

int main() {
    //MessageBoxA();


    return 0;

}