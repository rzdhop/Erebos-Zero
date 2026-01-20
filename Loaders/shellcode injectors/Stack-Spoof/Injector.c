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
    BOOL state = TRUE;


    return state;

}

PVOID FindROPGadget(LPCSTR moduleName)
{
    // Gadget: FF 23 -> jmp QWORD PTR [rbx]
    PBYTE hModule = (PBYTE)GetModuleHandleA(moduleName);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(hModule + dos->e_lfanew);

    DWORD textRva  = nt->OptionalHeader.BaseOfCode;
    DWORD textSize = nt->OptionalHeader.SizeOfCode;

    PBYTE text = hModule + textRva;

    for (DWORD i = 0; i < textSize - 1; i++)
    {
        if (text[i] == 0xFF && text[i + 1] == 0x23)
        {
            PVOID gadget = &text[i];
            printf("[*] Found ROP gadget (FF 23) in %s @ %p\n", moduleName, gadget);
            return gadget;
        }
    }

    return NULL;
}

int main() {
    //MessageBoxA();


    return 0;

}