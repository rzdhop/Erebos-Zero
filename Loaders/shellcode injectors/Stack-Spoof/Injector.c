#include <winternl.h>
#include <windows.h>

#include <stdlib.h>
#include <stdio.h>

/*
- before executing the shellcode setup the return Addr as one instruction of kernel32.dll (for exemple)
- This instruction need to be a JMP to a dereferenced register so that we can set the register value ourselves

*/
typedef struct _STACK_CONFIG {
    PVOID pRopGadget; //PTR to Gadget
    PVOID pRbx; //PTR to the RBX set for the kernel32 spoofed function
    PVOID pTarget; //PTR to function (MessageBoxA or stv)
    PVOID pArgs; //PTR to the args of the functions
    DWORD dwNumberOfArgs; //Nb of ars of the function
} STACK_CONFIG, *PSTACK_CONFIG;

extern PVOID spoofCall(PSTACK_CONFIG pConfig);

BOOL SetupConfig(PSTACK_CONFIG pConfig, PVOID pRopGadget, PVOID pTarget, DWORD dwNumberOfArgs) {
    BOOL state = TRUE;
    va_list additionalArgs;

    //According to the fascall ABI convention there is always 4 arguments RCX, RDX, R8, R9
    pConfig->dwNumberOfArgs = (dwNumberOfArgs > 4) ? dwNumberOfArgs : 4;
    //If the arguments are impair we add une arg to make it %16 before the call (1 push = 8 bytes)
    pConfig->dwNumberOfArgs += (dwNumberOfArgs % 2 != 0) ? 1 : 0; //if odd than add one argument (8bytes) else 0

    pConfig->pRopGadget = pRopGadget;
    pConfig->pTarget = pTarget;
    pConfig->pArgs = malloc(8 * pConfig->dwNumberOfArgs); //allocate 8 bytes time number of args

    memset(pConfig->pArgs, 0, 8 * pConfig->dwNumberOfArgs);
    
    //Say that there is more argument to our function avec DWORD dwNumberOfArgs
    va_start(additionalArgs, dwNumberOfArgs); //make additianlArgs point to the stack after DWORD dwNumberOfArgs and can be pop
    for (int i = 0; i < dwNumberOfArgs; i++){
        ((PUINT64)pConfig->pArgs)[i] = va_arg(additionalArgs, UINT64);
    }

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
    PSTACK_CONFIG config_messagebox = malloc(sizeof(STACK_CONFIG));
    memset(config_messagebox, 0, sizeof(STACK_CONFIG));

    PVOID pGadget = FindROPGadget("kernel32");

    HANDLE hUser32 = GetModuleHandleA("User32");
    PVOID pMessageBox = GetProcAddress(hUser32, "MessageBoxA");

    //MessageBoxA( NULL, "injected !", "Pwned by Rida", MB_ICONEXCLAMATION);
    SetupConfig(config_messagebox, pGadget, pMessageBox, 4, NULL, "injected !", "Pwned by Rida", MB_ICONEXCLAMATION);

    spoofCall(config_messagebox);

    return 0;

}