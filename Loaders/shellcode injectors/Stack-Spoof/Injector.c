#include <winternl.h>
#include <windows.h>

#include <stdlib.h>
#include <stdio.h>

// gcc injector.c spoofer.o -o injector.exe -lkernel32

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

extern PVOID SpoofCall(PSTACK_CONFIG pConfig);

BOOL SetupConfig(PSTACK_CONFIG pConfig, PVOID pRopGadget, PVOID pTarget, DWORD dwNumberOfArgs, ...) {
    BOOL state = TRUE;
    va_list additionalArgs;

    printf("[*] Setup spoof calling\n");

    //According to the fascall ABI convention there is always 4 arguments RCX, RDX, R8, R9
    pConfig->dwNumberOfArgs = (dwNumberOfArgs > 4) ? dwNumberOfArgs : 4;
    printf("[*] pConfig->dwNumberOfArgs set to %d\n", pConfig->dwNumberOfArgs);

    pConfig->pRopGadget = pRopGadget;
    printf("[*] pConfig->pRopGadget set to 0x%p\n", pConfig->pRopGadget);
    pConfig->pTarget = pTarget;
    printf("[*] pConfig->pTarget set to 0x%p\n", pConfig->pTarget);

    pConfig->pArgs = malloc(8 * pConfig->dwNumberOfArgs); //allocate 8 bytes time number of args
    printf("[*] Allocating %d bytes for %d args\n", (8 * pConfig->dwNumberOfArgs), pConfig->dwNumberOfArgs);
    memset(pConfig->pArgs, 0, 8 * pConfig->dwNumberOfArgs);
    
    //Say that there is more argument to our function avec DWORD dwNumberOfArgs
    va_start(additionalArgs, dwNumberOfArgs); //make additianlArgs point to the stack after DWORD dwNumberOfArgs and can be pop
    for (int i = 0; i < dwNumberOfArgs; i++){
        ((PUINT64)pConfig->pArgs)[i] = va_arg(additionalArgs, UINT64);
        printf("[*] Populating pConfig->pArgs[%d]\n", i);
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
    printf("[*] Finding ROP gadget\n");
    PVOID pGadget = FindROPGadget("kernel32.dll");
    
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    PVOID pMessageBox = GetProcAddress(hUser32, "MessageBoxA");

    //typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
    //MessageBoxA_t fnMessageBox = (MessageBoxA_t)pMessageBox;

    // Appeler la fonction
    //fnMessageBox(NULL, "injected !", "Pwned by Rida", MB_ICONEXCLAMATION);
    
    SetupConfig(config_messagebox, pGadget, pMessageBox, 4, NULL, "injected !", "Pwned by Rida", MB_ICONEXCLAMATION);

    printf("[*] Performing SpoofCall !\n");

    SpoofCall(config_messagebox);

    printf("[*] Done !\n");

    free(config_messagebox->pArgs);
    free(config_messagebox);
    return 0;
}