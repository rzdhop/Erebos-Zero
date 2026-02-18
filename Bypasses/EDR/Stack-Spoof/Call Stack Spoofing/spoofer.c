#include <winternl.h>
#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>

// gcc spoofer.c spoofer.o -o spoofer.exe -lkernel32

/*
    We are going to do it in 3 steps,
Step 1 : Choose 2 (or more) legitimate functions (I choosed : RtlUserThreadStart & BaseThreadInitThunk)
            - Retrieve their RUNTIME_FUNCTION entries (.pdata)
            - Parse and get associated UNWIND_INFO (.xdata)
                    - Stack allocation size (UWOP_ALLOC_*)
                    - Non-volatile registers saved (UWOP_PUSH_NONVOL / SAVE_NONVOL)
                    - Frame register usage (if any)
            - So we get the exact expected stack layout for each frame

Step 2 : Then in the assembly we build the stack frames from outer to inner (RtlUserThreadStart -> Init chunk)
            - Allocate required stack space (calculated from the unwind_code)
            - Emulate saved registers layout
            - Place correct return address

        for each frame we have to ensure 3 main points : 
                - 16-byte stack alignment (before the call (retaddr))
                - Correct shadow space handling (32bytesbefore the call)
                - Return addresses inside legitimate .text sections

Step 3 : Then as for the return address spoofing we rebuild the call stack and fake the return addr to a JOP (jmp gadget) 

*/

typedef enum _UNWIND_OP_CODES {
	UWOP_PUSH_NONVOL,
	UWOP_ALLOC_LARGE,
	UWOP_ALLOC_SMALL,
	UWOP_SET_FPREG,
	UWOP_SAVE_NONVOL,
	UWOP_SAVE_NONVOL_FAR,
	UWOP_PUSH_MACHFRAME = 10
} UNWIND_OP_CODES;

typedef UCHAR UBYTE;
typedef union _UNWIND_CODE
{
	struct
	{
		UBYTE CodeOffset;
		UBYTE UnwindOp : 4;
		UBYTE OpInfo : 4;
	};
	USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
	UCHAR Version : 3;
	UCHAR Flags : 5;
	UCHAR SizeOfPrologue;
	UCHAR CountOfUnwindCodes;
	UCHAR FrameRegister : 4;
	UCHAR FrameRegisterOffset : 4;
	UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, * PUNWIND_INFO;


typedef struct _STACK_CONFIG {
    PVOID pRsp; //PTR to a placeholder of RSP (Easier for me in asm)
    PVOID pSpoofed1_ret; 
    DWORD Spoofed1StackSize;
    PVOID pSpoofed2_ret;
    DWORD Spoofed2StackSize;
    PVOID pRopGadget; //PTR to Gadget
    DWORD SpoofedGagdetSize;
    PVOID pTarget; //PTR to function (MessageBoxA or anyhing)
    PVOID pArgs; //PTR to the args of the functions
    DWORD dwNumberOfArgs; //Nb of ars of the function
} STACK_CONFIG, *PSTACK_CONFIG;

extern PVOID SpoofCall(PSTACK_CONFIG pConfig);

PVOID FindROPGadget(HMODULE hModule ) {
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
            printf("[*] Found ROP gadget (FF 23) @ %p\n", gadget);
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
    
    printf("[*] Reading module image for Ntheader -> OptionalHeader \n");
    pImgNtHdr = (UINT64)modulePTR + ((PIMAGE_DOS_HEADER)modulePTR)->e_lfanew;
	pImgOptHdr = &((PIMAGE_NT_HEADERS64)pImgNtHdr)->OptionalHeader;

    pExceptionDirectory = (UINT64)modulePTR + pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress; //section .PDATA addr
	printf("[*] Section .PDATA (OptionalHeader[ExceptionDirectory] -> PRUNTIME_FUNCTION table) @ 0x%p\n", pExceptionDirectory);
    dwRuntimeFunctionCount = pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION); // Count of runtime_function in .PDATA section
    printf("[*] PRUNTIME_FUNCTION table has %d entries\n", dwRuntimeFunctionCount);
    dwFuncOffset = (UINT64)funcPTR - (UINT64)modulePTR;
    printf("[*] Searching in PRUNTIME_FUNCTION entries for function @ 0x%p\n", funcPTR);

    PRUNTIME_FUNCTION pRuntimeFunction = (PRUNTIME_FUNCTION)pExceptionDirectory;

    for (int i = 0 ; i < dwRuntimeFunctionCount; i++ ) {
        if (dwFuncOffset >= pRuntimeFunction->BeginAddress && dwFuncOffset <= pRuntimeFunction->EndAddress) {
            printf("[*] Found entry !\n");
			break;
		}

		pRuntimeFunction++;
    }

    //pUnwindInfo = ((PUNWIND_INFO)(modulePTR + pRuntimeFunction->UnwindInfoAddress));
    pUnwindInfo = (PUNWIND_INFO)((UINT64)modulePTR + pRuntimeFunction->UnwindData);
    pUnwindCode = pUnwindInfo->UnwindCode;
    printf("[*] Parsing UNWIND_INFO struct for UNWIND_CODE of Spoofed function prelude\n");

    /*
        Parse UNWIND_CODE entries to reconstruct the total stack allocation performed in the function prologue (simulate RtlVirtualUnwind logic).
        We accumulate stack size based on UWOP_* operations.
        More about UNWIND_CODES : learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170#unwind-operation-code
    */
    for (int i = 0; i < pUnwindInfo->CountOfUnwindCodes; i++) {

		UBYTE bUnwindCode = pUnwindCode[i].UnwindOp;

		switch (bUnwindCode)
		{
		    case UWOP_ALLOC_SMALL:
			    dwStackSize += (pUnwindCode[i].OpInfo + 1) * 8;
			    break;
		    case UWOP_PUSH_NONVOL:
		    	if (pUnwindCode[i].OpInfo == 4)
		    		return 0;
		    	dwStackSize += 8;
		    	break;
		    case UWOP_ALLOC_LARGE:
		    	if (pUnwindCode[i].OpInfo == 0) {
		    		dwStackSize += pUnwindCode[i + 1].FrameOffset * 8;
		    		i++;
		    	}
		    	else {
		    		dwStackSize += *(ULONG*)(&pUnwindCode[i + 1]);
		    		i += 2;
		    	}
		    	break;
		    case UWOP_PUSH_MACHFRAME:
		    	if (pUnwindCode[i].OpInfo == 0)
		    		dwStackSize += 40;
		    	else
		    		dwStackSize += 48;
                break;
		    case UWOP_SAVE_NONVOL:
		    	i++;
		    	break;
		    case UWOP_SAVE_NONVOL_FAR:
		    	i += 2;
		    	break;
		    default:
		    	break;
		}
	}
    printf("[*] Stack frame is %llu bytes !\n", dwStackSize);
	return dwStackSize;
}

int CallStackSpoof(PVOID pTarget, DWORD dwNumberOfArgs, ...){
    va_list additionalArgs;

    PSTACK_CONFIG stackConfig = malloc(sizeof(STACK_CONFIG));
    memset(stackConfig, 0, sizeof(STACK_CONFIG));

    PVOID pGadget, pRtlUserThreadStart, pBaseThreadInitThunk;
	HMODULE pNtdll, pKernel32;

	pNtdll = GetModuleHandleA("ntdll");
	pKernel32 = GetModuleHandleA("kernel32");

	pRtlUserThreadStart = GetProcAddress(pNtdll, "RtlUserThreadStart");
	pBaseThreadInitThunk = GetProcAddress(pKernel32, "BaseThreadInitThunk");

    printf("[*] Got RtlUserThreadStart from ntdll.dll @ 0x%p\n", pRtlUserThreadStart);
    printf("[*] Got BaseThreadInitThunk from kernel32.dll @ 0x%p\n", pBaseThreadInitThunk);
    pGadget = FindROPGadget(pKernel32);

    stackConfig->pRopGadget             = pGadget;
    stackConfig->pSpoofed1_ret          = (PVOID)((UINT64)pRtlUserThreadStart + 0x7);   //Getting a random point in the function to fake the ret of the spoofed frame
    stackConfig->Spoofed1StackSize      = getStackFrameSize(pRtlUserThreadStart, pNtdll);
    stackConfig->pSpoofed2_ret          = (PVOID)((UINT64)pBaseThreadInitThunk + 0x11); //Same random point
    stackConfig->Spoofed2StackSize      = getStackFrameSize(pBaseThreadInitThunk, pKernel32);
    stackConfig->SpoofedGagdetSize      = getStackFrameSize(pGadget, pKernel32);

    stackConfig->dwNumberOfArgs         = (dwNumberOfArgs > 4) ? dwNumberOfArgs : 4;
    stackConfig->pTarget = pTarget;
    printf("[*] pConfig->pTarget set to 0x%p\n", stackConfig->pTarget);

    stackConfig->pArgs = malloc(8 * stackConfig->dwNumberOfArgs); //allocate 8 bytes time number of args
    printf("[*] Allocating %d bytes for %d args\n", (8 * stackConfig->dwNumberOfArgs), stackConfig->dwNumberOfArgs);
    memset(stackConfig->pArgs, 0, 8 * stackConfig->dwNumberOfArgs);
    
    //Say that there is more argument to our function w/ DWORD dwNumberOfArgs
    va_start(additionalArgs, dwNumberOfArgs); //make additianlArgs point to the stack after DWORD dwNumberOfArgs and can be pop
    for (int i = 0; i < dwNumberOfArgs; i++){
        ((PUINT64)stackConfig->pArgs)[i] = va_arg(additionalArgs, UINT64);
        printf("[*] Populating stackConfig->pArgs[%d]\n", i);
    }

    printf("[*] Performing the call spoofed !\n");
    SpoofCall(stackConfig);

    free(stackConfig->pArgs);
    free(stackConfig);
    return 0;
}


int main(int argc, char **argv) {
    printf("   _______  _______  ____  ____\n");
    printf("  / __/ _ \\/ __/ _ )/ __ \\/ __/\n");
    printf(" / _// , _/ _// _  / /_/ /\\ \\  \n");
    printf("/___/_/|_/___/____/\\____/___/  \n");
    printf("          by : 0xRzdhop\n");
    printf("[*] Performing SpoofCall on Messagebox !\n");

    HMODULE hUser32 = LoadLibraryA("user32.dll");
    PVOID pMessageBox = GetProcAddress(hUser32, "MessageBoxA");

    printf("[+] Open your system informer ! \n[Press any key to continue]\n");
    getchar();
    CallStackSpoof(pMessageBox, 4, NULL, "injected !", "Pwned by Rida", MB_ICONEXCLAMATION);
    printf("[*] Done !\n");

    return 0;
}