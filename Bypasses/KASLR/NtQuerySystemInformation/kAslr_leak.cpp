#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

typedef struct _SYSTEM_MODULE_ENTRY {
    PVOID  Reserved1;
    PVOID  Reserved2;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    WORD   Id;
    WORD   Rank;
    WORD   LoadCount;
    WORD   NameOffset;
    CHAR   Name[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG ModulesCount;
    SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef NTSTATUS(WINAPI* _NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

BOOL IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    return isAdmin;
}

int main() {
    if (!IsRunningAsAdmin()) {
        printf("[-] Run me as admin bro!\n");
        return 1;
    }

    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

    if (!NtQuerySystemInformation) {
        printf("[-] Failed to resolve NtQuerySystemInformation\n");
        return 1;
    }

    ULONG size = 0;
    //La class 11 : SystemModuleInformation permet de récupérer la listes des Drivers (ntoskrnl en faisant parti)
    //ici on get la taille de lodule info
    NTSTATUS status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, NULL, 0, &size);

    PSYSTEM_MODULE_INFORMATION moduleInfo = (PSYSTEM_MODULE_INFORMATION)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!moduleInfo) {
        printf("[-] Failed to allocate memory\n");
        return 1;
    }

    //On popule moduleInfo
    status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, moduleInfo, size, &size);
    if (!NT_SUCCESS(status)) {
        printf("[-] NtQuerySystemInformation failed: 0x%X\n", status);
        VirtualFree(moduleInfo, 0, MEM_RELEASE);
        return 1;
    }

    //Le premier module est tout le temps ntoskrnl.exe
    PSYSTEM_MODULE_ENTRY firstModule = &moduleInfo->Modules[0];
    printf("[+] ntoskrnl base address: 0x%p\n", firstModule->ImageBase);
    printf("[+] module name: %s\n", firstModule->Name);

    VirtualFree(moduleInfo, 0, MEM_RELEASE);
    return 0;
}
