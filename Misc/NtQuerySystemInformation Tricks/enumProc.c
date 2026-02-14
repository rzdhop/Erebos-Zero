#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>

typedef NTSTATUS (NTAPI* fnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);

int main (int argc, char **argv) {
    LPCWSTR procName = L"Notepad.exe";

    fnNtQuerySystemInformation pNtQuerySystemInformation = NULL;

    pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtQuerySystemInformation");

    ULONG uReturnLenAllocSz = 0, uReturnLenOutput = 0;
    PSYSTEM_PROCESS_INFORMATION SystemProcInfo = NULL; //Will be populated with the output of NtQuerySystemInformation
    NTSTATUS STATUS;

    pNtQuerySystemInformation(SystemProcessInformation, NULL, 0, &uReturnLenAllocSz);

    SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLenAllocSz);

    STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLenAllocSz, &uReturnLenOutput);
    
    PVOID pValueToFree = SystemProcInfo;
    DWORD dwPid;
    HANDLE hProcess;
    
    while (1) {
        if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, procName) == 0) {
            dwPid = (DWORD)SystemProcInfo->UniqueProcessId;
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);   
        }

        if (!SystemProcInfo->NextEntryOffset)
			break;

		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
    }

    HeapFree(GetProcessHeap(), 0, pValueToFree);

    if (dwPid == 0 || hProcess == NULL) {
        printf("[*] PID of %ls : NOT FOUND", procName);
        return FALSE;
    } 
    else {
        printf("[*] PID of %ls : %d", procName, dwPid);
		return TRUE;
    }

    return 0;
}