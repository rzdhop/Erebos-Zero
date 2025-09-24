#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>

/*
    The created process need EXTENDED_STARTUPINFO_PRESENT flag, desc from microsoft: 
        "The process is created with extended startup information; the lpStartupInfo parameter specifies a STARTUPINFOEX structure."

    So we'll need STARTUPINFOEXA structure ! That reference the attribute list that store attributes about a given proces/Thread
    The attribute list is firstly populated by InitializeProcThreadAttributeList WinAPI
*/

int get_process(LPCSTR lpName, PHANDLE hProc, PDWORD PID){
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
        if (strcmpi(pe32.szExeFile, lpName) == 0) {
            printf("[+] Found ! PID: %u - %s\n", pe32.th32ProcessID, pe32.szExeFile);
            *PID = pe32.th32ProcessID;
            *hProc = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, *PID);
            break;
        }
    } while (Process32Next(snapshot, &pe32));

    CloseHandle(snapshot);
    return 1;
}

int main (int argc, char** argv){
    SIZE_T                             sThreadAttList       = 0;
	PPROC_THREAD_ATTRIBUTE_LIST        pThreadAttList       = NULL;
    
    STARTUPINFOEXA                     SiEx                = { 0 };
    SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	PROCESS_INFORMATION                Pi                  = { 0 };

    RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    CHAR lpPath[] = "C:\\windows\\System32\\notepad.exe";

    // This will fail with ERROR_INSUFFICIENT_BUFFER
    // First call to populate the size of the required buffer
	InitializeProcThreadAttributeList(NULL, 1, 0, &sThreadAttList);

    pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)calloc(1, sThreadAttList);

    // now we populate attributesList
	if (!InitializeProcThreadAttributeList(pThreadAttList, 1, 0, &sThreadAttList)) {
		printf("[!] InitializeProcThreadAttributeList Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

    DWORD  PID     = 0;
    HANDLE hParentProcess   = nullptr;
    get_process("ms-teams.exe", &hParentProcess, &PID);

    if (!UpdateProcThreadAttribute(pThreadAttList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
		printf("[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

    // On inject le Startup info pour le Create process
    SiEx.lpAttributeList = pThreadAttList;

    if (!CreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		NULL,
		&SiEx.StartupInfo,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	DWORD dwProcessId	= Pi.dwProcessId;
	HANDLE hProcess	    = Pi.hProcess;
	HANDLE hThread		= Pi.hThread;

    DeleteProcThreadAttributeList(pThreadAttList);
	CloseHandle(hParentProcess);

    if (dwProcessId != 0 && hProcess != 0 && hThread != 0)
		return TRUE;

    return 1;
}