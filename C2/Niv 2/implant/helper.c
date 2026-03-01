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

    int dataSize = MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)Data, -1, NULL, 0); //Get effective size of data buffer
    
    LPCWSTR dataW = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dataSize* sizeof(WCHAR));

    MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)Data, -1, (LPWSTR)dataW, dataSize);

    return (LPCWSTR)dataW;
}