#pragma once

#include "..\helper.h"

typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

BOOL ApplyVehBypass(HANDLE hProcess, HANDLE hThread);