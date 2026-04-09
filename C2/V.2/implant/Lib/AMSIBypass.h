#pragma once

#include "..\helper.h"

typedef NTSTATUS (NTAPI *pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);
typedef BOOL (WINAPI * SetProcessValidCallTargets_t)(HANDLE, PVOID, SIZE_T, ULONG, PCFG_CALL_TARGET_INFO);

BOOL ApplyVehBypass(HANDLE hProcess, HANDLE hThread, PVOID ImageBase);