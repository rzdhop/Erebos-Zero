#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wininet.h>
#include <winternl.h>
#include <tlhelp32.h>

#include "..\helper.h"

typedef NTSTATUS (NTAPI *_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

BOOL ReadFromTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, OUT PVOID* ppReadBuffer, IN SIZE_T dwBufferSize);
BOOL WriteToTargetProcess(IN HANDLE hProcess, IN PVOID pAddressToWriteTo, IN PVOID pBuffer, IN SIZE_T dwBufferSize);
LPSTR ExecPowerShell(LPCWSTR psCommand);