#pragma once

#include "..\helper.h"

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

BOOL WrapperWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
BOOL WrapperReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);

LPVOID WrapperVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
LPVOID WrapperVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

BOOL WrapperVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
BOOL WrapperVirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

HANDLE WrapperCreateThread(LPSECURITY_ATTRIBUTES lpAttr, SIZE_T dwStack, LPTHREAD_START_ROUTINE lpStart, LPVOID lpParam, DWORD dwFlags, LPDWORD lpId);
BOOL WrapperCreateRemoteThreadEx(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, SIZE_T dwStackSize, PHANDLE phThread);

BOOL WrapperQueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);
BOOL WrapperResumeThread(HANDLE hThread);
HANDLE WrapperOpenProcess(DWORD dwPid);
BOOL WrapperWaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);

HANDLE WrapperCreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName);
HANDLE WrapperCreateTimerQueue();
