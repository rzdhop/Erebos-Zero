#include <windows.h>

DWORD g_SSN_NtAllocateVirtualMemory	= 0;
LPVOID g_SYSADDR_NtAllocateVirtualMemory	= 0;
extern "C" NTSTATUS stubNtAllocateVirtualMemory(/* TO BE DEFINED */);

DWORD g_SSN_NtWriteVirtualMemory	= 0;
LPVOID g_SYSADDR_NtWriteVirtualMemory	= 0;
extern "C" NTSTATUS stubNtWriteVirtualMemory(/* TO BE DEFINED */);

DWORD g_SSN_NtProtectVirtualMemory	= 0;
LPVOID g_SYSADDR_NtProtectVirtualMemory	= 0;
extern "C" NTSTATUS stubNtProtectVirtualMemory(/* TO BE DEFINED */);

DWORD g_SSN_NtResumeThread	= 0;
LPVOID g_SYSADDR_NtResumeThread	= 0;
extern "C" NTSTATUS stubNtResumeThread(/* TO BE DEFINED */);

DWORD g_SSN_NtWaitForSingleObject	= 0;
LPVOID g_SYSADDR_NtWaitForSingleObject	= 0;
extern "C" NTSTATUS stubNtWaitForSingleObject(/* TO BE DEFINED */);

DWORD g_SSN_NtQueueApcThread	= 0;
LPVOID g_SYSADDR_NtQueueApcThread	= 0;
extern "C" NTSTATUS stubNtQueueApcThread(/* TO BE DEFINED */);

