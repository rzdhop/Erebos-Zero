#pragma once 
#include <windows.h>
#include <ntdef.h>

typedef int (WINAPI *PFN_MESSAGEBOXW)(HWND, LPCWSTR, LPCWSTR, UINT);
typedef DWORD (WINAPI *PFN_GETMODULEFILENAMEW)(HMODULE, LPWSTR, DWORD);
typedef BOOL (WINAPI *PFN_GETUSERNAMEW)(LPWSTR, LPDWORD);
typedef HANDLE (WINAPI *PFN_CREATEFILEW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL (WINAPI *PFN_READFILE)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *PFN_CLOSEHANDLE)(HANDLE);

typedef struct _PARAMS {
    PFN_MESSAGEBOXW pMessageBoxW;
    PFN_GETMODULEFILENAMEW pGetModuleFileNameW;
    PFN_GETUSERNAMEW pGetUserNameW;
    PFN_CREATEFILEW pCreateFileW;
    PFN_READFILE    pReadFile;
    PFN_CLOSEHANDLE pCloseHandle;
} PARAMS;


typedef VOID (NTAPI *PS_APC_ROUTINE)(
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

typedef struct _SYSCALL_STUB {
    DWORD SyscallId;
    PVOID SyscallFunc;
} SYSCALL_STUB, *PSYSCALL_STUB;

// windows-internals-book:"Chapter 5"
typedef enum _PS_CREATE_STATE
{
    PsCreateInitialState,
    PsCreateFailOnFileOpen,
    PsCreateFailOnSectionCreate,
    PsCreateFailExeFormat,
    PsCreateFailMachineMismatch,
    PsCreateFailExeName, // Debugger specified
    PsCreateSuccess,
    PsCreateMaximumStates
} PS_CREATE_STATE;


//https://ntdoc.m417z.com/ps_create_info
typedef struct _PS_CREATE_INFO
{
    SIZE_T Size;
    PS_CREATE_STATE State;
    union
    {
        // PsCreateInitialState
        struct
        {
            union
            {
                ULONG InitFlags;
                struct
                {
                    UCHAR WriteOutputOnExit : 1;
                    UCHAR DetectManifest : 1;
                    UCHAR IFEOSkipDebugger : 1;
                    UCHAR IFEODoNotPropagateKeyState : 1;
                    UCHAR SpareBits1 : 4;
                    UCHAR SpareBits2 : 8;
                    USHORT ProhibitedImageCharacteristics : 16;
                };
            };
            ACCESS_MASK AdditionalFileAccess;
        } InitState;

        // PsCreateFailOnSectionCreate
        struct
        {
            HANDLE FileHandle;
        } FailSection;

        // PsCreateFailExeFormat
        struct
        {
            USHORT DllCharacteristics;
        } ExeFormat;

        // PsCreateFailExeName
        struct
        {
            HANDLE IFEOKey;
        } ExeName;

        // PsCreateSuccess
        struct
        {
            union
            {
                ULONG OutputFlags;
                struct
                {
                    UCHAR ProtectedProcess : 1;
                    UCHAR AddressSpaceOverride : 1;
                    UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
                    UCHAR ManifestDetected : 1;
                    UCHAR ProtectedProcessLight : 1;
                    UCHAR SpareBits1 : 3;
                    UCHAR SpareBits2 : 8;
                    USHORT SpareBits3 : 16;
                };
            };
            HANDLE FileHandle;
            HANDLE SectionHandle;
            ULONGLONG UserProcessParametersNative;
            ULONG UserProcessParametersWow64;
            ULONG CurrentParameterFlags;
            ULONGLONG PebAddressNative;
            ULONG PebAddressWow64;
            ULONGLONG ManifestAddress;
            ULONG ManifestSize;
        } SuccessState;
    };
} PS_CREATE_INFO, *PPS_CREATE_INFO;

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

extern "C" VOID NTAPI RtlInitUnicodeString(
        PUNICODE_STRING DestinationString,
        PCWSTR SourceString
    );


//=============== stub definitions ================
DWORD g_SSN_NtAllocateVirtualMemory     = 0;
LPVOID g_SYSADDR_NtAllocateVirtualMemory        = 0;
extern "C" NTSTATUS stubNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

DWORD g_SSN_NtWriteVirtualMemory        = 0;
LPVOID g_SYSADDR_NtWriteVirtualMemory   = 0;
extern "C" NTSTATUS stubNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PUCHAR Buffer, SIZE_T NumberOfBytesToWrite, PULONG NumberOfBytesWritten);

DWORD g_SSN_NtProtectVirtualMemory      = 0;
LPVOID g_SYSADDR_NtProtectVirtualMemory = 0;
extern "C" NTSTATUS stubNtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, ULONG NewProtection, PULONG OldProtection);

DWORD g_SSN_NtResumeThread      = 0;
LPVOID g_SYSADDR_NtResumeThread = 0;
extern "C" NTSTATUS stubNtResumeThread( HANDLE ThreadHandle, PULONG PreviousSuspendCount);

DWORD g_SSN_NtWaitForSingleObject       = 0;
LPVOID g_SYSADDR_NtWaitForSingleObject  = 0;
extern "C" NTSTATUS stubNtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

DWORD g_SSN_NtQueueApcThread    = 0;
LPVOID g_SYSADDR_NtQueueApcThread       = 0;
extern "C" NTSTATUS stubNtQueueApcThread(HANDLE ThreadHandle, LPVOID ApcRoutine, PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);
//=================================================
