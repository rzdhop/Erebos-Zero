#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>

/*
    We spawn a suspendend process & edit it's _RTL_USER_PROCESS_PARAMETERS PEB element for what we want
    Step by step : 
        step 1 : Spawn process suspended
        step 2 : Use NtQuerySystemInformation with ProcessBasicInformation to get the PEB addr
        step 3 : use ReadFromTargetProcess to get _RTL_USER_PROCESS_PARAMETERS structure
        step 4 : et ecrire dans le Buffer la nouvelle valeur + changé la lenght

*/
typedef VOID (WINAPI *PPS_POST_PROCESS_INIT_ROUTINE)(VOID);
typedef struct _PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
  } PEB_LDR_DATA,*PPEB_LDR_DATA;

typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef LONG KPRIORITY, *PKPRIORITY;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS    ExitStatus;
    PPEB        PebBaseAddress;                // Points to a PEB structure.
    ULONG_PTR   AffinityMask;
    KPRIORITY   BasePriority;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

BOOL ReadFromTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, OUT PVOID* ppReadBuffer, IN DWORD dwBufferSize) {

	SIZE_T	sNmbrOfBytesRead	= NULL;

	*ppReadBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);
	
	if (!ReadProcessMemory(hProcess, pAddress, *ppReadBuffer, dwBufferSize, &sNmbrOfBytesRead) || sNmbrOfBytesRead != dwBufferSize){
		printf("[!] ReadProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[i] Bytes Read : %d Of %d \n", sNmbrOfBytesRead, dwBufferSize);
		return FALSE;
	}

	return TRUE;
}

int main(int argc, char** argv) {

    STARTUPINFOW                  Si       = { 0 };
	PROCESS_INFORMATION           Pi       = { 0 };
    RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOW));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    PROCESS_BASIC_INFORMATION     PBI      = { 0 };

    PPEB                          pPeb     = NULL;
	PRTL_USER_PROCESS_PARAMETERS  pParms   = NULL;



    return 0;
}