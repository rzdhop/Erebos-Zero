#include "common.h"
#include <windows.h>

void XOR(PUCHAR data, size_t data_sz, PUCHAR key, size_t key_sz){
    for (int i = 0; i < data_sz; i++){
        data[i] = data[i] ^ key[i%key_sz];
    }
}

FARPROC __stdcall MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    PBYTE pBase = (PBYTE) hModule;

    //Cast DOS header
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

    //Get NTHeader ptr from DOS header
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

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

    for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++){
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        if (strcmp(pFunctionName, lpProcName) == 0) {
            WORD wFunctionOrdinal = FunctionOrdinalArray[i];
            PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[wFunctionOrdinal]);
            return (FARPROC)pFunctionAddress;
        }
    }
    return NULL;
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