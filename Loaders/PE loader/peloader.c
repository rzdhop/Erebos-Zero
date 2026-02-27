#include <winternl.h>
#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

int WINAPI MyMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    return MessageBoxA(NULL, "Completely hijacked !", "Am i loaded ?", MB_ICONHAND);
}

PBYTE LoadPE(PBYTE pe_base) {
    PBYTE pe_loaded_base;

    printf("[*] Reading PE bytes\n");
    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)pe_base;
    
    printf("[*] Getting ImageSize\n");
    PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(pe_base + dosHdr->e_lfanew);
    size_t image_sz = ntHdr->OptionalHeader.SizeOfImage;
    
    pe_loaded_base = VirtualAlloc(NULL, image_sz, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
    memset(pe_loaded_base, 0, image_sz);
    printf("[*] Allocating Image size (%zu bytes) at 0x%p\n", image_sz, pe_loaded_base);
    
    size_t headers_sz = ntHdr->OptionalHeader.SizeOfHeaders; 
    printf("[*] Copying headers (%zu bytes)!\n", headers_sz);
    memcpy(pe_loaded_base, pe_base, headers_sz);

    int section_count = ntHdr->FileHeader.NumberOfSections;
    printf("[*] Copying %d sections\n", section_count);

    //&ntHdr->OptionalHeader + ntHdr->FileHeader.SizeOfOptionalHeader
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHdr);
    for(int i = 0; i < section_count; i++, section++) {
        PBYTE section_dst   = pe_loaded_base + section->VirtualAddress;
        PBYTE section_data  = pe_base + section->PointerToRawData;
        size_t section_sz   = section->SizeOfRawData;
        memcpy(section_dst, section_data, section_sz);
    }

    printf("[*] Getting .reloc addr\n");
    
    IMAGE_DATA_DIRECTORY relocs_table = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    PIMAGE_BASE_RELOCATION reloc_section = (PIMAGE_BASE_RELOCATION)(pe_loaded_base + relocs_table.VirtualAddress);
    PBYTE reloc_section_end = (PBYTE)reloc_section + relocs_table.Size;

    printf("[*] Patching relocations \n");
    ULONG_PTR delta = (ULONG_PTR)pe_loaded_base - ntHdr->OptionalHeader.ImageBase;
    PIMAGE_BASE_RELOCATION relocationBlock = reloc_section;

    if (delta != 0 && relocs_table.Size) {

        while((PBYTE)relocationBlock < reloc_section_end && relocationBlock->SizeOfBlock) {

            DWORD reloc_entry_count = (relocationBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD relocationEntries =(PWORD)(relocationBlock + 1);

            for (DWORD i = 0; i < reloc_entry_count; i++) {
                //entry : | 4 bits type | 12 bits offset |
                WORD type   = relocationEntries[i] >> 12;
                WORD offset = relocationEntries[i] & 0x0FFF;

                if (type == IMAGE_REL_BASED_DIR64) {
                    ULONG_PTR* patchAddress = (ULONG_PTR*)(pe_loaded_base + relocationBlock->VirtualAddress + offset);

                    *patchAddress += delta;
                }
            }
            relocationBlock = (PIMAGE_BASE_RELOCATION)((PBYTE)relocationBlock + relocationBlock->SizeOfBlock);

        }

    }

    printf("[*] Patching IAT on .idata section \n");
    IMAGE_DATA_DIRECTORY importDir = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if(importDir.Size) {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR) (pe_loaded_base + importDir.VirtualAddress);

        FARPROC func = NULL;
        while(importDesc->Name) {
            char* dllName = (char*)(pe_loaded_base + importDesc->Name);

            HMODULE hDll = LoadLibraryA(dllName);

            //INT function names
            PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)(pe_loaded_base +(importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk)); 
            //IAT function addresses
            PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(pe_loaded_base + importDesc->FirstThunk);

            while(origThunk->u1.AddressOfData)
            {
                //Guess if image is imported by Name or ordinal(kind of ID)
                if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal))
                {
                    func = GetProcAddress(hDll, (LPCSTR)IMAGE_ORDINAL(origThunk->u1.Ordinal));
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)(pe_loaded_base + origThunk->u1.AddressOfData);
                    if (stricmp("MessageBoxA", import->Name) == 0){
                        func = (FARPROC)&MyMessageBox;
                    } else func = GetProcAddress(hDll, import->Name);
                }
                //appliyng the func addr into IAT
                firstThunk->u1.Function = (ULONG_PTR)func;

                origThunk++;
                firstThunk++;
            }
            importDesc++;
        }
    }

    printf("[*] Applying section's memory protections\n");
    section = IMAGE_FIRST_SECTION(ntHdr);

    for (int i = 0; i < ntHdr->FileHeader.NumberOfSections; i++, section++) {
        DWORD protect = PAGE_NOACCESS;
        DWORD oldProtect;

        BOOL executable = section->Characteristics & IMAGE_SCN_MEM_EXECUTE;
        BOOL readable = section->Characteristics & IMAGE_SCN_MEM_READ;
        BOOL writable = section->Characteristics & IMAGE_SCN_MEM_WRITE;

        if (executable)
            protect = writable ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        else
            protect = writable ? PAGE_READWRITE : PAGE_READONLY;

        VirtualProtect(pe_loaded_base + section->VirtualAddress, section->Misc.VirtualSize, protect, &oldProtect);
    }

    printf("[*] Calling TLS Callbacks\n");
    IMAGE_DATA_DIRECTORY tlsDir = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    if (tlsDir.Size)
    {
        PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY) (pe_loaded_base + tlsDir.VirtualAddress);
        PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
        
        while (callbacks && *callbacks)
        {
            (*callbacks)(pe_loaded_base, DLL_PROCESS_ATTACH,NULL);

            callbacks++;
        }
    }
    printf("[*] Creating the loaded process thread\n");
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)(pe_loaded_base + ntHdr->OptionalHeader.AddressOfEntryPoint), NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    return pe_loaded_base;
}

int main(int argc, char ** argv) {
    LPCSTR pe_path = "random_pe.exe";
    FILE *fp = fopen(pe_path, "rb");

    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    rewind(fp);

    PBYTE fileBuffer = malloc(file_size);
    fread(fileBuffer, 1, file_size, fp);
    fclose(fp);

    printf("[*] Loading PE file (%zu bytes)\n", file_size);
    PBYTE loaded_pe = LoadPE(fileBuffer);
    
    return 0;
}