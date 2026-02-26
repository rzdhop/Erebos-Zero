#include <winternl.h>
#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>

/*
1) Charger le PE en mémoire 
2) Allouer la taille de : optionalHeader.SizeOfImage
3) Mapper chaque sections selon : 
    PointerToRawData  -> offset dans fichier
    VirtualAddress    -> offset dans mémoire
    SizeOfRawData
    VirtualSize
4) Appliquer les relocs : 
    si     :  allocated_base != OptionalHeader.ImageBase
    then   :  delta = allocated_base - ImageBase
5) Resolve Imports | section .idata contient IMAGE_IMPORT_DESCRIPTOR
   For DLL        : LoadLibraryA("kernel32.dll")
   For functions  : GetProcAddress(...)
6) Patch IAT
7) Start EntryPoint : 
    Entry = base + OptionalHeader.AddressOfEntryPoint;
    ((void(*)())Entry)();

*/

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

PBYTE LoadPE(PBYTE pe_base) {
    PBYTE pe_loaded_base;

    printf("[*] Reading PE bytes\n");
    PIMAGE_DOS_HEADER dosHdr = (PIMAGE_DOS_HEADER)pe_base;
    
    printf("[*] Getting ImageSize\n");
    PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(pe_base + dosHdr->e_lfanew);
    size_t image_sz = ntHdr->OptionalHeader.SizeOfImage;
    
    pe_loaded_base = malloc(image_sz);
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

    printf("[*] Getting IAT \n");
    IMAGE_DATA_DIRECTORY importDir = ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR) (pe_loaded_base + importDir.VirtualAddress);

    return pe_loaded_base;
}


int main(int argc, char ** argv) {
    LPCSTR pe_path = TEXT(".\random_pe.exe");
    FILE *fp = fopen(pe_path, "rb");

    fseek(fp, 0, SEEK_END);
    size_t file_size = ftell(fp);
    rewind(fp);

    // Read entire file
    PBYTE fileBuffer = malloc(file_size);
    fread(fileBuffer, 1, file_size, fp);
    fclose(fp);

    PBYTE loaded_pe = LoadPE(fileBuffer);
    return 0;
}