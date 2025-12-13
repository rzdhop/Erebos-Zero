#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <time.h>

int optionalHdr_offset;
int optionalHdr_sz;

void hexdump(char *data, size_t size) {
    const size_t width = 16;

    for (size_t i = 0; i < size; i += width) {
        printf("%08zx  ", i);

        for (size_t j = 0; j < width; j++) {
            if (i + j < size)
                printf("%02X ", (unsigned char)data[i + j]);
            else
                printf("   ");
        }
        printf(" ");
        for (size_t j = 0; j < width; j++) {
            if (i + j < size) {
                unsigned char c = data[i + j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
        }
        printf("\n");
    }
}


IMAGE_DOS_HEADER parse_DOS_hdr(FILE* fp) {
    // IMAGE_DOS_HEADER
    IMAGE_DOS_HEADER dosHdr = {0};
    fread(&dosHdr, sizeof(dosHdr), 1, fp);

    if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Signature MZ invalide\n");
        return dosHdr;
    }

    printf("\n\t[*] Magic Bytes signature : %04X (%c%c)", dosHdr.e_magic, dosHdr.e_magic & 0xff, (dosHdr.e_magic >> 8) & 0xff);
    printf("\n\t[*] NT Header RVA : 0x%lx", dosHdr.e_lfanew);
    //printf("\n\t[*] Relocs Count : %u", dosHdr.e_crlc & 0xff);
    //printf("\n\t[*] Reloc table offset : 0x%x", dosHdr.e_lfarlc);
    printf("\n\t[*] Header Size : %d", dosHdr.e_lfanew);

    int stub_size = dosHdr.e_lfanew - sizeof(IMAGE_DOS_HEADER);
    char *dos_stub = calloc(1, stub_size);
    fseek(fp, sizeof(IMAGE_DOS_HEADER), SEEK_SET);
    fread(dos_stub, stub_size, 1, fp);
    printf("\n[*] DOS Stub (%d bytes): \n", stub_size);
    hexdump(dos_stub, stub_size);
    fseek(fp, 0, 0);

    return dosHdr;
}

int parse_NT_hdr(FILE* fp, IMAGE_DOS_HEADER dosHdr) {
    fseek(fp, dosHdr.e_lfanew, SEEK_SET);

    IMAGE_NT_HEADERS ntHdr;
    fread(&ntHdr, sizeof(IMAGE_NT_HEADERS), 1, fp);

    printf("\n\t[*] Offset : 0x%02x", dosHdr.e_lfanew);

    IMAGE_FILE_HEADER ntFileHdr = ntHdr.FileHeader;

    printf("\n\t[*] Number of sections : %d", ntFileHdr.NumberOfSections);
    printf("\n\t[*] NT signature :\n");
    hexdump((char*)&ntHdr, sizeof(IMAGE_NT_SIGNATURE));
    printf("\n\t[+] Image File Header :");
    printf("\n\t\t[*] Machine supported : 0x%x ", ntFileHdr.Machine);
    switch (ntFileHdr.Machine)
    {
    case 0x8664:
        printf("(AMD64 - x64)");
        break;
    case IMAGE_FILE_MACHINE_I386 :
        printf("(i386 - x86)");
        break;
    case 0x1c0:
        printf("(ARM little endian)");
        break;
    case 0xaa64:
        printf("(ARM64 little endian )");
        break;
    default:
        printf("(See. https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types)");
        break;
    }

    WORD chara = ntFileHdr.Characteristics;
    printf("\n\t\t[*] File Characteristics : 0x%x ", chara);
    if (chara & IMAGE_FILE_EXECUTABLE_IMAGE) printf("(EXE)");
    if (chara & IMAGE_FILE_LOCAL_SYMS_STRIPPED) printf("(Symbols Stripped)");
    if (chara & IMAGE_FILE_DLL) printf("(DLL)");
    if (chara & IMAGE_FILE_SYSTEM) printf("(SYSTEM)");
    if (chara & IMAGE_FILE_RELOCS_STRIPPED) printf("(NO RELOCS - NO ASLR)");

    printf("\n\t[*] Number of sections : %d", ntFileHdr.NumberOfSections);
    printf("\n\t[*] Number of symbols : %d", ntFileHdr.NumberOfSymbols);
    time_t ltime = ntFileHdr.TimeDateStamp;
    printf("\n\t[*] Linker's timestamp : %ld > %s", ntFileHdr.TimeDateStamp, asctime(localtime(&ltime)));
    printf("\t[*] COFF symbol's table offset : 0x%x", ntFileHdr.PointerToSymbolTable);

    DWORD symtab_sz  = ntFileHdr.NumberOfSymbols * sizeof(IMAGE_SYMBOL);
    int sTableOff = ntFileHdr.PointerToSymbolTable + symtab_sz;
    printf("\n\t[*] PE String table : 0x%x", sTableOff);


    printf("\n\t[*] Symbol extract :\n");
    fseek(fp, ntFileHdr.PointerToSymbolTable, SEEK_SET);
    IMAGE_SYMBOL sym;
    char name[9];
    long saved_pos;

    for (int i = 0; i < 16; i++) {
        fread(&sym, sizeof(IMAGE_SYMBOL), 1, fp);

        // Nom court (inline)
        if (sym.N.Name.Short != 0) {
            memcpy(name, sym.N.ShortName, 8);
            name[8] = '\0';
            printf("\t\t - %s\n", name);
        }
         // Nom long (string table)
        else {
            saved_pos = ftell(fp);

            fseek(fp, sTableOff + sym.N.Name.Long, SEEK_SET);
            fgets(name, sizeof(name), fp);

            printf("\t\t - %s\n", name);

            fseek(fp, saved_pos, SEEK_SET);
        }

        // Skip AUX symbols
        fseek(fp, sym.NumberOfAuxSymbols * sizeof(IMAGE_SYMBOL), SEEK_CUR);
        i += sym.NumberOfAuxSymbols;
    }
    
    DWORD optionalHdr_offset =
        dosHdr.e_lfanew 
     + sizeof(DWORD)
     + sizeof(IMAGE_FILE_HEADER);

    DWORD optionalHdr_sz = ntFileHdr.SizeOfOptionalHeader;

    printf("\n\t[*] Optional Header offset : 0x%x", optionalHdr_offset);
    printf("\n\t[*] Optional Header size   : 0x%x", optionalHdr_sz);
    return 0;
}

int parse_Opt_hdr(FILE* fp) {
    

    return 0;
}

int main (int argc, char **argv){
    if (argc < 1) {
        goto ErrorExit;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        goto ErrorExit;
    }

    printf("\n[+] Parsing DOS Header (size : %d bytes)", sizeof(IMAGE_DOS_HEADER));
    IMAGE_DOS_HEADER dosHdr = parse_DOS_hdr(fp);

    printf("\n[+] Parsing NT Header");
    parse_NT_hdr(fp, dosHdr);

    
    printf("\n[+] Parsing Optional Header");
    parse_Opt_hdr(fp);


    printf("\n[+].... to implement.");





    return 0;
    ErrorExit :
        printf("\n[-] Error during execution\n");
        return 1;
}