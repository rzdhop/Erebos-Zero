#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
int rd_offset;

void hexdump(char *data, size_t size) {
    const size_t width = 16;

    for (size_t i = 0; i < size; i += width) {
        printf("%08zx  ", i);

        for (size_t j = 0; j < width; j++) {
            if (i + j < size)
                printf("%02X ", data[i + j]);
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


int parse_DOS_hdr(FILE* fp) {
    // IMAGE_DOS_HEADER
    IMAGE_DOS_HEADER dosHdr;
    fread(&dosHdr, sizeof(dosHdr), 1, fp);

    if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Signature MZ invalide\n");
        return -1;
    }

    printf("\n\t[*] Magic Bytes signature : %04X (%c%c)", dosHdr.e_magic, dosHdr.e_magic & 0xff, (dosHdr.e_magic >> 8) & 0xff);
    printf("\n\t[*] NT HDR RVA : 0x%lx", dosHdr.e_lfanew);
    printf("\n\t[*] Relocs Count : %u", dosHdr.e_crlc & 0xff);
    printf("\n\t[*] Reloc table offset : 0x%x", dosHdr.e_lfarlc);
    printf("\n\t[*] Hdr Size : %d", dosHdr.e_lfanew);

    int stub_size = dosHdr.e_lfanew - sizeof(IMAGE_DOS_HEADER);
    char *dos_stub = calloc(1, stub_size);
    fseek(fp, sizeof(IMAGE_DOS_HEADER), SEEK_SET);
    fread(dos_stub, stub_size, 1, fp);
    printf("\n[*] DOS Stub (%d bytes): \n", stub_size);
    hexdump(dos_stub, stub_size);
    fseek(fp, 0, 0);

    return stub_size;
}

int parse_NT_hdr(FILE* fp, int stub_size){
    fseek(fp, sizeof(IMAGE_DOS_HEADER)+stub_size, 0);
    IMAGE_NT_HEADERS ntHdr;
    fread(&ntHdr, sizeof(IMAGE_NT_HEADERS), 1, fp);

    printf("\n\t[*] Offset : 0x%02x", sizeof(IMAGE_DOS_HEADER)+stub_size);
    printf("\n\t[*] NT signature :\n");
    hexdump((char*)&ntHdr, sizeof(IMAGE_NT_SIGNATURE));
    IMAGE_FILE_HEADER ntFileHdr;
    //fseek();
    //fread();
    printf("\n\t[+] Image File Header :");
    printf("\n\t\t[*] next...");


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
    int stub_size = parse_DOS_hdr(fp);

    printf("\n[+] Parsing NT Header");
    parse_NT_hdr(fp, stub_size);

    printf("\n[+].... to implement.");





    return 0;
    ErrorExit :
        printf("\n[-] Error during execution\n");
        return 1;
}