#include <stdlib.h>
#include <stdio.h>
#include <windows.h>


int parse_DOS_hdr(FILE* fp) {
    // IMAGE_DOS_HEADER
    IMAGE_DOS_HEADER dosHdr;
    fread(&dosHdr, sizeof(dosHdr), 1, fp);
    fclose(fp);

    if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Signature MZ invalide\n");
        return -1;
    }

    printf("\n\t[*] Magic Bytes signature : %04X (%c%c)", dosHdr.e_magic, dosHdr.e_magic & 0xff, (dosHdr.e_magic >> 8) & 0xff);
    printf("\n\t[*] NT HDR RVA : 0x%lx", dosHdr.e_lfanew);
    printf("\n\t[*] Relocs Count : %u", dosHdr.e_crlc & 0xff);
    printf("\n\t[*] Reloc table offset : 0x%x", dosHdr.e_lfarlc);

    return 0;
}

int parse_NT_hdr(FILE* fp){
    
    
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

    printf("\n[+] Parsing DOS Header");
    parse_DOS_hdr(fp);

    printf("\n[+] Parsing NT Header");
    parse_NT_hdr(fp);

    printf("\n[+].... to implement.");





    return 0;
    ErrorExit :
        printf("\n[-] Error during execution\n");
        return 1;
}