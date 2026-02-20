#include <winternl.h>
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

/*
1) Charger le PE en mémoire 
2) Allouer la taille de : ptionalHeader.SizeOfImage
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


int main(int argc, char ** argv) {

    return 0;
}