#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>

HMODULE CustomGetModuleHandleW(LPCWSTR moduleName){
    HMODULE hModule = 0;
    size_t moduleName_sz = lstrlenW(moduleName);

    printf("[*] Getting TEB Addr\n");
    PTEB pTebBase = NtCurrentTeb();
    PTEB pTebByGS = (PTEB)__readgsqword(0x30);    
    printf("\t[*] TEB from NtCurrentTEB() : 0x%p\n\t[*] TEB from GS:0x30 : 0x%p\n", pTebBase, pTebByGS);

    //TEB (GS:0x30) + offset PEB (0x30)
    printf("[*] Getting PEB via GS+offset(0x60)\n");
    PPEB pPeb = (PPEB)__readgsqword(0x60); // PPEB ProcessEnvironmentBlock;
    printf("\t[*] __readgsqword(0x60) -> 0x%p\n", pPeb);
    
    printf("[*] Getting PEB via TEB ptr\n");
    printf("\t[*] TEB::ProcessEnvironmentBlock -> 0x%p\n", pTebByGS->ProcessEnvironmentBlock);

    /* for 32-bit systems
        (PTEB)__readfsdword(0x18)
        (PPEB)(__readfsdword(0x30));
    */

    printf("[*] Getting PEB_LDR_DATA via PEB\n");
    PPEB_LDR_DATA Ldr = pPeb->Ldr;//PPEB_LDR_DATA LoaderData
    printf("\t[*] PEB::LoaderData : 0x%p\n");

    PLIST_ENTRY _InMemoryOrderModuleList = &Ldr->InMemoryOrderModuleList;
    printf("[*] Getting lists of _LDR_DATA_TABLE_ENTRY via LoaderData::InMemoryOrderModuleList\n");
    printf("[*] Iterating InMemoryOrderModuleList\n");
    int DoneFlag = 0;
    for (PLIST_ENTRY currElem = _InMemoryOrderModuleList->Flink; (currElem != _InMemoryOrderModuleList) && !DoneFlag; currElem = currElem->Flink){
        PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)((BYTE*)currElem - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
        LPCWSTR BaseName = wcsrchr(entry->FullDllName.Buffer, L'\\')+1;

        if (!_wcsnicmp(moduleName, BaseName, moduleName_sz)) { //Case insensitive
            printf("[*] Found Module '%ls' !\n", moduleName);
            printf("[*] %ls DllBase (HMODULE) : 0x%p \n", BaseName, entry->DllBase);
            hModule = (HMODULE)entry->DllBase;
            DoneFlag = 1;
        } else printf("[Debug] Skiping '%ls' ('%ls')\n", BaseName, entry->FullDllName.Buffer);
    } 

    return hModule;
}  
int main(int argc, char **argv) {

    HMODULE hmodule = GetModuleHandleW(L"kernel32.dll");
    printf("[*] Basic GetModuleHandle : 0x%p\n", hmodule);

    HMODULE chmodule = CustomGetModuleHandleW(L"kernel32.dll");
    printf("[*] Custom GetModuleHandle : 0x%p\n", chmodule);


    return 0;
}