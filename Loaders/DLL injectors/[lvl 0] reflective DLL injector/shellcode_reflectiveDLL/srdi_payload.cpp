//#include "pch.h"
#include <windows.h>
#include <stdlib.h>
/*
    Covert en shellcode : https://github.com/monoxgas/sRDI 

    Import-Module .\Invoke-Shellcode.ps1
    Import-Module .\ConvertTo-Shellcode.ps1
    ConvertTo-Shellcode -File srdi_payload.dll
*/

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            MessageBoxA(NULL, "Called by DLL_PROCESS_ATTACH", "Pwned by rzdhop", MB_ICONEXCLAMATION);
            break;
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        default:
            break;
    }
    return TRUE;
}