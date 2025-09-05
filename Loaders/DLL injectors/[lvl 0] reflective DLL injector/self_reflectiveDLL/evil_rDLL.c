//#include "pch.h"
#include <windows.h>
#include <stdlib.h>
/*
    Compile w/ gcc -shared -o evil_rDLL.dll evil_rDLL.c -Wall -mwindows
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