//#include "pch.h"
#include <windows.h>

/*
Compile w/ gcc -shared -o evil_dll.dll evil_dll.cpp -Wall -mwindows
*/


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            MessageBoxA(NULL, "Called by DLL_PROCESS_ATTACH", "Pwned by rida", MB_ICONEXCLAMATION);
            break;
        case DLL_PROCESS_DETACH:
            MessageBoxA(NULL, "Called by DLL_PROCESS_DETACH", "Pwned by rida", MB_ICONEXCLAMATION);
            break;
        case DLL_THREAD_ATTACH:
            MessageBoxA(NULL, "Called by DLL_THREAD_ATTACH", "Pwned by rida", MB_ICONEXCLAMATION);
            break;
        case DLL_THREAD_DETACH:
            MessageBoxA(NULL, "Called by DLL_THREAD_DETACH", "Pwned by rida", MB_ICONEXCLAMATION);
            break;
        default:
            break;
    }
    return true;
}