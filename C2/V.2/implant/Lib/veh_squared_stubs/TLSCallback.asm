[BITS 64]

; nasm -f bin TLSCallback.asm -o TLSCallback.bin ; xxd -i TLSCallback.bin
CustomCallback :
    ; (PVOID DllHandle, DWORD dwReason, PVOID Reserved)

    ; RDX has "Reason". 2 == DLL_THREAD_ATTACH
    cmp edx, 2               ; DLL_THREAD_ATTACH
    jne .ignore

    ; Sauvegarde de la stack et alignement
    push rbp
    mov rbp, rsp
    and rsp, -16             ; Alignement sur 16 bytes (0xFFFFFFFFFFFFFFF0)
    sub rsp, 32              ; Allocation du Shadow Space (0x20)

    mov rax, 0x1337133713371337
    lea rcx, [rel debug_string]
    call rax                 ; OutputDebugStringA

    ; Restauration de la stack
    mov rsp, rbp
    pop rbp
.ignore:
    ret

debug_string:
    db "TLS CALLBACK HIT", 0

    

    
