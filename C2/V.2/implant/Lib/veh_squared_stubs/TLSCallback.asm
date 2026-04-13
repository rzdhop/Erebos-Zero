[BITS 64]

; nasm -f bin TLSCallback.asm -o TLSCallback.bin ; xxd -i TLSCallback.bin
CustomCallback :
    ; (PVOID DllHandle, DWORD dwReason, PVOID Reserved)

    cmp edx, 1              ; DLL_PROCESS_ATTACH (apply on main thread)
    je apply_bp
    cmp edx, 2              ; DLL_THREAD_ATTACH
    je apply_bp
    ret

apply_bp:
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

    int3                     ; Breakpoint to trigger VEH and apply HWBP
    ret

debug_string:
    db "TLS CALLBACK HIT", 0

    

    
