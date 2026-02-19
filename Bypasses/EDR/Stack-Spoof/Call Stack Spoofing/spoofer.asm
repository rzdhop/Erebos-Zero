; nasm -f win64 spoofer.asm -o spoofer.o
BITS 64
DEFAULT REL

struc STACK_CONFIG
    .pRsp:              RESQ 1      ; +0x00
    .pSpoofed1_ret:     RESQ 1      ; +0x08
    .Spoofed1StackSize: RESQ 1      ; +0x10
    .pSpoofed2_ret:     RESQ 1      ; +0x18
    .Spoofed2StackSize: RESQ 1      ; +0x20
    .pRopGadget:        RESQ 1      ; +0x28
    .SpoofedGadgetSize: RESQ 1      ; +0x30
    .pTarget:           RESQ 1      ; +0x38
    .pArgs:             RESQ 1      ; +0x40
    .dwNumberOfArgs:    RESQ 1      ; +0x48
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

    ; Save non-volatile regs
    push r14
    push rdi
    push rbx
    push r13
    push r12
    push r15

    mov r13, rcx                    ; r13 = stackConfig
    mov [rel saved_rsp], rsp        ; save rsp for the end restoration of non-volatile regs

    ; End unwinding of RtlVirtualUnwind
    push 0

    ; === Frame 1 : RtlUserThreadStart ===
    mov r10, [r13 + STACK_CONFIG.Spoofed1StackSize]
    sub rsp, r10
    mov r10, [r13 + STACK_CONFIG.pSpoofed1_ret]
    push r10

    ; === Frame 2 : BaseThreadInitThunk ===
    mov r10, [r13 + STACK_CONFIG.Spoofed2StackSize]
    sub rsp, r10
    mov r10, [r13 + STACK_CONFIG.pSpoofed2_ret]
    push r10

    ; === Frame 3 : Gadget ===
    mov r10, [r13 + STACK_CONFIG.SpoofedGadgetSize]
    sub rsp, r10
    mov r10, [r13 + STACK_CONFIG.pRopGadget]
    push r10                        ; retaddr of MessageBoxA = gadget FF23


    ; Setup 4 first args
    mov rax, [r13 + STACK_CONFIG.pArgs]
    mov rcx, [rax + 0x00]           ; arg0
    mov rdx, [rax + 0x08]           ; arg1
    mov r8,  [rax + 0x10]           ; arg2
    mov r9,  [rax + 0x18]           ; arg3

    ; si more args than 4
    mov r11, [r13 + STACK_CONFIG.dwNumberOfArgs]
    sub r11, 4                      
    jle .setup_rbx                  

    lea r12, [r11 * 8]
    sub rsp, r12                    ; Save space for ABI call convention Shadow (0x20) + args

.stack_args_loop:
    dec r11
    mov r15, [rax + 0x20 + r11 * 8]
    mov [rsp + r11 * 8], r15
    test r11, r11
    jnz .stack_args_loop

.setup_rbx:
    ; Setup rbx -> gadget_target -> gadget_fallback
    lea rax, [gadget_fallback]
    mov [rel gadget_target], rax
    lea rbx, [rel gadget_target]

    mov r10, rsp
    and r10, 0xF
    cmp r10, 8
    je .aligned_ok
    sub rsp, 8                      ; Force rsp%16 == 8
.aligned_ok:

    mov rax, [r13 + STACK_CONFIG.pTarget]
    jmp rax

; MessageBoxA ret -> gadget FF23 (jmp [rbx]) -> Here
gadget_fallback:
    mov rsp, [rel saved_rsp]        ; Restore RSP
    pop r15
    pop r12
    pop r13
    pop rbx
    pop rdi
    pop r14

    jmp [rel saved_ret]             ; not using ret to keep the flow hidden from RtlVitualUnwind