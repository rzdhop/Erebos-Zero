; nasm -f win64 spoofer.asm -o spoofer.o
BITS 64
DEFAULT REL
struc STACK_CONFIG
    .pRsp:                 RESQ 1      ; +0x00 (8)

    .pSpoofed1_ret:        RESQ 1      ; +0x08 (8)
    .Spoofed1StackSize:    RESD 1      ; +0x10 (4)
    ._pad1:                RESD 1      ; +0x14 (4) align

    .pSpoofed2_ret:        RESQ 1      ; +0x18 (8)
    .Spoofed2StackSize:    RESD 1      ; +0x20 (4)
    ._pad2:                RESD 1      ; +0x24 (4) align

    .pRopGadget:           RESQ 1      ; +0x28 (8)
    .SpoofedGagdetSize:    RESD 1
    ._pad3:                RESD 1 

    .pTarget:              RESQ 1     
    .pArgs:                RESQ 1      

    .dwNumberOfArgs:       RESD 1    
    ._pad4:                RESD 1 
endstruc

global SpoofCall
section .data
    gadget_addr dq 0

section .text
SpoofCall:
    push    r14                ; Save original R14 value on the stack
    push    rdi                ; Save original RDI (non-volatile) on stack
    push    rbx                ; Save original RBX (non-volatile)
    push    r13                ; Save original R13 (non-volatile)
    push    r12                ; Save original R12 (non-volatile)
    push    r15                ; Save original R15 (non-volatile)

    mov     r10, rcx           ; r10 = stackConfig
    mov     [r10 + STACK_CONFIG.pRsp], rsp
    
    ; Here we stop the unwinding of RtlVirtualUnwind 
    push    0

    ; Setting the first stack frame (Here RtlUserThreadStart)
    mov r13d, [r10 + STACK_CONFIG.Spoofed1StackSize]
	sub rsp, r13
	mov r13, [r10 + STACK_CONFIG.pSpoofed1_ret]
	push r13

    ; Setting the Second stack frame (Here RtlUserThreadStart)
    mov r13d, [r10 + STACK_CONFIG.Spoofed2StackSize]
	sub rsp, r13
	mov r13, [r10 + STACK_CONFIG.pSpoofed2_ret]
	push r13

    ; Now the stack frame of the gadget !
    mov r13d, [r10 + STACK_CONFIG.SpoofedGagdetSize]
	sub rsp, r13
	mov r13, [r10 + STACK_CONFIG.pRopGadget]
	push r13

    mov     r11d, [r10 + STACK_CONFIG.dwNumberOfArgs]
    sub     r11, 4                  ; r11 = (total args - 4) = count of args to place on stack (if any)

    mov     rax, [r10 + STACK_CONFIG.pArgs]   ; RAX = base address of arguments array
    mov     rcx, [rax + 0x00]            ; RCX = arg0
    mov     rdx, [rax + 0x08]            ; RDX = arg1
    mov     r8,  [rax + 0x10]            ; R8  = arg2
    mov     r9,  [rax + 0x18]            ; R9  = arg3

    lea     r12, [r11 * 8]       ; r12 = total bytes needed for stack arguments
    add     r12, 0x20            ; +32 bytes shadow space for callee

    ; Align stack pointer to modulo 16 BEFORE pushing return address
    mov     rbx, rsp             
    sub     rbx, r12
    and     rbx, 0xF             ; Check alignment mask
    jz      .aligned_ok
    add     r12, 8               ; Add 8 bytes padding if needed to align
.aligned_ok:
    sub     rsp, r12             ; Reserve stack space (stack args + shadow + padding)

    lea     r11, [r11 * 8]       ; r11 = byte size of stack args region
    xor     r12, r12             ; r12 = 0 (offset index for copying)

.args_loop:
    test    r11, r11
    jz      .no_stack_args
    sub     r11, 8
    mov     r15, [rax + 0x20 + r11]    ; load next stack argument from pArgs (offset 0x20 is arg5 start)
    mov     [rsp + 0x20 + r12], r15    ; store it into allocated stack space (after 0x20 shadow)
    add     r12, 8
    jmp     .args_loop

.no_stack_args:
    mov     r13, r10                ; Preserve STACK_CONFIG pointer in R13 (non-volatile) for later use

    lea     rax, [gadget_fallback]
    mov     [rel gadget_addr], rax
    lea     rbx, [rel gadget_addr]  ; RBX pointe vers cette variable


    mov     rax, [r10 + STACK_CONFIG.pTarget]
    jmp     rax                 ; the jump to the pTarger with built stack frame simulating a normal Call with the jump
                                ; Target will return to the gadget (jmp [rbx]), which will jump to gadget_fallback.


gadget_fallback:
    mov     rsp, [r13 + STACK_CONFIG.pRsp]   ; Restore original RSP value (saved before stack allocation)
    pop     r15
    pop     r12
    pop     r13
    pop     rbx
    pop     rdi
    pop     r14                        ; Restore original R14 (that was pushed as rax in first place)
    
    ret                                 ; Jump to the real return address (resume execution in caller)
