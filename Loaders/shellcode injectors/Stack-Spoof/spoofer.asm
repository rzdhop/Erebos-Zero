; nasm -f win64 spoofer.asm -o spoofer.o
BITS 64
DEFAULT REL

struc pConfig
    .pRopGadget:     RESQ 1  ; +0  (8 bytes) 
    .pRbx:           RESQ 1  ; +8  (8 bytes) 
    .pTarget:        RESQ 1  ; +16 (8 bytes)
    .pArgs:          RESQ 1  ; +24 (8 bytes)
    .dwNumberOfArgs: RESD 1  ; +32 (4 bytes)
    ._PADDING:       RESD 1  ; +36 (4 bytes padding to 8-byte align)
endstruc

global SpoofCall
section .text

; SpoofCall(pConfig):
; Sets up a fake call stack frame with a return address into a legitimate module (the ROP gadget),
; then jumps to the target function. After the target returns (to the gadget), execution flows to gadget_fallback,
; which restores all registers and returns to the original caller.

SpoofCall:
    ; --- Save original non-volatile registers and get return address ---
    mov     rax, r14            ; Save original R14 in RAX (temporary)
    pop     r14                ; Pop return address of SpoofCall into R14 (target return address)
    push    rax                ; Save original R14 value on the stack
    push    rdi                ; Save original RDI (non-volatile) on stack
    push    rbx                ; Save original RBX (non-volatile)
    push    r13                ; Save original R13 (non-volatile)
    push    r12                ; Save original R12 (non-volatile, will be used)
    push    r15                ; Save original R15 (non-volatile, will be used)

    mov     r10, rcx           ; r10 = pConfig (RCX holds first argument)
    mov     [r10 + pConfig.pRbx], rsp 
    ; ^ Store current RSP (after saving regs) into pConfig->pRbx for later restoration.

    ; ------------------------------------------------------------------
    ; Calculate number of stack arguments (args beyond the first 4)
    ; ------------------------------------------------------------------
    mov     r11d, [r10 + pConfig.dwNumberOfArgs]
    sub     r11, 4                  ; r11 = (total args - 4) = count of args to place on stack (if any)

    ; ------------------------------------------------------------------
    ; Load the first four arguments into RCX, RDX, R8, R9 from the pArgs array
    ; ------------------------------------------------------------------
    mov     rax, [r10 + pConfig.pArgs]    ; RAX = base address of arguments array
    mov     rcx, [rax + 0x00]            ; RCX = arg0
    mov     rdx, [rax + 0x08]            ; RDX = arg1
    mov     r8,  [rax + 0x10]            ; R8  = arg2
    mov     r9,  [rax + 0x18]            ; R9  = arg3

    ; ------------------------------------------------------------------
    ; Allocate stack space for:
    ;   - additional arguments (r11 * 8 bytes each)
    ;   - 32-byte shadow space (required by ABI)
    ;   - alignment padding (to 16-byte boundary)
    ; ------------------------------------------------------------------
    lea     r12, [r11 * 8]       ; r12 = total bytes needed for stack arguments
    add     r12, 0x20            ; +32 bytes shadow space for callee

    ; ---- Align stack pointer to 16 bytes BEFORE pushing return address ---- 
    ; We ensure (RSP - r12) is 16-byte aligned, so that after pushing the fake return (8 bytes),
    ; the stack will be 8-byte misaligned inside the target function (as expected by ABI).
    mov     rbx, rsp             
    sub     rbx, r12
    and     rbx, 0xF             ; Check alignment mask
    jz      .aligned_ok
    add     r12, 8               ; Add 8 bytes padding if needed to align
.aligned_ok:
    sub     rsp, r12             ; Reserve stack space (stack args + shadow + padding)

    ; ------------------------------------------------------------------
    ; Copy any additional arguments (5th and beyond) into the reserved stack space
    ; ------------------------------------------------------------------
    lea     r11, [r11 * 8]       ; r11 = byte size of stack args region
    xor     r12, r12             ; r12 = 0 (offset index for copying)
.args_loop:
    test    r11, r11
    jz      .no_stack_args
    sub     r11, 8
    mov     r15, [rax + 0x20 + r11]    ; load next stack argument from pArgs (offset 0x20 is arg5 start)
    mov     [rsp + 0x28 + r12], r15    ; store it into allocated stack space (after 0x20 shadow + padding)
    add     r12, 8
    jmp     .args_loop
.no_stack_args:

    ; ------------------------------------------------------------------
    ; Set up the fake return address and jump to target function
    ; ------------------------------------------------------------------
    mov     rax, [r10 + pConfig.pRopGadget]
    push    rax                 ; Push fake return address (ROP gadget address in kernel32.dll)
    mov     r13, r10            ; Preserve pConfig pointer in R13 (non-volatile) for later use
    lea     rbx, [gadget_fallback]  ; RBX will point to our fallback stub (jmp [rbx] gadget will jump here)
    mov     rax, [r10 + pConfig.pTarget]
    jmp     rax                 ; **Tail jump** to target function (RCX, RDX, R8, R9 already set)
                                ; Target will return to the gadget (jmp [rbx]), which will jump to gadget_fallback.

; ------------------------------------------------------------------
; gadget_fallback:
; This code is executed after the target function returns. 
; The gadget 'jmp [rbx]' in kernel32.dll will transfer control here, with:
;    RBX = address of gadget_fallback (set above),
;    R13 = pConfig pointer (preserved),
;    R14 = still holding the original return address,
;    other registers unchanged or preserved by the target.
; This stub will restore the original stack pointer and registers, then jump back to the real return address.
; ------------------------------------------------------------------
gadget_fallback:
    mov     rsp, [r13 + pConfig.pRbx]   ; Restore original RSP value (saved before stack allocation)
    pop     r15                        ; Restore original R15
    pop     r12                        ; Restore original R12
    pop     r13                        ; Restore original R13
    pop     rbx                        ; Restore original RBX
    pop     rdi                        ; Restore original RDI
    
    mov     rax, r14                   ; Move return address (in R14) to RAX (volatile register)
    pop     r14                        ; Restore original R14

    jmp     rax                        ; Jump to the real return address (resume execution in caller)
