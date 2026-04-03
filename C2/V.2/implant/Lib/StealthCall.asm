BITS 64
DEFAULT REL

; =========================================================================================
;                           STEALTH CALL - EXECUTION FLOW
; =========================================================================================
;
;     [ 1. C CALLER ]
;            |
;            v
;     [ 2. SpoofCall (spoofer.asm) ]
;            |
;            |-- Push RBP & Non-Volatile Registers (Save Context)
;            |-- Setup RBX for 'gadget_fallback'
;            |-- Push Fake Frame #1 (RtlUserThreadStart)
;            |-- Push Fake Frame #2 (BaseThreadInitThunk)                                     
;            |-- [Stack Align]
;            |-- Push 'JmpRbxGadget' address 
;            |-- Allocate AddRspSize (sub rsp, X)                        
;            |-- Write 'AddRspRetGadget' at [RSP](                       
;            |-- Map Target Arguments into Stack                          
;            |-- jmp [pTarget]                                           
;            |                                                           
;            v                                                           
;     [ 3. TARGET FUNCTION (ntdll/kernel32) ]                            
;            |                                                           
;            |-- Executes normally...                                    
;            |-- ret   =======================================+                                    
;            |                                                |          
;            v                                                |        
;     [ 4. AddRspRetGadget (kernel32.dll) ] <-----------------+          
;            |                                                           
;            |-- add rsp, X  (Skips shadow space & args)                 
;            |-- ret   =======================================+
;            |                                                |
;            v                                                |
;     [ 5. JmpRbxGadget (kernel32.dll) ]  <-------------------+
;            |
;            |-- jmp rbx ================================================+
;            |                                                           |
;            v                                                           |
;     [ 6. gadget_fallback (spoofer.asm) ] <-----------------------------+
;            |
;            |-- lea rsp, [rbp - 0x38] (Restores true Stack Pointer!)
;            |-- Pop RBP & Non-Volatile Registers
;            |-- ret
;            |
;            v
;     [ 7. C CALLER (Resumed Safely) ]
;
; =========================================================================================


struc STACK_CONFIG
    .pSpoofed1_ret:      RESQ 1  ; Offset 0x00
    .Spoofed1StackSize:  RESQ 1  ; Offset 0x08
    .pSpoofed2_ret:      RESQ 1  ; Offset 0x10
    .Spoofed2StackSize:  RESQ 1  ; Offset 0x18
    .pJmpRbxGadget:      RESQ 1  ; Offset 0x20
    .pAddRspRetGadget:   RESQ 1  ; Offset 0x28
    .AddRspSize:         RESQ 1  ; Offset 0x30
    .pTarget:            RESQ 1  ; Offset 0x38
    .pArgs:              RESQ 1  ; Offset 0x40
    .dwNumberOfArgs:     RESQ 1  ; Offset 0x48
    .ssn:                RESQ 1  ; Offset 0x50
endstruc

global SpoofCall

section .text

SpoofCall:
    ; === Prologue & State Preservation ===
    ; We establish a frame pointer (RBP) to act as a permanent anchor.
    ; This allows us to recover execution after the add rsp gadget wrecks the stack pointer.
    push rbp
    mov rbp, rsp
    push r15
    push r14
    push r13
    push r12
    push rdi
    push rsi
    push rbx

    mov r13, rcx                    ; r13 = STACK_CONFIG

    ; Setup desync fallback target
    ; The JMP RBX gadget will redirect execution to 'gadget_fallback'
    lea rbx, [rel gadget_fallback]

    ; === Unwinder Chain Setup ===
    
    ; Frame 1 : RtlUserThreadStart
    mov r10, [r13 + STACK_CONFIG.Spoofed1StackSize]
    sub rsp, r10
    mov r10, [r13 + STACK_CONFIG.pSpoofed1_ret]
    push r10

    ; Frame 2 : BaseThreadInitThunk
    mov r10, [r13 + STACK_CONFIG.Spoofed2StackSize]
    sub rsp, r10
    mov r10, [r13 + STACK_CONFIG.pSpoofed2_ret]
    push r10

    ; === ABI Stack Alignment Calculation ===
    ; The Windows x64 ABI requires RSP % 16 == 8 immediately before executing the target instruction (after pushing return address).
    ; We simulate the stack shifts: (CurrentRSP - 8 [for JmpRbx] - AddRspSize) % 16
    mov r11, rsp
    sub r11, 8                              
    sub r11, [r13 + STACK_CONFIG.AddRspSize]
    and r11, 0xF
    cmp r11, 8
    je .aligned
    sub rsp, 8                      ; Insert padding to align

.aligned:
    ; Push the secondary return gadget (Jmp Rbx). 
    ; The 'add rsp, X' gadget will ret into this.
    mov r10, [r13 + STACK_CONFIG.pJmpRbxGadget]
    push r10

    ; === Target Frame Allocation ===
    ; This allocation jumps over the shadow space + stack arguments.
    ; Its size exactly matches the 'add rsp, X' gadget we found.
    mov r10, [r13 + STACK_CONFIG.AddRspSize]
    sub rsp, r10

    ; Primary Return Address (Add Rsp Gadget)
    mov r10, [r13 + STACK_CONFIG.pAddRspRetGadget]
    mov [rsp], r10

    ; === Argument Staging ===
    mov rax, [r13 + STACK_CONFIG.pArgs]
    mov rcx, [rax + 0x00]           ; Arg 1
    mov rdx, [rax + 0x08]           ; Arg 2
    mov r8,  [rax + 0x10]           ; Arg 3
    mov r9,  [rax + 0x18]           ; Arg 4

    mov r11, [r13 + STACK_CONFIG.dwNumberOfArgs]
    sub r11, 4
    jle .exec_target

.stack_args_loop:
    ; Map remaining arguments into the stack above the shadow space (RSP + 0x20)
    ; r11 is the index offset. Example: For Arg 5 (r11 = 1), read from [rax+32], write to [rsp+40]
    mov r15, [rax + 24 + r11 * 8]   
    mov [rsp + 32 + r11 * 8], r15   
    dec r11
    jnz .stack_args_loop

.exec_target:
    ; SSN is moved to EAX. RCX is copied to R10 to satisfy native indirect syscall ABI.
    mov eax, dword [r13 + STACK_CONFIG.ssn]
    mov r10, rcx                    
    
    mov r12, [r13 + STACK_CONFIG.pTarget]
    jmp r12                         ; Transfer execution

; === Execution Recovery Anchor ===
gadget_fallback:
    ; We land here via: Target -> ret -> add rsp, X; ret -> jmp rbx -> gadget_fallback.
    ; The stack pointer is currently pointing into the spoofed frames. It must be reset.
    ; We recover RSP using the RBP frame pointer. 0x38 is exactly 7 QWORDs pushed after RBP.
    lea rsp, [rbp - 0x38]           
    pop rbx
    pop rsi
    pop rdi
    pop r12
    pop r13
    pop r14
    pop r15
    pop rbp
    ret                             ; Return gracefully to C caller

; Little schema to see the exacte stack before the jmp to the target
; +=======================================================================+ <--- Higher Memory
; | Caller's Return Address                                               | [Entry RSP]
; +-----------------------------------------------------------------------+
; | Saved RBP                                                             | [RBP]
; +-----------------------------------------------------------------------+
; | Saved R15                                                             | [RBP - 0x08]
; | Saved R14                                                             | [RBP - 0x10]
; | Saved R13                                                             | [RBP - 0x18]
; | Saved R12                                                             | [RBP - 0x20]
; | Saved RDI                                                             | [RBP - 0x28]
; | Saved RSI                                                             | [RBP - 0x30]
; | Saved RBX (Holds pointer to gadget_fallback)                          | [RBP - 0x38]
; +=======================================================================+
; |                                                                       |
; | Spoofed Frame 1 Allocation                                            | Size: Spoofed1StackSize
; | (Simulates RtlUserThreadStart local variables / shadow space)         |
; |                                                                       |
; +-----------------------------------------------------------------------+
; | pSpoofed1_ret (Return to RtlUserThreadStart + 0x31)                   | 
; +=======================================================================+
; |                                                                       |
; | Spoofed Frame 2 Allocation                                            | Size: Spoofed2StackSize
; | (Simulates BaseThreadInitThunk local variables / shadow space)        | 
; |                                                                       |
; +-----------------------------------------------------------------------+
; | pSpoofed2_ret (Return to BaseThreadInitThunk + 0x20)                  | 
; +=======================================================================+
; | Optional Padding (0 or 8 bytes)                                       | Dynamic ABI alignment
; +-----------------------------------------------------------------------+
; | pJmpRbxGadget (Secondary return, hit after 'add rsp, X')              | <--- Unwinder stops here
; +=======================================================================+ <--- RSP + AddRspSize
; | Stack Argument N                                                      | 
; | ...                                                                   | Size: AddRspSize 
; | Stack Argument 5                                                      | [RSP + 0x28]
; +-----------------------------------------------------------------------+
; | Shadow Space (Home for Arg 4 / R9)                                    | [RSP + 0x20]
; | Shadow Space (Home for Arg 3 / R8)                                    | [RSP + 0x18]
; | Shadow Space (Home for Arg 2 / RDX)                                   | [RSP + 0x10]
; | Shadow Space (Home for Arg 1 / RCX)                                   | [RSP + 0x08]
; +-----------------------------------------------------------------------+
; | pAddRspRetGadget (Primary return address for the Target function)     | [RSP] <--- CURRENT RSP 
; +=======================================================================+ <--- Lower Memory