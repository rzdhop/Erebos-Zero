;nasm -f win64 spoofer.asm -o spoofer.o
BITS 64
DEFAULT REL

struc pConfig
    .pRopGadget :       RESQ    1 ; 8
    .pRbx :             RESQ    1 ; 8
    .pTarget :          RESQ    1 ; 8
    .pArgs :            RESQ    1 ; 8
    .dwNumberOfArgs :   RESD    1 ; 4
    ._PADDING :         RESD    1 ; + 4 padding (align) 
endstruc 

global SpoofCall
section .text:

SpoofCall2:
    pop rdi
    mov r10, rcx ; argv[1] -> pConfig
    mov r11, [r10 + pConfig.]



;MARCHE PAS PTN
SpoofCall:
    pop rdi                                     ;Get the original return Address
    mov r10, rcx                                ;now r10 is our pConfig base offset
    mov r12, [r10 + pConfig.dwNumberOfArgs]
    sub r12, 4                                 ;Remove the registers args (rcx, rdx, r8, r9)
    mov r13, [r10 + pConfig.pArgs]             ;r13 points to args   
    mov rcx, [r13] 
    mov rdx, [r13 + 8]
    mov r8, [r13 + 16]
    mov r9, [r13 + 24]

    ; Now we rebuild the stack with the next args with a loop on pConfig.dwNumberOfArgs (r12 here)
    lea r12, [r12*8]                          ;Calculating the effective size of args to store on stack
                                                ;We could use imul but using lea is less noisy as it calcule r12 * 8 as if it was an addr even if it's not
    sub rsp, r12                               ;Allocate space in stack

loop_start :
    cmp r12, 0                                  
    jle loop_end
    ;We add them from last arg to first
    ;for (r12 = dwNumberOfArgs*8, r12 <= 0, r12 -= 8) {     ;r12 act a i
    ;   r15 = rsp + r12
    ;   r15 -= 8 
    ;   rax = pArgs[-1]                           ;last position in python lol (r13 = pArgs)
    ;   *r15 = rax
    ;}
    mov r15, rsp
    add r15, r12
    sub r15, 8
    mov rax, [r13 + 32 + r12]                   ; rax = pArgs[dwArgs] - the last arg
    mov [r15], rax
    sub r12d, 8
    jmp loop_start



loop_end :
    mov r13, [r10 + pConfig.dwNumberOfArgs]    ; save to after set back the stack
    sub rsp, 32                                 ; The shadow space 32 before the call
    mov rax, [r10 + pConfig.pRopGadget]         ; we will set the return addr to the ROP gadget : jmp rbx
    push rax                                    ; the return addr of the function that will be called
    test rsp, 0xf                               ; check if stack is aligned RSP%16 == 0
    jz aligned
    sub rsp, 8

aligned :
    lea rbx, [spoofedFallback]                  ; The spoofed function of kernel32 will jmp to [spoofedFallback]
    mov [r10 + pConfig.pRbx], rbx
    mov r12, [r10 + pConfig.pTarget]
    jmp r12

spoofedFallback:
    lea r13, [r13*8]
    add rsp, r13
    add rsp, 32 
    add rsp, 8
    jmp rdi                                     ;The original return addr


