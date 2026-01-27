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

;
; [RSP+00] = return address
; [RSP+08] = shadow space arg1
; [RSP+10] = shadow space arg2
; [RSP+18] = shadow space arg3
; [RSP+20] = shadow space arg4
; [RSP+28] = arg7
; [RSP+30] = arg6
; [RSP+38] = arg5

SpoofCall:
    pop rdi
    mov r10, rcx ; argv[1] -> pConfig

    mov r11d, [r10 + pConfig.dwNumberOfArgs]
    ;movzx r11, r11d
    sub r11, 4 ; get the nb of args to be pushed into the stack

    ; setting the 4 reserved registers in volatile registers
    mov rcx, [r10 + pConfig.pArgs + 0x0]
    mov rdx, [r10 + pConfig.pArgs + 0x8]
    mov r8, [r10 + pConfig.pArgs + 0x10]
    mov r9, [r10 + pConfig.pArgs + 0x18]
    
    lea r12, [r11*8]    ; add space for args (size in Bytes) 
    add r12, 0x20       ; add sapce for 32 bytes shadow stack
    add r12, 0x8        ; add space for return addr
    
    test r12, 8         ; check if r12 % 16 == 8 if so : we add 8 to align
    jnz continue
    add r12, 8          ; added the 8 bytes to be % 16 aligned
continue :
    sub rsp, r12        ; rsp has now space for args + shadows space + ret addr + alignment if needed
    lea r11, [r11*8]    ; get Byte size of args to iterate 8 by 8

args_loop:
    cmp r11, 0
    jz args_loop_end

    sub r11, 8
    mov r15, [r10 + pConfig.pArgs + 0x20 + r11] ; get last argument in pArgs
    mov [rsp + 0x28 + r11], r15
    jmp args_loop


args_loop_end:
    mov rax, [r10 + pConfig.pRopGadget]
    mov [rsp], rax
    
    mov rbx, gadget_fallback
    jmp [r10 + pConfig.pTarget]

gadget_fallback : 
    add rsp, r12  ; restore the stack as before we allocate for our call
    jmp rdi       ; return to our C code

