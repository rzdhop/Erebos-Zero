; w/ nasm -f win64 NtCreateThreadEx.asm -o NtCreateThreadEx.o
default rel
extern g_SSN_NtCreateThreadEx
global stubNtCreateThreadEx
section .text

stubNtCreateThreadEx:
    mov     r10, rcx       
    mov     eax, [g_SSN_NtCreateThreadEx]
    syscall
    ret 