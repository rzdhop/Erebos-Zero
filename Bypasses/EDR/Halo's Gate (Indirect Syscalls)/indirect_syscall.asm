; w/ nasm -f win64 indirect_syscall.asm -o indirect_syscall.o
default rel
extern g_SSN_NtCreateThreadEx
extern g_SYSADDR_NtCreateThreadEx
global stubNtCreateThreadEx
section .text

stubNtCreateThreadEx:
    xor     eax, eax
    mov     r10, rcx       
    mov     eax, [g_SSN_NtCreateThreadEx]
    jmp     [g_SYSADDR_NtCreateThreadEx]
    ret 