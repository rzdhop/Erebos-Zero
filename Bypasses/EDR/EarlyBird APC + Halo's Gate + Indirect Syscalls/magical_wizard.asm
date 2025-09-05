; w/ nasm -f win64 magical_wizard.asm -o magical_wizard.o
default rel
extern g_SSN_NtQueueApcThread
extern g_SYSADDR_NtQueueApcThread
global stubNtQueueApcThread
section .text

stubNtQueueApcThread:
    xor     eax, eax
    mov     r10, rcx       
    mov     eax, [g_SSN_NtQueueApcThread]
    jmp     [g_SYSADDR_NtQueueApcThread]
    ret 