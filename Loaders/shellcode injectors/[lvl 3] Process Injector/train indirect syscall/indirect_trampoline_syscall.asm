; w/ nasm -f win64 NtCreateThreadEx.asm -o NtCreateThreadEx.o
default rel
extern g_SSN_NtCreateThreadEx
extern g_Stub_NtCreateThreadEx  
global stubNtCreateThreadEx
section .text

stubNtCreateThreadEx:
    mov     r10, rcx       
    mov     eax, [g_SSN_NtCreateThreadEx]        ; eax : SSN
    jmp [g_Stub_NtCreateThreadEx]                ; jmp to syscall instruction
    ret 