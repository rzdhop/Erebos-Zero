[BITS 64]
; nasm -f bin Debug_stub.asm -o shellcode.bin
global _start

_start:
    ; Sauvegarde et alignement strict de la pile (requis pour les appels API x64)
    push rbp
    mov rbp, rsp
    and rsp, -16            ; Alignement sur 16 octets
    sub rsp, 32             ; Shadow space de 32 octets pour l'API Windows

    ; --- 1. Résolution de kernel32.dll via le PEB ---
    mov rax, gs:[0x60]      ; PEB
    mov rax, [rax + 0x18]   ; PEB->Ldr
    mov rax, [rax + 0x20]   ; InMemoryOrderModuleList
    mov rax, [rax]          ; Premier module (ntdll.dll)
    mov rax, [rax]          ; Deuxième module (kernel32.dll)
    mov rbx, [rax + 0x20]   ; rbx = DllBase de kernel32.dll

    ; --- 2. Parsing du PE Header de kernel32.dll ---
    mov eax, dword [rbx + 0x3C] ; e_lfanew (Offset NT Headers)
    add rax, rbx                ; Adresse NT Headers
    mov eax, dword [rax + 0x88] ; RVA de l'Export Directory
    add rax, rbx                ; VMA de l'Export Directory

    ; --- 3. Récupération des tables d'export ---
    mov ecx, dword [rax + 0x18] ; NumberOfNames
    mov r8d, dword [rax + 0x20] ; AddressOfNames RVA
    add r8, rbx                 ; AddressOfNames VMA
    mov r9d, dword [rax + 0x24] ; AddressOfNameOrdinals RVA
    add r9, rbx                 ; AddressOfNameOrdinals VMA
    mov r10d, dword [rax + 0x1C]; AddressOfFunctions RVA
    add r10, rbx                ; AddressOfFunctions VMA

find_function:
    dec rcx
    mov esi, dword [r8 + rcx * 4] ; RVA du nom actuel
    add rsi, rbx                  ; VMA du nom actuel

    ; Check des 8 premiers octets pour matcher "OutputDebugStringA"
    ; "Outp" = 0x7074754F
    ; "utDe" = 0x65447475
    mov r11d, dword [rsi]
    cmp r11d, 0x7074754F
    jne find_function
    mov r11d, dword [rsi + 4]
    cmp r11d, 0x65447475
    jne find_function

    ; --- 4. Calcul de l'adresse de la fonction ---
    movzx r11d, word [r9 + rcx * 2] ; Récupère l'Ordinal
    mov eax, dword [r10 + r11 * 4]  ; Récupère la RVA de la fonction
    add rax, rbx                    ; rax = adresse de OutputDebugStringA

    ; --- 5. Préparation de l'argument et appel ---
    ; Construction de la chaîne "PIC OK!" + null byte sur la pile
    ; 'P'=0x50, 'I'=0x49, 'C'=0x43, ' '=0x20, 'O'=0x4F, 'K'=0x4B, '!'=0x21, '\0'=0x00
    mov rdx, 0x00214B4F20434950
    push rdx
    mov rcx, rsp            ; Arg1 (rcx) : pointeur vers la chaîne

    call rax                ; Appel à OutputDebugStringA

    ; --- 6. Fin sécurisée ---
    ; Boucle infinie pour retenir le thread sans crasher
infinite_loop:
    jmp infinite_loop