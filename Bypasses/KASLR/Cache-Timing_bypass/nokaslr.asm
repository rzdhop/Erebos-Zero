; w/ nasm -f win64 nokaslr.asm -o nokaslr.o
default rel
global cacheTiming

section .text
cacheTiming:

    ; Setup registers to 0
	xor r8, r8
	xor r9, r9
	xor r10, r10
	xor rax, rax
	xor rdx, rdx

    ; argv[1] de la fonction
	mov r10, rcx

    ; Memory fence : une sorte de WaitForSingleObject mais pour les actions R/W mémoire
    ; Wait for all Read & Writyes operation to finish before executing 
	mfence

    ; Read Time-Stamp Counter and Processor ID : récupère le nombre de cycle CPU depuis le dernier reset
    ; return dans edx:eax (64bits dispatch en 2 registres 32 bits) et dans ecx le processor ID (le p dans rdtsc'p')
	;   En profondeur il fait un rdmsr sur le registre MSR C0000103H (IA32_TSC) et pour le processor ID dans les low 32 bit du MSR IA32_TSC_AUX
    rdtscp

    ; on set r8 avec les 32 bits de poid faible eax et poids fort de edx
	mov r8, rax
	mov r9, rdx

	shl r9, 32
	or r9, r8

    ; load fence : Comme mfence mais pour les operations de lecture uniquement
	lfence

    ; Ces instructions interagissent avec la hiérarchie des caches processeurs (L1 à L3).
    ; prefetchnta (Non Temporal Access) :
    ;   Indique au processeur de précharger la ligne mémoire pointée par r10
    ;   dans le cache (genre L1 ou L2), en la marquant comme "non-temporelle".
    ;       Cela signifie que cette donnée ne sera probablement pas réutilisée immédiatement.

    ; prefetcht2 :
    ;   Donne un hint au CPU pour précharger la mémoire dans un cache plus deep (L3 mais aussi L2),
    ;   Utile quand on s'attend à un accès futur, mais pas imminent.

    ; Ce sont des hints, pas des ordres : le CPU n'est pas obligé de les respecter.
    ;    Si la donnée est déjà en cache, l'accès sera plus rapide (via rdtscp on peut le mesurer).
    
    ; ici on va mesurer les cycles CPU fait pour charger ces addr dans le cache CPU, car si l'addr est déjà dans le cache il va skip l'instrcuion et être plus rapide 
	prefetchnta byte [r10]
	prefetcht2 byte [r10]

	mfence

    ; On récupère les cycles apres les opérations
	rdtscp
    
	shl rdx, 32
	or rdx, rax

	lfence

	sub rdx, r9
    mov rax, rdx

	ret
