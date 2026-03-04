```
   _______  _______  ____  ____
  / __/ _ \/ __/ _ )/ __ \/ __/
 / _// , _/ _// _  / /_/ /\ \  
/___/_/|_/___/____/\____/___/  
          by : 0xRzdhop
```
## 🕷️ Erebos-Zero 
> **Erebos-Zero** est mon arsenal perso de **maldev** et autres

Grosso-modo, pour le moment voici les techniques implémentés :
```
/loaders
├── shellcode
│   ├── EarlyBird APC injection : Thread queuing before execution
│   └── Process injector (4 levels) : Escalating evasion complexity levels
│       ├── Custom GetProcAddress : Manual EAT/PEB parsing
│       ├── Constantes XORed : String and data obfuscation
│       ├── Indirect syscall : Using legitimate ntdll gadgets
│       ├── Basic Anti-VM : Environment and CPUID checks
│       └── Basic Anti-Debug : PEB and flag monitoring
│
├── dll
│   ├── Basic DLL injection : Standard remote thread loading
│   └── shellcode Reflective DLL injection (sRDI) : Converting DLLs to PIC
│
├── Function stomping injection : Overwriting legitimate function bodies
├── Mapping injection : Shared sections, no WPM
└── Thread hijacking : Redirecting RIP/EIP contexts

/misc
├── PPID Spoofing : Breaking process tree analysis
├── Process Argument Spoofing : Masking CLI in ProcMon
├── IAT Hiding : Hashing imports via DJB2
└── Registry Stager : Fileless shellcode storage

/bypass
├── EDR
│   ├── Direct syscall : Manual SSN transition
│   ├── Indirect syscall : Stealthy return address
│   ├── Halo's Gate : Unhooked neighbor SSN recovery
│   ├── Hell's Gate : Dynamic EAT SSN extraction
│   ├── Dynamic SSN retrieval : Sorting Zw* functions
│   └── VEH AMSI Bypass : Hardware breakpoint interception
│
└── KASLR
├── Cache Prefetch side-channel : Timing attack on kernel
└── NtQuerySystemInformation : System module leak

/C2
├── V.1 (Legacy) : Basic modular beaconing
└── V.2 (Advanced) : High-stealth orchestration
├── StealthCall : Unified stack/syscall engine
├── Call Stack Spoofing : Synthetic frame reconstruction
└── PE Loader : Memory-resident EXE execution

/stagers
└── Web Stagers
└── basic HTTP stager : WinHttp payload fetching

```


## ⚠️ Disclaimer

Projet publié uniquement pour **recherche & éducation**.  
Ne pas utiliser sur des systèmes sans autorisation.  
