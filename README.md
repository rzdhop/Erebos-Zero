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
│ ├── EarlyBird APC injection (Suspended/Debug)
│ └── Process injector (4 levels)
│ ├── Custom GetProcAddress
│ ├── Constantes XORed
│ ├── Indirect syscall
│ ├── Basic Anti-VM
│ └── Basic Anti-Debug
│
└── dll
  ├── Basic DLL injection
  └── shellcode Reflective DLL injection (sRDI)

/bypass
├── EDR
│ ├── Direct syscall
│ ├── Indirect syscall
│ ├── Halo's Gate
│ ├── Hell's Gate
│ └── Dynamic SSN retrieval
│
└── KASLR
  ├── Cache Prefetch side-channel
  └── NtQuerySystemInformation
```

## ⚠️ Disclaimer

Projet publié uniquement pour **recherche & éducation**.  
Ne pas utiliser sur des systèmes sans autorisation.  
