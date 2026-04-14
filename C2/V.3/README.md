# Erebos C2 (Version 3)

**Erebos C2** is an advanced, research-oriented Command & Control (C2) framework designed to demonstrate advanced-level Windows systems manipulation, evasion primitives, and offensive capability engineering.

# Disclaimer
This project is for educational purposes, conceptual debugging, and authorized security research only. Using this tool on systems without prior explicit permission is strictly illegal. 

## Version 3.0

### Features Architecture & Advanced Features

Erebos V2 implements a comprehensive suite of stealth and evasion techniques, leaving no default defensive telemetry untampered. The implant operates almost entirely independently of standard Windows API tracking.

### 1. Indirect Syscall Dispatch Engine & Halo's Gate
Bypasses userland EDR hooks through a dynamic, hybridized syscall execution engine.
* **Dynamic SSN Retrieval**: Resolves System Service Numbers (SSNs) on the fly by scanning backwards through NTDLL memory. It correctly handles hooked stubs (tracking JMP rel32 instructions) and calculates the correct SSN via step-offsets without relying on static disk reads.
* **Halo's Gate Integration**: Dynamically extracts clean syscall stubs (0x0F 0x05) from neighboring unhooked NTDLL functions when the targeted function is heavily modified by EDR telemetry.

### 2. Full Call Stack Spoofing
Evades malicious call stack telemetry by synthesizing legitimate thread initialization frames.
* **Unwind Metadata Parsing**: Dynamically parses the target module's .PDATA section, resolving PRUNTIME_FUNCTION and UNWIND_INFO arrays. It calculates precise stack frame sizes by translating UNWIND_CODE operations (UWOP_ALLOC_SMALL, UWOP_ALLOC_LARGE, etc.).
* **Synthetic Frame Construction**: Reconstructs pristine RtlUserThreadStart and BaseThreadInitThunk frames.
* **Desync-Free Execution**: Utilizes a specific ROP/JOP gadget chain leveraging an <add rsp, X ; ret> gadget paired with a <jmp [rbx]> fallback to pass RtlVirtualUnwind scrutiny safely, ensuring the exception handler remains intact without application crashes.

### 3. VEH² (VEH Squared) AMSI Bypass via Runtime PIC Stubs
A hardware-level bypass utilizing Vectored Exception Handling to blind the Antimalware Scan Interface.
* **Runtime PIC Forging**: Dynamically patches 8-byte placeholders within raw Position-Independent Code (PIC) stubs at runtime, embedding resolved addresses for AmsiScanBuffer and RtlAddVectoredExceptionHandler.
* **APC Injection**: Allocates the forged PIC stubs into remote processes and triggers execution via QueueUserAPC.
* **Hardware Breakpoints**: The injected stub registers a VEH and places a Hardware Breakpoint (HWBP) via Dr0/Dr7 debug registers on AmsiScanBuffer. 
* **Execution Hijacking**: Intercepts EXCEPTION_SINGLE_STEP (0x80000004), spoofing the context return to E_INVALIDARG (0x80070057), effectively neutralizing AMSI without standard memory patching (which is heavily monitored).

### 4. Sleep Obfuscation (Sleep Masking)
Erases the implant's memory footprint during idle C2 wait times.
* **Asynchronous ROP Chains**: Abuses CreateTimerQueueTimer to build a threadless ROP chain executed by NtContinue.
* **In-Memory Encryption**: Utilizes the undocumented advapi32.dll API SystemFunction032 (RC4) to encrypt the implant's mapped image in memory.
* **Memory Toggling**: Automates PAGE_READWRITE to PAGE_EXECUTE_READWRITE transitions mapped tightly around the sleep execution flow, evading periodic memory scanners.

### 5. Custom PE Loader & API Hooking
Performs complete manual PE mapping over the C2 network stream.
* **Memory Alignment**: Allocates and maps sections respecting VirtualAddress and SizeOfRawData.
* **Relocation Engine**: Dynamically resolves base relocations (IMAGE_REL_BASED_DIR64) adjusting to the newly allocated memory space.
* **IAT Resolution & Hooking**: Parses the Import Directory, dynamically resolving dependencies while applying inline hooks to specific APIs (MessageBoxA, ExitProcess, VirtualAllocEx) to redirect guest PE calls to safe wrapper functions within the implant.
* **TLS Initialization**: Manually executes Thread Local Storage (TLS) callbacks prior to invoking the EntryPoint.

### 6. Process Manipulation & Opsec Primitives
* **PPID Spoofing**: Modifies the Parent Process ID of child processes via InitializeProcThreadAttributeList, breaking parent-child heuristic detection.
* **Process Argument Spoofing**: Spawns processes in a suspended state with a decoy command line (e.g., a RickRoll YouTube link). It locates the remote PEB via NtQueryInformationProcess, traverses to RTL_USER_PROCESS_PARAMETERS, and overwrites the true malicious command line before thread resumption.
* **Dynamic API Resolution**: Entirely bypasses GetProcAddress and GetModuleHandle by manually walking the PEB (Ldr->InMemoryOrderModuleList).
* **String/API Obfuscation**: Utilizes XOR encryption for critical NTAPI names and DJB2 hashing for dependency resolution.

## Usage & Compilation

### 1. Start the C2 Server
Run the controller on your attack machine:
<pre><code>python Server.py</code></pre>

### 2. Compile the Implant
Compilation requires MinGW-w64 and NASM to correctly assemble the stack spoofing routines and merge object files.
Run the following from the root directory:

<pre><code>nasm -f win64 .\Lib\StealthCall.asm -o .\Lib\StealthCall.o
gcc -s -fmerge-all-constants .\implant.c .\helper.c .\Attacks\*.c .\Lib\*.c .\Lib\*.o -lwininet -lws2_32 -ladvapi32 -lntdll -o implant.exe</code></pre>

**Developed by**: 0xRzdhop