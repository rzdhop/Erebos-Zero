# Erebos C2 (Version 1)

**Erebos C2** is an educational Command & Control (C2) framework designed to demonstrate advanced Windows process manipulation, argument spoofing, and shellcode injection techniques.
It combines all the techniques featured in the Erebos-Zero Project.

# Disclaimer
This project is for educational purposes and authorized security research only. Using this tool on systems without prior explicit permission is illegal.

## Version 1 Features
* **Multi-Session Management**: A Python-based server handles multiple simultaneous implant connections using a threaded CLI.
* **Process Argument Spoofing**: Executes PowerShell commands hidden behind legitimate process names using a "RickRoll" decoy buffer to mask real command lines.
* **EarlyBird Injection**: Injects shellcode into a suspended process and executes it via Early Bird;  Asynchronous Procedure Call (APC) queuing.
* **PPID Spoofing**: Modifies the Parent Process ID (PPID) of child processes to evade process tree analysis.

## Usage !

### 1. Start the C2 Server
Run the controller on your attack machine:
```bash
python Server.py
```

### 2. Compile the Implant
Use gcc (via MinGW-w64 on Windows) to build the agent:
```bash
gcc .\implant.c .\helper.c .\Attacks\* -o .\implant.exe -lwininet -lws2_32
```

**Developed by**: 0xRzdhop.