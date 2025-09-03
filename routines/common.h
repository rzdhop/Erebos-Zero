#pragma once
#include <windows.h>

typedef enum {
    OS_UNKNOWN = 0,
    OS_WIN10,
    OS_WIN11
} OS_VERSION;

extern OS_VERSION g_osVersion;


FARPROC __stdcall MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName);
