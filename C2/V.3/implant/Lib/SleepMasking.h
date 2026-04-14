#pragma once

#include "..\helper.h"

typedef struct {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;

typedef NTSTATUS(NTAPI* _SystemFunction032)(USTRING* data, USTRING* key);

void GoDark(INT sleepTime);