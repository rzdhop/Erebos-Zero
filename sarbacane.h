#pragma once
#include <windows.h>
#include <winternl.h>

#include "libs/hidden_apis.h" //All obfuscated vars
#include "libs/indirect_calls_def.h" 

#include "routines/common.h"


typedef struct _SYSCALL_STUB {
    DWORD SyscallId;
    PVOID SyscallFunc;
} SYSCALL_STUB, *PSYSCALL_STUB;