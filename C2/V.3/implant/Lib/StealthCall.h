#pragma once

#include "..\helper.h"

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0,    /* info == register number */
    UWOP_ALLOC_LARGE = 1,    /* info == 0 or 1, slots == 2 or 3 */
    UWOP_ALLOC_SMALL = 2,    /* info == size/8 - 1 */
    UWOP_SET_FPREG = 3,      /* info == 0 */
    UWOP_SAVE_NONVOL = 4,    /* info == register number, slot == 1 */
    UWOP_SAVE_NONVOL_FAR = 5, /* info == register number, slots == 2 */
    UWOP_SAVE_XMM128 = 8,    /* info == XMM reg number, slot == 1 */
    UWOP_SAVE_XMM128_FAR = 9, /* info == XMM reg number, slots == 2 */
    UWOP_PUSH_MACHFRAME = 10  /* info == 0 or 1 */
} UNWIND_OP_CODES;

typedef UCHAR UBYTE;
typedef union _UNWIND_CODE
{
	struct
	{
		UBYTE CodeOffset;
		UBYTE UnwindOp : 4;
		UBYTE OpInfo : 4;
	};
	USHORT FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO {
	UCHAR Version : 3;
	UCHAR Flags : 5;
	UCHAR SizeOfPrologue;
	UCHAR CountOfUnwindCodes;
	UCHAR FrameRegister : 4;
	UCHAR FrameRegisterOffset : 4;
	UNWIND_CODE UnwindCode[1];
} UNWIND_INFO, * PUNWIND_INFO;

typedef struct _STACK_CONFIG {
    PVOID pSpoofed1_ret;       // 0x00
    ULONG64 Spoofed1StackSize; // 0x08
    PVOID pSpoofed2_ret;       // 0x10
    ULONG64 Spoofed2StackSize; // 0x18
    PVOID pJmpRbxGadget;       // 0x20
    PVOID pAddRSPRetGadget;    // 0x28
    ULONG64 AddRspSize;        // 0x30
    PVOID pTarget;             // 0x38
    PVOID pArgs;               // 0x40
    ULONG64 dwNumberOfArgs;    // 0x48  <-- Changed from DWORD to ULONG64
    ULONG64 ssn;               // 0x50  <-- Changed from DWORD to ULONG64
} STACK_CONFIG, *PSTACK_CONFIG; 

extern PVOID SpoofCall(PSTACK_CONFIG stackConfig);

ULONG StealthCall(DWORD funcSSN, PVOID pTarget, DWORD dwNumberOfArgs, ...);
DWORD getInDirectSyscallStub(HMODULE hNTDLL, const char* NtFunctionName, DWORD *funcSSN, PVOID *ppTarget);
DWORD dynamicSSN_retreive(BYTE* NtFunctionAddr);
LPVOID Halo_gate(HMODULE hNtdll);
DWORD getStackFrameSize(PVOID funcPTR, HMODULE modulePTR);
PVOID FindJMPGadget(HMODULE hModule);