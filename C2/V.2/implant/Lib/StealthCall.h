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

// Struct update: use UINT64 to prevent C/ASM alignment padding issues
typedef struct _STACK_CONFIG {
    UINT64 pSpoofed1_ret;
    UINT64 Spoofed1StackSize;
    UINT64 pSpoofed2_ret;
    UINT64 Spoofed2StackSize;
    UINT64 pJmpRbxGadget;      // Keep this to bounce back after the AddRsp Gadget
    UINT64 pAddRspRetGadget;   // Primary target return address
    UINT64 AddRspSize;         // The 'X' value
    UINT64 pTarget;
    UINT64 pArgs;
    UINT64 dwNumberOfArgs;
    UINT64 ssn;
} STACK_CONFIG, *PSTACK_CONFIG;

extern PVOID SpoofCall(PSTACK_CONFIG stackConfig);

ULONG StealthCall(DWORD funcSSN, PVOID pTarget, DWORD dwNumberOfArgs, ...);
DWORD getInDirectSyscallStub(HMODULE hNTDLL, const char* NtFunctionName, DWORD *funcSSN, PVOID *ppTarget);
DWORD dynamicSSN_retreive(BYTE* NtFunctionAddr);
LPVOID Halo_gate(HMODULE hNtdll);
DWORD getStackFrameSize(PVOID funcPTR, HMODULE modulePTR);
PVOID FindJMPGadget(HMODULE hModule);