#pragma once

#include "..\helper.h"

typedef enum _UNWIND_OP_CODES {
	UWOP_PUSH_NONVOL,
	UWOP_ALLOC_LARGE,
	UWOP_ALLOC_SMALL,
	UWOP_SET_FPREG,
	UWOP_SAVE_NONVOL,
	UWOP_SAVE_NONVOL_FAR,
	UWOP_PUSH_MACHFRAME = 10
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
    PVOID pSpoofed1_ret;
    ULONG64 Spoofed1StackSize;
    PVOID pSpoofed2_ret;
    ULONG64 Spoofed2StackSize;
    PVOID pRopGadget;
    ULONG64 SpoofedGadgetSize;
    PVOID pTarget;             // The Syscall addr
    PVOID pArgs;
    ULONG64 dwNumberOfArgs;
    ULONG64 ssn;               // Syscall SSN
} STACK_CONFIG, *PSTACK_CONFIG;