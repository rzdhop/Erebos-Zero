hdr_HIDDEN_API		= ".\hidden_api.h"
hdr_INDIRECT_CALL	= ".\indirect_calls_def.h"

asm_INDIRECT_CALL	= ".\libs\indirect_calls.asm"

Gen_hdr:
	@echo [+] Generating hidden_api.h header
	python .\libs\scripts\genXoredAPIs_as_C.py

	@echo [+] Generating indirect_calls_def.h header
	python .\libs\scripts\indirectSyscallGen_def.py

	@echo [+] Generating indirect_calls.asm header
	python .\libs\scripts\indirectSyscallGen.py
