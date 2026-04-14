def to_c_array(data: bytes, varname: str, ctype="UCHAR") -> str:
    hex_vals = ", ".join(f"0x{b:02x}" for b in data)
    return f"{ctype} {varname}[] = {{ {hex_vals} }};"

def unxor_line() :
    for name in API_NAMES :
        print(f"XOR(_{name}, sizeof(_{name}), key, sizeof(key));")

def xor(data: bytes, key: bytes) -> bytes:
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))

API_NAMES = [
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "NtResumeThread",
    "NtWaitForSingleObject",
    "NtQueueApcThread",
    "_NtQueryInformationProcess",
    "NtReadVirtualMemory",
    "NtCreateThreadEx",
    "NtOpenProcess", 
    "NtCreateEvent", 
    "NtCreateTimer"
]

key = b"rzdhop_is_a_nice_guy"

for name in API_NAMES:
    enc = xor(name.encode() + b"\x00", key)
    c_name = "_" + name
    print(to_c_array(enc, c_name))

print(to_c_array(key, "key"))
print()
unxor_line()