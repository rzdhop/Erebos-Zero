import subprocess

key = b"rzdhop_is_a_nice_guy_yeahhhh"

def xor(data: bytes, key: bytes) -> bytes:
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))

def to_c_array(data: bytes, varname: str, ctype="UCHAR") -> str:
    hex_vals = ", ".join(f"0x{b:02x}" for b in data)
    return f"{ctype} {varname}[] = {{ {hex_vals} }};"

def run_cmd(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    if result.returncode != 0:
        print(f"[-] Error: {result.stderr}")
    return result.stdout


if __name__ == "__main__":
    dll_path = "../sRDI/VEHsquared.dll"
    output_bin = "../sRDI/VEHsquared.bin"
    cmd = f"python monoxgas_sRDI/ConvertToShellcode.py {dll_path} -c -i -d 1 -of raw"
    print(f"Running command: {cmd}")
    print(run_cmd(cmd))

    with open(output_bin, 'rb') as f:
        shellcode = f.read()
        enc = xor(shellcode + b"\x00", key)
        with open("../sRDI/VEHsquared_enc.txt", 'wb') as f:
            f.write(to_c_array(enc, "VEH_squared_PIC").encode())
            f.write(b"\n")
            f.write(to_c_array(key, "VEH_squared_PIC_key").encode())

        

    
