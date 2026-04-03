
def to_c_array(data: bytes, varname: str, ctype="UCHAR") -> str:
    hex_vals = ", ".join(f"0x{b:02x}" for b in data)
    return f"{ctype} {varname}[] = {{ {hex_vals} }};"


if __name__ == "__main__":
    stub_path = "shellcode.bin"

    with open(stub_path, 'rb') as f:
        shellcode = f.read()
        with open("stub_c_array.txt", 'wb') as f:
            f.write(to_c_array(shellcode, "DEBUG_STUB").encode())
            f.write(b"\n")

        

    
