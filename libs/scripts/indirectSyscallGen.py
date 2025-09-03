from random import randint

ntAPIs_path = "ntAPIs.txt"
with open(ntAPIs_path, "r") as apis:
    API_NAMES = [line.rstrip() for line in apis]

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

asm_stubs("./libs/indirect_calls.asm")