ntAPIs_path = "ntAPIs.txt"
with open(ntAPIs_path, "r") as apis:
    API_NAMES = [line.rstrip() for line in apis]

with open("./libs/indirect_calls_def.h", "w") as def_file: 
    def_file.write("#pragma once\n#include <windows.h>\n\n")
    for name in API_NAMES :
        if name.startswith("Nt"):
            def_file.write(f"DWORD g_SSN_{name}\t= 0;\n")
            def_file.write(f"LPVOID g_SYSADDR_{name}\t= 0;\n")
            def_file.write(f"extern \"C\" NTSTATUS stub{name}(/* TO BE DEFINED */);\n\n")