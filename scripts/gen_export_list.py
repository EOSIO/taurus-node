#!/usr/bin/env python3

import sys
import platform

is_linux = platform.system() == "Linux"
is_macos = platform.system() == "Darwin"
if is_linux: 
    print("{")
with open(sys.argv[1]) as f:
    for line in f:
        if line.startswith("INTRINSIC_EXPORT"):
            func_name = line.split()[2]
            leftparam_index = func_name.find('(')
            func_name = func_name[0:leftparam_index]
            if is_linux:
                func_name += ";"
            if is_macos:
                func_name = "_" + func_name
            print(func_name)
if is_linux: 
    print("};")