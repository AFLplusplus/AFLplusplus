#!/usr/bin/env python3

import subprocess
import sys

with open(".clang-format") as f:
    fmt = f.read()

COLUMN_LIMIT = 80
for line in fmt.split("\n"):
    line = line.split(":")
    if line[0].strip() == "ColumnLimit":
        COLUMN_LIMIT = int(line[1].strip())

def custom_format(filename):
    p = subprocess.Popen(['clang-format-7', filename], stdout=subprocess.PIPE)
    src, _ = p.communicate()
    src = str(src, "utf-8")

    macro_indent = 0

    out = ""
    for line in src.split("\n"):
        if line.startswith("#"):
            i = macro_indent
            if line.startswith("#end") and macro_indent > 0:
                macro_indent -= 1
                i -= 1
            elif line.startswith("#el") and macro_indent > 0:
                i -= 1
            elif line.startswith("#if") and not (line.startswith("#ifndef") and line.endswith("_H")):
                macro_indent += 1
            r = "#" + (i * "  ") + line[1:]
            if i != 0 and line.endswith("\\"):
                r = r[:-1]
                while r[-1].isspace() and len(r) != (len(line)-1):
                    r = r[:-1]
                r += "\\"
            if len(r) <= COLUMN_LIMIT:
                line = r
        
        elif "/*" in line and not line.strip().startswith("/*") and line.endswith("*/") and len(line) < (COLUMN_LIMIT-2):
            cmt_start = line.rfind("/*")
            line = line[:cmt_start] + " " * (COLUMN_LIMIT-2 - len(line)) + line[cmt_start:]

        out += line + "\n"

    return (out)

args = sys.argv[1:]
if len(args) == 0:
    print ("Usage: ./format.py [-i] <filename>")
    print ()
    print (" The -i option, if specified, let the script to modify in-place")
    print (" the source files. By default the results are written to stdout.")
    print()
    exit(1)

in_place = False
if args[0] == "-i":
    in_place = True
    args = args[1:]

for filename in args:
    code = custom_format(filename)
    if in_place:
        with open(filename, "w") as f:
            f.write(code)
    else:
        print(code)

