#!/usr/bin/env python3

import subprocess
import sys
import os
import re

# string_re = re.compile('(\\"(\\\\.|[^"\\\\])*\\")') # future use

with open(".clang-format") as f:
    fmt = f.read()

CLANG_FORMAT_BIN = os.getenv("CLANG_FORMAT_BIN")
if CLANG_FORMAT_BIN is None:
    p = subprocess.Popen(["clang-format", "--version"], stdout=subprocess.PIPE)
    o, _ = p.communicate()
    o = str(o, "utf-8")
    o = o[len("clang-format version "):].strip()
    o = o[:o.find(".")]
    o = int(o)
    if o < 7:
        if subprocess.call(['which', 'clang-format-7'], stdout=subprocess.PIPE) == 0:
            CLANG_FORMAT_BIN = 'clang-format-7'
        elif subprocess.call(['which', 'clang-format-8'], stdout=subprocess.PIPE) == 0:
            CLANG_FORMAT_BIN = 'clang-format-8'
        elif subprocess.call(['which', 'clang-format-9'], stdout=subprocess.PIPE) == 0:
            CLANG_FORMAT_BIN = 'clang-format-9'
        elif subprocess.call(['which', 'clang-format-10'], stdout=subprocess.PIPE) == 0:
            CLANG_FORMAT_BIN = 'clang-format-10'
        else:
            print ("clang-format 7 or above is needed. Aborted.")
            exit(1)
    else:
        CLANG_FORMAT_BIN = 'clang-format'
            
COLUMN_LIMIT = 80
for line in fmt.split("\n"):
    line = line.split(":")
    if line[0].strip() == "ColumnLimit":
        COLUMN_LIMIT = int(line[1].strip())


def custom_format(filename):
    p = subprocess.Popen([CLANG_FORMAT_BIN, filename], stdout=subprocess.PIPE)
    src, _ = p.communicate()
    src = str(src, "utf-8")

    macro_indent = 0
    in_define = False
    last_line = None
    out = ""
    
    for line in src.split("\n"):
        if line.startswith("#"):
            i = macro_indent
            if line.startswith("#end") and macro_indent > 0:
                macro_indent -= 1
                i -= 1
            elif line.startswith("#el") and macro_indent > 0:
                i -= 1
            elif line.startswith("#if") and not (line.startswith("#ifndef") and (line.endswith("_H") or line.endswith("H_"))):
                macro_indent += 1
            elif line.startswith("#define"):
                in_define = True
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

        define_padding = 0
        if last_line is not None and in_define and last_line.endswith("\\"):
            last_line = last_line[:-1]
            define_padding = max(0, len(last_line[last_line.rfind("\n")+1:]))

        if last_line is not None and last_line.strip().endswith("{") and line.strip() != "":
            line = (" " * define_padding + "\\" if in_define else "") + "\n" + line
        elif last_line is not None and last_line.strip().startswith("}") and line.strip() != "":
            line = (" " * define_padding + "\\" if in_define else "") + "\n" + line
        elif line.strip().startswith("}") and last_line is not None and last_line.strip() != "":
            line = (" " * define_padding + "\\" if in_define else "") + "\n" + line

        if not line.endswith("\\"):
            in_define = False

        out += line + "\n"
        last_line = line

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

