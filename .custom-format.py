#!/usr/bin/env python3
#
# american fuzzy lop++ - custom code formatter
# --------------------------------------------
#
# Written and maintaned by Andrea Fioraldi <andreafioraldi@gmail.com>
#
# Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
# Copyright 2019-2022 AFLplusplus Project. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#

import subprocess
import sys
import os
import re
import shutil

# string_re = re.compile('(\\"(\\\\.|[^"\\\\])*\\")') # future use

with open(".clang-format") as f:
    fmt = f.read()

CURRENT_LLVM = os.getenv('LLVM_VERSION', 14)
CLANG_FORMAT_BIN = os.getenv("CLANG_FORMAT_BIN", "")

if shutil.which(CLANG_FORMAT_BIN) is None:
    CLANG_FORMAT_BIN = f"clang-format-{CURRENT_LLVM}"

if shutil.which(CLANG_FORMAT_BIN) is None:
    print(f"[!] clang-format-{CURRENT_LLVM} is needed. Aborted.")
    exit(1)

COLUMN_LIMIT = 80
for line in fmt.split("\n"):
    line = line.split(":")
    if line[0].strip() == "ColumnLimit":
        COLUMN_LIMIT = int(line[1].strip())


def custom_format(filename):
    p = subprocess.Popen([CLANG_FORMAT_BIN, filename], stdout=subprocess.PIPE)
    src, _ = p.communicate()
    src = str(src, "utf-8")

    in_define = False
    last_line = None
    out = ""

    for line in src.split("\n"):
        if line.lstrip().startswith("#"):
            if line[line.find("#") + 1 :].lstrip().startswith("define"):
                in_define = True

        if (
            "/*" in line
            and not line.strip().startswith("/*")
            and line.endswith("*/")
            and len(line) < (COLUMN_LIMIT - 2)
        ):
            cmt_start = line.rfind("/*")
            line = (
                line[:cmt_start]
                + " " * (COLUMN_LIMIT - 2 - len(line))
                + line[cmt_start:]
            )

        define_padding = 0
        if last_line is not None and in_define and last_line.endswith("\\"):
            last_line = last_line[:-1]
            define_padding = max(0, len(last_line[last_line.rfind("\n") + 1 :]))

        if (
            last_line is not None
            and last_line.strip().endswith("{")
            and line.strip() != ""
        ):
            line = (" " * define_padding + "\\" if in_define else "") + "\n" + line
        elif (
            last_line is not None
            and last_line.strip().startswith("}")
            and line.strip() != ""
        ):
            line = (" " * define_padding + "\\" if in_define else "") + "\n" + line
        elif (
            line.strip().startswith("}")
            and last_line is not None
            and last_line.strip() != ""
        ):
            line = (" " * define_padding + "\\" if in_define else "") + "\n" + line

        if not line.endswith("\\"):
            in_define = False

        out += line + "\n"
        last_line = line

    return out


args = sys.argv[1:]
if len(args) == 0:
    print("Usage: ./format.py [-i] <filename>")
    print()
    print(" The -i option, if specified, let the script to modify in-place")
    print(" the source files. By default the results are written to stdout.")
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
