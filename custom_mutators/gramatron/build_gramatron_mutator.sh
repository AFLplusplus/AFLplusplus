#!/bin/sh
set -e
#
# american fuzzy lop++ - gramatron build script
# ------------------------------------------------
#
# Originally written by Nathan Voss <njvoss99@gmail.com>
#
# Adapted from code by Andrew Griffiths <agriffiths@google.com> and
#                      Michal Zalewski
#
# Adapted for AFLplusplus by Dominik Maier <mail@dmnk.co>
#
# Copyright 2017 Battelle Memorial Institute. All rights reserved.
# Copyright 2019-2023 AFLplusplus Project. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# This script downloads cJSON and compiles gramatron for Linux systems.

CJSON_VERSION="1.7.18"
CJSON_URL="https://raw.githubusercontent.com/DaveGamble/cJSON/v${CJSON_VERSION}"

echo "================================================="
echo "Gramatron Mutator build script"
echo "================================================="
echo

echo "[*] Performing basic sanity checks..."

if [ ! -f "../../config.h" ]; then
  echo "[-] Error: key files not found - wrong working directory?"
  exit 1
fi

if [ ! -f "../../src/afl-performance.o" ]; then
  echo "[-] Error: you must build afl-fuzz first and not do a \"make clean\""
  exit 1
fi

# Check for required tools
PREREQ_NOTFOUND=
for i in curl; do
  T=`command -v "$i" 2>/dev/null`
  if [ "$T" = "" ]; then
    echo "[-] Error: '$i' not found. Run 'sudo apt-get install $i' or similar."
    PREREQ_NOTFOUND=1
  fi
done

# Set compiler - try to match what built AFL++
if [ -z "$CC" ]; then
  # Try gcc-14 first (commonly used), then fall back
  if command -v gcc-14 >/dev/null 2>&1; then
    export CC=gcc-14
  elif command -v clang >/dev/null 2>&1; then
    export CC=clang
  else
    export CC=cc
  fi
fi

if echo "$CC" | grep -qF /afl-; then
  echo "[-] Error: do not use afl-gcc or afl-clang to compile this tool."
  PREREQ_NOTFOUND=1
fi

if [ "$PREREQ_NOTFOUND" = "1" ]; then
  exit 1
fi

echo "[*] Compiler: $CC"
echo "[+] All checks passed!"

# Download cJSON if needed
mkdir -p cJSON
if [ ! -f "cJSON/cJSON.c" ] || [ ! -f "cJSON/cJSON.h" ]; then
  echo "[*] Downloading cJSON v${CJSON_VERSION}..."

  curl -s -o cJSON/cJSON.c "${CJSON_URL}/cJSON.c" || {
    echo "[-] Error: Failed to download cJSON.c"
    exit 1
  }

  curl -s -o cJSON/cJSON.h "${CJSON_URL}/cJSON.h" || {
    echo "[-] Error: Failed to download cJSON.h"
    exit 1
  }

  echo "[+] cJSON downloaded successfully"
else
  echo "[*] cJSON already present"
fi

echo
echo "[+] Building gramatron now..."

# Compile afl-performance.c directly to avoid LTO issues
$CC -O3 -g -fPIC -c -Wno-unused-result \
    -I../../include \
    ../../src/afl-performance.c -o afl-performance-custom.o || exit 1

# Build the shared library
$CC -O3 -g -fPIC -Wno-unused-result -Wno-pointer-sign \
    -Wl,--allow-multiple-definition \
    -I../../include \
    -I. \
    -IcJSON \
    -o gramatron.so -shared \
    gramfuzz.c gramfuzz-helpers.c gramfuzz-mutators.c gramfuzz-util.c hashmap.c json-parser.c cJSON/cJSON.c \
    afl-performance-custom.o || exit 1

# Clean up
rm -f afl-performance-custom.o

echo
echo "[+] gramatron successfully built!"
echo "[*] Output: gramatron.so"