#!/bin/sh
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
# This script builds json-c with cmake and compiles gramatron
# with fixes for GCC 14 compatibility on Linux systems.

JSONC_VERSION="$(cat ./JSONC_VERSION)"
JSONC_REPO="https://github.com/json-c/json-c"

echo "================================================="
echo "Gramatron Mutator build script (Linux)"
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

PYTHONBIN=`command -v python3 || command -v python || echo python3`
MAKECMD=make

# Detect number of cores for parallel build
if command -v nproc >/dev/null 2>&1; then
  CORES=`nproc`
else
  CORES=2
fi

PREREQ_NOTFOUND=
for i in git $MAKECMD cmake; do
  T=`command -v "$i" 2>/dev/null`
  if [ "$T" = "" ]; then
    echo "[-] Error: '$i' not found. Run 'sudo apt-get install $i' or similar."
    PREREQ_NOTFOUND=1
  fi
done

# Detect compiler - prefer the one that built AFL++
if [ -z "$CC" ]; then
  if [ -f "../../src/afl-performance.o" ]; then
    # Check if afl-performance.o has clang or gcc signatures
    if strings ../../src/afl-performance.o 2>/dev/null | grep -qi "clang"; then
      if command -v clang-14 >/dev/null 2>&1; then
        export CC=clang-14
        echo "[*] Detected Clang in AFL++ build, using clang-14"
      elif command -v clang >/dev/null 2>&1; then
        export CC=clang
        echo "[*] Detected Clang in AFL++ build, using clang"
      else
        export CC=gcc-14
        echo "[*] Clang not found, falling back to gcc-14"
      fi
    else
      # GCC was likely used
      if command -v gcc-14 >/dev/null 2>&1; then
        export CC=gcc-14
        echo "[*] Using gcc-14"
      elif command -v gcc >/dev/null 2>&1; then
        export CC=gcc
        echo "[*] Using gcc"
      else
        export CC=cc
        echo "[*] Using system default compiler"
      fi
    fi
  else
    # Fallback
    if command -v gcc-14 >/dev/null 2>&1; then
      export CC=gcc-14
    elif command -v clang-14 >/dev/null 2>&1; then
      export CC=clang-14
    elif command -v clang >/dev/null 2>&1; then
      export CC=clang
    else
      export CC=cc
    fi
    echo "[*] Using compiler: $CC"
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

echo "[*] Making sure json-c is checked out"

# Check if we're in a git repository
git status 1>/dev/null 2>/dev/null
if [ $? -eq 0 ]; then
  echo "[*] Detected git repository, attempting submodule initialization"

  # Try to initialize submodule from AFL++ root
  if [ -f "../../.gitmodules" ]; then
    (cd ../.. && git submodule init && git submodule update custom_mutators/gramatron/json-c) 2>/dev/null
  fi

  # Check if submodule was successfully initialized
  if [ ! -d json-c/.git ]; then
    echo "[*] Submodule initialization failed, will clone directly"
    NEED_CLONE=1
  else
    echo "[+] Submodule initialized successfully"
    NEED_CLONE=0
  fi
else
  echo "[*] Not in a git repository, will clone directly"
  NEED_CLONE=1
fi

# Clone json-c if needed
if [ "$NEED_CLONE" = "1" ]; then
  echo "[*] Cloning json-c from GitHub"
  if [ ! -d json-c/.git ]; then
    CNT=1
    while [ ! -d json-c/.git ] && [ "$CNT" -lt 4 ]; do
      echo "Trying to clone json-c (attempt $CNT/3)"
      rm -rf json-c
      git clone "$JSONC_REPO" json-c
      CNT=`expr "$CNT" + 1`
    done
  fi
fi

if [ ! -e json-c/.git ]; then
  echo "[-] Error: Could not checkout json-c"
  echo "[-] Please check your internet connection or manually clone:"
  echo "    git clone $JSONC_REPO json-c"
  exit 1
fi

echo "[+] Got json-c."

# Build json-c if not already built
if [ ! -e "json-c/build/libjson-c.a" ]; then
  echo "[*] Building json-c"

  # Clean any previous builds
  rm -rf json-c/build

  cd "json-c" || exit 1

  echo "[*] Resetting json-c to clean state"
  git reset --hard HEAD 2>/dev/null || true
  git clean -fd 2>/dev/null || true

  echo "[*] Checking out $JSONC_VERSION"
  git checkout "$JSONC_VERSION" || exit 1

  echo "[*] Applying ssize_t patch for GCC 14 compatibility"

  # Check if the file needs patching
  if grep -q "error Unable to determine size of ssize_t" json_object.c 2>/dev/null; then
    echo "[*] Found problematic SSIZE_T_MAX block, applying fix..."

    # Use Python to properly fix the preprocessor directives
    $PYTHONBIN << 'PYEOF'
with open('json_object.c', 'r') as f:
    lines = f.readlines()

new_lines = []
i = 0
skip = False
depth = 0

while i < len(lines):
    # Look for the start of the problematic block
    if '#ifndef SSIZE_T_MAX' in lines[i] and not skip:
        # Check if next line has the problematic pattern
        if i + 1 < len(lines) and 'SIZEOF_SSIZE_T' in lines[i + 1]:
            new_lines.append('#ifndef SSIZE_T_MAX\n')
            new_lines.append('#define SSIZE_T_MAX SSIZE_MAX\n')
            new_lines.append('#endif\n')
            new_lines.append('\n')
            skip = True
            depth = 1
            i += 1
            continue

    if skip:
        # Count nested preprocessor directives
        if lines[i].strip().startswith('#if'):
            depth += 1
        elif lines[i].strip().startswith('#endif'):
            depth -= 1
            if depth == 0:
                skip = False
        i += 1
        continue

    new_lines.append(lines[i])
    i += 1

with open('json_object.c', 'w') as f:
    f.writelines(new_lines)

print("Fix applied successfully")
PYEOF

    if [ $? -ne 0 ]; then
      echo "[-] Python fix failed, trying awk fallback..."

      # Fallback to awk
      awk '
        BEGIN {
          in_block = 0
          block_depth = 0
          fixed = 0
        }

        # Detect start of problematic block
        /^#ifndef SSIZE_T_MAX/ && !fixed {
          print "#ifndef SSIZE_T_MAX"
          print "#define SSIZE_T_MAX SSIZE_MAX"
          print "#endif"
          print ""
          in_block = 1
          block_depth = 1
          fixed = 1
          next
        }

        # While in block, track depth
        in_block {
          if (/^#if/) {
            block_depth++
          }
          else if (/^#endif/) {
            block_depth--
            if (block_depth == 0) {
              in_block = 0
            }
          }
          next
        }

        # Print all other lines
        !in_block { print }
      ' json_object.c > json_object.c.tmp || exit 1

      if [ ! -s json_object.c.tmp ]; then
        echo "[-] ERROR: Fix produced empty file"
        rm -f json_object.c.tmp
        exit 1
      fi

      mv json_object.c.tmp json_object.c || exit 1
    fi

    echo "[+] Applied fix to json_object.c"
  else
    echo "[*] SSIZE_T_MAX appears OK or already fixed"
  fi

  # Final verification
  if grep -q "error Unable to determine size of ssize_t" json_object.c; then
    echo "[-] ERROR: Patch verification failed - error directive still present!"
    exit 1
  fi

  echo "[+] Verified: ssize_t fix is in place"

  # Build with cmake
  mkdir -p build
  cd build || exit 1

  echo "[*] Configuring json-c with cmake"
  cmake -DBUILD_SHARED_LIBS=OFF \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DCMAKE_C_FLAGS="-fPIC -D_POSIX_C_SOURCE=200809L" \
        -DBUILD_TESTING=OFF \
        -DBUILD_APPS=OFF \
        -DDISABLE_WERROR=ON \
        .. || exit 1

  echo "[*] Building json-c"
  $MAKECMD -j${CORES} || exit 1

  cd ../..
else
  echo "[*] json-c already built"
fi

echo
echo "[+] Json-c successfully prepared!"

# Create a symlink in the build directory so json-c/json.h can be found
if [ ! -e json-c/build/json-c ]; then
  echo "[*] Creating json-c symlink in build directory for headers"
  cd json-c/build && ln -sf . json-c && cd ../..
fi

echo "[+] Building gramatron now."

$CC -O3 -g -fPIC -fno-lto -Wno-unused-result -Wno-pointer-sign \
    -Wl,--allow-multiple-definition \
    -I../../include \
    -I. \
    -I./json-c \
    -I./json-c/build \
    -I/prg/dev/include \
    -o gramatron.so -shared \
    gramfuzz.c gramfuzz-helpers.c gramfuzz-mutators.c gramfuzz-util.c hashmap.c \
    ../../src/afl-performance.o json-c/build/libjson-c.a || exit 1

echo
echo "[+] gramatron successfully built!"
echo "[*] Output: gramatron.so"