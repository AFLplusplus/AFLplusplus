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
# Copyright 2019-2020 AFLplusplus Project. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# This script downloads, patches, and builds a version of Unicorn with
# minor tweaks to allow Unicorn-emulated binaries to be run under
# afl-fuzz.
#
# The modifications reside in patches/*. The standalone Unicorn library
# will be written to /usr/lib/libunicornafl.so, and the Python bindings
# will be installed system-wide.
#
# You must make sure that Unicorn Engine is not already installed before
# running this script. If it is, please uninstall it first.

JSONC_VERSION="$(cat ./JSONC_VERSION)"
JSONC_REPO="https://github.com/json-c/json-c"

echo "================================================="
echo "Gramatron Mutator build script"
echo "================================================="
echo

echo "[*] Performing basic sanity checks..."

PLT=`uname -s`

if [ ! -f "../../config.h" ]; then

  echo "[-] Error: key files not found - wrong working directory?"
  exit 1

fi

if [ ! -f "../../src/afl-performance.o" ]; then

  echo "[-] Error: you must build afl-fuzz first and not do a \"make clean\""
  exit 1

fi

PYTHONBIN=`command -v python3 || command -v python || command -v python2 || echo python3`
MAKECMD=make
TARCMD=tar

if [ "$PLT" = "Darwin" ]; then
  CORES=`sysctl -n hw.ncpu`
  TARCMD=tar
fi

if [ "$PLT" = "FreeBSD" ]; then
  MAKECMD=gmake
  CORES=`sysctl -n hw.ncpu`
  TARCMD=gtar
fi

if [ "$PLT" = "NetBSD" ] || [ "$PLT" = "OpenBSD" ]; then
  MAKECMD=gmake
  CORES=`sysctl -n hw.ncpu`
  TARCMD=gtar
fi

PREREQ_NOTFOUND=
for i in git $MAKECMD $TARCMD; do

  T=`command -v "$i" 2>/dev/null`

  if [ "$T" = "" ]; then

    echo "[-] Error: '$i' not found. Run 'sudo apt-get install $i' or similar."
    PREREQ_NOTFOUND=1

  fi

done

test -z "$CC" && export CC=cc

if echo "$CC" | grep -qF /afl-; then

  echo "[-] Error: do not use afl-gcc or afl-clang to compile this tool."
  PREREQ_NOTFOUND=1

fi

if [ "$PREREQ_NOTFOUND" = "1" ]; then
  exit 1
fi

echo "[+] All checks passed!"

echo "[*] Making sure json-c is checked out"

git status 1>/dev/null 2>/dev/null
if [ $? -eq 0 ]; then
  echo "[*] initializing json-c submodule"
  git submodule init || exit 1
  git submodule update ./json-c 2>/dev/null # ignore errors
else
  echo "[*] cloning json-c"
  test -d json-c || {
    CNT=1
    while [ '!' -d json-c -a "$CNT" -lt 4 ]; do
      echo "Trying to clone json-c (attempt $CNT/3)"
      git clone "$JSONC_REPO" 
      CNT=`expr "$CNT" + 1`
    done
  }
fi

test -d json-c || { echo "[-] not checked out, please install git or check your internet connection." ; exit 1 ; }
echo "[+] Got json-c."

test -e json-c/.libs/libjson-c.a || {
  cd "json-c" || exit 1
  echo "[*] Checking out $JSONC_VERSION"
  sh -c 'git stash && git stash drop' 1>/dev/null 2>/dev/null
  git checkout "$JSONC_VERSION" || exit 1
  sh autogen.sh || exit 1
  export CFLAGS=-fPIC
  ./configure --disable-shared || exit 1
  make || exit 1
  cd ..
}

echo
echo
echo "[+] Json-c successfully prepared!"
echo "[+] Builing gramatron now."
$CC -O3 -g -fPIC -Wno-unused-result -Wl,--allow-multiple-definition -I../../include -o gramatron.so -shared -I. -I/prg/dev/include gramfuzz.c gramfuzz-helpers.c gramfuzz-mutators.c gramfuzz-util.c hashmap.c ../../src/afl-performance.o json-c/.libs/libjson-c.a || exit 1
echo
echo "[+] gramatron successfully built!"
