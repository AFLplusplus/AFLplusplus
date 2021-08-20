#!/bin/sh
#
# american fuzzy lop++ - optimin build script
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
# This script builds the OptiMin corpus minimizer.

EVALMAXSAT_VERSION="$(cat ./EVALMAXSAT_VERSION)"
EVALMAXSAT_REPO="https://github.com/FlorentAvellaneda/EvalMaxSAT"

echo "================================================="
echo "OptiMin build script"
echo "================================================="
echo

echo "[*] Performing basic sanity checks..."

PLT=`uname -s`

if [ ! -f "../../config.h" ]; then

  echo "[-] Error: key files not found - wrong working directory?"
  exit 1

fi

LLVM_CONFIG="${LLVM_CONFIG:-llvm-config}"
CMAKECMD=cmake
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
for i in git $CMAKECMD $MAKECMD $TARCMD; do

  T=`command -v "$i" 2>/dev/null`

  if [ "$T" = "" ]; then

    echo "[-] Error: '$i' not found. Run 'sudo apt-get install $i' or similar."
    PREREQ_NOTFOUND=1

  fi

done

if echo "$CC" | grep -qF /afl-; then

  echo "[-] Error: do not use afl-gcc or afl-clang to compile this tool."
  PREREQ_NOTFOUND=1

fi

if [ "$PREREQ_NOTFOUND" = "1" ]; then
  exit 1
fi

echo "[+] All checks passed!"

echo "[*] Making sure EvalMaxSAT is checked out"

git status 1>/dev/null 2>/dev/null
if [ $? -eq 0 ]; then
  echo "[*] initializing EvalMaxSAT submodule"
  git submodule init || exit 1
  git submodule update ./EvalMaxSAT 2>/dev/null # ignore errors
else
  echo "[*] cloning EvalMaxSAT"
  test -d EvalMaxSAT || {
    CNT=1
    while [ '!' -d EvalMaxSAT -a "$CNT" -lt 4 ]; do
      echo "Trying to clone EvalMaxSAT (attempt $CNT/3)"
      git clone "$GRAMMAR_REPO"
      CNT=`expr "$CNT" + 1`
    done
  }
fi

test -d EvalMaxSAT || { echo "[-] not checked out, please install git or check your internet connection." ; exit 1 ; }
echo "[+] Got EvalMaxSAT."

cd "EvalMaxSAT" || exit 1
echo "[*] Checking out $EVALMAXSAT_VERSION"
sh -c 'git stash && git stash drop' 1>/dev/null 2>/dev/null
git checkout "$EVALMAXSAT_VERSION" || exit 1
cd ..

echo
echo
echo "[+] EvalMaxSAT successfully prepared!"
echo "[+] Building OptiMin now."
mkdir -p build
cd build || exit 1
cmake .. -DLLVM_DIR=`$LLVM_CONFIG --cmakedir` || exit 1
make -j$CORES || exit 1
cd ..
echo
cp -fv build/src/optimin . || exit 1
echo "[+] OptiMin successfully built!"
