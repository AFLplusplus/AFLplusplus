#!/bin/sh
#
# american fuzzy lop++ - unicorn mode build script
# ------------------------------------------------
#
# Originally written by Nathan Voss <njvoss99@gmail.com>
#
# Adapted from code by Andrew Griffiths <agriffiths@google.com> and
#                      Michal Zalewski
#
# Adapted for AFLplusplus by Dominik Maier <mail@dmnk.co>
#
# CompareCoverage and NeverZero counters by Andrea Fioraldi
#                                <andreafioraldi@gmail.com>
#
# Copyright 2017 Battelle Memorial Institute. All rights reserved.
# Copyright 2019-2022 AFLplusplus Project. All rights reserved.
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

GRAMMAR_VERSION="$(cat ./GRAMMAR_VERSION)"
GRAMMAR_REPO="https://github.com/AFLplusplus/grammar-mutator"

echo "================================================="
echo "Grammar Mutator build script"
echo "================================================="
echo

echo "[*] Performing basic sanity checks..."

PLT=`uname -s`

if [ ! -f "../../config.h" ]; then

  echo "[-] Error: key files not found - wrong working directory?"
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

if echo "$CC" | grep -qF /afl-; then

  echo "[-] Error: do not use afl-gcc or afl-clang to compile this tool."
  PREREQ_NOTFOUND=1

fi

if [ "$PREREQ_NOTFOUND" = "1" ]; then
  exit 1
fi

echo "[+] All checks passed!"

echo "[*] Making sure grammar mutator is checked out"

git status 1>/dev/null 2>/dev/null
if [ $? -eq 0 ]; then
  echo "[*] initializing grammar mutator submodule"
  git submodule init || exit 1
  git submodule update ./grammar_mutator 2>/dev/null # ignore errors
else
  echo "[*] cloning grammar mutator"
  test -d grammar_mutator/.git || {
    CNT=1
    while [ '!' -d grammar_mutator/.git -a "$CNT" -lt 4 ]; do
      echo "Trying to clone grammar_mutator (attempt $CNT/3)"
      git clone "$GRAMMAR_REPO" 
      CNT=`expr "$CNT" + 1`
    done
  }
fi

test -f grammar_mutator/.git || { echo "[-] not checked out, please install git or check your internet connection." ; exit 1 ; }
echo "[+] Got grammar mutator."

cd "grammar_mutator" || exit 1
echo "[*] Checking out $GRAMMAR_VERSION"
git pull >/dev/null 2>&1
sh -c 'git stash && git stash drop' 1>/dev/null 2>/dev/null
git checkout "$GRAMMAR_VERSION" || exit 1
echo "[*] Downloading antlr..."
wget -c https://www.antlr.org/download/antlr-4.8-complete.jar
cd ..

echo
echo
echo "[+] All successfully prepared!"
echo "[!] To build for your grammar just do:"
echo "      cd grammar_mutator"
echo "      make GRAMMAR_FILE=/path/to/your/grammar"
echo "[+] You will find a JSON and RUBY grammar in grammar_mutator/grammars to play with."
echo
