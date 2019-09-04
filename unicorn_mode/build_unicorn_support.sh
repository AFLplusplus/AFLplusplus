#!/bin/sh
#
# american fuzzy lop++ - unicorn mode build script
# ------------------------------------------------
#
# Originally written by Nathan Voss <njvoss99@gmail.com>
# 
# Adapted from code by Andrew Griffiths <agriffiths@google.com> and
#                      Michal Zalewski <lcamtuf@google.com>
#
# Adapted for AFLplusplus by Dominik Maier <mail@dmnk.co>
#
# CompareCoverage and NeverZero counters by Andrea Fioraldi
#                                <andreafioraldi@gmail.com>
#
# Copyright 2017 Battelle Memorial Institute. All rights reserved.
# Copyright 2019 AFLplusplus Project. All rights reserved.
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

UNICORN_URL="https://github.com/unicorn-engine/unicorn/archive/24f55a7973278f20f0de21b904851d99d4716263.tar.gz"
UNICORN_SHA384="7180d47ca52c99b4c073a343a2ead91da1a829fdc3809f3ceada5d872e162962eab98873a8bc7971449d5f34f41fdb93"

echo "================================================="
echo "Unicorn-AFL build script"
echo "================================================="
echo

echo "[*] Performing basic sanity checks..."

if [ ! "`uname -s`" = "Linux" ]; then

  echo "[-] Error: Unicorn instrumentation is supported only on Linux."
  exit 1
  
fi

if [ ! -f "patches/afl-unicorn-cpu-inl.h" -o ! -f "../config.h" ]; then

  echo "[-] Error: key files not found - wrong working directory?"
  exit 1

fi

if [ ! -f "../afl-showmap" ]; then

  echo "[-] Error: ../afl-showmap not found - compile AFL first!"
  exit 1

fi

for i in wget python automake autoconf sha384sum; do

  T=`which "$i" 2>/dev/null`

  if [ "$T" = "" ]; then

    echo "[-] Error: '$i' not found. Run 'sudo apt-get install $i'."
    exit 1

  fi

done

if ! which easy_install > /dev/null; then

  # work around for unusual installs
  if [ '!' -e /usr/lib/python2.7/dist-packages/easy_install.py ]; then

    echo "[-] Error: Python setup-tools not found. Run 'sudo apt-get install python-setuptools'."
    exit 1

  fi

fi

if echo "$CC" | grep -qF /afl-; then

  echo "[-] Error: do not use afl-gcc or afl-clang to compile this tool."
  exit 1

fi

echo "[+] All checks passed!"

ARCHIVE="`basename -- "$UNICORN_URL"`"

CKSUM=`sha384sum -- "$ARCHIVE" 2>/dev/null | cut -d' ' -f1`

if [ ! "$CKSUM" = "$UNICORN_SHA384" ]; then

  echo "[*] Downloading Unicorn v1.0.1 from the web..."
  rm -f "$ARCHIVE"
  wget -O "$ARCHIVE" -- "$UNICORN_URL" || exit 1

  CKSUM=`sha384sum -- "$ARCHIVE" 2>/dev/null | cut -d' ' -f1`

fi

if [ "$CKSUM" = "$UNICORN_SHA384" ]; then

  echo "[+] Cryptographic signature on $ARCHIVE checks out."

else

  echo "[-] Error: signature mismatch on $ARCHIVE (perhaps download error?)."
  exit 1

fi

echo "[*] Uncompressing archive (this will take a while)..."

rm -rf "unicorn" || exit 1
mkdir "unicorn" || exit 1
tar xzf "$ARCHIVE" -C ./unicorn --strip-components=1 || exit 1

echo "[+] Unpacking successful."

#rm -rf "$ARCHIVE" || exit 1

echo "[*] Applying patches..."

cp patches/*.h unicorn || exit 1
patch -p1 --directory unicorn < patches/patches.diff || exit 1
patch -p1 --directory unicorn < patches/compcov.diff || exit 1

echo "[+] Patching done."

echo "[*] Configuring Unicorn build..."

cd "unicorn" || exit 1

echo "[+] Configuration complete."

echo "[*] Attempting to build Unicorn (fingers crossed!)..."

UNICORN_QEMU_FLAGS='--python=python2' make -j `nproc` || exit 1

echo "[+] Build process successful!"

echo "[*] Installing Unicorn python bindings..."
cd bindings/python || exit 1
if [ -z "$VIRTUAL_ENV" ]; then
  echo "[*] Info: Installing python unicorn using --user"
  python setup.py install --user || exit 1
else
  echo "[*] Info: Installing python unicorn to virtualenv: $VIRTUAL_ENV"
  python setup.py install || exit 1
fi
export LIBUNICORN_PATH='$(pwd)' # in theory, this allows to switch between afl-unicorn and unicorn so files.

cd ../../ || exit 1

echo "[+] Unicorn bindings installed successfully."

# Compile the sample, run it, verify that it works!
echo "[*] Testing unicorn-mode functionality by running a sample test harness under afl-unicorn"

cd ../samples/simple || exit 1

# Run afl-showmap on the sample application. If anything comes out then it must have worked!
unset AFL_INST_RATIO
echo 0 | ../../../afl-showmap -U -m none -q -o .test-instr0 -- python simple_test_harness.py ./sample_inputs/sample1.bin || exit 1

if [ -s .test-instr0 ]
then
  
  echo "[+] Instrumentation tests passed. "
  echo "[+] All set, you can now use Unicorn mode (-U) in afl-fuzz!"
  RETVAL=0

else

  echo "[-] Error: Unicorn mode doesn't seem to work!"
  RETVAL=1

fi

rm -f .test-instr0

exit $RETVAL
