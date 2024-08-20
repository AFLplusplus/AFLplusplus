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
# Copyright 2019-2024 AFLplusplus Project. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   https://www.apache.org/licenses/LICENSE-2.0
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

UNICORNAFL_VERSION="$(cat ./UNICORNAFL_VERSION)"

echo "================================================="
echo "UnicornAFL build script"
echo "================================================="
echo

echo "[*] Performing basic sanity checks..."

PLT=`uname -s`

if [ ! "$PLT" = "Linux" ] && [ ! "$PLT" = "Darwin" ] && [ ! "$PLT" = "FreeBSD" ] && [ ! "$PLT" = "NetBSD" ] && [ ! "$PLT" = "OpenBSD" ] && [ ! "$PLT" = "DragonFly" ]; then

  echo "[-] Error: Unicorn instrumentation is unsupported on $PLT."
  exit 1

fi

if [ ! -f "../config.h" ]; then

  echo "[-] Error: key files not found - wrong working directory?"
  exit 1

fi

if [ ! -f "../afl-showmap" ]; then

  echo "[-] Error: ../afl-showmap not found - compile AFL first!"
  exit 1

fi

PYTHONBIN=`command -v python3 || command -v python || command -v python2 || echo python3`
MAKECMD=make
TARCMD=tar

if [ "$PLT" = "Linux" ]; then
  MUSL=`ldd --version 2>&1 | head -n 1 | cut -f 1 -d " "`
  if [ "musl" = $MUSL ]; then
  	echo "[-] Error: Unicorn instrumentation is unsupported with the musl's libc."
  	exit 1
  fi
  CORES=`nproc`
fi

if [ "$PLT" = "Darwin" ]; then
  CORES=`sysctl -n hw.ncpu`
  TARCMD=tar
fi

if [ "$PLT" = "FreeBSD" ]; then
  MAKECMD=gmake
  CORES=`sysctl -n hw.ncpu`
  TARCMD=gtar
fi

if [ "$PLT" = "DragonFly" ]; then
  MAKECMD=gmake
  CORES=`sysctl -n hw.ncpu`
  TARCMD=tar
fi

if [ "$PLT" = "NetBSD" ] || [ "$PLT" = "OpenBSD" ]; then
  MAKECMD=gmake
  CORES=`sysctl -n hw.ncpu`
  TARCMD=gtar
fi

PREREQ_NOTFOUND=
for i in $PYTHONBIN automake autoconf git $MAKECMD $TARCMD; do

  T=`command -v "$i" 2>/dev/null`

  if [ "$T" = "" ]; then

    echo "[-] Error: '$i' not found. Run 'sudo apt-get install $i' or similar."
    PREREQ_NOTFOUND=1

  fi

done

# some python version should be available now
PYTHONS="`command -v python3` `command -v python` `command -v python2`"
PIP_FOUND=0
for PYTHON in $PYTHONS ; do

  if $PYTHON -c "import pip" ; then
    if $PYTHON -c "import wheel" ; then

      PIP_FOUND=1
      PYTHONBIN=$PYTHON
      break

    fi
  fi

done
if [ "0" = $PIP_FOUND ]; then

  echo "[-] Error: Python pip or python wheel not found. Run 'sudo apt-get install python3-pip', or run '$PYTHONBIN -m ensurepip', or create a virtualenv, or ... - and 'pip3 install wheel'"
  PREREQ_NOTFOUND=1

fi

if echo "$CC" | grep -qF /afl-; then

  echo "[-] Error: do not use afl-gcc or afl-clang to compile this tool."
  PREREQ_NOTFOUND=1

fi

if [ "$PREREQ_NOTFOUND" = "1" ]; then
  exit 1
fi

unset CFLAGS

echo "[+] All checks passed!"

echo "[*] Making sure unicornafl is checked out"

git status 1>/dev/null 2>/dev/null
if [ $? -eq 0 ]; then
  echo "[*] initializing unicornafl submodule"
  git submodule init || exit 1
  git submodule update ./unicornafl 2>/dev/null # ignore errors
  git submodule sync ./unicornafl 2>/dev/null # ignore errors
else
  echo "[*] cloning unicornafl"
  test -d unicornafl/.git || {
    CNT=1
    while [ '!' -d unicornafl/.git -a "$CNT" -lt 4 ]; do
      echo "Trying to clone unicornafl (attempt $CNT/3)"
      git clone https://github.com/AFLplusplus/unicornafl
      CNT=`expr "$CNT" + 1`
    done
  }
fi

test -e unicornafl/.git || { echo "[-] not checked out, please install git or check your internet connection." ; exit 1 ; }
echo "[+] Got unicornafl."

cd "unicornafl" || exit 1
echo "[*] Checking out $UNICORNAFL_VERSION"
git pull
sh -c 'git stash && git stash drop' 1>/dev/null 2>/dev/null
git checkout "$UNICORNAFL_VERSION" || exit 1

echo "[*] making sure AFL++ header files match"
cp "../../include/config.h" "./include" || exit 1

echo "[*] Configuring Unicorn build..."

echo "[+] Configuration complete."

echo "[*] Attempting to build unicornafl (fingers crossed!)..."

$MAKECMD clean  # make doesn't seem to work for unicorn
# Fixed to 1 core for now as there is a race condition in the makefile
$MAKECMD -j1 || exit 1

echo "[+] Build process successful!"

echo "[*] Installing Unicorn python bindings..."
XOPT=
#$PYTHONBIN -m pip install --help 2>/dev/null | grep -q break-system-packages && XOPT=--break-system-packages
cd unicorn/bindings/python || exit 1
if [ -z "$VIRTUAL_ENV" ]; then
  echo "[*] Info: Installing python unicornafl using --user"
  THREADS=$CORES $PYTHONBIN setup.py install --user $XOPT --force || exit 1
else
  echo "[*] Info: Installing python unicornafl to virtualenv: $VIRTUAL_ENV"
  THREADS=$CORES $PYTHONBIN setup.py install --force || exit 1
fi
cd ../../../
echo "[*] Installing Unicornafl python bindings..."
cd bindings/python || exit 1
if [ -z "$VIRTUAL_ENV" ]; then
  echo "[*] Info: Installing python unicornafl using --user"
  THREADS=$CORES $PYTHONBIN setup.py install --user $XOPT --force || exit 1
else
  echo "[*] Info: Installing python unicornafl to virtualenv: $VIRTUAL_ENV"
  THREADS=$CORES $PYTHONBIN setup.py install --force || exit 1
fi
echo '[*] If needed, you can (re)install the bindings in `./unicornafl/bindings/python` using `python setup.py install --force .`'

cd ../../ || exit 1

echo "[*] Unicornafl bindings installed successfully."

# Compile the sample, run it, verify that it works!
echo "[*] Testing unicornafl python functionality by running a sample test harness"

cd ../samples/python_simple || echo "Cannot cd"

# Run afl-showmap on the sample application. If anything comes out then it must have worked!
unset AFL_INST_RATIO
# pwd; echo "echo 0 | ../../../afl-showmap -U -m none -t 2000 -o ./.test-instr0 -- $PYTHONBIN ./simple_test_harness.py ./sample_inputs/sample1.bin"
echo 0 | ../../../afl-showmap -U -m none -t 2000 -o ./.test-instr0 -- $PYTHONBIN ./simple_test_harness.py ./sample_inputs/sample1.bin >/dev/null 2>&1 || echo "Showmap"

if [ -s ./.test-instr0 ]
then

  echo "[+] Instrumentation tests passed. "
  echo '[+] Make sure to adapt older scripts to `import unicornafl` and use `uc.afl_forkserver_start`'
  echo '    or `uc.afl_fuzz` to kick off fuzzing.'
  echo "[+] All set, you can now use Unicorn mode (-U) in afl-fuzz!"
  RETVAL=0

else

  echo "[-] Error: Unicorn mode doesn't seem to work!"
  RETVAL=1

fi

rm -f ./.test-instr0

exit $RETVAL
