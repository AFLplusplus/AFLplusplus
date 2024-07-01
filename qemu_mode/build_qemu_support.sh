#!/bin/sh
#
# american fuzzy lop++ - QEMU build script
# --------------------------------------
#
# Originally written by Andrew Griffiths <agriffiths@google.com> and
#                       Michal Zalewski
#
# TCG instrumentation and block chaining support by Andrea Biondo
#                                    <andrea.biondo965@gmail.com>
#
# QEMU 5+ port, TCG thread-safety, CompareCoverage and NeverZero
# counters by Andrea Fioraldi <andreafioraldi@gmail.com>
#
# Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
# Copyright 2019-2024 AFLplusplus Project. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# This script downloads, patches, and builds a version of QEMU with
# minor tweaks to allow non-instrumented binaries to be run under
# afl-fuzz. 
#
# The modifications reside in patches/*. The standalone QEMU binary
# will be written to ../afl-qemu-trace.
#

QEMUAFL_VERSION="$(cat ./QEMUAFL_VERSION)"

echo "================================================="
echo "           QemuAFL build script"
echo "================================================="
echo

echo "[*] Performing basic sanity checks..."

if [ ! "`uname -s`" = "Linux" ]; then

  echo "[-] Error: QEMU instrumentation is supported only on Linux."
  exit 0

fi

if [ ! -f "../config.h" ]; then

  echo "[-] Error: key files not found - wrong working directory?"
  exit 1

fi

if [ ! -f "../afl-showmap" ]; then

  echo "[-] Error: ../afl-showmap not found - compile AFL first!"
  exit 1

fi

if echo "$CC" | grep -qF /afl-; then

  echo "[-] Error: do not use afl-gcc or afl-clang to compile this tool."
  exit 1

fi

echo "[+] All checks passed!"

echo "[*] Making sure qemuafl is checked out"

git status 1>/dev/null 2>/dev/null
if [ $? -eq 0 ]; then
  echo "[*] initializing qemuafl submodule"
  git submodule init || exit 1
  git submodule update ./qemuafl 2>/dev/null # ignore errors
else
  echo "[*] cloning qemuafl"
  test -d qemuafl/.git || {
    CNT=1
    while [ '!' -d qemuafl/.git -a "$CNT" -lt 4 ]; do
      echo "Trying to clone qemuafl (attempt $CNT/3)"
      git clone --depth 1 https://github.com/AFLplusplus/qemuafl
      CNT=`expr "$CNT" + 1`
    done
  }
fi

test -e qemuafl/.git || { echo "[-] Not checked out, please install git or check your internet connection." ; exit 1 ; }
echo "[+] Got qemuafl."

cd "qemuafl" || exit 1
if [ -n "$NO_CHECKOUT" ]; then
  echo "[*] Skipping checkout to $QEMUAFL_VERSION"
else
  echo "[*] Checking out $QEMUAFL_VERSION"
  sh -c 'git stash' 1>/dev/null 2>/dev/null
  git pull
  git checkout "$QEMUAFL_VERSION" || echo Warning: could not check out to commit $QEMUAFL_VERSION
fi

echo "[*] Making sure imported headers matches"
cp "../../include/config.h" "./qemuafl/imported/" || exit 1
cp "../../include/cmplog.h" "./qemuafl/imported/" || exit 1
cp "../../include/snapshot-inl.h" "./qemuafl/imported/" || exit 1
cp "../../include/types.h" "./qemuafl/imported/" || exit 1

if [ -n "$HOST" ]; then
  echo "[+] Configuring host architecture to $HOST..."
  CROSS_PREFIX=$HOST-
else
  CROSS_PREFIX=
fi

echo "[*] Configuring QEMU for $CPU_TARGET..."

ORIG_CPU_TARGET="$CPU_TARGET"

if [ "$ORIG_CPU_TARGET" = "" ]; then
  CPU_TARGET="`uname -m`"
  test "$CPU_TARGET" = "i686" && CPU_TARGET="i386"
  test "$CPU_TARGET" = "arm64v8" && CPU_TARGET="aarch64"
  case "$CPU_TARGET" in 
    *arm*)
      CPU_TARGET="arm"
      ;;
  esac
fi

echo "Building for CPU target $CPU_TARGET"

# --enable-pie seems to give a couple of exec's a second performance
# improvement, much to my surprise. Not sure how universal this is..
# --enable-plugins allows loading TCG plugins at runtime, for example to obtain
# coverage information, and does not seem to negatively impact performance
QEMU_CONF_FLAGS=" \
  --enable-plugins \
  --audio-drv-list= \
  --disable-blobs \
  --disable-bochs \
  --disable-brlapi \
  --disable-bsd-user \
  --disable-bzip2 \
  --disable-cap-ng \
  --disable-cloop \
  --disable-curl \
  --disable-curses \
  --disable-dmg \
  --disable-fdt \
  --disable-gcrypt \
  --disable-glusterfs \
  --disable-gnutls \
  --disable-gtk \
  --disable-guest-agent \
  --disable-iconv \
  --disable-libiscsi \
  --disable-libnfs \
  --disable-libssh \
  --disable-libusb \
  --disable-linux-aio \
  --disable-live-block-migration \
  --disable-lzo \
  --disable-nettle \
  --disable-numa \
  --disable-opengl \
  --disable-parallels \
  --disable-qcow1 \
  --disable-qed \
  --disable-rbd \
  --disable-rdma \
  --disable-replication \
  --disable-sdl \
  --disable-seccomp \
  --disable-sheepdog \
  --disable-smartcard \
  --disable-snappy \
  --disable-spice \
  --disable-system \
  --disable-tools \
  --disable-tpm \
  --disable-usb-redir \
  --disable-vde \
  --disable-vdi \
  --disable-vhost-crypto \
  --disable-vhost-kernel \
  --disable-vhost-net \
  --disable-vhost-scsi \
  --disable-vhost-user \
  --disable-vhost-vdpa \
  --disable-vhost-vsock \
  --disable-virglrenderer \
  --disable-virtfs \
  --disable-vnc \
  --disable-vnc-jpeg \
  --disable-vnc-png \
  --disable-vnc-sasl \
  --disable-vte \
  --disable-vvfat \
  --disable-xen \
  --disable-xen-pci-passthrough \
  --disable-xfsctl \
  --target-list="${CPU_TARGET}-linux-user" \
  --without-default-devices \
  --extra-cflags=-Wno-int-conversion \
  --disable-werror \
  "

if [ -n "${CROSS_PREFIX}" ]; then

  QEMU_CONF_FLAGS="$QEMU_CONF_FLAGS --cross-prefix=$CROSS_PREFIX"

fi

if [ "$STATIC" = "1" ]; then

  echo Building STATIC binary

  # static PIE causes https://github.com/AFLplusplus/AFLplusplus/issues/892
  # plugin support requires dynamic linking
  QEMU_CONF_FLAGS="$QEMU_CONF_FLAGS \
    --static --disable-pie \
    --disable-plugins \
    --extra-cflags=-DAFL_QEMU_STATIC_BUILD=1 \
    "

else

  QEMU_CONF_FLAGS="${QEMU_CONF_FLAGS} --enable-pie "

fi

if [ "$DEBUG" = "1" ]; then

  echo Building DEBUG binary

  # --enable-gcov might go here but incurs a mesonbuild error on meson
  # versions prior to 0.56:
  # https://github.com/qemu/meson/commit/903d5dd8a7dc1d6f8bef79e66d6ebc07c
  QEMU_CONF_FLAGS="$QEMU_CONF_FLAGS \
    --disable-strip \
    --enable-debug \
    --enable-debug-info \
    --enable-debug-mutex \
    --enable-debug-stack-usage \
    --enable-debug-tcg \
    --enable-qom-cast-debug \
    "

else

  QEMU_CONF_FLAGS="$QEMU_CONF_FLAGS \
    --disable-debug-info \
    --disable-debug-mutex \
    --disable-debug-tcg \
    --disable-qom-cast-debug \
    --disable-stack-protector \
    --disable-docs \
    "

fi

if [ "$PROFILING" = "1" ]; then

  echo Building PROFILED binary

  QEMU_CONF_FLAGS="$QEMU_CONF_FLAGS \
    --enable-gprof \
    --enable-profiler \
    "

fi

# shellcheck disable=SC2086
./configure $QEMU_CONF_FLAGS || exit 1

echo "[+] Configuration complete."

echo "[*] Attempting to build QEMU (fingers crossed!)..."

make -j$(nproc) || exit 1

echo "[+] Build process successful!"

echo "[*] Copying binary..."

cp -f "build/${CPU_TARGET}-linux-user/qemu-${CPU_TARGET}" "../../afl-qemu-trace" || exit 1

cd ..
ls -l ../afl-qemu-trace || exit 1

echo "[+] Successfully created '../afl-qemu-trace'."

if [ "$ORIG_CPU_TARGET" = "" ]; then

  echo "[*] Testing the build..."

  cd ..

  make >/dev/null || exit 1

  cc test-instr.c -o test-instr || exit 1

  unset AFL_INST_RATIO
  export ASAN_OPTIONS=detect_leaks=0

  echo "[*] Comparing two afl-showmap -Q outputs..."
  echo 0 | ./afl-showmap -m none -Q -q -o .test-instr0 ./test-instr || exit 1
  echo 1 | ./afl-showmap -m none -Q -q -o .test-instr1 ./test-instr || exit 1

  rm -f test-instr

  cmp -s .test-instr0 .test-instr1
  DR="$?"

  rm -f .test-instr0 .test-instr1

  if [ "$DR" = "0" ]; then

    echo "[-] Error: afl-qemu-trace instrumentation doesn't seem to work!"
    exit 1

  fi

  echo "[+] Instrumentation tests passed. "
  echo "[+] All set, you can now use the -Q mode in afl-fuzz!"

  cd qemu_mode || exit 1

else

  echo "[!] Note: can't test instrumentation when CPU_TARGET set."
  echo "[+] All set, you can now (hopefully) use the -Q mode in afl-fuzz!"

fi

ORIG_CROSS="$CROSS"

if [ "$ORIG_CROSS" = "" ]; then
  CROSS=$CPU_TARGET-linux-gnu-gcc
  if ! command -v "$CROSS" > /dev/null
  then # works on Arch Linux
    CROSS=$CPU_TARGET-pc-linux-gnu-gcc
  fi
  if ! command -v "$CROSS" > /dev/null && [ "$CPU_TARGET" = "i386" ]
  then
    CROSS=i686-linux-gnu-gcc
    if ! command -v "$CROSS" > /dev/null
    then # works on Arch Linux
      CROSS=i686-pc-linux-gnu-gcc
    fi
    if ! command -v "$CROSS" > /dev/null && [ "`uname -m`" = "x86_64" ]
    then # set -m32
      test "$CC" = "" && CC="gcc"
      CROSS="$CC"
      CROSS_FLAGS=-m32
    fi
  fi
fi

if ! command -v "$CROSS" > /dev/null ; then
  if [ "$CPU_TARGET" = "$(uname -m)" ] ; then
    echo "[+] Building AFL++ qemu support libraries with CC=$CC"
    echo "[+] Building libcompcov ..."
    make -C libcompcov && echo "[+] libcompcov ready"
    echo "[+] Building unsigaction ..."
    make -C unsigaction && echo "[+] unsigaction ready"
    echo "[+] Building fastexit ..."
    make -C fastexit && echo "[+] fastexit ready"
    echo "[+] Building libqasan ..."
    make -C libqasan && echo "[+] libqasan ready"
    echo "[+] Building qemu libfuzzer helpers ..."
    make -C ../utils/aflpp_driver
  else
    echo "[!] Cross compiler $CROSS could not be found, cannot compile libcompcov libqasan and unsigaction"
  fi
else
  echo "[+] Building AFL++ qemu support libraries with CC=\"$CROSS $CROSS_FLAGS\""
  echo "[+] Building libcompcov ..."
  make -C libcompcov CC="$CROSS $CROSS_FLAGS" && echo "[+] libcompcov ready"
  echo "[+] Building unsigaction ..."
  make -C unsigaction CC="$CROSS $CROSS_FLAGS" && echo "[+] unsigaction ready"
  echo "[+] Building fastexit ..."
  make -C fastexit CC="$CROSS $CROSS_FLAGS" && echo "[+] fastexit ready"
  echo "[+] Building libqasan ..."
  make -C libqasan CC="$CROSS $CROSS_FLAGS" && echo "[+] libqasan ready"
fi

#### Hooking support
if [ "$ENABLE_HOOKING" = "1" ];then
  echo "[+] ENABLING HOOKING"
  set -e
  cd ./hooking_bridge || exit 255
  mkdir -p ./build
  echo "[+] Hook compiler = $CROSS"
  make CC="$CROSS $CROSS_FLAGS" GLIB_H="$GLIB_H" GLIB_CONFIG_H="$GLIB_CONFIG_H"
  set +e
  cd ..
fi
#### End of hooking support

echo "[+] All done for qemu_mode, enjoy!"

exit 0
