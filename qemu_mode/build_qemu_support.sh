#!/bin/sh
#
# american fuzzy lop - QEMU build script
# --------------------------------------
#
# Originally written by Andrew Griffiths <agriffiths@google.com> and
#                       Michal Zalewski
#
# TCG instrumentation and block chaining support by Andrea Biondo
#                                    <andrea.biondo965@gmail.com>
#
# QEMU 3.1.1 port, TCG thread-safety, CompareCoverage and NeverZero
# counters by Andrea Fioraldi <andreafioraldi@gmail.com>
#
# Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
# Copyright 2019 AFLplusplus Project. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# This script downloads, patches, and builds a version of QEMU with
# minor tweaks to allow non-instrumented binaries to be run under
# afl-fuzz. 
#
# The modifications reside in patches/*. The standalone QEMU binary
# will be written to ../afl-qemu-trace.
#


VERSION="3.1.1"
QEMU_URL="http://download.qemu-project.org/qemu-${VERSION}.tar.xz"
QEMU_SHA384="28ff22ec4b8c957309460aa55d0b3188e971be1ea7dfebfb2ecc7903cd20cfebc2a7c97eedfcc7595f708357f1623f8b"

echo "================================================="
echo "AFL binary-only instrumentation QEMU build script"
echo "================================================="
echo

PLT=`uname -s`

echo "[*] Performing basic sanity checks..."

if [ ! "$PLT" = "Linux" ] && [ ! "$PLT" = "FreeBSD" ] && [ ! "$PLT" = "NetBSD" ] && [ ! "$PLT" = "OpenBSD" ]; then

  echo "[-] Error: QEMU instrumentation is not supported on $PLT."
  exit 1

fi

if [ ! -f "patches/afl-qemu-cpu-inl.h" -o ! -f "../config.h" ]; then

  echo "[-] Error: key files not found - wrong working directory?"
  exit 1

fi

if [ ! -f "../afl-showmap" ]; then

  echo "[-] Error: ../afl-showmap not found - compile AFL first!"
  exit 1

fi

ORIG_CPU_TARGET="$CPU_TARGET"

test "$CPU_TARGET" = "" && CPU_TARGET="`uname -m`"
test "$CPU_TARGET" = "amd64" && CPU_TARGET="x86_64"
test "$CPU_TARGET" = "i686" && CPU_TARGET="i386"

WGETCMD='wget'

if [ "$PLT" = "Linux" ]; then
	CKSUMCMD="sha384sum --"
	TARCMD='tar'
	TARGET="$CPU_TARGET-linux-user"
	OSCFGFLAGS='--enable-linux-user --disable-bsd-user'
	PYTHONBIN=python
	MAKECMD="make -j `nproc`"

	for i in libtool wget python automake autoconf sha384sum bison iconv; do

  	T=`which "$i" 2>/dev/null`

  	if [ "$T" = "" ]; then

    	echo "[-] Error: '$i' not found, please install first."
    	exit 1

  	fi

	done
fi

if [ "$PLT" = "FreeBSD" ]; then
	CKSUMCMD="shasum -a 384"
	TARCMD='gtar'
	TARGET="$CPU_TARGET-bsd-user"
	OSCFGFLAGS='--disable-linux-user --enable-bsd-user'
	PYTHONBIN=python2.7
	MAKECMD='gmake -j2'

	for i in libtool wget python2.7 automake autoconf gmake gtar bison iconv; do

  	T=`which "$i" 2>/dev/null`

  	if [ "$T" = "" ]; then

    	echo "[-] Error: '$i' not found, please install first."
    	exit 1

  	fi

	done
fi

if [ "$PLT" = "NetBSD" ] || [ "$PLT" = "OpenBSD" ]; then
	CKSUMCMD="cksum -a sha384 -q"
	TARCMD='gtar'
	TARGET="$CPU_TARGET-bsd-user"
	OSCFGFLAGS='--disable-linux-user --enable-bsd-user'
	PYTHONBIN=python2.7
	MAKECMD='gmake -j2'

	for i in libtool wget python2.7 automake autoconf gmake gtar bison iconv; do

  	T=`which "$i" 2>/dev/null`

  	if [ "$T" = "" ]; then

    	echo "[-] Error: '$i' not found, please install first."
    	exit 1

  	fi

	done
fi

if [ ! -d "/usr/include/glib-2.0/" -a ! -d "/usr/local/include/glib-2.0/" ]; then

  echo "[-] Error: devel version of 'glib2' not found, please install first."
  exit 1

fi

if echo "$CC" | grep -qF /afl-; then

  echo "[-] Error: do not use afl-gcc or afl-clang to compile this tool."
  exit 1

fi

echo "[+] All checks passed!"

ARCHIVE="`basename -- "$QEMU_URL"`"

CKSUM=`$CKSUMCMD -- "$ARCHIVE" 2>/dev/null | cut -d' ' -f1`

if [ ! "$CKSUM" = "$QEMU_SHA384" ]; then

  echo "[*] Downloading QEMU ${VERSION} from the web..."
  rm -f "$ARCHIVE"
  $WGETCMD -O "$ARCHIVE" -- "$QEMU_URL" || exit 1

  CKSUM=`$CKSUMCMD -- "$ARCHIVE" 2>/dev/null | cut -d' ' -f1`

fi

if [ "$CKSUM" = "$QEMU_SHA384" ]; then

  echo "[+] Cryptographic signature on $ARCHIVE checks out."

else

  echo "[-] Error: signature mismatch on $ARCHIVE (perhaps download error?), removing archive ..."
  rm -f "$ARCHIVE"
  exit 1

fi

echo "[*] Uncompressing archive (this will take a while)..."

rm -rf "qemu-${VERSION}" || exit 1
$TARCMD xf "$ARCHIVE" || exit 1

echo "[+] Unpacking successful."

if [ -n "$HOST" ]; then
  echo "[+] Configuring host architecture to $HOST..."
  CROSS_PREFIX=$HOST-
else
  CROSS_PREFIX=
fi

echo "[*] Configuring QEMU for $CPU_TARGET..."

cd qemu-$VERSION || exit 1

echo "[*] Applying patches..."

patch -p1 <../patches/elfload.diff || exit 1
patch -p1 <../patches/cpu-exec.diff || exit 1
patch -p1 <../patches/syscall.diff || exit 1
patch -p1 <../patches/translate-all.diff || exit 1
patch -p1 <../patches/tcg.diff || exit 1
patch -p1 <../patches/i386-translate.diff || exit 1
patch -p1 <../patches/arm-translate.diff || exit 1
patch -p1 <../patches/i386-ops_sse.diff || exit 1
patch -p1 <../patches/i386-fpu_helper.diff || exit 1
patch -p1 <../patches/softfloat.diff || exit 1

echo "[+] Patching done."

if [ "$STATIC" = "1" ]; then

  CFLAGS="-O3 -ggdb" ./configure --disable-guest-agent --disable-strip --disable-werror \
	  --disable-gcrypt --disable-debug-info --disable-debug-tcg --enable-docs --disable-tcg-interpreter \
	  --enable-attr --disable-brlapi --disable-linux-aio --disable-bzip2 --disable-bluez --disable-cap-ng \
	  --disable-curl --disable-fdt --disable-glusterfs --disable-gnutls --disable-nettle --disable-gtk \
	  --disable-rdma --disable-libiscsi --disable-vnc-jpeg --enable-kvm --disable-lzo --disable-curses \
	  --disable-libnfs --disable-numa --disable-opengl --disable-vnc-png --disable-rbd --disable-vnc-sasl \
	  --disable-sdl --disable-seccomp --disable-smartcard --disable-snappy --disable-spice --disable-libssh2 \
	  --disable-libusb --disable-usb-redir --disable-vde --disable-vhost-net --disable-virglrenderer \
	  --disable-virtfs --disable-vnc --disable-vte --disable-xen --disable-xen-pci-passthrough --disable-xfsctl \
	  $OSCFGFLAGS --disable-system --disable-blobs --disable-tools \
	  --target-list="${TARGET}" --static --disable-pie --cross-prefix=$CROSS_PREFIX --python=$PYTHONBIN || exit 1

else

  # --enable-pie seems to give a couple of exec's a second performance
  # improvement, much to my surprise. Not sure how universal this is..

  CFLAGS="-O3 -ggdb" ./configure --disable-system \
    $OSCFGFLAGS --disable-gtk --disable-sdl --disable-vnc \
    --target-list="${TARGET}" --enable-pie --enable-kvm $CROSS_PREFIX --python=$PYTHONBIN || exit 1

fi

echo "[+] Configuration complete."

echo "[*] Attempting to build QEMU (fingers crossed!)..."

$MAKECMD || exit 1

echo "[+] Build process successful!"

echo "[*] Copying binary..."

cp -f "${TARGET}/qemu-${CPU_TARGET}" "../../afl-qemu-trace" || exit 1

cd ..
ls -l ../afl-qemu-trace || exit 1

echo "[+] Successfully created '../afl-qemu-trace'."

if [ "$ORIG_CPU_TARGET" = "" ]; then

  echo "[*] Testing the build..."

  cd ..

  $MAKECMD >/dev/null || exit 1

  cc test-instr.c -o test-instr || exit 1

  unset AFL_INST_RATIO

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

if [ "$PLT" = "Linux" ]; then
	echo "[+] Building libcompcov ..."
	$MAKECMD -C libcompcov
fi

echo "[+] Building unsigaction ..."
$MAKECMD -C unsigaction
echo "[+] libcompcov ready"
echo "[+] All done for qemu_mode, enjoy!"

exit 0
