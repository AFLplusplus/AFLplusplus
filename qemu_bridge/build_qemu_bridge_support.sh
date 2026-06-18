#!/bin/sh

export PATH="/usr/bin:$PATH"

test -f ../config.h || { echo "[-] ../config.h not found, build AFL++ first"; exit 1; }
test -f ../afl-showmap || { echo "[-] ../afl-showmap not found, build AFL++ first"; exit 1; }

VERSION=$(cat ./QEMU_BRIDGE_VERSION)
test -n "$VERSION" || { echo "QEMU_BRIDGE_VERSION is empty"; exit 1; }

if [ -z "$NO_CHECKOUT" ]; then
  echo "[*] Making sure qemu-libafl-bridge is checked out"
  git status 1>/dev/null 2>/dev/null
  if [ $? -eq 0 ]; then
    echo "[*] initializing qemu-libafl-bridge submodule"
    git submodule init qemu-libafl-bridge 2>/dev/null
    git submodule update qemu-libafl-bridge 2>/dev/null
  else
    echo "[*] cloning qemu-libafl-bridge"
    test -d qemu-libafl-bridge/.git || {
      CNT=1
      while [ '!' -d qemu-libafl-bridge/.git -a "$CNT" -lt 4 ]; do
        echo "Trying to clone qemu-libafl-bridge (attempt $CNT/3)"
        git clone https://github.com/AFLplusplus/qemu-libafl-bridge
        CNT=`expr "$CNT" + 1`
      done
    }
  fi
  test -e qemu-libafl-bridge/.git || { echo "[-] Not checked out, please install git or check your internet connection."; exit 1; }
  cur=$(cd qemu-libafl-bridge && git rev-parse HEAD 2>/dev/null)
  dirty=$(cd qemu-libafl-bridge && git status --porcelain 2>/dev/null)
  if [ "$cur" != "$VERSION" ] && [ -z "$dirty" ]; then
    ( cd qemu-libafl-bridge && git checkout "$VERSION" ) || exit 1
  elif [ -n "$dirty" ] && [ "$cur" != "$VERSION" ]; then
    echo "[!] bridge has local modifications and HEAD ($cur) != pin ($VERSION); skipping auto-checkout. Use update_ref.sh to bump deliberately."
  fi
fi

AFL_LINK=qemu-libafl-bridge/libafl/afl
if [ -L "$AFL_LINK" ] || [ -e "$AFL_LINK" ]; then
  rm -rf "$AFL_LINK"
fi

mkdir -p libaflqemubridge/imported || exit 1
cp -f ../include/config.h libaflqemubridge/imported/ || exit 1
cp -f ../include/types.h libaflqemubridge/imported/ || exit 1
cp -f ../include/cmplog.h libaflqemubridge/imported/ || exit 1
cp -f ../include/snapshot-inl.h libaflqemubridge/imported/ || exit 1

test "$CPU_TARGET" = "" && CPU_TARGET="$(uname -m)"
test "$CPU_TARGET" = "i686" && CPU_TARGET="i386"
test "$CPU_TARGET" = "arm64v8" && CPU_TARGET="aarch64"
echo "$CPU_TARGET" | grep -q arm && test "$CPU_TARGET" != "aarch64" && CPU_TARGET="arm"

cd qemu-libafl-bridge || exit 1
CONF="--target-list=${CPU_TARGET}-linux-user --disable-docs --afl"
test "$STATIC" = "1" && CONF="$CONF --static --disable-pie"
test "$DEBUG"  = "1" && CONF="$CONF --enable-debug"
test -n "$HOST" && CONF="$CONF --cross-prefix=${HOST}-"
test -x /usr/bin/python3 && CONF="$CONF --python=/usr/bin/python3"
./configure $CONF || exit 1
ninja -C build "qemu-${CPU_TARGET}" || exit 1
cd ..
cp -f "qemu-libafl-bridge/build/qemu-${CPU_TARGET}" ../afl-qemu-bridge || exit 1

echo "afl-qemu-bridge built: $(file ../afl-qemu-bridge | cut -d: -f2-)"

make -C libqasan clean >/dev/null 2>&1
if make -C libqasan; then
  echo "libqasan built: $(file ../libqasan.so | cut -d: -f2-)"
else
  echo "[!] libqasan build failed"
fi

ORIG_CROSS="$CROSS"

if [ "$ORIG_CROSS" = "" ]; then
  CROSS=$CPU_TARGET-linux-gnu-gcc
  if ! command -v "$CROSS" > /dev/null; then
    CROSS=$CPU_TARGET-pc-linux-gnu-gcc
  fi
  if ! command -v "$CROSS" > /dev/null && [ "$CPU_TARGET" = "i386" ]; then
    CROSS=i686-linux-gnu-gcc
    if ! command -v "$CROSS" > /dev/null; then
      CROSS=i686-pc-linux-gnu-gcc
    fi
    if ! command -v "$CROSS" > /dev/null && [ "$(uname -m)" = "x86_64" ]; then
      test "$CC" = "" && CC="gcc"
      CROSS="$CC"
      CROSS_FLAGS=-m32
    fi
  fi
fi

if ! command -v "$CROSS" > /dev/null; then
  if [ "$CPU_TARGET" = "$(uname -m)" ] || [ "$CPU_TARGET" = "i386" ]; then
    echo "[+] Building libcompcov ..."
    make -C libcompcov clean >/dev/null 2>&1
    make -C libcompcov && echo "[+] libcompcov ready"
    echo "[+] Building unsigaction ..."
    make -C unsigaction clean >/dev/null 2>&1
    make -C unsigaction && echo "[+] unsigaction ready"
    echo "[+] Building fastexit ..."
    make -C fastexit clean >/dev/null 2>&1
    make -C fastexit && echo "[+] fastexit ready"
  else
    echo "[!] Cross compiler $CROSS could not be found, cannot compile companion libs"
  fi
else
  echo "[+] Building libcompcov ..."
  make -C libcompcov clean >/dev/null 2>&1
  make -C libcompcov CC="$CROSS $CROSS_FLAGS" && echo "[+] libcompcov ready"
  echo "[+] Building unsigaction ..."
  make -C unsigaction clean >/dev/null 2>&1
  make -C unsigaction CC="$CROSS $CROSS_FLAGS" && echo "[+] unsigaction ready"
  echo "[+] Building fastexit ..."
  make -C fastexit clean >/dev/null 2>&1
  make -C fastexit CC="$CROSS $CROSS_FLAGS" && echo "[+] fastexit ready"
fi

echo "[+] qemu_bridge build complete"
