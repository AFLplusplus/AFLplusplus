#!/bin/bash

set -e

echo "================================================="
echo "           Nyx build script"
echo "================================================="
echo

echo "[*] Performing basic sanity checks..."

if [ "$CI" = "true" ]; then

  echo "[-] Error: nyx_mode cannot be tested in the Github CI, skipping ..."
  exit 0

fi


if [ -n "$NO_NYX" ]; then

  echo "[-] Error: the NO_NYX environment variable is set, please unset."
  exit 0

fi

if [ ! "$(uname -s)" = "Linux" ]; then

  echo "[-] Error: Nyx mode is only available on Linux."
  exit 0

fi

if [ ! "$(uname -m)" = "x86_64" ]; then

  echo "[-] Error: Nyx mode is only available on x86_64 (yet)."
  exit 0

fi

cargo help > /dev/null 2>&1 || {
   echo "[-] Error: Rust is not installed."
   exit 0
}

echo "[*] Making sure all Nyx is checked out"


if git status 1>/dev/null 2>&1; then

  set +e
  git submodule init
  echo "[*] initializing QEMU-Nyx submodule"
  git submodule update ./QEMU-Nyx 2>/dev/null # ignore errors
  echo "[*] initializing packer submodule"
  git submodule update ./packer 2>/dev/null # ignore errors
  echo "[*] initializing libnyx submodule"
  git submodule update ./libnyx 2>/dev/null # ignore errors
  set -e

else

  test -d QEMU-Nyx/.git || git clone https://github.com/nyx-fuzz/qemu-nyx QEMU-Nyx
  test -d packer/.git || git clone https://github.com/nyx-fuzz/packer
  test -d libnyx/.git || git clone https://github.com/nyx-fuzz/libnyx

fi

test -e packer/.git || { echo "[-] packer not checked out, please install git or check your internet connection." ; exit 1 ; }
test -e libnyx/.git || { echo "[-] libnyx not checked out, please install git or check your internet connection." ; exit 1 ; }
test -e QEMU-Nyx/.git || { echo "[-] QEMU-Nyx not checked out, please install git or check your internet connection." ; exit 1 ; }


QEMU_NYX_VERSION="$(cat ./QEMU_NYX_VERSION)"
cd "./QEMU-Nyx" || exit 1
if [ -n "$NO_CHECKOUT" ]; then
  echo "[*] Skipping checkout to $QEMU_NYX_VERSION"
else
  echo "[*] Checking out $QEMU_NYX_VERSION"
  set +e
  sh -c 'git stash' 1>/dev/null 2>/dev/null
  git pull 1>/dev/null 2>/dev/null
  git checkout "$QEMU_NYX_VERSION" || echo Warning: could not check out to commit $QEMU_NYX_VERSION
  set -e
fi
cd - > /dev/null

PACKER_VERSION="$(cat ./PACKER_VERSION)"
cd "./packer" || exit 1
if [ -n "$NO_CHECKOUT" ]; then
  echo "[*] Skipping checkout to $PACKER_VERSION"
else
  echo "[*] Checking out $PACKER_VERSION"
  set +e
  sh -c 'git stash' 1>/dev/null 2>/dev/null
  git pull 1>/dev/null 2>/dev/null
  git checkout "$PACKER_VERSION" || echo Warning: could not check out to commit $PACKER_VERSION
  set -e
fi
cd - > /dev/null

LIBNYX_VERSION="$(cat ./LIBNYX_VERSION)"
cd "./libnyx/" || exit 1
if [ -n "$NO_CHECKOUT" ]; then
  echo "[*] Skipping checkout to $LIBNYX_VERSION"
else
  echo "[*] Checking out $LIBNYX_VERSION"
  set +e
  sh -c 'git stash' 1>/dev/null 2>/dev/null
  git pull 1>/dev/null 2>/dev/null
  git checkout "$LIBNYX_VERSION" || echo Warning: could not check out to commit $LIBNYX_VERSION
  set -e
fi
cd - > /dev/null

echo "[*] checking packer init.cpio.gz ..."
(cd packer/linux_initramfs/ && sh pack.sh)

echo "[*] Checking libnyx ..."
(cd libnyx/libnyx && cargo build --release)

echo "[*] Checking QEMU-Nyx ..."
(cd QEMU-Nyx && ./compile_qemu_nyx.sh static )

echo "[*] Checking libnyx.so ..."
cp libnyx/libnyx/target/release/liblibnyx.so ../libnyx.so

echo "[+] All done for nyx_mode, enjoy!"

exit 0
