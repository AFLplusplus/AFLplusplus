#!/bin/bash

set -e

echo "================================================="
echo "           Nyx build script"
echo "================================================="
echo

echo "[*] Performing basic sanity checks..."

if [ ! "$(uname -s)" = "Linux" ]; then

  echo "[-] Error: Nyx mode is only available on Linux."
  exit 0

fi

if [ ! "$(uname -m)" = "x86_64" ]; then

  echo "[-] Error: Nyx mode is only available on x86_64 (yet)."
  exit 0

fi

echo "[*] Making sure all Nyx is checked out"


if git status 1>/dev/null 2>&1; then

  git submodule init
  echo "[*] initializing QEMU-Nyx submodule"
  git submodule update ./QEMU-Nyx 2>/dev/null # ignore errors
  echo "[*] initializing packer submodule"
  git submodule update ./packer 2>/dev/null # ignore errors
  echo "[*] initializing libnyx submodule"
  git submodule update ./libnyx 2>/dev/null # ignore errors

else

  test -d QEMU-Nyx/.git || git clone https://github.com/nyx-fuzz/qemu-nyx QEMU-Nyx
  test -d packer/.git || git clone https://github.com/nyx-fuzz/packer
  test -d libnyx/.git || git clone https://github.com/nyx-fuzz/libnyx

fi

test -e packer/.git || { echo "[-] packer not checked out, please install git or check your internet connection." ; exit 1 ; }
test -e libnyx/.git || { echo "[-] libnyx not checked out, please install git or check your internet connection." ; exit 1 ; }
test -e QEMU-Nyx/.git || { echo "[-] QEMU-Nyx not checked out, please install git or check your internet connection." ; exit 1 ; }

echo "[*] checking packer init.cpio.gz ..."
if [ ! -f "packer/linux_initramfs/init.cpio.gz" ]; then
    (cd packer/linux_initramfs/ && sh pack.sh)
fi

echo "[*] Checking libnyx ..."
if [ ! -f "libnyx/libnyx/target/release/liblibnyx.a" ]; then
    (cd libnyx/libnyx && cargo build --release)
fi

echo "[*] Checking QEMU-Nyx ..."
if [ ! -f "QEMU-Nyx/x86_64-softmmu/qemu-system-x86_64" ]; then
    
    if ! dpkg -s gtk3-devel > /dev/null 2>&1; then
        echo "[-] Disabling GTK because gtk3-devel is not installed."
        sed -i 's/--enable-gtk//g' QEMU-Nyx/compile_qemu_nyx.sh
    fi
    (cd QEMU-Nyx && ./compile_qemu_nyx.sh static)
fi

echo "[*] Checking libnyx.so ..."
cp libnyx/libnyx/target/release/liblibnyx.so ../libnyx.so

echo "[+] All done for nyx_mode, enjoy!"

exit 0
