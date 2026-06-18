#!/bin/sh
test "$1" = "" && { echo "usage: update_ref.sh <commit-hash>"; exit 1; }
echo "$1" > QEMU_BRIDGE_VERSION
cd qemu-libafl-bridge || exit 1
git fetch origin
git checkout "$1" || exit 1
echo done
