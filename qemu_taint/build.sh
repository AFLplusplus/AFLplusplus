#!/bin/bash
test -d qemu ||  git clone https://github.com/vanhauser-thc/qemu_taint qemu || exit 1
cd qemu || exit 1
test -d .git || { git stash ; git pull ; }
cp -fv ../../include/config.h .
./build.sh
cp -fv ./afl-qemu-taint ../..
