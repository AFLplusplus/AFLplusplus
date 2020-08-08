#!/bin/bash
test -d qemu ||  git clone https://github.com/vanhauser-thc/qemu_taint qemu || exit 1
cd qemu || exit 1
test -d .git || { git stash ; git pull ; }
./build.sh
cp -f ./afl-qemu-taint ../..
