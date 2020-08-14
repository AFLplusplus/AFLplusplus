#!/bin/sh
rm -f afl-qemu-taint qemu/afl-qemu-taint ../afl-qemu-taint
test -d qemu && { cd qemu ; ./clean.sh ; }
