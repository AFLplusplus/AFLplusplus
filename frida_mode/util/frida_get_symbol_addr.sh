#!/bin/bash
# Copyright 2024 AFLplusplus
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

target="$1"
symbol="$2"
base="$3"

test -z "$target" -o -z "$symbol" -o '!' -x "$target" && {
  echo "Syntax: $0 executable function [baseaddress]"
  echo
  echo Help script to calculate the function address of a binary QEMU will load it to.
  echo function is e.g. LLVMFuzzerTestOneInput, afl_qemu_driver_stdin, etc.
  echo "baseaddress is tried to be auto-detected, you can use 'AFL_QEMU_DEBUG_MAPS=1 afl-qemu-trace ./executable' to see the maps."
  exit 1
}

file=$(file $target|sed 's/.*: //')

arch=$(echo $file|awk -F, '{print$2}'|tr -d ' ')
bits=$(echo $file|sed 's/-bit .*//'|sed 's/.* //')
pie=$(echo $file|grep -wqi pie && echo pie)
dso=$(echo $file|grep -wqi "shared object" && echo dso)

test $(uname -s) = "Darwin" && symbol=_"$symbol"
tmp_addr=$(nm "$target" | grep -i "T $symbol" | awk '{print$1}' | tr a-f A-F)

test -z "$tmp_addr" && { echo Error: function $symbol not found 1>&2; exit 1; }
test -z "$pie" && test -z "$dso" && { echo 0x$tmp_addr; exit 0; }

test -z "$base" && {
  test "$bits" = 32 -o "$bits" = 64 || { echo "Error: could not identify arch (bits=$bits)" 1>&2 ; exit 1; }
  # is this true for arm/aarch64/i386 too?
  base=0x555555554000
  #test "$arch" = Intel80386 && base=0x5555554000
  #test "$arch" = x86-64 && base=0x555555554000
  #test "$arch" = ARMaarch64 && base=0x5500000000
  # add more here, e.g. "$arch" = ARM
}

test -z "$base" && { echo "Error: could not identify base address! bits=$bits arch=$arch" 1>&2 ; exit 1; }

hex_base=$(echo "$base" | awk '{sub("^0x","");print $0}' | tr a-f A-F )
echo $tmp_addr | echo "ibase=16;obase=10;$hex_base + $tmp_addr" | bc | tr A-F a-f | awk '{print "0x"$0}'
exit 0
