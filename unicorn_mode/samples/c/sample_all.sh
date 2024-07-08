#!/bin/sh

[ -z "${UNAME}" ] && UNAME=$(uname)

DIR=`dirname $0`

if [ "$UNAME" = Darwin ]; then
  export DYLD_LIBRARY_PATH=../../unicorn
else
  export LD_LIBRARY_PATH=../../unicorn
fi



if [ ! -e $DIR/harness ]; then
  echo "[!] harness not found in $DIR"
  exit 1
fi
