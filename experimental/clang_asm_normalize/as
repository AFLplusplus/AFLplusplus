#!/bin/sh
#
# american fuzzy lop - clang assembly normalizer
# ----------------------------------------------
#
# Written and maintained by Michal Zalewski <lcamtuf@google.com>
# The idea for this wrapper comes from Ryan Govostes.
#
# Copyright 2013, 2014 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# This 'as' wrapper should allow you to instrument unruly, hand-written
# assembly with afl-as.
#
# Usage:
#
# export AFL_REAL_PATH=/path/to/directory/with/afl-as/
# AFL_PATH=/path/to/this/directory/ make clean all

if [ "$#" -lt "2" ]; then
  echo "[-] Error: this utility can't be called directly." 1>&2
  exit 1
fi

if [ "$AFL_REAL_PATH" = "" ]; then
  echo "[-] Error: AFL_REAL_PATH not set!" 1>&2
  exit 1
fi

if [ ! -x "$AFL_REAL_PATH/afl-as" ]; then
  echo "[-] Error: AFL_REAL_PATH does not contain the 'afl-as' binary." 1>&2
  exit 1
fi

unset __AFL_AS_CMDLINE __AFL_FNAME

while [ ! "$#" = "0" ]; do

  if [ "$#" = "1" ]; then
    __AFL_FNAME="$1"
  else
    __AFL_AS_CMDLINE="${__AFL_AS_CMDLINE} $1"
  fi

  shift

done

test "$TMPDIR" = "" && TMPDIR=/tmp

TMPFILE=`mktemp $TMPDIR/.afl-XXXXXXXXXX.s`

test "$TMPFILE" = "" && exit 1

clang -cc1as -filetype asm -output-asm-variant 0 "${__AFL_FNAME}" >"$TMPFILE"

ERR="$?"

if [ ! "$ERR" = "0" ]; then
  rm -f "$TMPFILE"
  exit $ERR
fi

"$AFL_REAL_PATH/afl-as" ${__AFL_AS_CMDLINE} "$TMPFILE"

ERR="$?"

rm -f "$TMPFILE"

exit "$ERR"
