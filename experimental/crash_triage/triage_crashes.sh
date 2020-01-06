#!/bin/sh
#
# american fuzzy lop++ - crash triage utility
# -----------------------------------------
#
# Originally written by Michal Zalewski
#
# Copyright 2013, 2014, 2017 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Note that this assumes that the targeted application reads from stdin
# and requires no other cmdline parameters. Modify as needed if this is
# not the case.
#
# Note that on OpenBSD, you may need to install a newer version of gdb
# (e.g., from ports). You can set GDB=/some/path to point to it if
# necessary.
#

echo "crash triage utility for afl-fuzz by Michal Zalewski"
echo

ulimit -v 100000 2>/dev/null
ulimit -d 100000 2>/dev/null

if [ "$#" -lt "2" ]; then
  echo "Usage: $0 /path/to/afl_output_dir /path/to/tested_binary [...target params...]" 1>&2
  echo 1>&2
  exit 1
fi

DIR="$1"
BIN="$2"
shift
shift

if [ "$AFL_ALLOW_TMP" = "" ]; then

  echo "$DIR" | grep -qE '^(/var)?/tmp/'
  T1="$?"

  echo "$BIN" | grep -qE '^(/var)?/tmp/'
  T2="$?"

  if [ "$T1" = "0" -o "$T2" = "0" ]; then
    echo "[-] Error: do not use shared /tmp or /var/tmp directories with this script." 1>&2
    exit 1
  fi

fi

if
 [ "$GDB" = "" ]; then
  GDB=gdb
fi

if [ ! -f "$BIN" -o ! -x "$BIN" ]; then
  echo "[-] Error: binary '$2' not found or is not executable." 1>&2
  exit 1
fi

if [ ! -d "$DIR/queue" ]; then
  echo "[-] Error: directory '$1' not found or not created by afl-fuzz." 1>&2
  exit 1
fi

CCOUNT=$((`ls -- "$DIR/crashes" 2>/dev/null | wc -l`))

if [ "$CCOUNT" = "0" ]; then
  echo "No crashes recorded in the target directory - nothing to be done."
  exit 0
fi

echo

for crash in $DIR/crashes/id:*; do

  id=`basename -- "$crash" | cut -d, -f1 | cut -d: -f2`
  sig=`basename -- "$crash" | cut -d, -f2 | cut -d: -f2`

  # Grab the args, converting @@ to $crash

  use_args=""
  use_stdio=1

  for a in $@; do

    if [ "$a" = "@@" ] ; then
      args="$use_args $crash"
      unset use_stdio
    else
      args="$use_args $a"
    fi

  done

  # Strip the trailing space
  use_args="${use_args# }"

  echo "+++ ID $id, SIGNAL $sig +++"
  echo

  if [ "$use_stdio" = "1" ]; then  
    $GDB --batch -q --ex "r $use_args <$crash" --ex 'back' --ex 'disass $pc, $pc+16' --ex 'info reg' --ex 'quit' "$BIN" 0</dev/null
  else
    $GDB --batch -q --ex "r $use_args" --ex 'back' --ex 'disass $pc, $pc+16' --ex 'info reg' --ex 'quit' "$BIN" 0</dev/null
  fi
  echo

done
