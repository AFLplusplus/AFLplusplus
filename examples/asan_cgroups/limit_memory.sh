#!/usr/bin/env bash
#
# american fuzzy lop++ - limit memory using cgroups
# -----------------------------------------------
#
# Written by Samir Khakimov <samir.hakim@nyu.edu> and
#            David A. Wheeler <dwheeler@ida.org>
#
# Edits to bring the script in line with afl-cmin and other companion scripts
# by Michal Zalewski. All bugs are my fault.
#
# Copyright 2015 Institute for Defense Analyses.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# This tool allows the amount of actual memory allocated to a program
# to be limited on Linux systems using cgroups, instead of the traditional
# setrlimit() API. This helps avoid the address space problems discussed in
# docs/notes_for_asan.md.
#
# Important: the limit covers *both* afl-fuzz and the fuzzed binary. In some
# hopefully rare circumstances, afl-fuzz could be killed before the fuzzed
# task.
#

echo "cgroup tool for afl-fuzz by <samir.hakim@nyu.edu> and <dwheeler@ida.org>"
echo

unset NEW_USER
MEM_LIMIT="50"

while getopts "+u:m:" opt; do

  case "$opt" in

    "u")
         NEW_USER="$OPTARG"
         ;;

    "m")
         MEM_LIMIT="$[OPTARG]"
         ;;

    "?")
         exit 1
         ;;

   esac

done

if [ "$MEM_LIMIT" -lt "5" ]; then
  echo "[-] Error: malformed or dangerously low value of -m." 1>&2
  exit 1
fi

shift $((OPTIND-1))

TARGET_BIN="$1"

if [ "$TARGET_BIN" = "" -o "$NEW_USER" = "" ]; then

  cat 1>&2 <<_EOF_
Usage: $0 [ options ] -- /path/to/afl-fuzz [ ...afl options... ]

Required parameters:

  -u user   - run the fuzzer as a specific user after setting up limits

Optional parameters:

  -m megs   - set memory limit to a specified value ($MEM_LIMIT MB)

This tool configures cgroups-based memory limits for a fuzzing job to simplify
the task of fuzzing ASAN or MSAN binaries. You would normally want to use it in
conjunction with '-m none' passed to the afl-fuzz binary itself, say:

  $0 -u joe ./afl-fuzz -i input -o output -m none /path/to/target

_EOF_

  exit 1

fi

# Basic sanity checks

if [ ! "`uname -s`" = "Linux" ]; then
 echo "[-] Error: this tool does not support non-Linux systems." 1>&2
 exit 1
fi

if [ ! "`id -u`" = "0" ]; then
 echo "[-] Error: you need to run this script as root (sorry!)." 1>&2
 exit 1
fi

if ! type cgcreate 2>/dev/null 1>&2; then

  echo "[-] Error: you need to install cgroup tools first." 1>&2

  if type apt-get 2>/dev/null 1>&2; then
    echo "    (Perhaps 'apt-get install cgroup-bin' will work.)" 1>&2
  elif type yum 2>/dev/null 1>&2; then
    echo "    (Perhaps 'yum install libcgroup-tools' will work.)" 1>&2
  fi

  exit 1

fi

if ! id -u "$NEW_USER" 2>/dev/null 1>&2; then
  echo "[-] Error: user '$NEW_USER' does not seem to exist." 1>&2
  exit 1
fi

# Create a new cgroup path if necessary... We used PID-keyed groups to keep
# parallel afl-fuzz tasks separate from each other.

CID="afl-$NEW_USER-$$"

CPATH="/sys/fs/cgroup/memory/$CID"

if [ ! -d "$CPATH" ]; then

  cgcreate -a "$NEW_USER" -g memory:"$CID" || exit 1

fi

# Set the appropriate limit...

if [ -f "$CPATH/memory.memsw.limit_in_bytes" ]; then

  echo "${MEM_LIMIT}M" > "$CPATH/memory.limit_in_bytes" 2>/dev/null
  echo "${MEM_LIMIT}M" > "$CPATH/memory.memsw.limit_in_bytes" || exit 1
  echo "${MEM_LIMIT}M" > "$CPATH/memory.limit_in_bytes" || exit 1

elif grep -qE 'partition|file' /proc/swaps; then

  echo "[-] Error: your system requires swap to be disabled first (swapoff -a)." 1>&2
  exit 1

else

  echo "${MEM_LIMIT}M" > "$CPATH/memory.limit_in_bytes" || exit 1

fi

# All right. At this point, we can just run the command.

cgexec -g "memory:$CID" su -c "$*" "$NEW_USER"

cgdelete -g "memory:$CID"
