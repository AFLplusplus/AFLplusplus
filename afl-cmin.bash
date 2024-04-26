#!/usr/bin/env bash
#
# american fuzzy lop++ - corpus minimization tool
# ---------------------------------------------
#
# Originally written by Michal Zalewski
#
# Copyright 2014, 2015 Google Inc. All rights reserved.
#
# Copyright 2019-2024 AFLplusplus
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# This tool tries to find the smallest subset of files in the input directory
# that still trigger the full range of instrumentation data points seen in
# the starting corpus. This has two uses:
#
#   - Screening large corpora of input files before using them as a seed for
#     afl-fuzz. The tool will remove functionally redundant files and likely
#     leave you with a much smaller set.
#
#     (In this case, you probably also want to consider running afl-tmin on
#     the individual files later on to reduce their size.)
#
#   - Minimizing the corpus generated organically by afl-fuzz, perhaps when
#     planning to feed it to more resource-intensive tools. The tool achieves
#     this by removing all entries that used to trigger unique behaviors in the
#     past, but have been made obsolete by later finds.
#
# Note that the tool doesn't modify the files themselves. For that, you want
# afl-tmin.
#
# This script must use bash because other shells may have hardcoded limits on
# array sizes.
#

echo "corpus minimization tool for afl-fuzz"
echo

#########
# SETUP #
#########

# Process command-line options...

MEM_LIMIT=none
TIMEOUT=5000

unset IN_DIR OUT_DIR STDIN_FILE EXTRA_PAR MEM_LIMIT_GIVEN F_ARG \
  AFL_CMIN_CRASHES_ONLY AFL_CMIN_ALLOW_ANY QEMU_MODE UNICORN_MODE T_ARG

export AFL_QUIET=1

while getopts "+i:o:f:m:t:T:eOQUAChXY" opt; do

  case "$opt" in 

    "h")
	;;

    "i")
         IN_DIR="$OPTARG"
         ;;

    "o")
         OUT_DIR="$OPTARG"
         ;;
    "f")
         STDIN_FILE="$OPTARG"
         F_ARG=1
         ;;
    "m")
         MEM_LIMIT="$OPTARG"
         MEM_LIMIT_GIVEN=1
         ;;
    "t")
         TIMEOUT="$OPTARG"
         ;;
    "e")
         EXTRA_PAR="$EXTRA_PAR -e"
         ;;
    "A")
         export AFL_CMIN_ALLOW_ANY=1
         ;;
    "C")
         export AFL_CMIN_CRASHES_ONLY=1
         ;;
    "O")
         EXTRA_PAR="$EXTRA_PAR -O"
         FRIDA_MODE=1
         ;;         
    "Q")
         EXTRA_PAR="$EXTRA_PAR -Q"
         QEMU_MODE=1
         ;;
    "Y")
         EXTRA_PAR="$EXTRA_PAR -X"
         NYX_MODE=1
         ;;
    "X")
         EXTRA_PAR="$EXTRA_PAR -X"
         NYX_MODE=1
         ;;
    "U")
         EXTRA_PAR="$EXTRA_PAR -U"
         UNICORN_MODE=1
         ;;    
    "T")
         T_ARG="$OPTARG"
         ;;
    "?")
         exit 1
         ;;

   esac

done

shift $((OPTIND-1))

TARGET_BIN="$1"

if [ "$TARGET_BIN" = "" -o "$IN_DIR" = "" -o "$OUT_DIR" = "" ]; then

  cat 1>&2 <<_EOF_
Usage: $0 [ options ] -- /path/to/target_app [ ... ]

Required parameters:

  -i dir        - input directory with the starting corpus
  -o dir        - output directory for minimized files

Execution control settings:

  -T tasks      - how many parallel processes to create (default=1, "all"=nproc)
  -f file       - location read by the fuzzed program (default: stdin)
  -m megs       - memory limit for child process (default=$MEM_LIMIT MB)
  -t msec       - run time limit for child process (default: 5000ms)
  -O            - use binary-only instrumentation (FRIDA mode)
  -Q            - use binary-only instrumentation (QEMU mode)
  -U            - use unicorn-based instrumentation (Unicorn mode)
  -X            - use Nyx mode
  
Minimization settings:

  -A            - allow crashing and timeout inputs
  -C            - keep crashing inputs, reject everything else
  -e            - solve for edge coverage only, ignore hit counts

For additional tips, please consult README.md.
This script cannot read filenames that end with a space ' '.

Environment variables used:
AFL_KEEP_TRACES: leave the temporary <out_dir>\.traces directory
AFL_NO_FORKSRV: run target via execve instead of using the forkserver
AFL_PATH: last resort location to find the afl-showmap binary
AFL_SKIP_BIN_CHECK: skip check for target binary
AFL_CUSTOM_MUTATOR_LIBRARY: custom mutator library (post_process and send)
AFL_PYTHON_MODULE: custom mutator library (post_process and send)
_EOF_
  exit 1
fi

# Do a sanity check to discourage the use of /tmp, since we can't really
# handle this safely from a shell script.

if [ "$AFL_ALLOW_TMP" = "" ]; then

  echo "$IN_DIR" | grep -qE '^(/var)?/tmp/'
  T1="$?"

  echo "$TARGET_BIN" | grep -qE '^(/var)?/tmp/'
  T2="$?"

  echo "$OUT_DIR" | grep -qE '^(/var)?/tmp/'
  T3="$?"

  echo "$STDIN_FILE" | grep -qE '^(/var)?/tmp/'
  T4="$?"

  echo "$PWD" | grep -qE '^(/var)?/tmp/'
  T5="$?"

  if [ "$T1" = "0" -o "$T2" = "0" -o "$T3" = "0" -o "$T4" = "0" -o "$T5" = "0" ]; then
    echo "[-] Warning: do not use this script in /tmp or /var/tmp for security reasons." 1>&2
  fi

fi

# If @@ is specified, but there's no -f, let's come up with a temporary input
# file name.

TRACE_DIR="$OUT_DIR/.traces"

if [ "$STDIN_FILE" = "" ]; then

  if echo "$*" | grep -qF '@@'; then
    STDIN_FILE="$TRACE_DIR/.cur_input"
  fi

fi

# Check for obvious errors.

if [ ! "$T_ARG" = "" -a -n "$F_ARG" -a ! "$NYX_MODE" == 1 ]; then
  echo "[-] Error: -T and -f can not be used together." 1>&2
  exit 1
fi

if [ ! "$MEM_LIMIT" = "none" ]; then

  if [ "$MEM_LIMIT" -lt "5" ]; then
    echo "[-] Error: dangerously low memory limit." 1>&2
    exit 1
  fi

fi

if [ ! "$TIMEOUT" = "none" ]; then

  if [ "$TIMEOUT" -lt "10" ]; then
    echo "[-] Error: dangerously low timeout." 1>&2
    exit 1
  fi

fi

if [ "$NYX_MODE" = "" ]; then
  if [ ! -f "$TARGET_BIN" -o ! -x "$TARGET_BIN" ]; then

    TNEW="`which "$TARGET_BIN" 2>/dev/null`"

    if [ ! -f "$TNEW" -o ! -x "$TNEW" ]; then
      echo "[-] Error: binary '$TARGET_BIN' not found or not executable." 1>&2
      exit 1
    fi

    TARGET_BIN="$TNEW"

  fi

fi

grep -aq AFL_DUMP_MAP_SIZE "$TARGET_BIN" && {
  echo "[!] Trying to obtain the map size of the target ..."
  MAPSIZE=`AFL_DUMP_MAP_SIZE=1 "./$TARGET_BIN" 2>/dev/null`
  test -n "$MAPSIZE" && {
    export AFL_MAP_SIZE=$MAPSIZE
    echo "[+] Setting AFL_MAP_SIZE=$MAPSIZE"
  }
}

if [ "$AFL_SKIP_BIN_CHECK" = "" -a "$QEMU_MODE" = "" -a "$FRIDA_MODE" = "" -a "$UNICORN_MODE" = "" -a "$NYX_MODE" = "" ]; then

  if ! grep -qF "__AFL_SHM_ID" "$TARGET_BIN"; then
    echo "[-] Error: binary '$TARGET_BIN' doesn't appear to be instrumented." 1>&2
    exit 1
  fi

fi

if [ ! -d "$IN_DIR" ]; then
  echo "[-] Error: directory '$IN_DIR' not found." 1>&2
  exit 1
fi

test -d "$IN_DIR/default" && IN_DIR="$IN_DIR/default"
test -d "$IN_DIR/queue" && IN_DIR="$IN_DIR/queue"

find "$OUT_DIR" -name 'id[:_]*' -maxdepth 1 -exec rm -- {} \; 2>/dev/null
rm -rf "$TRACE_DIR" 2>/dev/null

rmdir "$OUT_DIR" 2>/dev/null

if [ -d "$OUT_DIR" ]; then
  echo "[-] Error: directory '$OUT_DIR' exists and is not empty - delete it first." 1>&2
  exit 1
fi

mkdir -m 700 -p "$TRACE_DIR" || exit 1

if [ ! "$STDIN_FILE" = "" ]; then
  rm -f "$STDIN_FILE" || exit 1
  touch "$STDIN_FILE" || exit 1
fi

SHOWMAP=`command -v afl-showmap 2>/dev/null`

if [ -z "$SHOWMAP" ]; then
  TMP="${0%/afl-cmin.bash}/afl-showmap"
  if [ -x "$TMP" ]; then
    SHOWMAP=$TMP
  fi
fi

if [ -z "$SHOWMAP" -a -x "./afl-showmap" ]; then
  SHOWMAP="./afl-showmap"
else
  if [ -n "$AFL_PATH" ]; then
    SHOWMAP="$AFL_PATH/afl-showmap"
  fi
fi

if [ ! -x "$SHOWMAP" ]; then
  echo "[-] Error: can't find 'afl-showmap' - please set AFL_PATH." 1>&2
  rm -rf "$TRACE_DIR"
  exit 1
fi

THREADS=
if [ ! "$T_ARG" = "" ]; then
  if [ "$T_ARG" = "all" ]; then
    THREADS=$(nproc)
  else
    if [ "$T_ARG" -gt 1 -a "$T_ARG" -le "$(nproc)" ]; then
      THREADS=$T_ARG
    else
      echo "[-] Error: -T parameter must between 2 and $(nproc) or \"all\"." 1>&2
    fi
  fi
else
  if [ -z "$F_ARG" ]; then
    echo "[*] Are you aware of the '-T all' parallelize option that massively improves the speed?"
  fi
fi

IN_COUNT=$((`ls -- "$IN_DIR" 2>/dev/null | wc -l`))

if [ "$IN_COUNT" = "0" ]; then
  echo "[-] Hmm, no inputs in the target directory. Nothing to be done."
  rm -rf "$TRACE_DIR"
  exit 1
fi

echo "[*] Are you aware that afl-cmin is faster than this afl-cmin.bash script?"
echo "[+] Found $IN_COUNT files for minimizing."

if [ -n "$THREADS" ]; then
  if [ "$IN_COUNT" -lt "$THREADS" ]; then
    THREADS=$IN_COUNT
    echo "[!] WARNING: less inputs than threads, reducing threads to $THREADS and likely the overhead of threading makes things slower..."
  fi
fi

FIRST_FILE=`ls "$IN_DIR" | head -1`

# Make sure that we're not dealing with a directory.

if [ -d "$IN_DIR/$FIRST_FILE" ]; then
  echo "[-] Error: The target directory contains subdirectories - please fix." 1>&2
  rm -rf "$TRACE_DIR"
  exit 1
fi

# Check for the more efficient way to copy files...

if ln "$IN_DIR/$FIRST_FILE" "$TRACE_DIR/.link_test" 2>/dev/null; then
  CP_TOOL=ln
else
  CP_TOOL=cp
fi

# Make sure that we can actually get anything out of afl-showmap before we
# waste too much time.

echo "[*] Testing the target binary..."

if [ "$STDIN_FILE" = "" ]; then

  AFL_CMIN_ALLOW_ANY=1 "$SHOWMAP" -m "$MEM_LIMIT" -t "$TIMEOUT" -o "$TRACE_DIR/.run_test" -Z $EXTRA_PAR -- "$@" <"$IN_DIR/$FIRST_FILE"

else

  cp "$IN_DIR/$FIRST_FILE" "$STDIN_FILE"
  AFL_CMIN_ALLOW_ANY=1 "$SHOWMAP" -m "$MEM_LIMIT" -t "$TIMEOUT" -o "$TRACE_DIR/.run_test" -Z $EXTRA_PAR -H "$STDIN_FILE" -- "$@" </dev/null

fi

FIRST_COUNT=$((`grep -c . "$TRACE_DIR/.run_test"`))

if [ "$FIRST_COUNT" -gt "0" ]; then

  echo "[+] OK, $FIRST_COUNT tuples recorded."

else

  echo "[-] Error: no instrumentation output detected (perhaps crash or timeout)." 1>&2
  test "$AFL_KEEP_TRACES" = "" && rm -rf "$TRACE_DIR"
  exit 1

fi

TMPFILE=$OUT_DIR/.list.$$
if [ ! "$THREADS" = "" ]; then
  ls -- "$IN_DIR" > $TMPFILE 2>/dev/null
  IN_COUNT=$(cat $TMPFILE | wc -l)
  SPLIT=$(($IN_COUNT / $THREADS))
  if [ "$(($IN_COUNT % $THREADS))" -gt 0 ]; then
    SPLIT=$(($SPLIT + 1))
  fi
  echo "[+] Splitting workload into $THREADS tasks with $SPLIT items on average each."
  split -l $SPLIT $TMPFILE $TMPFILE.
fi

# Let's roll!

#############################
# STEP 1: COLLECTING TRACES #
#############################

echo "[*] Obtaining traces for input files in '$IN_DIR'..."

if [ "$THREADS" = "" ]; then
(

  CUR=0

  if [ "$STDIN_FILE" = "" ]; then

    ls "$IN_DIR" | while read -r fn; do

      if [ -s "$IN_DIR/$fn" ]; then

        CUR=$((CUR+1))
        printf "\\r    Processing file $CUR/$IN_COUNT... "

        "$SHOWMAP" -m "$MEM_LIMIT" -t "$TIMEOUT" -o "$TRACE_DIR/$fn" -Z $EXTRA_PAR -- "$@" <"$IN_DIR/$fn"
      
      fi

    done

  else

    ls "$IN_DIR" | while read -r fn; do

      if [ -s "$IN_DIR/$fn" ]; then

        CUR=$((CUR+1))
        printf "\\r    Processing file $CUR/$IN_COUNT... "

        cp "$IN_DIR/$fn" "$STDIN_FILE"
        "$SHOWMAP" -m "$MEM_LIMIT" -t "$TIMEOUT" -o "$TRACE_DIR/$fn" -Z $EXTRA_PAR -H "$STDIN_FILE" -- "$@" </dev/null

      fi

    done

  fi

  echo

)

else

  PIDS=
  CNT=0
  for inputs in $(ls ${TMPFILE}.*); do

(

  if [ "$STDIN_FILE" = "" ]; then

    cat $inputs | while read -r fn; do

      if [ -s "$IN_DIR/$fn" ]; then

        "$SHOWMAP" -m "$MEM_LIMIT" -t "$TIMEOUT" -o "$TRACE_DIR/$fn" -Z $EXTRA_PAR -- "$@" <"$IN_DIR/$fn"

      fi

    done

  else

    if [ -s "$IN_DIR/$fn" ]; then
      STDIN_FILE="$inputs.$$"
      cat $inputs | while read -r fn; do

        cp "$IN_DIR/$fn" "$STDIN_FILE"
        "$SHOWMAP" -m "$MEM_LIMIT" -t "$TIMEOUT" -o "$TRACE_DIR/$fn" -Z $EXTRA_PAR -H "$STDIN_FILE" -- "$@" </dev/null

      done

    fi

  fi

) &

  PIDS="$PIDS $!"
  done

  echo "[+] Waiting for running tasks IDs:$PIDS"
  wait
  echo "[+] all $THREADS running tasks completed."
  rm -f ${TMPFILE}*

  #echo trace dir files: $(ls $TRACE_DIR/*|wc -l)

fi


##########################
# STEP 2: SORTING TUPLES #
##########################

# With this out of the way, we sort all tuples by popularity across all
# datasets. The reasoning here is that we won't be able to avoid the files
# that trigger unique tuples anyway, so we will want to start with them and
# see what's left.

echo "[*] Sorting trace sets (this may take a while)..."

ls "$IN_DIR" | sed "s#^#$TRACE_DIR/#" | tr '\n' '\0' | xargs -0 -n 1 cat | \
  sort | uniq -c | sort -k 1,1 -n >"$TRACE_DIR/.all_uniq"

TUPLE_COUNT=$((`grep -c . "$TRACE_DIR/.all_uniq"`))

echo "[+] Found $TUPLE_COUNT unique tuples across $IN_COUNT files."

#####################################
# STEP 3: SELECTING CANDIDATE FILES #
#####################################

# The next step is to find the best candidate for each tuple. The "best"
# part is understood simply as the smallest input that includes a particular
# tuple in its trace. Empirical evidence suggests that this produces smaller
# datasets than more involved algorithms that could be still pulled off in
# a shell script.

echo "[*] Finding best candidates for each tuple..."

CUR=0

ls -rS "$IN_DIR" | while read -r fn; do

  CUR=$((CUR+1))
  printf "\\r    Processing file $CUR/$IN_COUNT... "

  sed "s#\$# $fn#" "$TRACE_DIR/$fn" >>"$TRACE_DIR/.candidate_list"

  test -s "$TRACE_DIR/$fn" || echo Warning: $fn is ignored because of crashing the target

done

echo

##############################
# STEP 4: LOADING CANDIDATES #
##############################

# At this point, we have a file of tuple-file pairs, sorted by file size
# in ascending order (as a consequence of ls -rS). By doing sort keyed
# only by tuple (-k 1,1) and configured to output only the first line for
# every key (-s -u), we end up with the smallest file for each tuple.

echo "[*] Sorting candidate list (be patient)..."

sort -k1,1 -s -u "$TRACE_DIR/.candidate_list" | \
  sed 's/^/BEST_FILE[/;s/ /]="/;s/$/"/' >"$TRACE_DIR/.candidate_script"

if [ ! -s "$TRACE_DIR/.candidate_script" ]; then
  echo "[-] Error: no traces obtained from test cases, check syntax!" 1>&2
  test "$AFL_KEEP_TRACES" = "" && rm -rf "$TRACE_DIR"
  exit 1
fi

# The sed command converted the sorted list to a shell script that populates
# BEST_FILE[tuple]="fname". Let's load that!

. "$TRACE_DIR/.candidate_script"

##########################
# STEP 5: WRITING OUTPUT #
##########################

# The final trick is to grab the top pick for each tuple, unless said tuple is
# already set due to the inclusion of an earlier candidate; and then put all
# tuples associated with the newly-added file to the "already have" list. The
# loop works from least popular tuples and toward the most common ones.

echo "[*] Processing candidates and writing output files..."

CUR=0

touch "$TRACE_DIR/.already_have"

while read -r cnt tuple; do

  CUR=$((CUR+1))
  printf "\\r    Processing tuple $CUR/$TUPLE_COUNT with count $cnt... "

  # If we already have this tuple, skip it.

  grep -q "^$tuple\$" "$TRACE_DIR/.already_have" && continue

  FN=${BEST_FILE[tuple]}

#  echo "tuple nr $CUR ($tuple cnt=$cnt) -> $FN" >> "$TRACE_DIR/.log"
  $CP_TOOL "$IN_DIR/$FN" "$OUT_DIR/$FN"

  if [ "$((CUR % 5))" = "0" ]; then
    sort -u "$TRACE_DIR/$FN" "$TRACE_DIR/.already_have" >"$TRACE_DIR/.tmp"
    mv -f "$TRACE_DIR/.tmp" "$TRACE_DIR/.already_have"
  else
    cat "$TRACE_DIR/$FN" >>"$TRACE_DIR/.already_have"
  fi

done <"$TRACE_DIR/.all_uniq"

echo

OUT_COUNT=`ls -- "$OUT_DIR" | wc -l`

if [ "$OUT_COUNT" = "1" ]; then
  echo "[!] WARNING: All test cases had the same traces, check syntax!"
fi

echo "[+] Narrowed down to $OUT_COUNT files, saved in '$OUT_DIR'."
echo

test "$AFL_KEEP_TRACES" = "" && rm -rf "$TRACE_DIR"

exit 0
