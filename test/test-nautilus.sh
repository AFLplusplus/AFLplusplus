#!/bin/sh

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: nautilus mutator"

# normalize path
# normalize path
CUSTOM_MUTATOR_PATH=$(cd $(pwd)/../custom_mutators/libafl_nautilus;pwd)

# OS detection
UNAME_S=$(uname -s)
if [ "$UNAME_S" = "Darwin" ]; then
  DLL="dylib"
else
  DLL="so"
fi

# compile custom mutator
$ECHO "$GREY[*] compiling nautilus custom mutator..."
(cd "$CUSTOM_MUTATOR_PATH" && cargo build --release) || {
  $ECHO "$RED[!] failed to compile nautilus custom mutator"
  exit 1
}

LIB_PATH="${CUSTOM_MUTATOR_PATH}/target/release/liblibafl_nautilus.${DLL}"

if [ ! -f "$LIB_PATH" ]; then
    $ECHO "$RED[!] liblibafl_nautilus.${DLL} not found at $LIB_PATH"
    exit 1
fi

  # Compile the vulnerable program
  ../afl-cc -o test-nautilus-target test-nautilus-target.c > compilation_errors 2>&1

  # Create input directory
  mkdir -p in-nautilus
  echo "A" > in-nautilus/in

  # Verify target compilation
  if [ ! -x "./test-nautilus-target" ]; then
    $ECHO "$RED[!] test-nautilus-target failed to compile."
    echo "Compiler output:"
    cat compilation_errors
    rm -f compilation_errors
    exit 1
  fi
  rm -f compilation_errors

  # Run afl-fuzz with Nautilus mutator
  # We set AFL_NO_UI=1 to avoid UI artifacts in logs
  # We use -V 20 to run for 20 seconds (should be enough to crash)
  $ECHO "$GREY[*] running afl-fuzz for the Nautilus mutator, this will take approx 20 seconds"
  export NAUTILUS_GRAMMAR_FILE="$(pwd)/test-nautilus-grammar.json"
  AFL_NO_UI=1 AFL_CUSTOM_MUTATOR_LIBRARY="$LIB_PATH" AFL_CUSTOM_MUTATOR_ONLY=1 AFL_POST_PROCESS_KEEP_ORIGINAL=1 ../afl-fuzz -V 20 -m ${MEM_LIMIT} -i in-nautilus -o out-nautilus -d -- ./test-nautilus-target >> errors 2>&1
  unset NAUTILUS_GRAMMAR_FILE

  # Check if afl-fuzz ran successfully and loaded the mutator
  if grep -F "Found 'afl_custom_mutator'" errors >/dev/null; then
    if grep -F "PROGRAM ABORT" errors >/dev/null; then
        echo CUT------------------------------------------------------------------CUT
        cat errors
        echo CUT------------------------------------------------------------------CUT
        $ECHO "$RED[!] afl-fuzz aborted even though mutator was loaded"
        CODE=1
    else
        $ECHO "$GREEN[+] afl-fuzz is working correctly with the Nautilus mutator"
    fi
  else
    echo CUT------------------------------------------------------------------CUT
    cat errors
    echo CUT------------------------------------------------------------------CUT
    $ECHO "$RED[!] afl-fuzz is not working correctly with the Nautilus mutator"
    CODE=1
  fi

  # Check if we found a crash (optional but good verification)
  if ls out-nautilus/default/crashes/id* >/dev/null 2>&1; then
      $ECHO "$GREEN[+] Crash found! Nautilus generated the target string."
  else
      $ECHO "$RED[!] No crash found. Nautilus might not be generating the target string."
      $ECHO "$RED[!] Check 'errors' file for details."
      # echo CUT------------------------------------------------------------------CUT
      # tail -n 20 errors
      # echo CUT------------------------------------------------------------------CUT
  fi

  # Check if queue or crashes contains files
  if ls out-nautilus/default/queue/id* >/dev/null 2>&1 || ls out-nautilus/default/crashes/id* >/dev/null 2>&1; then
      $ECHO "$GREEN[+] Queue/Crashes contains files."
  else
      $ECHO "$RED[!] Queue/Crashes is empty. Post-process persistence might be failing or afl-fuzz aborted."
      echo CUT------------------------------------------------------------------CUT
      cat errors
      echo CUT------------------------------------------------------------------CUT
      CODE=1
  fi

  # Clean
  rm -rf out-nautilus in-nautilus core.* test-nautilus-target
  # rm -rf errors # Keep errors for debugging


. ./test-post.sh
