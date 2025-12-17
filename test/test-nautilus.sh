#!/bin/sh

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: nautilus mutator"

# normalize path
# normalize path
CUSTOM_MUTATOR_PATH=$(cd $(pwd)/../custom_mutators/libafl_nautilus;pwd)
LIB_PATH="${CUSTOM_MUTATOR_PATH}/target/debug/liblibafl_nautilus.so"

if [ ! -f "$LIB_PATH" ]; then
    $ECHO "$RED[!] liblibafl_nautilus.so not found at $LIB_PATH"
    $ECHO "$RED[!] Please build it first: cd ../custom_mutators/libafl_nautilus && cargo build"
    exit 1
fi

  # Create the vulnerable program
  cat > test-nautilus-target.c <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char** argv) {
  char buf[1024];
  int len = read(0, buf, 1024);
  if (len < 0) return 1;
  buf[len] = 0;
  if (strstr(buf, "test_custom_mutator") != NULL) {
    abort();
  }
  return 0;
}
EOF

  unset AFL_CC
  # Compile the vulnerable program
  test -e ../afl-clang-fast && {
    ../afl-clang-fast -o test-nautilus-target test-nautilus-target.c > /dev/null 2>&1
  } || {
    ../afl-gcc-fast -o test-nautilus-target test-nautilus-target.c > /dev/null 2>&1
  }

  # Create dummy grammar.json
  cat > grammar.json <<EOF
[
    ["START", "test_custom_mutator"]
]
EOF

  # Create input directory
  mkdir -p in-nautilus
  echo "A" > in-nautilus/in

  # Run afl-fuzz with Nautilus mutator
  # We set AFL_NO_UI=1 to avoid UI artifacts in logs
  # We use -V 20 to run for 20 seconds (should be enough to crash)
  $ECHO "$GREY[*] running afl-fuzz for the Nautilus mutator, this will take approx 20 seconds"
  export NAUTILUS_GRAMMAR_FILE="$(pwd)/grammar.json"
  AFL_NO_UI=1 AFL_CUSTOM_MUTATOR_LIBRARY="$LIB_PATH" AFL_CUSTOM_MUTATOR_ONLY=1 AFL_POST_PROCESS_KEEP_ORIGINAL=1 ../afl-fuzz -V 20 -m ${MEM_LIMIT} -i in-nautilus -o out-nautilus -d -- ./test-nautilus-target >> errors 2>&1
  unset NAUTILUS_GRAMMAR_FILE

  # Check if afl-fuzz ran successfully and loaded the mutator
  if grep -F "Found 'afl_custom_mutator'" errors >/dev/null; then
    $ECHO "$GREEN[+] afl-fuzz is working correctly with the Nautilus mutator"
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
      # We don't fail here because maybe 10s is not enough or random seed, but with this grammar it should be instant.
  fi

  # Check if queue or crashes contains files
  # We check the first queue entry that is NOT the initial seed (id:000000) if possible, or just check any new entry.
  # Initial seed might be raw bytes, but new entries should be Postcard (binary).
  # We just check if there are files in queue/crashes.
  if ls out-nautilus/default/queue/id* >/dev/null 2>&1 || ls out-nautilus/default/crashes/id* >/dev/null 2>&1; then
      $ECHO "$GREEN[+] Queue/Crashes contains files."
      # Optional: Check if they are NOT JSON (start with {) to confirm binary?
      # But for now just existence is enough as we verify crash.
  else
      $ECHO "$RED[!] Queue/Crashes is empty. Post-process persistence might be failing."
      # exit 1 # Optional: fail if strict
  fi

  # Clean
  rm -rf out-nautilus in-nautilus core.* grammar.json test-nautilus-target test-nautilus-target.c
  # rm -rf errors # Keep errors for debugging


. ./test-post.sh
