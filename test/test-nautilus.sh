#!/bin/sh

TEST_DIR=$(pwd)
. ./test-pre.sh

$ECHO "$BLUE[*] Testing: nautilus mutator"

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

$ECHO "$BLUE[*] Running libafl_base mutator unit tests"
(cd "$CUSTOM_MUTATOR_PATH/../libafl_base" && cargo test --features="mutator") || exit 1

$ECHO "$BLUE[*] Running libafl_nautilus unit tests"
(cd "$CUSTOM_MUTATOR_PATH" && cargo test) || exit 1

LIBAFL_BASE_PATH=$(cd $(pwd)/../custom_mutators/libafl_base;pwd)
$ECHO "$BLUE[*] Running libafl_base unit tests"
(cd "$LIBAFL_BASE_PATH" && cargo test --features=mutator) || exit 1

  # Create the vulnerable program
  cat > test-nautilus-target.c <<EOF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void funcA(char* buf) {
    buf[1] = 'A';
}
void funcB(char* buf) {
    buf[2] = 'B';
}

int main(int argc, char** argv) {
  char buf[1024];
  int len = read(0, buf, 1024);
  if (len < 0) return 1;
  buf[len] = 0;
  
  if (buf[0] == 'A') {
    for (int i = 0; i < 1000; i++) buf[i % 1024] ^= 1;
  } else if (buf[0] == 'B') {
    abort();
  } else if (buf[0] == 'C') {
    for (int i = 0; i < 500; i++) buf[i % 1024] ^= 2;
  }
  
  if (strstr(buf, "test_custom_mutator") != NULL) {
    abort();
  }
  return 0;
}
EOF

  unset AFL_CC
  # Compile the vulnerable program
  rm -f test-nautilus-target
  ../afl-cc -o test-nautilus-target test-nautilus-target.c > compilation_errors 2>&1


  # Create input directory
  mkdir -p in-nautilus
  printf "AAAA" > in-nautilus/in

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
  export AFL_NO_UI=1
  export AFL_DISABLE_TRIM=1
  # export AFL_CUSTOM_MUTATOR_ONLY=1
  export AFL_MAP_SIZE=65536
  export AFL_DRIVER_DONT_DEFER=1
  export NAUTILUS_LOG=trace
  
  echo "DEBUG: Starting afl-fuzz..."
  touch errors
  AFL_CUSTOM_MUTATOR_LIBRARY="$LIB_PATH" timeout 60s ../afl-fuzz -V 20 -m ${MEM_LIMIT} -i in-nautilus -o out-nautilus -d -- ./test-nautilus-target >> errors 2>&1
  echo "DEBUG: afl-fuzz finished with code $?"
  ls -l errors
  
  unset NAUTILUS_GRAMMAR_FILE
  unset AFL_NO_UI
  unset AFL_CUSTOM_MUTATOR_ONLY

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
      # Verify shadow corpus exists and has files
      if ls out-nautilus/shadow_corpus/* >/dev/null 2>&1; then
         $ECHO "$GREEN[+] Shadow corpus populated."
         
         # Run dump_inputs on shadow corpus using cargo run directly
         $ECHO "$BLUE[*] Running dump_inputs on shadow_corpus..."
         mkdir -p out-nautilus/dumped_shadow
         
         (cd "$CUSTOM_MUTATOR_PATH" && cargo run --release --bin dump_inputs -- --grammar "$TEST_DIR/test-nautilus-grammar.json" --input "$TEST_DIR/out-nautilus/shadow_corpus" --output "$TEST_DIR/out-nautilus/dumped_shadow") || {
            $ECHO "$RED[!] dump_inputs failed"
            exit 1
         }
         
         if ls out-nautilus/dumped_shadow/* >/dev/null 2>&1; then
             $ECHO "$GREEN[+] dump_inputs successfully dumped shadow corpus files."
         else
             $ECHO "$RED[!] dump_inputs ran but produced no output!"
             exit 1
         fi

      else
         $ECHO "$RED[!] Shadow corpus empty or missing!"
         echo "--- Nautilus logs from errors ---"
         grep "Nautilus" errors | head -n 50
         echo "---------------------------------"
         CODE=1
      fi
  else
      $ECHO "$RED[!] Queue/Crashes is empty. Post-process persistence might be failing or afl-fuzz aborted."
      echo CUT------------------------------------------------------------------CUT
      cat errors
      echo CUT------------------------------------------------------------------CUT
      CODE=1
  fi

   # Resume verification
   if [ "$CODE" -eq 0 ]; then
     $ECHO "$BLUE[*] Testing resume logic..."
     
     # Run afl-fuzz again using the same output dir to trigger resume
     # We use a short timeout as we only care about initialization logs
     export NAUTILUS_LOG=info
     export NAUTILUS_GRAMMAR_FILE="$(pwd)/test-nautilus-grammar.json"
     export AFL_NO_UI=1
     
     # Capture stderr to resume_log.txt. 
     # We use || true because we might kill it with timeout or it might run briefly
     (AFL_CUSTOM_MUTATOR_LIBRARY="$LIB_PATH" timeout 5s ../afl-fuzz -V 5 -m ${MEM_LIMIT} -i in-nautilus -o out-nautilus -d -- ./test-nautilus-target >> resume_log.txt 2>&1) || true
     
     unset NAUTILUS_GRAMMAR_FILE
     unset AFL_NO_UI
     unset NAUTILUS_LOG
 
     if grep -q "RESUMED" resume_log.txt; then
         $ECHO "$GREEN[+] Resume logic verified: Loaded from shadow corpus."
     else
         $ECHO "$RED[!] Resume logic failed: Did not find 'RESUMED' in logs."
         echo "--- resume_log.txt ---"
         cat resume_log.txt
         echo "----------------------"
         CODE=1
     fi
   fi
 
   # Clean
   rm -rf resume_log.txt
   rm -rf out-nautilus in-nautilus core.* test-nautilus-target
   rm -rf errors


. ./test-post.sh
