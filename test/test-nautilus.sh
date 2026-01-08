#!/bin/sh

TEST_DIR=$(pwd)
. ./test-pre.sh

#$ECHO "$BLUE[*] Testing: nautilus mutator"

#temp block
$ECHO "$BLUE[*] Testing: nautilus mutator $RED DISABLED$WHITE"
. ./test-post.sh
exit 0

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

# Compile the vulnerable program
rm -f test-nautilus-target
../afl-cc -o test-nautilus-target test-nautilus-target.c > compilation_errors 2>&1


# Create input directory
rm -rf in-nautilus
mkdir -p in-nautilus
printf "SIMPLE" > in-nautilus/in

# Verify target compilation
if [ ! -x "./test-nautilus-target" ]; then
  $ECHO "$RED[!] test-nautilus-target failed to compile."
  echo "Compiler output:"
  cat compilation_errors
  rm -f compilation_errors
  exit 1
fi
rm -f compilation_errors

# --- A/B TEST START ---

$ECHO "$BLUE[*] Starting A/B testing..."

# 1. Negative Test: Run WITHOUT Nautilus for 30s
# We expect this to FAIL to find the crash because the target is hard
$ECHO "$GREY[*] [A/B] Running AFL++ WITHOUT Nautilus (Negative Test - 30s)..."

rm -rf out-nautilus-neg
export AFL_NO_UI=1
export AFL_DISABLE_TRIM=1
export AFL_MAP_SIZE=65536
export AFL_DRIVER_DONT_DEFER=1

timeout 30s ../afl-fuzz -V 30 -m ${MEM_LIMIT} -i in-nautilus -o out-nautilus-neg -- ./test-nautilus-target >/dev/null 2>&1

if ls out-nautilus-neg/default/crashes/id* >/dev/null 2>&1; then
  $ECHO "$RED[!] [A/B] Unexpected test result: AFL++ found a crash WITHOUT Nautilus."
  $ECHO "$RED[!] It found: $(ls out-nautilus-neg/default/crashes/id*)"
  exit 1
else
  $ECHO "$GREEN[+] [A/B] Negative test passed: AFL++ found no crashes starting from 'SIMPLE' (as expected)."
fi

$ECHO "$GREY[*] [A/B] Running AFL++ WITH Nautilus (Positive Test - 120s)..."

rm -rf out-nautilus
export NAUTILUS_GRAMMAR_FILE="$(pwd)/test-nautilus-grammar.json"
export NAUTILUS_LOG=info

AFL_CUSTOM_MUTATOR_LIBRARY="$LIB_PATH" timeout 120s ../afl-fuzz -V 120 -m ${MEM_LIMIT} -i in-nautilus -o out-nautilus -d -- ./test-nautilus-target > errors 2>&1

unset NAUTILUS_GRAMMAR_FILE
unset NAUTILUS_LOG

# Check if afl-fuzz ran successfully and loaded the mutator
if grep -F "Found 'afl_custom_mutator'" errors >/dev/null; then
  if grep -F "PROGRAM ABORT" errors >/dev/null; then
    echo CUT------------------------------------------------------------------CUT
    cat errors
    echo CUT------------------------------------------------------------------CUT
    $ECHO "$RED[!] afl-fuzz aborted even though mutator was loaded"
    exit 1
  else
    $ECHO "$GREEN[+] afl-fuzz is working correctly with the Nautilus mutator"
  fi
else
  echo CUT------------------------------------------------------------------CUT
  cat errors
  echo CUT------------------------------------------------------------------CUT
  $ECHO "$RED[!] afl-fuzz is not working correctly with the Nautilus mutator"
  exit 1
fi

# Check for pure grammar crash
if grep -r "Nautilus_Grammar_Crash" out-nautilus/default/crashes/id* >/dev/null 2>&1; then
  $ECHO "$GREEN[+] [A/B] Positive test passed: Nautilus found the pure GRAMMAR crash!"
else
  $ECHO "$RED[!] [A/B] Positive test failed: Nautilus did NOT find the pure GRAMMAR crash!"
  exit 1
fi

# Check if we found Grammar + Normal Mutation crash
if grep -r "Nautilus_Token_0" out-nautilus/default/crashes/id* >/dev/null 2>&1; then
  $ECHO "$GREEN[+] [A/B] Positive test passed: Nautilus found the HYBRID crash (Grammar+Normal)!"
else
  $ECHO "$RED[!] [A/B] Positive test failed: Nautilus did NOT find the HYBRID crash ('...Token_0') in 30s."
  $ECHO "$RED[!] Check 'errors' file for details."
  cat errors
  exit 1
fi

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
  exit 1
fi

# Resume verification
$ECHO "$BLUE[*] Testing resume logic..."

export NAUTILUS_LOG=info
export NAUTILUS_GRAMMAR_FILE="$(pwd)/test-nautilus-grammar.json"
export AFL_NO_UI=1

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
  exit 1
fi

# Clean
rm -rf resume_log.txt
rm -rf out-nautilus out-nautilus-neg in-nautilus core.* test-nautilus-target
rm -rf errors

