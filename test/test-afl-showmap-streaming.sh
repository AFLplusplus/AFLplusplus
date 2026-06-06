#!/bin/sh

# Test afl-showmap streaming mode (-S flag)
# Verifies that streaming mode produces identical coverage to batch mode

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: afl-showmap streaming mode (-S flag)"

# Check if afl-showmap exists
test -e ../afl-showmap || {
  $ECHO "$YELLOW[-] afl-showmap not found, skipping streaming tests"
  INCOMPLETE=1
  . ./test-post.sh
  exit 0
}

# Check if streaming mode is supported
../afl-showmap -h 2>&1 | grep -q '\-S' || {
  $ECHO "$YELLOW[-] afl-showmap does not support -S streaming mode, skipping"
  INCOMPLETE=1
  . ./test-post.sh
  exit 0
}

$ECHO "$GREEN[+] afl-showmap supports streaming mode (-S flag)"

# Check for Python (needed to parse binary streaming output)
command -v python3 >/dev/null 2>&1 || {
  $ECHO "$YELLOW[-] python3 not found, skipping streaming tests"
  INCOMPLETE=1
  . ./test-post.sh
  exit 0
}

# Compile test binary if needed
AFL_COMPILER=afl-clang-fast
test -e ../afl-clang-fast || AFL_COMPILER=afl-cc
test -e ../${AFL_COMPILER} || {
  $ECHO "$RED[!] no AFL compiler found, cannot compile test binary"
  CODE=1
  . ./test-post.sh
  exit 1
}

test -e test-instr.plain || {
  $ECHO "$GREY[*] compiling test-instr.plain..."
  ../${AFL_COMPILER} -o test-instr.plain -O0 ../test-instr.c > /dev/null 2>&1
}

test -e test-instr.plain || {
  $ECHO "$RED[!] failed to compile test-instr.plain"
  CODE=1
  . ./test-post.sh
  exit 1
}

# Python helper to create streaming input: [u32 len][data]... [u32 0]
# Usage: create_streaming_input "input1" "input2" ... > output_file
create_streaming_input() {
  python3 -c "
import sys
import struct

for arg in sys.argv[1:]:
    data = (arg + '\n').encode()
    sys.stdout.buffer.write(struct.pack('<I', len(data)))
    sys.stdout.buffer.write(data)
sys.stdout.buffer.write(struct.pack('<I', 0))
" "$@"
}

# Python helper to parse streaming binary output to sorted edge list
# Streaming output: [u16 status][u32 edge_count][{u32 edge_id, u8 hit_count}*]
# Output format matches batch mode: 6-digit zero-padded edge IDs
parse_streaming() {
  python3 -c "
import sys, struct
read = sys.stdin.buffer.read
while True:
    hdr = read(6)
    if len(hdr) < 6:
        break
    status, n_edges = struct.unpack('<HI', hdr)
    edges = [struct.unpack('<IB', read(5))[0] for _ in range(n_edges)]
    for e in sorted(edges):
        print(f'{e:06d}')
"
}

# Helper to extract edge IDs from text showmap output
parse_text() {
  cut -d: -f1 | sort -n
}

# ============================================================================
# Test 1: Streaming vs batch mode produce same coverage (input "0")
# ============================================================================
$ECHO "$GREY[*] Test 1: streaming vs batch mode equivalence (input '0')"

# Batch mode
echo "0" | AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o .streaming-batch0 -- ./test-instr.plain > /dev/null 2>&1
BATCH0=$(cat .streaming-batch0 | parse_text)

# Streaming mode
create_streaming_input "0" > .streaming-input0
AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -S -t 1000 -- ./test-instr.plain < .streaming-input0 > .streaming-stream0 2>/dev/null
STREAM0=$(cat .streaming-stream0 | parse_streaming)

test "$BATCH0" = "$STREAM0" && {
  $ECHO "$GREEN[+] streaming mode produces same coverage as batch mode for input '0'"
} || {
  $ECHO "$RED[!] streaming mode coverage differs from batch mode for input '0'"
  CODE=1
}

rm -f .streaming-batch0 .streaming-stream0 .streaming-input0

# ============================================================================
# Test 2: Streaming vs batch mode produce same coverage (input "1")
# ============================================================================
$ECHO "$GREY[*] Test 2: streaming vs batch mode equivalence (input '1')"

# Batch mode
echo "1" | AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -o .streaming-batch1 -- ./test-instr.plain > /dev/null 2>&1
BATCH1=$(cat .streaming-batch1 | parse_text)

# Streaming mode
create_streaming_input "1" > .streaming-input1
AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -S -t 1000 -- ./test-instr.plain < .streaming-input1 > .streaming-stream1 2>/dev/null
STREAM1=$(cat .streaming-stream1 | parse_streaming)

test "$BATCH1" = "$STREAM1" && {
  $ECHO "$GREEN[+] streaming mode produces same coverage as batch mode for input '1'"
} || {
  $ECHO "$RED[!] streaming mode coverage differs from batch mode for input '1'"
  CODE=1
}

rm -f .streaming-batch1 .streaming-stream1 .streaming-input1

# ============================================================================
# Test 3: Different inputs produce different coverage in streaming mode
# ============================================================================
$ECHO "$GREY[*] Test 3: streaming mode differentiates inputs"

test "$STREAM0" != "$STREAM1" && {
  $ECHO "$GREEN[+] streaming mode produces different coverage for different inputs"
} || {
  $ECHO "$RED[!] streaming mode should produce different coverage for '0' vs '1'"
  CODE=1
}

# ============================================================================
# Test 4: Streaming mode determinism
# ============================================================================
$ECHO "$GREY[*] Test 4: streaming mode determinism"

create_streaming_input "0" > .streaming-det-input
AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -S -t 1000 -- ./test-instr.plain < .streaming-det-input > .streaming-det1 2>/dev/null
AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -S -t 1000 -- ./test-instr.plain < .streaming-det-input > .streaming-det2 2>/dev/null

DET1=$(cat .streaming-det1 | parse_streaming)
DET2=$(cat .streaming-det2 | parse_streaming)

test "$DET1" = "$DET2" && {
  $ECHO "$GREEN[+] streaming mode is deterministic"
} || {
  $ECHO "$RED[!] streaming mode is not deterministic"
  CODE=1
}

rm -f .streaming-det1 .streaming-det2 .streaming-det-input

# ============================================================================
# Test 5: Multiple inputs in single streaming session
# ============================================================================
$ECHO "$GREY[*] Test 5: multiple inputs in single streaming session"

create_streaming_input "0" "1" "test" > .streaming-multi-input
AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} -S -t 1000 -- ./test-instr.plain < .streaming-multi-input > .streaming-multi 2>/dev/null

# Should have 3 coverage maps in output
MULTI_SIZE=$(wc -c < .streaming-multi)
test "$MULTI_SIZE" -gt 20 && {
  $ECHO "$GREEN[+] streaming mode handled multiple inputs (${MULTI_SIZE} bytes)"
} || {
  $ECHO "$RED[!] streaming mode failed with multiple inputs"
  CODE=1
}

rm -f .streaming-multi .streaming-multi-input

# Cleanup
rm -f test-instr.plain

. ./test-post.sh
