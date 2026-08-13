#!/bin/bash
# Verifies that AFL_LLVM_C11 instrumentation (afl-c11-pass) is ignored by the
# comparison-learning passes (laf/cmplog) and the coverage passes (PCGUARD/LTO):
# enabling C11 must not let those passes act on the synthetic C11 comparison or
# give the synthetic C11 basic block a coverage guard.
#
# The C11 pass inserts, in the function entry, an artificial comparison
#   c11_gt = icmp ugt i32 <locals>, *(map+1)
# and splits the block, creating an artificial "Then" block holding only
#   store i32 <locals>, map+1        (carrying afl.skip metadata)
# Every check below targets that synthetic comparison / block specifically.
#
# Method notes (why these signals and not simpler ones):
#   - total instrumented-location counts are NOT used: C11 adds a real branch,
#     so coverage legitimately gains an edge block; the artificial-block guard
#     is masked in the total. We check the artificial block directly instead.
#   - laf byte-compares are re-merged by the post-laf -O2 pipeline, so we assert
#     the C11 icmp survives carrying afl.skip rather than counting byte splits.

cd "$(dirname "$0")/.." || exit 1

TEMP_DIR=$(mktemp -d)
cleanup() { rm -rf "$TEMP_DIR"; }
trap cleanup EXIT

RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'; GREY="\033[1;90m"
PASS=0; FAIL=0

if [ ! -x "./afl-clang-fast" ]; then
    echo "Error: afl-clang-fast not found. Build AFL++ first (make -f GNUmakefile.llvm)."
    exit 1
fi

# prefer the LLVM that afl-cc was built against: another opt cannot load our
# pass plugins and another llvm-dis cannot read our LTO bitcode
BINDIR=$(./afl-cc --version 2>/dev/null | sed -n 's/^InstalledDir: //p' | head -1)
test -d "$BINDIR" || BINDIR=.

OPT=$(command -v "$BINDIR/opt" || command -v opt || true)
OBJDUMP=$(command -v "$BINDIR/llvm-objdump" || command -v llvm-objdump || \
    command -v objdump)
LLVMDIS=$(command -v "$BINDIR/llvm-dis" || command -v llvm-dis || true)

SRC="$TEMP_DIR/c11test.c"
cat > "$SRC" <<'EOF'
int target(int a) {
  volatile int w = a;
  volatile int x = a + 1;
  volatile int y = a + 2;
  volatile int z = a + 3;
  if ((w ^ x ^ y ^ z) == 0x12345678) return 1;
  return 0;
}
int main(int argc, char **argv) { return target(argc); }
EOF

ok()   { printf "%-50s ${GREEN}PASS${NC}\n" "$1"; PASS=$((PASS+1)); }
bad()  { printf "%-50s ${RED}FAIL${NC} (%s)\n" "$1" "$2"; FAIL=$((FAIL+1)); }
skip() { printf "%-50s ${GREY}SKIP${NC} (%s)\n" "$1" "$2"; }

# Print the IR basic block(s) (blank-line-separated paragraphs) that contain the
# C11 store, i.e. the artificial "Then" block.
artificial_block() { awk 'BEGIN{RS="";} /store i32 [0-9]+, ptr %[0-9]+, align 1, !nosanitize.*!afl\.skip/' "$1"; }

echo -e "$GREY[*] C11 interference checks..."

# --- 0. C11 actually inserts its comparison (opt-only, names intact) --------
if [ -n "$OPT" ] && [ -x ./afl-c11-pass.so ]; then
    ./afl-clang-fast -O0 -Xclang -disable-O0-optnone -S -emit-llvm "$SRC" \
        -o "$TEMP_DIR/pre.ll" >/dev/null 2>&1
    "$OPT" -load-pass-plugin=./afl-c11-pass.so -passes=c11-instr -S \
        "$TEMP_DIR/pre.ll" -o "$TEMP_DIR/post.ll" 2>/dev/null
    if grep -q 'c11_gt' "$TEMP_DIR/post.ll"; then
        ok "C11 inserts its comparison"
    else
        bad "C11 inserts its comparison" "c11_gt not found after c11-instr"
    fi
else
    skip "C11 inserts its comparison" "opt or pass .so missing"
fi

# --- 1. laf must not split the C11 icmp -------------------------------------
# If split, the afl.skip i32 icmp is consumed; the re-merged wide compare (if
# any) does not carry afl.skip. So "an icmp still carries afl.skip" == not split.
AFL_LLVM_C11=1 AFL_LLVM_LAF_ALL=1 ./afl-clang-fast -O2 -S -emit-llvm "$SRC" \
    -o "$TEMP_DIR/laf.ll" >/dev/null 2>&1
n=$(grep -cE 'icmp .*!afl\.skip' "$TEMP_DIR/laf.ll")
if [ "$n" -ge 1 ]; then
    ok "laf: C11 icmp not split (afl.skip icmp survives)"
else
    bad "laf: C11 icmp not split" "no icmp carries afl.skip (C11 icmp was split)"
fi

# --- 2. cmplog must not hook the C11 icmp -----------------------------------
AFL_CMPLOG=1 ./afl-clang-fast -O2 -c "$SRC" -o "$TEMP_DIR/cl_off.o" >/dev/null 2>&1
AFL_LLVM_C11=1 AFL_CMPLOG=1 ./afl-clang-fast -O2 -c "$SRC" \
    -o "$TEMP_DIR/cl_on.o" >/dev/null 2>&1
# substring match: real hook symbols are __cmplog_ins_hook{1,2,4,8,16,N}
off=$("$OBJDUMP" -r "$TEMP_DIR/cl_off.o" 2>/dev/null | grep -c '__cmplog_ins_hook')
on=$("$OBJDUMP" -r "$TEMP_DIR/cl_on.o" 2>/dev/null | grep -c '__cmplog_ins_hook')
if [ "$off" = "$on" ]; then
    ok "cmplog: C11 icmp not hooked (hooks: $off)"
else
    bad "cmplog: C11 icmp not hooked" "off=$off on=$on (C11 icmp got hooked)"
fi

# --- 3. PCGUARD must not put a guard on the artificial block -----------------
AFL_LLVM_C11=1 ./afl-clang-fast -O2 -S -emit-llvm "$SRC" \
    -o "$TEMP_DIR/pcg.ll" >/dev/null 2>&1
blk=$(artificial_block "$TEMP_DIR/pcg.ll")
if [ -z "$blk" ]; then
    bad "PCGUARD: artificial block not instrumented" "C11 store block not found in IR"
elif echo "$blk" | grep -q '__sancov_gen_'; then
    bad "PCGUARD: artificial block not instrumented" "guard (__sancov_gen_) in C11 block"
else
    ok "PCGUARD: artificial block not instrumented"
fi

# --- 4. LTO must not put a guard on the artificial block --------------------
if [ -x ./afl-clang-lto ] && [ -n "$LLVMDIS" ]; then
    AFL_LLVM_C11=1 ./afl-clang-lto -O2 "$SRC" -o "$TEMP_DIR/lto.bc" \
        -Wl,--lto-emit-llvm >/dev/null 2>&1
    "$LLVMDIS" "$TEMP_DIR/lto.bc" -o "$TEMP_DIR/lto.ll" 2>/dev/null
    blk=$(artificial_block "$TEMP_DIR/lto.ll")
    if [ -z "$blk" ]; then
        bad "LTO: artificial block not instrumented" "C11 store block not found in IR"
    elif echo "$blk" | grep -qE 'add i8 %[0-9]+, 1'; then
        bad "LTO: artificial block not instrumented" "coverage increment in C11 block"
    else
        ok "LTO: artificial block not instrumented"
    fi
else
    skip "LTO: artificial block not instrumented" "afl-clang-lto or llvm-dis missing"
fi

echo -e "$GREY[*] $PASS passed, $FAIL failed.${NC}"
[ "$FAIL" -eq 0 ]
