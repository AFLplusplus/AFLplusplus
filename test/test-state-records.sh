#!/bin/bash

set -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
SRC_DIR="${ROOT_DIR}/custom_mutators/state_records"

cd "${SCRIPT_DIR}" || exit 1
export AFL_PATH="${ROOT_DIR}"

GREY="\033[1;90m"
BLUE="\033[1;94m"
GREEN="\033[0;32m"
RED="\033[0;31m"
RESET="\033[0m"

CODE=0
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/afl-state-records.XXXXXX")"
MUTATOR="${WORKDIR}/state_records.so"
BIN="${WORKDIR}/example_harness"

say() {

  printf "%b\n" "$*"

}

fail() {

  say "${RED}[!] $*${RESET}"
  CODE=1

}

cleanup() {

  rm -rf "${WORKDIR}"

}

count_queue() {

  find "$1" -maxdepth 1 -type f -name 'id:*' 2>/dev/null | wc -l | tr -d ' '

}

trap cleanup EXIT

say "${BLUE}[*] Testing: state_records custom mutator${RESET}"

if [ ! -x "${ROOT_DIR}/afl-clang-fast" ] || [ ! -x "${ROOT_DIR}/afl-fuzz" ]; then

  say "${GREY}[*] afl-clang-fast or afl-fuzz is missing, skipping${RESET}"
  exit 0

fi

if ${CC:-cc} -O3 -fPIC -shared -g -I "${ROOT_DIR}/include" -I "${SRC_DIR}" \
  "${SRC_DIR}/state_records.c" -o "${MUTATOR}" \
  > "${WORKDIR}/mutator.log" 2>&1; then

  say "${GREEN}[+] Custom mutator built${RESET}"

else

  cat "${WORKDIR}/mutator.log"
  fail "Custom mutator failed to build"
  exit "${CODE}"

fi

if AFL_QUIET=1 "${ROOT_DIR}/afl-clang-fast" -O0 -g -I "${SRC_DIR}" \
  "${SRC_DIR}/example_harness.c" -o "${BIN}" \
  > "${WORKDIR}/harness.log" 2>&1; then

  say "${GREEN}[+] Example harness built${RESET}"

else

  cat "${WORKDIR}/harness.log"
  fail "Example harness failed to build"
  exit "${CODE}"

fi

IN_DIR="${WORKDIR}/in"
OUT_DIR="${WORKDIR}/out"
mkdir -p "${IN_DIR}"

# OPEN slot 1 with "AAAA", WRITE slot 2 from slot 1, COMMIT
printf '\132\245\001\001\000\000\004\000AAAA\132\245\002\002\001\002\000\000\132\245\006\000\000\000\000\000' \
  > "${IN_DIR}/program1"
# OPEN slot 3 with "BBBBBBBB", READ slot 3
printf '\132\245\001\003\000\000\010\000BBBBBBBB\132\245\003\000\003\000\000\000' \
  > "${IN_DIR}/program2"

SEEDS="$(find "${IN_DIR}" -maxdepth 1 -type f | wc -l | tr -d ' ')"

say "${BLUE}[*] Running afl-fuzz with the record mutator on ${SEEDS} seeds${RESET}"

if AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_TRY_AFFINITY=1 \
  AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
  AFL_CUSTOM_MUTATOR_LIBRARY="${MUTATOR}" \
  "${ROOT_DIR}/afl-fuzz" -V5 -d -s 1 -m none -i "${IN_DIR}" -o "${OUT_DIR}" \
  -- "${BIN}" > "${WORKDIR}/fuzz.log" 2>&1; then

  say "${GREEN}[+] Fuzzing run completed${RESET}"

else

  cat "${WORKDIR}/fuzz.log"
  fail "Fuzzing run failed"
  exit "${CODE}"

fi

if grep -q "Loading custom mutator library" "${WORKDIR}/fuzz.log"; then

  say "${GREEN}[+] afl-fuzz loaded the record mutator${RESET}"

else

  cat "${WORKDIR}/fuzz.log"
  fail "afl-fuzz did not load the record mutator"

fi

QUEUE="${OUT_DIR}/default/queue"
FOUND="$(count_queue "${QUEUE}")"

if [ "${FOUND}" -gt "${SEEDS}" ]; then

  say "${GREEN}[+] Queue grew from ${SEEDS} to ${FOUND} entries${RESET}"

else

  fail "Queue did not grow, ${SEEDS} seeds and ${FOUND} entries"

fi

DESCRIBED="$(find "${QUEUE}" -maxdepth 1 -type f -name '*rec_*' 2>/dev/null | wc -l | tr -d ' ')"

if [ "${DESCRIBED}" -gt 0 ]; then

  say "${GREEN}[+] ${DESCRIBED} queue entries were found by a record operator${RESET}"

else

  say "${GREY}[*] No queue entry came from a record operator in this run${RESET}"

fi

# The payload arena is grown with afl_realloc(), which may move it. A record
# operator that copies inside the arena must therefore not hold a pointer
# across the growth. The seed program below leaves the arena eight bytes below
# its capacity, so the first operator that appends has to reallocate.

say "${BLUE}[*] Checking record operators against arena growth under ASAN${RESET}"

cat > "${WORKDIR}/arena_driver.c" <<'DRIVER_EOF'
#include <stdint.h>
#include <stdlib.h>
#include "state_records.h"

void  *afl_custom_init(void *afl, unsigned int seed);
size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size);
void   afl_custom_deinit(void *data);

#define NREC 65
#define PLEN 1008

int main(int argc, char **argv) {

  static state_rec_t recs[NREC];
  static uint8_t     pay[PLEN];
  static uint8_t     in[1 << 20];
  size_t             i, len;
  unsigned           seed = argc > 1 ? (unsigned)atoi(argv[1]) : 1;

  for (i = 0; i < PLEN; i++) { pay[i] = (uint8_t)i; }

  for (i = 0; i < NREC; i++) {

    state_rec_make(&recs[i], STATE_OP_WRITE, (uint8_t)i, 0, 0, pay, PLEN);

  }

  len = state_rec_encode(recs, NREC, in, sizeof(in));

  void *d = afl_custom_init(NULL, seed);
  if (!d) { return 1; }

  for (i = 0; i < 3; i++) {

    uint8_t *out = NULL;
    size_t   r = afl_custom_fuzz(d, in, len, &out, in, len, 1 << 20);
    if (r && out) {

      volatile uint8_t s = out[0] ^ out[r - 1];
      (void)s;

    }

  }

  afl_custom_deinit(d);
  return 0;

}
DRIVER_EOF

if ${CC:-cc} -fsanitize=address -O1 -g -I "${ROOT_DIR}/include" -I "${SRC_DIR}" \
  "${SRC_DIR}/state_records.c" "${WORKDIR}/arena_driver.c" \
  -o "${WORKDIR}/arena_driver" > "${WORKDIR}/arena.log" 2>&1; then

  ARENA_FAIL=0

  for SEED in $(seq 1 120); do

    if ! ASAN_OPTIONS=detect_leaks=0 "${WORKDIR}/arena_driver" "${SEED}" \
      >> "${WORKDIR}/arena.log" 2>&1; then

      ARENA_FAIL=$((ARENA_FAIL + 1))

    fi

  done

  if [ "${ARENA_FAIL}" -eq 0 ]; then

    say "${GREEN}[+] Record operators survive arena growth over 120 seeds${RESET}"

  else

    grep -m1 "ERROR: AddressSanitizer" "${WORKDIR}/arena.log"
    fail "${ARENA_FAIL} of 120 seeds hit a memory error during arena growth"

  fi

else

  cat "${WORKDIR}/arena.log"
  say "${GREY}[*] ASAN build unavailable, skipping the arena growth check${RESET}"

fi

JB_DIR="${WORKDIR}/out_jb"

if AFL_NO_UI=1 AFL_SKIP_CPUFREQ=1 AFL_TRY_AFFINITY=1 \
  AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
  AFL_CUSTOM_MUTATOR_LIBRARY="${MUTATOR}" \
  "${ROOT_DIR}/afl-fuzz" -Jb -V5 -d -s 1 -m none -i "${IN_DIR}" -o "${JB_DIR}" \
  -- "${BIN}" > "${WORKDIR}/jb.log" 2>&1; then

  if grep -q "^cost_prefix_pct" "${JB_DIR}/default/fuzzer_stats"; then

    say "${GREEN}[+] -Jb reports cost_prefix_pct with a boundary-aware mutator${RESET}"

  else

    grep -E "cost_fork_us|cost_setup_us|cost_prefix" \
      "${JB_DIR}/default/fuzzer_stats" || true
    fail "-Jb does not report cost_prefix_pct"

  fi

else

  tail -20 "${WORKDIR}/jb.log"
  fail "-Jb run with the record mutator failed"

fi

# nm -D is the ELF spelling; Mach-O has no dynamic symbol table and nm -D
# fails there, so fall back to nm -g. The Mach-O name carries a leading
# underscore, which the unanchored grep below matches either way.
if { nm -D "${MUTATOR}" 2>/dev/null || nm -g "${MUTATOR}" 2>/dev/null; } \
     | grep -q afl_custom_describe_state_ops; then

  say "${GREEN}[+] state_records exports afl_custom_describe_state_ops${RESET}"

else

  fail "state_records does not export afl_custom_describe_state_ops"

fi

exit "${CODE}"
