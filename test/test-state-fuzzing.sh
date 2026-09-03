#!/bin/bash

set -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

cd "${SCRIPT_DIR}" || exit 1
export AFL_PATH="${ROOT_DIR}"

GREY="\033[1;90m"
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;93m"
RESET="\033[0m"

CODE=0
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/afl-state-fuzzing.XXXXXX")"

say() {

  printf "%b\n" "$*"

}

ok() {

  say "${GREEN}[+] $*${RESET}"

}

fail() {

  say "${RED}[!] $*${RESET}"
  CODE=1

}

skip() {

  say "${YELLOW}[-] skipped: $*${RESET}"

}

cleanup() {

  rm -rf "${WORKDIR}"

}

trap cleanup EXIT

say "${GREY}[*] testing state fuzzing mode (-J)${RESET}"

AFL_FUZZ="${ROOT_DIR}/afl-fuzz"
AFL_CC="${ROOT_DIR}/afl-clang-fast"

if [ ! -x "${AFL_FUZZ}" ]; then

  skip "afl-fuzz not built"
  exit 0

fi

# ---------------------------------------------------------------- option parsing

# -J with no argument, every part on.
# afl-fuzz -h exits non-zero, so capture first: with pipefail a direct pipe
# would report failure even on a match.
USAGE="$("${AFL_FUZZ}" -h 2>&1)"

if echo "${USAGE}" | grep -qF -- "-J[letters]"; then

  ok "-J is documented in the usage text"

else

  fail "-J missing from usage text"

fi

# An unknown letter must be a hard error, not a silent no-op.
OUT="$("${AFL_FUZZ}" -Jq -i "${WORKDIR}" -o "${WORKDIR}/o" -- /bin/true 2>&1)"
if echo "${OUT}" | grep -q "Unknown option value 'q' in -J"; then

  ok "-J rejects an unknown letter"

else

  fail "-J did not reject the unknown letter 'q'"
  echo "${OUT}" | tail -3

fi

# Every documented letter must be accepted. A rejected letter aborts before the
# target check, so we look for the absence of the -J complaint specifically.
for letter in d c b m w; do

  OUT="$("${AFL_FUZZ}" "-J${letter}" -i "${WORKDIR}" -o "${WORKDIR}/o" \
         -- /bin/true 2>&1)"
  if echo "${OUT}" | grep -q "in -J"; then

    fail "-J${letter} was rejected"

  fi

done

ok "-J accepts every documented letter"

# ------------------------------------------------------------------- end to end

if [ ! -x "${AFL_CC}" ]; then

  skip "afl-clang-fast not built, skipping the end-to-end part"
  exit ${CODE}

fi

BIN="${WORKDIR}/test-state-machine"

IJON_BUILD=1

# --allow-multiple-definition is a GNU ld spelling. Apple's ld rejects it
# outright, which made the IJON build fail for the wrong reason and quietly
# drop the whole test to the uninstrumented fallback below. Probe for it and
# only pass it where the linker knows it.
ALLOW_MULTI=""
printf 'int main(void) { return 0; }\n' > "${WORKDIR}/ldprobe.c"

if AFL_QUIET=1 "${AFL_CC}" -Wl,--allow-multiple-definition \
     -o "${WORKDIR}/ldprobe" "${WORKDIR}/ldprobe.c" > /dev/null 2>&1; then

  ALLOW_MULTI="-Wl,--allow-multiple-definition"

fi

if ! AFL_LLVM_IJON=1 AFL_QUIET=1 "${AFL_CC}" -O0 \
      -I "${ROOT_DIR}/include" ${ALLOW_MULTI} \
      -o "${BIN}" "${SCRIPT_DIR}/test-state-machine.c" \
      > "${WORKDIR}/build.log" 2>&1; then

  say "${GREY}[*] IJON build failed, retrying without it${RESET}"
  IJON_BUILD=0

  if ! AFL_QUIET=1 "${AFL_CC}" -O0 -I "${ROOT_DIR}/include" -o "${BIN}" \
        "${SCRIPT_DIR}/test-state-machine.c" \
        > "${WORKDIR}/build.log" 2>&1; then

    skip "cannot build the test target"
    tail -20 "${WORKDIR}/build.log"
    exit ${CODE}

  fi

fi

if [ "${IJON_BUILD}" = "1" ]; then

  ok "built the state machine target with IJON annotations"

else

  say "${GREY}[*] built the state machine target without IJON${RESET}"

fi

mkdir -p "${WORKDIR}/in"
printf 'SESS%060d' 0 > "${WORKDIR}/in/seed"
printf '\x10\x00\x00\x20\xa7\x00\x30\x00\x04AAAA\x60\x00\x00' \
  >> "${WORKDIR}/in/seed"

run_afl() {

  local out="$1"
  shift

  AFL_NO_UI=1 AFL_NO_AFFINITY=1 \
    timeout -s INT 40 "${AFL_FUZZ}" "$@" -V 15 \
      -i "${WORKDIR}/in" -o "${out}" -- "${BIN}" @@ \
      > "${out}.log" 2>&1

  return 0

}

stats_of() {

  local out="$1"

  if [ -r "${out}/default/fuzzer_stats" ]; then

    cat "${out}/default/fuzzer_stats"

  elif [ -r "${out}/fuzzer_stats" ]; then

    cat "${out}/fuzzer_stats"

  fi

}

has_key() {

  echo "$2" | grep -qE "^$1 *:"

}

# Baseline: without -J none of the new keys may appear. This is the guarantee
# that the feature is genuinely inert when it is not asked for.
run_afl "${WORKDIR}/out_plain"
PLAIN="$(stats_of "${WORKDIR}/out_plain")"

if [ -z "${PLAIN}" ]; then

  fail "baseline run produced no fuzzer_stats"
  tail -20 "${WORKDIR}/out_plain.log"

else

  LEAKED=""
  for key in state_mode shelf_cells_used contract_check cost_fork_us \
             target_time_pct slow_path_execs; do

    if has_key "${key}" "${PLAIN}"; then LEAKED="${LEAKED} ${key}"; fi

  done

  if [ -n "${LEAKED}" ]; then

    fail "state fuzzing keys present without -J:${LEAKED}"

  else

    ok "no state fuzzing keys leak into a plain run"

  fi

fi

# Full run with every part enabled. Bare -J does not do this any more, so the
# letters are spelled out.
if grep -qE '^#define AFL_TARGET_WATCHDOG' ../include/config.h; then

  ALL_LETTERS="dcbwm"

else

  ALL_LETTERS="dcbm"

fi

run_afl "${WORKDIR}/out_state" "-J${ALL_LETTERS}"
STATE="$(stats_of "${WORKDIR}/out_state")"

if [ -z "${STATE}" ]; then

  fail "-J${ALL_LETTERS} run produced no fuzzer_stats"
  tail -20 "${WORKDIR}/out_state.log"
  exit ${CODE}

fi

MISSING=""
for key in state_mode slow_path_execs slow_path_pct \
           shelf_cells_used shelf_members \
           contract_check contract_diff cost_fork_us cost_setup_us \
           hw_only_saves hw_credits hw_slots; do

  if ! has_key "${key}" "${STATE}"; then MISSING="${MISSING} ${key}"; fi

done

if [ -n "${MISSING}" ]; then

  fail "missing fuzzer_stats keys under -J${ALL_LETTERS}:${MISSING}"

else

  ok "every state fuzzing stat is reported when every letter is asked for"

fi

if has_key cost_prefix_pct "${STATE}"; then

  fail "cost_prefix_pct is reported without a mutator that knows the boundaries"

else

  ok "-Jb skips the prefix decomposition when no mutator reports boundaries"

fi

MODE="$(echo "${STATE}" | grep -E '^state_mode *:' | sed 's/.*: *//')"
if [ "${MODE}" = "${ALL_LETTERS}" ]; then

  ok "-J${ALL_LETTERS} enables every part (${MODE})"

else

  fail "-J${ALL_LETTERS} reported state_mode '${MODE}', expected '${ALL_LETTERS}'"

fi

run_afl "${WORKDIR}/out_default" -J
DEFSTATE="$(stats_of "${WORKDIR}/out_default")"
DEFMODE="$(echo "${DEFSTATE}" | grep -E '^state_mode *:' | sed 's/.*: *//')"
if [ "${DEFMODE}" = "dcb" ]; then

  ok "bare -J selects the measured default set (${DEFMODE})"

else

  fail "bare -J reported state_mode '${DEFMODE}', expected 'dcb'"

fi

LEAKED=""
for key in hw_only_saves hw_credits hw_slots; do

  if has_key "${key}" "${DEFSTATE}"; then LEAKED="${LEAKED} ${key}"; fi

done

if [ -n "${LEAKED}" ]; then

  fail "bare -J reported stats for letters it does not enable:${LEAKED}"

else

  ok "bare -J reports nothing for the letters it leaves off"

fi

# Time accounting is no longer implied by -J.
if has_key "target_time_pct" "${STATE}"; then

  fail "-J alone reported target_time_pct, that needs AFL_TIME_ACCOUNTING"

else

  ok "-J alone does not turn on time accounting"

fi

# The fuzzer must actually make progress, not just report about itself.
QCOUNT="$(echo "${STATE}" | grep -E '^corpus_count *:' | sed 's/.*: *//')"
if [ -n "${QCOUNT}" ] && [ "${QCOUNT}" -gt 1 ]; then

  ok "-J run grew the queue to ${QCOUNT} entries"

else

  fail "-J run did not grow the queue (corpus_count=${QCOUNT:-none})"
  tail -20 "${WORKDIR}/out_state.log"

fi

# Selective letters must enable only what was asked for.
run_afl "${WORKDIR}/out_dm" -Jdm
DM="$(stats_of "${WORKDIR}/out_dm")"

if [ -n "${DM}" ]; then

  MODE="$(echo "${DM}" | grep -E '^state_mode *:' | sed 's/.*: *//')"
  if [ "${MODE}" = "dm" ]; then

    ok "-Jdm enables only d and m"

  else

    fail "-Jdm reported state_mode '${MODE}', expected 'dm'"

  fi

  if has_key "contract_check" "${DM}" || has_key "cost_fork_us" "${DM}"; then

    fail "-Jdm reported stats belonging to letters that were not requested"

  else

    ok "-Jdm reports no stats for parts it did not enable"

  fi

fi

# Time accounting must be reachable without -J at all.
export AFL_TIME_ACCOUNTING=1
run_afl "${WORKDIR}/out_ta"
unset AFL_TIME_ACCOUNTING
TA="$(stats_of "${WORKDIR}/out_ta")"
if [ -n "${TA}" ] && has_key "target_time_pct" "${TA}"; then

  ok "AFL_TIME_ACCOUNTING works without -J"

else

  fail "AFL_TIME_ACCOUNTING did not produce target_time_pct"

fi

if [ ${CODE} -eq 0 ]; then

  say "${GREEN}[+] state fuzzing tests passed${RESET}"

else

  say "${RED}[!] state fuzzing tests failed${RESET}"

fi

exit ${CODE}
