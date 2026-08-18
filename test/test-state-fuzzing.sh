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
for letter in g p r d s c b h w; do

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

if ! AFL_LLVM_IJON=1 AFL_QUIET=1 "${AFL_CC}" -O0 \
      -I "${ROOT_DIR}/include" -Wl,--allow-multiple-definition \
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
  for key in state_mode ballast_pct gate_checked probe_pct state_signal \
             target_time_pct slow_path_execs; do

    if has_key "${key}" "${PLAIN}"; then LEAKED="${LEAKED} ${key}"; fi

  done

  if [ -n "${LEAKED}" ]; then

    fail "state fuzzing keys present without -J:${LEAKED}"

  else

    ok "no state fuzzing keys leak into a plain run"

  fi

fi

# Full run with every part enabled.
run_afl "${WORKDIR}/out_state" -J
STATE="$(stats_of "${WORKDIR}/out_state")"

if [ -z "${STATE}" ]; then

  fail "-J run produced no fuzzer_stats"
  tail -20 "${WORKDIR}/out_state.log"
  exit ${CODE}

fi

MISSING=""
for key in state_mode ballast_pct slow_path_execs slow_path_pct \
           gate_checked gate_rejected gate_partial \
           probe_pct probe_edge_pct probe_runs input_stab_avg \
           input_stab_min info_score_avg shelf_cells_used shelf_members \
           contract_check contract_diff cost_fork_us cost_setup_us \
           hot_region_hits state_signal state_transitions state_map_density \
           state_utility_pct state_util_pairs state_util_runs \
           state_util_cands state_util_status state_sit_report; do

  if ! has_key "${key}" "${STATE}"; then MISSING="${MISSING} ${key}"; fi

done

if [ -n "${MISSING}" ]; then

  fail "missing fuzzer_stats keys under -J:${MISSING}"

else

  ok "every state fuzzing stat is reported under -J"

fi

# The watchdog letter only exists when AFL_TARGET_WATCHDOG is compiled in.
if grep -qE '^#define AFL_TARGET_WATCHDOG' ../include/config.h; then

  WANT_MODE="gprdscbhw"

else

  WANT_MODE="gprdscbh"

fi

MODE="$(echo "${STATE}" | grep -E '^state_mode *:' | sed 's/.*: *//')"
if [ "${MODE}" = "${WANT_MODE}" ]; then

  ok "bare -J enables every part (${MODE})"

else

  fail "bare -J reported state_mode '${MODE}', expected '${WANT_MODE}'"

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
run_afl "${WORKDIR}/out_gp" -Jgp
GP="$(stats_of "${WORKDIR}/out_gp")"

if [ -n "${GP}" ]; then

  MODE="$(echo "${GP}" | grep -E '^state_mode *:' | sed 's/.*: *//')"
  if [ "${MODE}" = "gp" ]; then

    ok "-Jgp enables only g and p"

  else

    fail "-Jgp reported state_mode '${MODE}', expected 'gp'"

  fi

  if has_key "info_score_avg" "${GP}" || has_key "state_signal" "${GP}"; then

    fail "-Jgp reported stats belonging to letters that were not requested"

  else

    ok "-Jgp reports no stats for parts it did not enable"

  fi

fi

# state_signal must name what it knows, so that "cannot be measured on this
# target" is not read as "still deciding".
SIGNAL="$(echo "${STATE}" | grep -E '^state_signal *:' | sed 's/.*: *//')"
case "${SIGNAL}" in

  unsupported | observing | unmeasurable | trusted)
    ok "state_signal reports a known value (${SIGNAL})"
    ;;
  *)
    fail "state_signal reported '${SIGNAL}'"
    ;;

esac

# The state utility test has to keep trying. It used to run only at a queue
# cycle boundary, so a corpus that grows faster than it is fuzzed got the one
# attempt made at startup - with the queue too small to hold two entries in the
# same state - and never another one for the rest of the run.
mkdir -p "${WORKDIR}/in_many"
i=0
while [ ${i} -lt 40 ]; do

  printf 'SESS%060d' "${i}" > "${WORKDIR}/in_many/seed${i}"
  printf '\x10\x00\x00\x20\xa7\x00\x30\x00\x04AAAA\x60\x00\x00' \
    >> "${WORKDIR}/in_many/seed${i}"
  i=$((i + 1))

done

AFL_STATE_UTILITY_RETRY=1 AFL_NO_UI=1 AFL_NO_AFFINITY=1 \
  timeout -s INT 40 "${AFL_FUZZ}" -Js -V 15 \
    -i "${WORKDIR}/in_many" -o "${WORKDIR}/out_retry" -- "${BIN}" @@ \
    > "${WORKDIR}/out_retry.log" 2>&1

RETRY="$(stats_of "${WORKDIR}/out_retry")"
RUNS="$(echo "${RETRY}" | grep -E '^state_util_runs *:' | sed 's/.*: *//')"

if [ -n "${RUNS}" ] && [ "${RUNS}" -gt 1 ]; then

  ok "the state utility test repeats (${RUNS} runs in 15s)"

else

  fail "the state utility test ran ${RUNS:-no} time(s), it must repeat"
  grep -E '^state_util' "${WORKDIR}/out_retry/default/fuzzer_stats" 2>/dev/null

fi

# A repeated test must not repeat its verdict line, or a long run drowns in it.
VERDICTS="$(grep -c "state signal \(NOT \)\?validated" \
              "${WORKDIR}/out_retry.log" 2>/dev/null)"

if [ "${VERDICTS:-0}" -le 2 ]; then

  ok "repeated tests do not repeat their verdict (${VERDICTS:-0} line(s))"

else

  fail "the verdict was printed ${VERDICTS} times over ${RUNS} runs"

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
