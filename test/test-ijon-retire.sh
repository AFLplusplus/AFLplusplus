#!/bin/bash

set -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

cd "${SCRIPT_DIR}" || exit 1
export AFL_PATH="${ROOT_DIR}"

GREY="\033[1;90m"
BLUE="\033[1;94m"
GREEN="\033[0;32m"
RED="\033[0;31m"
RESET="\033[0m"

CODE=0
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/afl-ijon-retire.XXXXXX")"
BIN="${WORKDIR}/test-ijon-retire"
EXPECTED_IJON_MAX_SITES=4

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

make_repeated_seed() {

  local chr="$1"
  local count="$2"
  local out="$3"

  printf "%${count}s" "" | tr " " "${chr}" > "${out}"

}

count_numeric_files() {

  find "$1" -maxdepth 1 -type f -name '[0-9]*' 2>/dev/null | wc -l | tr -d ' '

}

list_numeric_files() {

  local max_dir="$1"
  local file

  while IFS= read -r file; do

    printf "%s %s\n" "$(basename "${file}")" "$(wc -c < "${file}" | tr -d ' ')"

  done < <(find "${max_dir}" -maxdepth 1 -type f -name '[0-9]*') | sort

}

run_fuzzer() {

  local in_dir="$1"
  local out_dir="$2"
  local log_file="$3"
  local retire="$4"

  local -a env_vars=(
    AFL_NO_UI=1
    AFL_QUIET=1
    AFL_EXIT_ON_TIME=5
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    AFL_SKIP_CPUFREQ=1
    AFL_TRY_AFFINITY=1
  )

  if [ "${retire}" = "1" ]; then

    env_vars+=(AFL_IJON_RETIRE_MAX=1)

  fi

  env "${env_vars[@]}" "${ROOT_DIR}/afl-fuzz" -V2 -d -s 1 -m none -G 256 \
    -i "${in_dir}" -o "${out_dir}" -- "${BIN}" > "${log_file}" 2>&1

}

trap cleanup EXIT

say "${BLUE}[*] Testing: IJON_MAX_UNTIL compilation and AFL_IJON_RETIRE_MAX retirement${RESET}"

if [ ! -x "${ROOT_DIR}/afl-clang-fast" ] || [ ! -x "${ROOT_DIR}/afl-fuzz" ]; then

  say "${GREY}[*] afl-clang-fast or afl-fuzz is missing, skipping${RESET}"
  exit 0

fi

if AFL_LLVM_IJON=1 "${ROOT_DIR}/afl-clang-fast" \
  "${SCRIPT_DIR}/test_ijon_retire_max.c" -o "${BIN}" \
  > "${WORKDIR}/compile.log" 2>&1; then

  say "${GREEN}[+] IJON_MAX_UNTIL target compiled successfully${RESET}"

else

  cat "${WORKDIR}/compile.log"
  fail "IJON_MAX_UNTIL target failed to compile"
  exit "${CODE}"

fi

KEEP_IN="${WORKDIR}/in-keep"
RETIRE_IN="${WORKDIR}/in-retire"
KEEP_OUT="${WORKDIR}/out-keep"
RETIRE_OUT="${WORKDIR}/out-retire"

mkdir -p "${KEEP_IN}" "${RETIRE_IN}"
make_repeated_seed "Y" 128 "${KEEP_IN}/y128"
make_repeated_seed "Z" 128 "${KEEP_IN}/z128"
make_repeated_seed "A" 64 "${KEEP_IN}/a64"
cp "${KEEP_IN}/y128" "${RETIRE_IN}/y128"
cp "${KEEP_IN}/z128" "${RETIRE_IN}/z128"
cp "${KEEP_IN}/a64" "${RETIRE_IN}/a64"

if run_fuzzer "${KEEP_IN}" "${KEEP_OUT}" "${WORKDIR}/keep.log" 0; then

  say "${GREEN}[+] Control fuzzing run without AFL_IJON_RETIRE_MAX completed${RESET}"

else

  cat "${WORKDIR}/keep.log"
  fail "Control fuzzing run failed"

fi

KEEP_MAX="${KEEP_OUT}/default/ijon_max"
KEEP_COUNT="$(count_numeric_files "${KEEP_MAX}")"

if [ "${KEEP_COUNT}" -le 1 ]; then

  list_numeric_files "${KEEP_MAX}"
  fail "Control run did not preserve multiple IJON max seeds"

else

  say "${GREEN}[+] Control run preserved ${KEEP_COUNT} IJON max seed file(s)${RESET}"

fi

if run_fuzzer "${RETIRE_IN}" "${RETIRE_OUT}" "${WORKDIR}/retire.log" 1; then

  say "${GREEN}[+] AFL_IJON_RETIRE_MAX fuzzing run completed${RESET}"

else

  cat "${WORKDIR}/retire.log"
  fail "AFL_IJON_RETIRE_MAX fuzzing run failed"

fi

RETIRE_MAX="${RETIRE_OUT}/default/ijon_max"
RETIRE_COUNT="$(count_numeric_files "${RETIRE_MAX}")"

if [ "${RETIRE_COUNT}" -gt 0 ] && [ "${RETIRE_COUNT}" -lt "${EXPECTED_IJON_MAX_SITES}" ]; then

  say "${GREEN}[+] AFL_IJON_RETIRE_MAX left ${RETIRE_COUNT}/${EXPECTED_IJON_MAX_SITES} IJON max seed file(s), so terminal entries were retired${RESET}"

else

  list_numeric_files "${RETIRE_MAX}"
  fail "AFL_IJON_RETIRE_MAX should leave at least one IJON_MAX seed but fewer than ${EXPECTED_IJON_MAX_SITES} total seeds"

fi

exit "${CODE}"
