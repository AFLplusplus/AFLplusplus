#!/bin/bash

set -o pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

GREY="\033[1;90m"
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;93m"
RESET="\033[0m"

ORACLE_DIR="${ROOT_DIR}/utils/state_oracles"

printf "%b\n" "${GREY}[*] testing the state fuzzing oracle helpers${RESET}"

if [ ! -d "${ORACLE_DIR}" ]; then

  printf "%b\n" "${YELLOW}[-] skipped: ${ORACLE_DIR} not present${RESET}"
  exit 0

fi

# Every detector ships with a deliberately broken example it must flag and a
# correct counterpart it must stay quiet on. A detector never seen to fire is
# not known to work: a leak self-test once reported "clean" at -O1 because the
# compiler had deleted the leak, which is why the self-tests build at -O0 with
# -fno-builtin.
if make -C "${ORACLE_DIR}" selftest > /tmp/afl-state-oracles.$$ 2>&1; then

  grep -E "^\[\+\]" /tmp/afl-state-oracles.$$
  printf "%b\n" "${GREEN}[+] oracle self-tests passed${RESET}"
  rm -f /tmp/afl-state-oracles.$$
  make -C "${ORACLE_DIR}" clean > /dev/null 2>&1
  exit 0

fi

printf "%b\n" "${RED}[!] oracle self-tests failed${RESET}"
tail -25 /tmp/afl-state-oracles.$$
rm -f /tmp/afl-state-oracles.$$
make -C "${ORACLE_DIR}" clean > /dev/null 2>&1
exit 1
