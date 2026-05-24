#!/bin/sh

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: persistent calibration timeout selection"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/afl-persistent-timeout.XXXXXX")"
TARGET="${WORKDIR}/test-persistent-timeout"
MIN_TIMEOUT_MS=200

cleanup() {

  rm -rf "${WORKDIR}"

}

fail() {

  $ECHO "$RED[!] $*"
  CODE=1

}

trap cleanup EXIT INT TERM

test -e ../afl-clang-fast -a -e ../afl-fuzz && {

  ../afl-clang-fast -O0 -o "${TARGET}" test-persistent-timeout.c \
    > "${WORKDIR}/compile.log" 2>&1 || {

    cat "${WORKDIR}/compile.log"
    fail "persistent timeout target failed to compile"

  }

  mkdir -p "${WORKDIR}/in"
  printf "A" > "${WORKDIR}/in/seed"

  env AFL_EXIT_WHEN_DONE= AFL_EXIT_ON_TIME= AFL_NO_UI=1 AFL_QUIET=1 \
    AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_TRY_AFFINITY=1 \
    ../afl-fuzz -V1 -m ${MEM_LIMIT} -i "${WORKDIR}/in" \
      -o "${WORKDIR}/out" -- "${TARGET}" \
      > "${WORKDIR}/fuzz.log" 2>&1 || {

    cat "${WORKDIR}/fuzz.log"
    fail "afl-fuzz failed during persistent timeout calibration test"

  }

  STATS="${WORKDIR}/out/default/fuzzer_stats"
  EXEC_TIMEOUT="$(awk '$1 == "exec_timeout" { print $3 }' "${STATS}")"

  case "${EXEC_TIMEOUT}" in
    ""|*[!0-9]*)
      cat "${WORKDIR}/fuzz.log"
      fail "could not read exec_timeout from fuzzer_stats"
      ;;
    *)
      if [ "${EXEC_TIMEOUT}" -lt "${MIN_TIMEOUT_MS}" ]; then

        cat "${WORKDIR}/fuzz.log"
        fail "exec_timeout ${EXEC_TIMEOUT}ms should include slow persistent fork run"

      else

        $ECHO "$GREEN[+] persistent calibration kept ${EXEC_TIMEOUT}ms timeout"

      fi
      ;;
  esac

} || {

  $ECHO "$YELLOW[-] afl is not compiled, cannot test"
  INCOMPLETE=1

}

cleanup
trap - EXIT INT TERM

. ./test-post.sh
