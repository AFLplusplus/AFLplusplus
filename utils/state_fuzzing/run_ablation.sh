#!/bin/bash
#
# The state fuzzing ablation experiment.
#
# Five arms, one thing changed at a time, so that "the executor got better" and
# "the state model got better" can finally be told apart:
#
#   A  normal coverage, normal executor
#   B  normal coverage, improved executor      -> B minus A = engineering wins
#   C  improved executor + record mutator
#   D  improved executor + state signal        -> D minus B = state wins
#   E  improved executor + records + state
#
# This experiment has never been published. Every existing comparison changes
# the executor and the state model at the same time, so nobody can tell which
# one helped.
#
# Results are written per arm and per repetition; analyze_ablation.py turns
# them into the three normalised numbers that are actually comparable.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

AFL_FUZZ="${AFL_FUZZ:-${ROOT_DIR}/afl-fuzz}"

TARGET=""
TARGET_RECORDS=""
SEEDS=""
OUTDIR="./ablation"
DURATION=3600
REPS=3
ARMS="A B C D E"
MUTATOR=""
PARALLEL=0

usage() {

  cat <<EOF
usage: $0 -t TARGET -i SEEDS [options] [-- target args]

  -t BIN        target binary, built with afl-clang-fast (required)
  -T BIN        record-format target for arms C and E; defaults to -t
  -i DIR        seed corpus (required)
  -o DIR        output directory (default: ${OUTDIR})
  -V SECONDS    duration of one run (default: ${DURATION})
  -n REPS       repetitions per arm (default: ${REPS})
  -a "A B ..."  arms to run (default: ${ARMS})
  -m SO         record mutator .so for arms C and E
                (default: ${ROOT_DIR}/custom_mutators/state_records/state_records.so)
  -p            run arms in parallel

Target arguments after -- are passed through; use @@ for a file argument.

Notes:
  Runs are SEQUENTIAL by default. On a machine with performance and efficiency
  cores, parallel runs land on the slow cores and halve execs/s, which silently
  changes what you are measuring. Only use -p if you know your cores are equal.

  Arms C and E need a target that speaks the record format. Point -T at the
  harness from custom_mutators/state_records/, or at your own.

  Report three numbers, never one, and never report "states found" as success:
  a broken observer that hashes the clock finds millions.
EOF

}

while getopts "t:T:i:o:V:n:a:m:ph" opt; do

  case "$opt" in
    t) TARGET="$OPTARG" ;;
    T) TARGET_RECORDS="$OPTARG" ;;
    i) SEEDS="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    V) DURATION="$OPTARG" ;;
    n) REPS="$OPTARG" ;;
    a) ARMS="$OPTARG" ;;
    m) MUTATOR="$OPTARG" ;;
    p) PARALLEL=1 ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac

done

shift $((OPTIND - 1))
TARGET_ARGS=("$@")

if [ -z "$TARGET" ] || [ -z "$SEEDS" ]; then usage; exit 1; fi
if [ ! -x "$AFL_FUZZ" ]; then echo "[-] $AFL_FUZZ not found, run make"; exit 1; fi
if [ ! -x "$TARGET" ]; then echo "[-] target $TARGET not executable"; exit 1; fi
if [ ! -d "$SEEDS" ]; then echo "[-] seed dir $SEEDS not found"; exit 1; fi

[ -z "$TARGET_RECORDS" ] && TARGET_RECORDS="$TARGET"
[ -z "$MUTATOR" ] && \
  MUTATOR="${ROOT_DIR}/custom_mutators/state_records/state_records.so"

mkdir -p "$OUTDIR" || exit 1

# Arm definitions. Keep these in one place: the whole point of the experiment
# is that exactly one thing differs between neighbouring arms.

arm_flags() {

  # The letters must be attached to -J; a detached argument is not consumed.
  case "$1" in
    A) echo "" ;;
    B) echo "-Jgprdcw" ;;
    C) echo "-Jgprdcw" ;;
    D) echo "-Jgprdcws" ;;
    E) echo "-Jgprdcws" ;;
    *) echo "__invalid__" ;;
  esac

}

arm_uses_records() {

  case "$1" in
    C|E) return 0 ;;
    *)   return 1 ;;
  esac

}

arm_desc() {

  case "$1" in
    A) echo "baseline: normal coverage, normal executor" ;;
    B) echo "improved executor (B-A = engineering wins)" ;;
    C) echo "improved executor + record mutator" ;;
    D) echo "improved executor + state signal (D-B = state wins)" ;;
    E) echo "improved executor + records + state" ;;
  esac

}

run_one() {

  local arm="$1" rep="$2"
  local dir="${OUTDIR}/${arm}/rep${rep}"
  local flags bin

  flags="$(arm_flags "$arm")"
  if [ "$flags" = "__invalid__" ]; then

    echo "[-] unknown arm '$arm'"
    return 1

  fi

  bin="$TARGET"
  if arm_uses_records "$arm"; then bin="$TARGET_RECORDS"; fi

  rm -rf "$dir"
  mkdir -p "$dir" || return 1

  (

    export AFL_NO_UI=1
    export AFL_NO_AFFINITY=1
    export AFL_TIME_ACCOUNTING=1
    export AFL_OPS_COUNTER_FILE="${dir}/ops_count"

    if arm_uses_records "$arm"; then

      if [ ! -r "$MUTATOR" ]; then

        echo "[-] arm $arm needs $MUTATOR, build it first" >&2
        exit 1

      fi

      export AFL_CUSTOM_MUTATOR_LIBRARY="$MUTATOR"

    fi

    # shellcheck disable=SC2086
    "$AFL_FUZZ" $flags -V "$DURATION" -i "$SEEDS" -o "$dir" \
      -- "$bin" "${TARGET_ARGS[@]}" > "${dir}/afl.log" 2>&1

  )

  local rc=$?
  if [ $rc -ne 0 ]; then

    echo "[!] arm $arm rep $rep exited $rc, see ${dir}/afl.log"

  fi

  return 0

}

echo "[*] output   : $OUTDIR"
echo "[*] duration : ${DURATION}s x ${REPS} reps x arms [${ARMS}]"
echo "[*] parallel : $PARALLEL"
echo

total=0
for arm in $ARMS; do

  echo "[*] arm $arm - $(arm_desc "$arm")"

  for rep in $(seq 1 "$REPS"); do

    total=$((total + 1))
    if [ "$PARALLEL" = "1" ]; then

      run_one "$arm" "$rep" &

    else

      echo "    rep $rep ..."
      run_one "$arm" "$rep"

    fi

  done

done

if [ "$PARALLEL" = "1" ]; then wait; fi

echo
echo "[+] $total runs done."
echo "[*] now run: ${SCRIPT_DIR}/analyze_ablation.py $OUTDIR"
