#!/bin/bash
#
# Replay a corpus through a coverage build and report source coverage.
#
# This exists because the number the fuzzer reports about itself cannot be
# compared between arms. edges_found counts bytes of a coverage map, and the
# map depends on the binary: a different build, a different instrumentation
# pass, or a state hash mixed into the edge index all change what one edge
# means. Two arms that used different binaries have no common unit at all.
# Source coverage does: replay both corpora through one build and count the
# lines and regions of the code under test.
#
# usage: replay_coverage.sh <cov-binary> <source-dir> <out-dir> <corpus-dir>...
#
# env:
#   CHUNK        inputs handed to one invocation (default 50)
#   REPLAY_TMOUT seconds one invocation may take (default 15)
#   IGNORE_RE    llvm-cov -ignore-filename-regex, to drop the harness itself
#                from the count so only the code under test is compared
#
# The coverage binary must take input files as argv. Build it with
# -fprofile-instr-generate -fcoverage-mapping and WITHOUT afl-clang-fast, so
# main() takes the argv path rather than the persistent loop.
#
# Notes on the two traps in here, both of which have cost real time:
#
#   * One input that kills the process discards the profile of every input in
#     the same invocation. A crashing corpus therefore silently reports the
#     coverage of whatever ran last. So a chunk that dies is bisected and the
#     offender is quarantined and printed - a shrunk corpus must never be able
#     to pass for a clean measurement.
#   * A corpus reliably contains inputs that do not terminate under coverage
#     instrumentation, which has no forkserver and no timeout of its own. Every
#     invocation is wrapped in `timeout`.

set -u

if [ $# -lt 4 ]; then

  echo "usage: $0 <cov-binary> <source-dir> <out-dir> <corpus-dir>..." >&2
  exit 1

fi

BIN="$1"; SRC="$2"; OUT="$3"; shift 3
CHUNK="${CHUNK:-50}"
REPLAY_TMOUT="${REPLAY_TMOUT:-15}"
IGNORE_RE="${IGNORE_RE:-}"

PROFDATA="${LLVM_PROFDATA:-llvm-profdata}"
COV="${LLVM_COV:-llvm-cov}"

if [ ! -x "$BIN" ]; then echo "[-] $BIN not executable" >&2; exit 1; fi
command -v "$PROFDATA" >/dev/null || { echo "[-] $PROFDATA not found" >&2; exit 1; }
command -v "$COV" >/dev/null || { echo "[-] $COV not found" >&2; exit 1; }

rm -rf "$OUT"
mkdir -p "$OUT/prof" || exit 1

# %m makes the runtime merge every invocation into one file per binary, so N
# invocations cost one profile, not N.
export LLVM_PROFILE_FILE="$OUT/prof/%m.profraw"

FILES=()
for d in "$@"; do

  [ -d "$d" ] || continue
  for f in "$d"/*; do [ -f "$f" ] && FILES+=("$f"); done

done

if [ "${#FILES[@]}" -eq 0 ]; then

  echo "[-] no inputs found in: $*" >&2
  exit 1

fi

quarantined=0

run_chunk() {

  timeout -s KILL "$REPLAY_TMOUT" "$BIN" "$@" >/dev/null 2>&1

}

bisect() {

  local -a f=("$@")

  if [ "${#f[@]}" -eq 1 ]; then

    echo "    quarantined: ${f[0]}"
    quarantined=$((quarantined + 1))
    return

  fi

  local h=$(( ${#f[@]} / 2 ))
  local -a a=("${f[@]:0:$h}") b=("${f[@]:$h}")

  run_chunk "${a[@]}" || bisect "${a[@]}"
  run_chunk "${b[@]}" || bisect "${b[@]}"

}

echo "[*] replaying ${#FILES[@]} inputs through $(basename "$BIN")"

for ((i = 0; i < ${#FILES[@]}; i += CHUNK)); do

  chunk=("${FILES[@]:i:CHUNK}")
  run_chunk "${chunk[@]}" || bisect "${chunk[@]}"

done

if ! "$PROFDATA" merge -sparse "$OUT"/prof/*.profraw -o "$OUT/merged.profdata" \
     2>"$OUT/profdata.err"; then

  echo "[-] profdata merge failed, see $OUT/profdata.err" >&2
  exit 1

fi

COV_ARGS=("$BIN" "-instr-profile=$OUT/merged.profdata")
[ -n "$IGNORE_RE" ] && COV_ARGS+=("-ignore-filename-regex=$IGNORE_RE")

"$COV" export -summary-only "${COV_ARGS[@]}" "$SRC" > "$OUT/coverage.json" \
  2>"$OUT/cov.err" || {

  echo "[-] llvm-cov export failed, see $OUT/cov.err" >&2
  exit 1

}

"$COV" report "${COV_ARGS[@]}" "$SRC" > "$OUT/coverage.txt" 2>/dev/null

python3 - "$OUT/coverage.json" "$OUT" "$quarantined" "${#FILES[@]}" <<'PY'
import json, sys

path, out, quarantined, total = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
with open(path) as fh:
    d = json.load(fh)

t = d["data"][0]["totals"]
res = {
    "inputs": int(total),
    "quarantined": int(quarantined),
    "lines_covered": t["lines"]["covered"],
    "lines_total": t["lines"]["count"],
    "regions_covered": t["regions"]["covered"],
    "regions_total": t["regions"]["count"],
    "branches_covered": t["branches"]["covered"],
    "branches_total": t["branches"]["count"],
    "functions_covered": t["functions"]["covered"],
    "functions_total": t["functions"]["count"],
}
with open(out + "/summary.json", "w") as fh:
    json.dump(res, fh, indent=2)

print("[+] lines %d/%d  regions %d/%d  branches %d/%d  functions %d/%d"
      " (%s inputs, %s quarantined)" % (
          res["lines_covered"], res["lines_total"],
          res["regions_covered"], res["regions_total"],
          res["branches_covered"], res["branches_total"],
          res["functions_covered"], res["functions_total"],
          res["inputs"], res["quarantined"]))
PY
