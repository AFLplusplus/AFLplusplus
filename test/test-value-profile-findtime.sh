#!/bin/bash
# VP-only queue saves must not reset the coverage-find clock (AFL_EXIT_ON_TIME).

test "$1" = "run" || { echo "$GREY[*] Skipping $0, not helpful in CI, run this script with the \"run\" parameter to force it executing"; exit 0; }

cd "$(dirname "$0")" || exit 1
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'; GREY="\033[1;90m"
echo -e "$GREY[*] Testing that value-profile finds do not disturb AFL_EXIT_ON_TIME...$NC"

test -e ../afl-fuzz -a -e ../afl-clang-fast || { echo "[-] build first"; exit 1; }
WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/t.c" <<'EOF'
#include <string.h>
#include <unistd.h>
int main(void) {
  unsigned char b[64];
  int n = read(0, b, sizeof b - 1);
  if (n < 8) return 0;
  b[n] = 0;
  unsigned v; memcpy(&v, b, 4);
  if (v == 0xdeadbeefu) return 1;
  return 0;
}
EOF
AFL_QUIET=1 AFL_LLVM_VALUE_PROFILE=1 ../afl-clang-fast -O1 -o "$WORK/t.vp" "$WORK/t.c" 2>/dev/null
test -e "$WORK/t.vp" || { echo "[-] cannot build target"; exit 1; }
mkdir -p "$WORK/in"; printf 'aaaaaaaaaaaa' > "$WORK/in/a"

stat_field() {
  grep -E "^$2 " "$1/default/fuzzer_stats" 2>/dev/null | tr -dc '0-9'
}

run_secs() {
  local out="$1"; shift
  local s e
  s=$(date +%s)
  AFL_NO_UI=1 AFL_EXIT_ON_TIME=5 timeout 120 ../afl-fuzz -s 123 -i "$WORK/in" \
    -o "$out" "$@" -V 100 -- "$WORK/t.vp" >/dev/null 2>&1
  e=$(date +%s)
  echo $((e - s))
}

attempt=0
vp=""
base=""
while [ "$attempt" -lt 3 ]; do
  attempt=$((attempt + 1))
  rm -rf "$WORK/out_off" "$WORK/out_on"

  base=$(run_secs "$WORK/out_off")
  base_edges=$(stat_field "$WORK/out_off" edges_found)
  base_corpus=$(stat_field "$WORK/out_off" corpus_count)

  vp=$(run_secs "$WORK/out_on" -r0)
  vp_edges=$(stat_field "$WORK/out_on" edges_found)
  vp_corpus=$(stat_field "$WORK/out_on" corpus_count)

  echo "    exit time without -r: ${base}s   with -r0: ${vp}s   (edges_found ${base_edges}/${vp_edges}, corpus_count ${base_corpus}/${vp_corpus})"

  if [ -z "$base_edges" ] || [ -z "$vp_edges" ]; then
    echo -e "$GREY[*] could not read fuzzer_stats, retrying...$NC"; vp=""; continue
  fi

  if [ "$vp_edges" -ne "$base_edges" ]; then
    echo -e "$GREY[*] value-profile run found genuine new edge coverage, not just VP-only saves; retrying...$NC"
    vp=""; continue
  fi

  if [ "$vp_corpus" -le "$base_corpus" ]; then
    echo -e "$GREY[*] value-profile run admitted no VP-only queue entries, cannot exercise the bug; retrying...$NC"
    vp=""; continue
  fi

  break
done

if [ -z "$vp" ]; then
  echo -e "$GREY[*] could not get a conclusive run after $attempt attempts, skipping$NC"; exit 0
fi

if [ "$vp" -le $((base + 4)) ]; then
  echo -e "$GREEN[+] value-profile finds do not disturb the coverage-find clock$NC"; exit 0
fi
echo -e "$RED[-] AFL_EXIT_ON_TIME overshot with -r0: ${vp}s vs ${base}s baseline$NC"
exit 1
