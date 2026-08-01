#!/bin/bash
# Verify no SysV segment leaks when the CmpLog attach fails mid-init.

test "$1" = "run" || { echo "$GREY[*] Skipping $0, not helpful in CI, run this script with the \"run\" parameter to force it executing"; exit 0; }

cd "$(dirname "$0")" || exit 1
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'; GREY="\033[1;90m"
echo -e "$GREY[*] Testing value-profile shared-memory cleanup on init failure...$NC"

test -e ../afl-fuzz -a -e ../afl-clang-fast || { echo "[-] build first"; exit 1; }

WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/failshmat.c" <<'EOF'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "cmplog.h"
void *shmat(int shmid, const void *shmaddr, int shmflg) {
  static void *(*real)(int, const void *, int);
  if (!real) real = dlsym(RTLD_NEXT, "shmat");
  struct shmid_ds ds;
  if (shmctl(shmid, IPC_STAT, &ds) == 0 &&
      ds.shm_segsz == sizeof(struct cmp_map)) {
    errno = EINVAL;
    return (void *)-1;
  }
  return real(shmid, shmaddr, shmflg);
}
EOF

cat > "$WORK/t.c" <<'EOF'
#include <unistd.h>
int main(void) { char b[16]; return read(0, b, sizeof b) > 0 ? 0 : 1; }
EOF

cc -O1 -fPIC -shared -I../include -o "$WORK/failshmat.so" "$WORK/failshmat.c" -ldl \
  || { echo "[-] cannot build injector"; exit 1; }
AFL_QUIET=1 AFL_LLVM_VALUE_PROFILE=1 ../afl-clang-fast -O1 -o "$WORK/t.vp" "$WORK/t.c" 2>/dev/null
AFL_QUIET=1 AFL_LLVM_CMPLOG=1 ../afl-clang-fast -O1 -o "$WORK/t.cmp" "$WORK/t.c" 2>/dev/null
test -e "$WORK/t.vp" -a -e "$WORK/t.cmp" || { echo "[-] cannot build targets"; exit 1; }

mkdir -p "$WORK/in"; echo aaaa > "$WORK/in/a"

# Only segments of exactly sizeof(vp_map_t) with no attached process can be
# ours. Matching on "anything new" would pick up - and ipcrm - the maps of any
# other afl-fuzz the same user starts while this test runs.
VP_MAP_BYTES=2498576
vp_orphans() {
  ipcs -m | awk -v b="$VP_MAP_BYTES" '$5==b && $6==0 {print $2}' | sort
}

vp_orphans > "$WORK/before.txt"
LD_PRELOAD="$WORK/failshmat.so" AFL_NO_UI=1 timeout 60 ../afl-fuzz -i "$WORK/in" \
  -o "$WORK/out" -r0 -c "$WORK/t.cmp" -V 3 -- "$WORK/t.vp" >/dev/null 2>&1
vp_orphans > "$WORK/after.txt"

leaked=$(comm -13 "$WORK/before.txt" "$WORK/after.txt")
if [ -z "$leaked" ]; then
  echo -e "$GREEN[+] no shared-memory segment leaked on CmpLog attach failure$NC"
  exit 0
fi
echo -e "$RED[-] shared-memory segment(s) leaked on CmpLog attach failure$NC"
for id in $leaked; do
  ipcs -m | awk -v i="$id" '$2==i {print "    leaked id="$2" bytes="$5" nattch="$6}'
  ipcrm -m "$id" 2>/dev/null
done
exit 1
