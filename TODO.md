# TODO list for AFL++

## Must

 - remove -n mode
 - find a solution that SAYF now prints to stderr (help!)
 - hardened_usercopy=0 page_alloc.shuffle=0

## Should

 - cmplog: add loop count resolving (byte -> loop cnt change, calc special values)
 - support persistent and deferred fork server in afl-showmap?
 - better autodetection of shifting runtime timeout values
 - parallel builds for source-only targets
 - get rid of check_binary, replace with more forkserver communication
 - first fuzzer should be a main automatically? not sure.

## Maybe

 - forkserver tells afl-fuzz if cmplog is supported and if so enable
   it by default, with AFL_CMPLOG_NO=1 (?) set to skip?
 - afl_custom_splice()
 - cmdline option from-to range for mutations

## Further down the road

Snapshot pool for state fuzzing (`-J`), the last unbuilt item of the plan in
`AFLppp.md` (C3):

 - Today every child is forked from one parent, stopped at one point. Keep
   several parked children instead, each stopped after a different program
   prefix, and fork the next test from whichever one matches the prefix it
   wants to extend. Files: `src/afl-forkserver.c` and the compiler runtime.
 - Why: it makes "append one operation to this program" cost the one operation
   instead of the whole program, and it gives exact credit assignment, because
   the only difference between parent and child is that operation.
 - Only worth it when setup is expensive, and that is a per-target question,
   not a default. Measured spread across four targets was 30x: snapshotting
   after init won 3.8x on QEMU (17.5 ms setup vs 4.1 ms fork), lost on libssh
   (4.4 ms/fork against a cheap handshake), and was a dead heat on lwext4.
 - The go/no-go measurement already ships: `afl-fuzz -Jb` (`state_cost_bench`
   in `src/afl-fuzz-statefuzz.c`) times a fork against a full process setup and
   prints the ratio and a recommendation. Run it before writing any of this.
 - Prerequisite audit, not optional: moving the snapshot point past the
   harness's own init means everything the parent holds is inherited by every
   child. File descriptors, mmaps, allocator arenas, RNG state and any live
   object in the harness all become shared history. `-Jc` (the harness
   self-check) catches the cheap half of that; the rest is a read of the
   harness.
 - Do not confuse this with pinning one deep state into the snapshot, which was
   measured and lost on every axis (fewer edges, 7.4 points less stability).
   The point of a pool is that it keeps many prefixes alive and stays free to
   abandon any of them.

QEMU mode/FRIDA mode:
 - non colliding instrumentation (done for qemu! frida todo)
 - rename qemu specific envs to AFL_QEMU (AFL_ENTRYPOINT, AFL_CODE_START/END,
   AFL_COMPCOV_LEVEL?)
 - support multiple AFL_QEMU_EXITPOINT

## Ideas

 - LTO/sancov: write current edge to prev_loc and use that information when
   using cmplog or __sanitizer_cov_trace_cmp*. maybe we can deduct by follow up
   edge numbers that both following cmp paths have been found and then disable
   working on this edge id -> cmplog_intelligence branch
 - use cmplog colorization taint result for havoc locations?
