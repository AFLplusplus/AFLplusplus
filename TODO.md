# TODO list for AFL++

## Must

 - hand the shared maps to the target as an inherited fd instead of a name or
   a SysV id, so they can be unlinked at creation and nothing survives a
   SIGKILLed tool: fuzzer does shm_open -> ftruncate -> mmap -> shm_unlink and
   exports the fd number (keep clear of FORKSRV_FD 198/199), afl-compiler-rt
   mmap()s that fd and falls back to shm_open(path)/shmat(id) when the env var
   is missing (targets built by an older afl-cc). This is what MacOS, the BSDs
   and the USEMMAP builds need - they cannot attach after IPC_RMID/shm_unlink,
   so AFL_SHM_AUTO_RECLAIM in afl-sharedmem.c is Linux only. It also moves
   MacOS off SysV and its kern.sysv.shmseg ceiling. Android needs nothing, its
   ashmem shim is already fd based.
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
