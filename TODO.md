# TODO list for AFL++

## Must

 - adapt MOpt to new mutation engine
 - Update afl->pending_not_fuzzed for MOpt
 - cmplog rtn sanity check on fixed length? + no length 1
 - afl-showmap -f support
 - afl-fuzz multicore wrapper script
 - when trimming then perform crash detection
 - either -L0 and/or -p mmopt results in zero new coverage


## Should

<<<<<<< Updated upstream
 - add value_profile but only enable after 15 minutes without finds?
=======
 - afl-showmap -f support
 - afl-fuzz multicore wrapper script
 - UI revamp
 - hardened_usercopy=0 page_alloc.shuffle=0
 - add value_profile but only enable after 15 minutes without finds
>>>>>>> Stashed changes
 - afl-crash-analysis
 - support persistent and deferred fork server in afl-showmap?
 - better autodetection of shifting runtime timeout values
 - afl-plot to support multiple plot_data
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
 - non colliding instrumentation
 - rename qemu specific envs to AFL_QEMU (AFL_ENTRYPOINT, AFL_CODE_START/END,
   AFL_COMPCOV_LEVEL?)
 - add AFL_QEMU_EXITPOINT (maybe multiple?)

## Ideas

 - LTO/sancov: write current edge to prev_loc and use that information when
   using cmplog or __sanitizer_cov_trace_cmp*. maybe we can deduct by follow up
   edge numbers that both following cmp paths have been found and then disable
   working on this edge id -> cmplog_intelligence branch
 - use cmplog colorization taint result for havoc locations?
