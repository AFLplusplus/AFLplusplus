# TODO list for AFL++

## Should

 - makefiles should show provide a build summary success/failure
 - better documentation for custom mutators
 - better autodetection of shifting runtime timeout values
 - Update afl->pending_not_fuzzed for MOpt
 - afl-plot to support multiple plot_data
 - parallel builds for source-only targets
 - get rid of check_binary, replace with more forkserver communication

## Maybe

 - forkserver tells afl-fuzz if cmplog is supported and if so enable
   it by default, with AFL_CMPLOG_NO=1 (?) set to skip?
 - afl_custom_fuzz_splice_optin()
 - afl_custom_splice()
 - cmdline option from-to range for mutations

## Further down the road

QEMU mode/FRIDA mode:
 - non colliding instrumentation
 - rename qemu specific envs to AFL_QEMU (AFL_ENTRYPOINT, AFL_CODE_START/END,
   AFL_COMPCOV_LEVEL?)
 - add AFL_QEMU_EXITPOINT (maybe multiple?), maybe pointless as there is
   persistent mode

## Ideas

 - LTO/sancov: write current edge to prev_loc and use that information when
   using cmplog or __sanitizer_cov_trace_cmp*. maybe we can deduct by follow up
   edge numbers that both following cmp paths have been found and then disable
   working on this edge id -> cmplog_intelligence branch
 - use cmplog colorization taint result for havoc locations?
