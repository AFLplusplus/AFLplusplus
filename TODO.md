# TODO list for AFL++

## TODO

 - AFL_USE_TSAN to docs/env_variables.md after work over
 - screen update during input2stage
 - better autodetection of shifting runtime timeout values
 - Update afl->pending_not_fuzzed for MOpt
 - afl-plot to support multiple plot_data
 - parallel builds for source-only targets

## Perhaps

 - afl_custom_fuzz_splice_optin()
 - afl_custom_splice()

## Further down the road

qemu_mode/frida_mode:
 - non colliding instrumentation
 - rename qemu specific envs to AFL_QEMU (AFL_ENTRYPOINT, AFL_CODE_START/END,
   AFL_COMPCOV_LEVEL?)
 - add AFL_QEMU_EXITPOINT (maybe multiple?), maybe pointless as we have
   persistent mode


## Ideas

 - LTO/sancov: write current edge to prev_loc and use that information when
   using cmplog or __sanitizer_cov_trace_cmp*. maybe we can deduct by follow
   up edge numbers that both following cmp paths have been found and then
   disable working on this edge id -> cmplog_intelligence branch
 - use cmplog colorization taint result for havoc locations?
