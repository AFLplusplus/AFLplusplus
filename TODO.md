# TODO list for AFL++

## Roadmap 3.00+

 - AFL_MAP_SIZE for qemu_mode and unicorn_mode
 - CPU affinity for many cores? There seems to be an issue > 96 cores
 - afl-plot to support multiple plot_data
 - afl_custom_fuzz_splice_optin()
 - intel-pt tracer

## Further down the road

afl-fuzz:
 - setting min_len/max_len/start_offset/end_offset limits for mutation output
 - add __sanitizer_cov_trace_cmp* support via shmem

llvm_mode:
 - add __sanitizer_cov_trace_cmp* support

qemu_mode:
 - non colliding instrumentation
 - rename qemu specific envs to AFL_QEMU (AFL_ENTRYPOINT, AFL_CODE_START/END,
   AFL_COMPCOV_LEVEL?)
 - add AFL_QEMU_EXITPOINT (maybe multiple?), maybe pointless as we have
   persistent mode
 - add/implement AFL_QEMU_INST_LIBLIST and AFL_QEMU_NOINST_PROGRAM
 - add/implement AFL_QEMU_INST_REGIONS as a list of _START/_END addresses

## Ideas

 - LTO/sancov: write current edge to prev_loc and use that information when
   using cmplog or __sanitizer_cov_trace_cmp*. maybe we can deduct by follow
   up edge numbers that both following cmp paths have been found and then
   disable working on this edge id -> cmplog_intelligence branch
