# TODO list for AFL++

## Roadmap 2.67+

 - AFL_MAP_SIZE for qemu_mode and unicorn_mode
 - CPU affinity for many cores? There seems to be an issue > 96 cores
 - afl-plot to support multiple plot_data

## Further down the road

afl-fuzz:
 - setting min_len/max_len/start_offset/end_offset limits for mutation output
 - add __sanitizer_cov_trace_cmp* support via shmem

llvm_mode:
 - add __sanitizer_cov_trace_cmp* support

gcc_plugin:
 - (wait for submission then decide)

qemu_mode:
 - update to 5.x (if the performance bug is gone)
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

 - new tancov: use some lightweight taint analysis to see which parts of a
   new queue entry is accessed and only fuzz these bytes - or better, only
   fuzz those bytes that are newly in coverage compared to the queue entry
   the new one is based on -> taint branch, not useful :-(
