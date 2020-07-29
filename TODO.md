# TODO list for AFL++

## Roadmap 2.67+

 - expand on AFL_LLVM_INSTRUMENT_FILE to also support sancov allowlist format
 - AFL_MAP_SIZE for qemu_mode and unicorn_mode
 - CPU affinity for many cores? There seems to be an issue > 96 cores

## Further down the road

afl-fuzz:
 - setting min_len/max_len/start_offset/end_offset limits for mutation output

llvm_mode:
 - LTO - imitate sancov

gcc_plugin:
 - (wait for submission then decide)
 - laf-intel
 - better instrumentation (seems to be better with gcc-9+)

better documentation:
 - flow graph
 - short intro
 - faq (how to increase stability, speed, many parallel ...)

qemu_mode:
 - update to 5.x (if the performance bug if gone)
 - non colliding instrumentation
 - rename qemu specific envs to AFL_QEMU (AFL_ENTRYPOINT, AFL_CODE_START/END,
   AFL_COMPCOV_LEVEL?)
 - add AFL_QEMU_EXITPOINT (maybe multiple?), maybe pointless as we have
   persistent mode
 - add/implement AFL_QEMU_INST_LIBLIST and AFL_QEMU_NOINST_PROGRAM
 - add/implement AFL_QEMU_INST_REGIONS as a list of _START/_END addresses
