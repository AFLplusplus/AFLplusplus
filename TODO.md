# TODO list for AFL++

## Roadmap 2.66+

 - AFL_MAP_SIZE for qemu_mode and unicorn_mode
 - namespace for targets? e.g. network
 - learn from honggfuzz (mutations, maybe ptrace?)
 - CPU affinity for many cores? There seems to be an issue > 96 cores

## Further down the road

afl-fuzz:
 - ascii_only mode for mutation output - or use a custom mutator for this?
 - setting min_len/max_len/start_offset/end_offset limits for mutation output

llvm_mode:
 - LTO - imitate sancov

gcc_plugin:
 - (wait for submission then decide)
 - laf-intel
 - better instrumentation (seems to be better with gcc-9+)

qemu_mode:
 - update to 5.x (if the performance bug if gone)
 - non colliding instrumentation
 - rename qemu specific envs to AFL_QEMU (AFL_ENTRYPOINT, AFL_CODE_START/END,
   AFL_COMPCOV_LEVEL?)
 - add AFL_QEMU_EXITPOINT (maybe multiple?), maybe pointless as we have
   persistent mode
 - add/implement AFL_QEMU_INST_LIBLIST and AFL_QEMU_NOINST_PROGRAM
 - add/implement AFL_QEMU_INST_REGIONS as a list of _START/_END addresses
