# TODO list for AFL++

## Roadmap 2.65+

 - AFL_MAP_SIZE for qemu_mode and unicorn_mode
 - random crc32 HASH_CONST per run? because with 65536 paths we have collisions
 - namespace for targets? e.g. network
 - libradamsa as a custom module?
 - learn from honggfuzz
 - for persistent mode, have a functionality that transports the test case
   via shared memory (and the int write to the FD from afl-fuzz is the size)
 - CPU affinity for many cores?

## Further down the road

afl-fuzz:
 - ascii_only mode for mutation output - or use a custom mutator for this?
 - setting min_len/max_len/start_offset/end_offset limits for mutation output

llvm_mode:
 - better whitelist solution for LTO

gcc_plugin:
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
