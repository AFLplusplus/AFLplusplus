# TODO list for AFL++

## Roadmap 2.65+

 - sync_fuzzers(): only masters sync from all, slaves only sync from master
   (@andrea: be careful, often people run all slaves)
 - AFL_MAP_SIZE for qemu_mode and unicorn_mode
 - random crc32 HASH_CONST per run? because with 65536 paths we have collisions
 - namespace for targets? e.g. network
 - libradamsa as a custom module?
 - focal for travis

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
