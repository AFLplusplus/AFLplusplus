# TODO list for AFL++

## Roadmap 2.63

 - complete custom_mutator API changes and documentation
 - fix stability calculation bug

## Roadmap 2.64

 - context sensitive branch coverage in llvm_mode
 - random crc32 HASH_CONST per run? because with 65536 paths we have collisions
 - namespace for targets? e.g. network
 - libradamsa as a custom module?
 - laf-intel build auto-dictionary?

## Further down the road

afl-fuzz:
 - sync_fuzzers(): only masters sync from all, slaves only sync from master
   (@andrea: be careful, often people run all slaves)
 - ascii_only mode for mutation output
 - setting min_len/max_len/start_offset/end_offset limits for mutation output

llvm_mode:
 - added context sensitive branch coverage
 - add CT cov and ngram cov to LTO and InsTrim
 - better whitelist solution for LTO

gcc_plugin:
 - laf-intel
 - better instrumentation (seems to be better with gcc-9+)

qemu_mode:
 - update to 4.x (probably this will be skipped :( )
 - non colliding instrumentation
 - instrim for QEMU mode via static analysis (with r2pipe? or angr?)
   Idea: The static analyzer outputs a map in which each edge that must be
   skipped is marked with 1. QEMU loads it at startup in the parent process.
 - rename qemu specific envs to AFL_QEMU (AFL_ENTRYPOINT, AFL_CODE_START/END,
   AFL_COMPCOV_LEVEL?)
 - add AFL_QEMU_EXITPOINT (maybe multiple?), maybe pointless as we have
   persistent mode
 - add/implement AFL_QEMU_INST_LIBLIST and AFL_QEMU_NOINST_PROGRAM
 - add/implement AFL_QEMU_INST_REGIONS as a list of _START/_END addresses

custom_mutators:
 - rip what Superion is doing into custom mutators for js, php, etc.

