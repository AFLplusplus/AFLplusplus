# TODO list for AFL++

## Must

 - adapt MOpt to new mutation engine
 - Update afl->pending_not_fuzzed for MOpt
 - cmplog rtn sanity check on fixed length? + no length 1
 - afl-showmap -f support
 - afl-fuzz multicore wrapper script
 - when trimming then perform crash detection
 - either -L0 and/or -p mmopt results in zero new coverage

afl-clang-fast  -Iapps -I. -Iinclude -Iapps/include  -pthread -m64 -fsanitize=address -fno-omit-frame-pointer -g -Wa,--noexecstack -Qunused-arguments -fno-inline-functions -g -pthread -Wno-unused-command-line-argument -O3 -fno-sanitize=alignment -DOPENSSL_BUILDING_OPENSSL -DPEDANTIC -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -MMD -MF apps/openssl-bin-speed.d.tmp -MT apps/openssl-bin-speed.o -c -o apps/openssl-bin-speed.o apps/speed.c
afl-cc++4.10a by Michal Zalewski, Laszlo Szekeres, Marc Heuse - mode: LLVM-PCGUARD
Split-compare-newpass by laf.intel@gmail.com, extended by heiko@hexco.de (splitting icmp to 8 bit)
Split-floatingpoint-compare-pass: 2 FP comparisons split
724 comparisons found
SanitizerCoveragePCGUARD++4.10a
[+] Instrumented 7356 locations with no collisions (non-hardened mode) of which are 99 handled and 7 unhandled selects.


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
