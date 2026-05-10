# TODO list for AFL++

## Next
 - analyse regression 87d26ff7de5ba8e762bccdda85e91f5c951f17e9
   - more?
 - new classify map VAR=1


## Must

 - find a solution that SAYF now prints to stderr (help!)
 - afl_fsrv_deinit cmplog
 - hardened_usercopy=0 page_alloc.shuffle=0
 - add value_profile but only enable after 15 minutes without finds
 - cmplog max items env?
 - cmplog rtn sanity check on fixed length? currently we ignore the length
 - when trimming then perform crash detection


## Should

 - cmplog: add loop count resolving (byte -> loop cnt change, calc special values)
 - cmplog: predicate-tightness tracking. When CmpLog logs an inequality
   (`a <= b`, `a < b`, etc.), also track the absolute slack (e.g.,
   `(rhs - lhs)` for `<=`). Retain corpus entries that hit minimum slack on
   each predicate — i.e., inputs where validation predicates were "barely
   passed" — and prioritize them in the queue. Catches the libwebp-1.3.1 /
   CVE-2023-4863 input pattern, where the triggering bitstream sits at the
   tight edge of four independent inequalities simultaneously
   (`MAX_ALLOWED_CODE_LENGTH`, `count[len] <= (1<<len)`, `num_open >= 0`,
   `num_nodes == 2*offset[15]-1`). Hook: extend
   `instrumentation/cmplog-instructions-pass.cc` to emit slack alongside
   operands; extend `src/afl-fuzz-cmplog.c` /
   `src/afl-fuzz-redqueen.c` to feed slack into corpus scheduling. See
   technique #5 in the bug-pass design notes (`docs/superpowers/plans/
   2026-05-10-afl-llvm-bug-pass.md`).
 - cmplog: size-formula instrumentation (CmpLog-on-derived-sizes). In the
   bug-pass / cmplog instrumentation, mark size-deriving expressions —
   any `mul`/`shl`/load-from-table that flows into a `malloc`/`calloc`
   size argument (e.g., `kTableSize[color_cache_bits] * num_htree_groups`).
   Instrument with an extended CmpLog record:
   `__afl_cmplog_size_derive(alloc_id, computed_size, observed_max_offset)`.
   When `observed_max_offset > computed_size`, log the delta so the fuzzer
   learns "this many extra bytes of write would have happened" and feeds
   the input bytes that produced the (num_htree_groups, color_cache_bits)
   tuple back through the CmpLog dictionary. Generalizes CmpLog's
   input-to-cmp-operand trick to input-to-allocation-size — high leverage
   for memory bugs because allocation-size operands tend to be 1–2
   mutations away from a buffer-overflow corner case. Pairs with the
   AllocSizeOracle pass (Component A in `NEXT.md` and the upcoming plan).
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
