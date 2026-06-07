# qemu_bridge — implementation status & TODO

Status of the AFL++ `-Q` backend built from `qemu-libafl-bridge` (QEMU 10.2).
See `docs/qemu_bridge_migration.md` for user-facing docs. This file tracks what
is implemented, what is not, and what is needed to close each gap.

Legend: ✅ implemented & runtime-verified · 🟡 implemented, build-verified only (not
runtime-tested) · ⚠️ partial/degraded · ❌ not implemented.

---

## TARGET (guest) feature matrix

| Feature | x86_64 | i386 | arm32 | aarch64 | mips(el) | ppc | riscv |
|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Edge coverage | ✅ | 🟡 | ✅ | 🟡 | 🟡 | 🟡 | 🟡 |
| Range / entrypoint / exitpoint filtering | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 |
| IJON (secondary map) | ✅ | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 | 🟡 |
| CompCov | ✅ | 🟡 | 🟡 | 🟡 | ❌ | ❌ | 🟡 |
| CmpLog (INS / operands) | ✅ | 🟡 | 🟡 | 🟡 | ❌ | ❌ | 🟡 |
| CmpLog (RTN / call args) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Persistent mode + futex sync | ✅ | 🟡 | ❌ | ❌ | ❌ | ❌ | ❌ |
| QASan — overflow detection | ✅ | 🟡 | 🟡 | 🟡 | ⚠️ | ⚠️ | ⚠️ |
| QASan — report context (pc/bp/sp, backtrace) | ✅ | 🟡 | 🟡 | 🟡 | ❌ | ❌ | ❌ |

Notes:
- "Runtime-verified" today = **x86_64** (all features) and **arm32 edge coverage**
  (the only non-x86 guest with a cross-compiler available during development).
  Everything marked 🟡 is implemented in code and build-verified but has not yet
  been exercised at runtime — see "Runtime verification gaps" below.
- riscv is not a requested target but is instrumented by the bridge, so it inherits
  edge/compcov/cmplog-INS for free.

---

## HOST (build/run machine) support

- **x86_64 host:** ✅ fully built and verified.
- **aarch64 host:** ❌ not built/tested. Expected to work — QEMU 10.2 has a native
  aarch64 TCG host backend, and the AFL layer is host-arch-generic (Linux
  `futex`/`shmat`/`mmap`, TCG-based codegen, no x86 host assembly; AFL++ core already
  runs on arm64). One caveat: the QASan giovese shadow constants assume the classic
  x86_64-Linux ~47-bit host virtual-address layout (see `LOW/HIGH_SHADOW_ADDR`,
  `SHADOW_OFFSET` referenced by `libafl/afl/afl_qasan.c`) and may need retuning on an
  arm64 host with a different VA split, or the shadow `mmap` will fail.
- HOST and TARGET are independent: on any supported host you can fuzz any supported
  target arch with that target's feature set from the matrix above.

---

## Not implemented — details & root cause

### 1. CompCov + CmpLog-INS on mips / ppc — BRIDGE gap (not the AFL layer)
The bridge only emits its cmp hook (`libafl_gen_cmp`) for x86 / arm / aarch64 / riscv:
`target/i386/tcg/translate.c`, `target/i386/tcg/emit.c.inc`,
`target/arm/tcg/translate.c`, `target/arm/tcg/translate-a64.c`,
`target/riscv/translate.c`. **`target/mips` and `target/ppc` contain no
`libafl_gen_cmp` calls.** Our compcov/cmplog callbacks (`libafl/afl/afl_compcov.c`,
`libafl/afl/afl_cmplog.c`) are arch-generic and would work unchanged, but they never
fire on mips/ppc because the bridge does not instrument their compare instructions.

### 2. CmpLog-RTN on every arch except x86_64 — AFL-layer gap (by design)
`AFL_RTN_SUPPORTED` is gated to `TARGET_X86_64` in `libafl/afl/afl_cmplog.c:20-26`
because RTN captures function-call argument registers (rdi/rsi), which is
calling-convention-specific. (qemuafl is also x86-only for RTN — this is a TODO
upstream too, so supporting more arches here would exceed qemuafl parity.)

### 3. Persistent mode + futex on non-x86 — AFL-layer gap (hardest)
`AFL_PERSISTENT_SUPPORTED` is x86/x86_64 only in `libafl/afl/afl_persistent.c:24-34`.
Two reasons: (a) it needs SP/PC GDB register indices per arch; (b) the loop-back
mechanism patches the **return address on the stack**, but arm/aarch64 return via the
**link register** (x30 / r14), mips via `$ra` (r31), ppc via the LR SPR — so "loop
back to the persistent address" is a fundamentally different operation per arch. The
futex child-sync itself is already arch-generic and would come along for free once the
per-arch loop-back exists.

### 4. QASan report context on mips / ppc — AFL-layer gap (cosmetic)
`libafl/afl/afl_qasan.c:21-37` defines `QASAN_PC/BP/SP_GET` for x86/i386, aarch64,
arm; mips/ppc fall to the `0` fallback. Overflow **detection still works** (the shadow
check rides the arch-generic read/write hooks in `tcg/tcg-op-ldst.c`); only the
printed pc/bp/sp and the alloc/free backtraces are empty.

### 5. Deferred from the migration (all arches) — see also `docs/qemu_bridge_migration.md`
- **Persistent-hook ABI** + `utils/aflpp_driver/aflpp_qemu_driver_hook.c`: not ported.
  Existing `AFL_QEMU_PERSISTENT_HOOK` `.so` files will not load; the bridge persistent
  mode works without a hook.
- **libqasan**: only the allocator interposition is ported. The libc str/mem
  interposition (`string.c`) and the dlmalloc backend are not, so glibc SIMD string
  routines can over-read small heap buffers (a known QASan false-positive without
  string interposition); symbolized backtraces are absent (`asan_giovese_printaddr`
  returns NULL).
- **hooking-bridge** (`qemu_mode/hooking_bridge`): not reimplemented; needs porting to
  the bridge's `libafl_qemu_add_instruction_hooks` + reg/mem accessors.
- **Generic `AFL_PRELOAD` → guest passthrough**: only the QASan `libqasan.so`
  auto-discovery is wired (`linux-user/main.c`, `#ifdef CONFIG_AFL`). Arbitrary
  `AFL_PRELOAD` is not converted to a guest preload.
- **AFL-Snapshot-LKM**: `imported/snapshot-inl.h` is present; persistent mode does not
  auto-use `/dev/afl_snapshot` yet — restore uses the userspace memory-backup path.
- **Persistent memory snapshot** is a full per-iteration memcpy of writable pages
  (correct, not dirty-page-optimized) — a perf TODO.

### 6. Runtime verification gaps
Only x86_64 (all features) and arm32 (edge) have been runtime-tested. aarch64, mips,
ppc, i386, and riscv are build-verified only — no cross-toolchains were available
during development for runtime self-tests. The CI workflow
(`.github/workflows/qemu_bridge.yml`) is set up to run the per-arch matrix once
cross-toolchains/runners are present.

---

## TODO (what is needed to close the gaps)

Ordered by value / effort.

### A. CompCov + CmpLog-INS for mips/ppc  (bridge change; moderate; unblocks the two named arches)
Add `libafl_gen_cmp(pc, op0, op1, memop)` calls in the bridge's
`target/mips/tcg/translate.c` and `target/ppc/translate.c` at their integer-compare
instructions (mips: `SLT/SLTU/SLTI(U)` and the conditional-branch operand pairs; ppc:
`cmp/cmpi/cmpl/cmpli`). Additive and benefits the Rust `libafl_qemu` consumer too, so
it stays libafl-safe. No AFL-layer changes needed — the existing generic callbacks
fire automatically. Verify with a per-arch magic-value target.

### B. CmpLog-RTN for arm32 / aarch64 / mips / ppc  (AFL layer; small)
Extend the `AFL_RTN_*` block in `libafl/afl/afl_cmplog.c:20-26` with per-arch
argument-register GDB indices: aarch64 `x0/x1` (0/1), arm32 `r0/r1` (0/1),
mips `$a0/$a1` (4/5), ppc `r3/r4` (3/4); set `AFL_RTN_SUPPORTED` for them. The RTN
body already reads via `libafl_qemu_read_reg` + guest-memory copy, so only the
register table + per-arch validation are needed.

### C. Persistent mode + futex for aarch64 → arm32 → mips → ppc  (AFL layer; significant)
In `libafl/afl/afl_persistent.c`: add SP/PC GDB indices per arch (aarch64/arm reg
numbers are already known from QASan) and implement loop-back via the **link register**
instead of stack-slot patching — on first hit save LR (x30 / r14 / `$ra` / LR-SPR) +
GPRs; each iteration restore them and `libafl_qemu_set_pc(persistent_addr)` (the
existing `_RET` path already does a PC set, which generalizes). Futex sync is already
arch-generic. Do aarch64 first. Verify with the persistent throughput test per arch.

### D. QASan report context for mips / ppc  (AFL layer; trivial)
Add `QASAN_PC/BP/SP_GET(env)` accessors for `TARGET_MIPS` / `TARGET_PPC` in
`libafl/afl/afl_qasan.c:21-37` (detection already works; this only restores the
report's pc/bp/sp + backtraces).

### E. HOST aarch64 bring-up
Build the backend on an aarch64 host and run `test/test-qemu-bridge.sh`. Validate/retune
the QASan shadow constants for the host VA layout. Add an aarch64 runner to CI.

### F. Runtime-verify the build-only arches (🟡 → ✅)
Wire cross-toolchains (`gcc-aarch64-linux-gnu`, `gcc-arm-linux-gnueabi`,
`gcc-mipsel-linux-gnu`, `gcc-powerpc-linux-gnu`, `libc6-dev-i386`) into CI and run the
per-arch instrumentation self-test + feature checks (the `arch-matrix` job in
`.github/workflows/qemu_bridge.yml` is the place).

### G. Remaining deferred items (see section 5)
persistent-hook ABI + driver; libqasan string.c + dlmalloc + symbolized backtraces;
hooking-bridge; generic `AFL_PRELOAD` passthrough; snapshot-LKM auto-use; dirty-page
persistent snapshot optimization.

### H. Final cut-over (maintainer step)
Retire qemuafl once CI A/B parity vs a built legacy qemuafl passes: remove the
`qemu_mode/qemuafl` entry from `.gitmodules`, `qemu_mode/QEMUAFL_VERSION`, the
`qemu_mode` build/install/clean targets in `GNUmakefile`, and the
`AFL_QEMU_BACKEND=legacy` fallback in `src/afl-forkserver.c` + `include/envs.h`.
