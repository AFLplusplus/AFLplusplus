# QEMU bridge migration

AFL++ binary-only fuzzing in `qemu_mode` has historically used **qemuafl**, a
fork of QEMU 5.2. The new **qemu_bridge** backend replaces it with a fork of the
modern **qemu-libafl-bridge** (based on QEMU 10.2), the same QEMU fork that
powers `libafl_qemu`. The bridge is now the default QEMU backend; qemuafl is
still present but deferred for removal until A/B parity has been confirmed in CI.

## Why

- QEMU 10.2 instead of 5.2: years of upstream CPU, target, and syscall fixes.
- Shared lineage with LibAFL's `libafl_qemu`, so AFL++ and LibAFL track the same
  QEMU fork. The AFL-specific changes are additive and live behind `CONFIG_AFL`,
  enabled by the `--afl` configure flag.
- Dynamic, collision-free edge coverage instead of the fixed XOR-hash map.

## Building

The backend builds to the repository-root `afl-qemu-trace`, alongside the
companion libraries `libqasan.so` and `libcompcov.so`.

```sh
make                 # build the AFL++ core first (needs config.h, afl-showmap)
cd qemu_bridge
./build_qemu_bridge_support.sh
```

or, as part of the normal binary-only build from the repository root:

```sh
make binary-only
```

Useful environment variables for the build script:

- `CPU_TARGET` selects the guest architecture (`x86_64` by default; also
  `i386`, `arm`, `aarch64`, `mips`, `ppc`).
- `NO_CHECKOUT=1` skips the submodule checkout/pin step (build whatever is
  checked out).
- `STATIC=1`, `DEBUG=1`, `HOST=<prefix>` for static, debug, and cross builds.
- `NO_QEMU=1` (passed to `make`) disables building QEMU support, both
  `qemu_mode` and the bridge.

The bridge QEMU source is the `qemu_bridge/qemu-libafl-bridge` submodule, pinned
by `qemu_bridge/QEMU_BRIDGE_VERSION`. When the script runs outside of a git
checkout (for example inside the Docker build, where `.git` is excluded), it
falls back to cloning `qemu-libafl-bridge` directly before checking out the
pinned commit.

## Choosing the backend

Both backends produce a repository-root `afl-qemu-trace`; whichever build ran
last wins on disk. At run time the AFL++ tools select bridge behaviour by
default and fall back to the legacy protocol on request:

- `AFL_QEMU_BACKEND=bridge` (default) — use the new bridge protocol.
- `AFL_QEMU_BACKEND=legacy` — use the qemuafl forkserver protocol. Point
  `AFL_PATH` at a directory containing a qemuafl `afl-qemu-trace` to run it.

## Coverage map

The bridge emits **dynamic, collision-free** edge coverage: each new edge is
assigned the next free slot in the shared map at translation time, instead of
hashing block addresses into a fixed-size table. This removes edge collisions
that the legacy XOR-hash scheme suffered from.

The map grows as needed; size it with `AFL_MAP_SIZE` when fuzzing large targets.
The AFL++ tools negotiate the map size with the forkserver automatically, so in
most cases no manual sizing is required.

## Feature support per architecture

| Feature                | x86_64 | arm / aarch64 | mips / ppc |
|------------------------|:------:|:-------------:|:----------:|
| Edge coverage          |  yes   |     yes       |   yes      |
| Range / entrypoint     |  yes   |     yes       |   yes      |
| Persistent mode        |  yes   |    partial    |  partial   |
| CompCov                |  yes   |     yes       |   yes      |
| CmpLog (instructions)  |  yes   |     yes       |   yes      |
| CmpLog routines (RTN)  |  yes   |      no       |   no       |
| QASan                  |  yes   |     yes       |   varies   |
| IJON                   |  yes   |     yes       |   yes      |

x86_64 is the fully supported, primary target: coverage, range/entrypoint
filtering, persistent mode, CompCov, CmpLog instructions and routines (RTN),
QASan, and IJON. arm/aarch64 add coverage, CompCov, instruction-level CmpLog,
and QASan. mips/ppc cover coverage, CompCov, and instruction-level CmpLog.

## Persistent mode

Persistent mode loops a chosen function in-process instead of fork+exec per
input, giving a large throughput win (roughly 30x on the bundled self-test).
Drive it with:

- `AFL_QEMU_PERSISTENT_ADDR=0x<addr>` — address of the loop function. For
  `-no-pie` binaries this is the raw `nm` address; for PIE binaries it must be
  the loaded address (see `test/test-qemu-bridge.sh` for the per-arch nibble
  reduction the test harness applies).
- `AFL_QEMU_PERSISTENT_GPR=1` — save/restore general-purpose registers each loop.
- `AFL_QEMU_PERSISTENT_RET=0x<addr>` / `AFL_QEMU_PERSISTENT_RETADDR_OFFSET` —
  return-address handling when the loop is not a clean function entry.
- `AFL_QEMU_PERSISTENT_EXITS=1` — treat `exit()` as the end of a loop iteration.
- `AFL_QEMU_PERSISTENT_CNT=N` — iterations before a real fork.
- `AFL_QEMU_PERSISTENT_MEM=1` — restore the writable memory snapshot each loop.

## Other environment variables

- Ranges: `AFL_INST_LIBS`, `AFL_QEMU_INST_RANGES`, `AFL_QEMU_EXCLUDE_RANGES`,
  `AFL_ENTRYPOINT`, `AFL_EXITPOINT`, `AFL_CODE_START`, `AFL_CODE_END`,
  `AFL_INST_RATIO`.
- CompCov: `AFL_COMPCOV_LEVEL=1|2` (or `AFL_QEMU_COMPCOV=1` for level 1).
- QASan: `AFL_USE_QASAN=1` (loads `libqasan.so` and enables the in-QEMU shadow).
- Map: `AFL_MAP_SIZE`.
- IJON: `AFL_QEMU_IJON=1`.

## IJON

IJON annotation support is wired into the bridge map; enable it with
`AFL_QEMU_IJON=1`. See `docs/IJON.md` for the source-level annotation API.

## Known changes and breaks

- **Persistent-hook ABI is not yet ported.** The legacy
  `AFL_QEMU_PERSISTENT_HOOK=<hook.so>` mechanism (custom input-placement hooks
  via a shared object) is not implemented in the bridge. Existing hook `.so`
  files will not load and must be rewritten against the bridge ABI once it
  lands. This is a deferred follow-up.
- **QASan uses the fake-syscall channel.** `libqasan.so` communicates with the
  in-QEMU sanitizer through a reserved fake syscall number (`0xa2a4`) rather
  than the legacy hypercall path. Custom QASan integrations relying on the old
  channel need updating.

### Deferred items

The following qemuafl features have not been ported to the bridge yet and are
tracked as follow-ups:

- `string.c` interposition in `libqasan` (libc string-function shadow checks).
- The `dlmalloc` allocator shim in `libqasan`.
- The hooking-bridge (`qemu_mode/hooking_bridge`) for user instrumentation.
- Generic `AFL_PRELOAD` passthrough into the guest (CompCov is currently driven
  by the in-QEMU TCG hooks via `AFL_COMPCOV_LEVEL`, not by preloading
  `libcompcov.so`).
- Automatic use of the snapshot LKM.

## Validation

`test/test-qemu-bridge.sh` is a self-contained acceptance harness. It builds
small targets and asserts: differential/deterministic edge coverage, range
filtering (`AFL_INST_LIBS`), persistent throughput (>=3x with 100% stability),
the CompCov gradient, a clean CmpLog dual-forkserver start, and QASan
heap-buffer-overflow detection. If a legacy qemuafl `afl-qemu-trace` is present
it additionally runs an A/B coverage comparison; otherwise that test is skipped.

CI runs the harness plus a per-architecture build-and-self-test matrix and a
LibAFL non-regression check in `.github/workflows/qemu_bridge.yml`.

## Final cut-over (maintainer step)

Once CI A/B parity passes, qemuafl can be retired. This is a deliberate
maintainer action and is **not** performed by this migration. To remove qemuafl:

1. Delete the `qemu_mode/qemuafl` submodule entry in `.gitmodules`:

   ```
   [submodule "qemu_mode/qemuafl"]
       path = qemu_mode/qemuafl
       url = https://github.com/AFLplusplus/qemuafl
   ```

   then `git rm` the submodule and remove `qemu_mode/qemuafl` from
   `.git/config` / `.git/modules`.

2. Delete `qemu_mode/QEMUAFL_VERSION` (the qemuafl revision pin).

3. Remove the `qemu_mode` build/install/clean targets in `GNUmakefile`:
   - the `cd qemu_mode && ... ./build_qemu_support.sh` lines in the `all` and
     `binary-only` build paths (around the `NO_QEMU` guards);
   - the `qemu_mode/qemuafl` lines in `clean` and `deepclean`
     (`$(MAKE) -C qemu_mode/qemuafl clean`, `rm -rf qemu_mode/qemuafl`,
     `git checkout qemu_mode/qemuafl`);
   - the `qemu_mode/{unsigaction,fastexit,libcompcov,libqasan}` clean lines if
     the companion sources are also removed.

4. Flip any remaining legacy default: remove the `AFL_QEMU_BACKEND=legacy`
   fallback branch in `src/afl-forkserver.c` (the `qemu_bridge` selection),
   drop `AFL_QEMU_BACKEND` from `include/envs.h`, and update the success message
   in `GNUmakefile` that currently mentions both `qemu_mode` and `qemu_bridge`.

5. Optionally delete the `qemu_mode/` tree (companion libs, READMEs) once nothing
   references it.
