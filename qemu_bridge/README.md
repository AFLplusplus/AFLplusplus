# qemu_bridge

The QEMU 10.2 binary-only backend for AFL++, built on the
`qemu-libafl-bridge` fork (the same QEMU fork used by `libafl_qemu`). The
AFL-specific code is additive and lives behind the `CONFIG_AFL` configure
option enabled by `--afl`.

This is the default QEMU backend. To revert to the legacy qemuafl backend at
run time set `AFL_QEMU_BACKEND=legacy`.

## Build

```sh
make                       # build the AFL++ core first
cd qemu_bridge
./build_qemu_bridge_support.sh
```

Produces the repository-root `afl-qemu-trace`, `libqasan.so`, and
`libcompcov.so`. Set `CPU_TARGET` to cross-target another architecture
(`i386`, `arm`, `aarch64`, `mips`, `ppc`).

See `../docs/qemu_bridge_migration.md` for the full migration guide, feature
matrix, environment variables, known changes, and the maintainer cut-over
checklist. Run `../test/test-qemu-bridge.sh` for the acceptance suite.
