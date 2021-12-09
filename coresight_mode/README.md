# AFL++ CoreSight mode

CoreSight mode enables binary-only fuzzing on ARM64 Linux using CoreSight (ARM's hardware tracing technology).

NOTE: CoreSight mode is in the early development stage. Not applicable for production use.
Currently the following hardware boards are supported:
* NVIDIA Jetson TX2 (NVIDIA Parker)
* NVIDIA Jetson Nano (NVIDIA Tegra X1)
* GIGABYTE R181-T90 (Marvell ThunderX2 CN99XX)

## Getting started

Please read the [RICSec/coresight-trace README](https://github.com/RICSecLab/coresight-trace/blob/master/README.md) and check the prerequisites (capstone) before getting started.

CoreSight mode supports the AFL++ fork server mode to reduce `exec` system call
overhead. To support it for binary-only fuzzing, it needs to modify the target
ELF binary to re-link to the patched glibc. We employ this design from
[PTrix](https://github.com/junxzm1990/afl-pt).

Check out all the git submodules in the `cs_mode` directory:

```bash
git submodule update --init --recursive
```

### Build coresight-trace

There are some notes on building coresight-trace. Refer to the [README](https://github.com/RICSecLab/coresight-trace/blob/master/README.md) for the details. Run make in the `cs_mode` directory:

```bash
make build
```

Make sure `cs-proxy` is placed in the AFL++ root directory as `afl-cs-proxy`.

### Patch COTS binary

The fork server mode requires patchelf and the patched glibc. The dependency build can be done by just run make:

```bash
make patch TARGET=$BIN
```

The above make command builds and installs the dependencies to `$PREFIX` (default to `$PWD/.local`) at the first time. Then, it runs `patchelf` to `$BIN` with output `$OUTPUT` (`$BIN.patched` by default).

### Run afl-fuzz

Run `afl-fuzz` with `-A` option to use CoreSight mode.

```bash
sudo afl-fuzz -A -i input -o output -- $OUTPUT @@
```

## Environment Variables

There are AFL++ CoreSight mode-specific environment variables for run-time configuration.

* `AFL_CS_CUSTOM_BIN` overrides the proxy application path. `afl-cs-proxy` will be used if not defined.

* `AFLCS_COV` specifies coverage type on CoreSight trace decoding. `edge` and `path` is supported. The default value is `edge`.
* `AFLCS_UDMABUF` is the u-dma-buf device number used to store trace data in the DMA region. The default value is `0`.

## TODO List

* Eliminate modified glibc dependency
* Support parallel fuzzing

## Acknowledgements

This project has received funding from the Acquisition, Technology & Logistics Agency (ATLA) under the National Security Technology Research Promotion Fund 2021 (JPJ004596).
