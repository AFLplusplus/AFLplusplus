# afl-network-proxy

If you want to run afl-fuzz over the network, then this is what you need. :)
Note that the impact on fuzzing speed will be huge, expect a loss of 90%.

## When to use this

1. when you have to fuzz a target that has to run on a system that cannot
   contain the fuzzing output (e.g., /tmp too small and file system is
   read-only)
2. when the target instantly reboots on crashes
3. ... any other reason you would need this

## how to get it running

### Compiling

Just type `make` and let the autodetection do everything for you.

Note that you will get a 40-50% performance increase if you have libdeflate-dev
installed. The GNUmakefile will autodetect it if present. Compression is
negotiated at connect time, so a client and a server that were built with
different libdeflate availability still work together.

If your target has large test cases (10+kb) that are ascii only or large chunks
of zero blocks then set `CFLAGS=-DCOMPRESS_TESTCASES=1` to compress them.
For most targets this hurts performance though so it is disabled by default.

Both sides speak a versioned protocol and refuse to run if they do not match,
so always deploy `afl-network-client` and `afl-network-server` from the same
AFL++ version.

### on the target

Run `afl-network-server` with your target with the -m and -t values you need.
Important is the -i parameter which is the TCP port to listen on.
e.g.:

```
afl-network-server -i 1111 -m 25M -t 1000 -- /bin/target -f @@
```

Persistent mode (`__AFL_LOOP()`) and shared memory test cases
(`__AFL_FUZZ_TESTCASE_BUF`) are supported and are detected automatically, they
give a large speed increase over the network too.

The server serves exactly one client and exits when that client disconnects.

### on the (afl-fuzz) main node

Just run afl-fuzz with your normal options, however, the target should be
`afl-network-client` with the IP and PORT of the `afl-network-server` and
increase the -t value:

```
afl-fuzz -i in -o out -t 2000+ -- afl-network-client TARGET-IP 1111
```

Note the '+' on the -t parameter value. The afl-network-server will take care of
proper timeouts hence afl-fuzz should not. The '+' increases the timeout and the
value itself should be 500-1000 higher than the one on afl-network-server.

Because afl-network-server enforces the timeout by killing the target, a target
run that hits the timeout arrives at afl-fuzz as a killed process and therefore
ends up in `crashes/` and not in `hangs/`.

### map size

The coverage map size of the remote target is determined by
`afl-network-server` and transmitted to `afl-network-client`, which reports it
to afl-fuzz. `AFL_MAP_SIZE` therefore only ever has to be set on the
afl-network-server side, and only if the target needs a map larger than the
default.

### networking

The TARGET can be an IPv4 or IPv6 address, or a host name that resolves to
either. Note that also the outgoing interface can be specified with a '%' for
`afl-network-client`, e.g., `fe80::1234%eth0`.

Also make sure your default TCP window size is larger than your MAP_SIZE
(130kb is a good value).
On Linux that is the middle value of `/proc/sys/net/ipv4/tcp_rmem`

## how to compile and install

`make && sudo make install`

