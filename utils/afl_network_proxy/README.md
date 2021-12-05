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
installed. The GNUmakefile will autodetect it if present.

If your target has large test cases (10+kb) that are ascii only or large chunks
of zero blocks then set `CFLAGS=-DCOMPRESS_TESTCASES=1` to compress them.
For most targets this hurts performance though so it is disabled by default.

### on the target

Run `afl-network-server` with your target with the -m and -t values you need.
Important is the -i parameter which is the TCP port to listen on.
e.g.:

```
afl-network-server -i 1111 -m 25M -t 1000 -- /bin/target -f @@
```

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

### networking

The TARGET can be an IPv4 or IPv6 address, or a host name that resolves to
either. Note that also the outgoing interface can be specified with a '%' for
`afl-network-client`, e.g., `fe80::1234%eth0`.

Also make sure your default TCP window size is larger than your MAP_SIZE
(130kb is a good value).
On Linux that is the middle value of `/proc/sys/net/ipv4/tcp_rmem`

## how to compile and install

`make && sudo make install`

