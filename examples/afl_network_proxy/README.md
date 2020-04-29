# afl-network-proxy

If you want to run afl-fuzz over the network than this is what you need :)
Note that the impact on fuzzing speed will be huge, expect a loss of 90%.

## When to use this

1. when you have to fuzz a target that has to run on a system that cannot
   contain the fuzzing output (e.g. /tmp too small and file system is read-only)
2. when the target instantly reboots on crashes
3. ... any other reason you would need this

## how to get it running

### on the target

Run `afl-network-server` with your target with the -m and -t values you need.
Important is the -i parameter which is the TCP port to liste on.
e.g.:
```
$ afl-network-server -i 1111 -m 25M -t 1000 -- /bin/target -f @@
```
### on the fuzzing master

Just run afl-fuzz with your normal options, however the target should be
`afl-network-client` with the IP and PORT of the `afl-network-server` and
increase the -t value:
```
$ afl-fuzz -i in -o out -t 2000+ -- afl-network-client TARGET-IP 1111
```
Note the '+' on the -t parameter value. the afl-network-server will take
care of proper timeouts hence afl-fuzz should not. The '+' increases the timout
and the value itself should be 500-1000 higher than the one on 
afl-network-server.

### networking

The TARGET can be an IPv4 or IPv6 address, or a host name that resolves to
either. Note that also the outgoing interface can be specified with a '%' for
`afl-network-client`, e.g. `fe80::1234%eth0`.

## how to compile and install

`make && sudo make install`
