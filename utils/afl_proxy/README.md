# afl-proxy

afl-proxy is an example skeleton file which can easily be used to fuzz
and instrument non-standard things.

You only need to change the while() loop of the main() to send the
data of buf[] with length len to the target and write the coverage
information to __afl_area_ptr[__afl_map_size]

UPDATE: you can also use [custom mutators](../../docs/custom_mutators.md) with
afl_custom_fuzz_send to send data to a target, which is much more efficient!
But you can only use this feature if you start the target via afl-fuzz and
a forkserver is active (e.g. via -Q qemu_mode or source compiled).

