# afl-proxy

afl-proxy is an example skeleton file which can easily be used to fuzz
and instrument non-standard things.

You only need to change the while() loop of the main() to send the
data of buf[] with length len to the target and write the coverage
information to __afl_area_ptr[__afl_map_size]

