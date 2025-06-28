# AFL++ TCP desocket library

Other desocketing solutions:
* https://github.com/zardus/preeny (desock and desock2)
* https://github.com/fkie-cad/libdesock
* https://github.com/zyingp/desockmulti
* https://github.com/vanhauser-thc/network-emulator

If these desocket solutions fail, then this one will likely easily work
for you - alass with slightly lower performance.
And it is easy to extend :-)

## Why might this solution work when others do not?

What makes this desocket library special is that only **only** intercepts
`accept()` calls bound to a specified port. Hence any other network stuff
the application does is still working as expected.

## How to use

`AFL_PRELOAD` this library and use the following environment variables:

* `DESOCK_PORT=8080` - required for intercepting incoming connections for fuzzing - sets the TCP port
* `DESOCK_FORK=1` - intercept and prevent forking
* `DESOCK_CLOSE_EXIT=1` - call _exit() when the desocketed file descriptor is `close`d or `shutdown`ed
* `DESOCK_DEBUG=1` - print debug information to `stderr`

** Internals

Currently the library intercepts the following calls:

```
shutdown
close
fork
accept
accept4
listen
bind
setsockopt
getsockopt
getpeername
getsockname
```

`