# socketfuzz

when you want to fuzz a network service and you can not/do not want to modify
the source (or just have a binary), then this LD_PRELOAD library will allow
for sending input to stdin which the target binary will think is coming from
a network socket.

This is desock_dup.c from the amazing preeny project
https://github.com/zardus/preeny

It is packaged in afl++ to have it at hand if needed
