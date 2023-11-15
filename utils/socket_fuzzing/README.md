# socketfuzz

when you want to fuzz a network service and you can not/do not want to modify
the source (or just have a binary), then this LD_PRELOAD library will allow
for sending input to stdin which the target binary will think is coming from
a network socket.
当你想要对一个网络服务进行模糊测试，而你不能或不想修改源代码（或者只有一个二进制文件）时，这个LD_PRELOAD库将允许你向stdin发送输入，目标二进制文件会认为这是来自网络套接字的输入。

This is desock_dup.c from the amazing preeny project
[https://github.com/zardus/preeny](https://github.com/zardus/preeny)
这是来自神奇的preeny项目的desock_dup.c [https://github.com/zardus/preeny](https://github.com/zardus/preeny)

It is packaged in AFL++ to have it at hand if needed
它被打包在AFL++中，以便在需要时使用 