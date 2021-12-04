# qbdi-based binary-only instrumentation for afl-fuzz

NOTE: this code is outdated and first would need to be adapted to the current
AFL++ versions.
Try FRIDA mode or fpicker [https://github.com/ttdennis/fpicker/](https://github.com/ttdennis/fpicker/) first, maybe they suite your need.

## 1) Introduction

The code in ./qbdi_mode allows you to build a standalone feature that
using the QBDI framework to fuzz android native library.

## 2) Build

First download the Android NDK

```
https://developer.android.com/ndk/downloads
https://dl.google.com/android/repository/android-ndk-r20-linux-x86_64.zip
```

Then unzip it and build the standalone-toolchain
For x86_64 standalone-toolchain

```
unzip android-ndk-r20-linux-x86_64.zip
cd android-ndk-r20/
./build/tools/make_standalone_toolchain.py --arch x86_64 --api 21 --install-dir ../android-standalone-toolchain-x86_64
```

For x86 standalone-toolchain

```
./build/tools/make_standalone_toolchain.py --arch x86 --api 21 --install-dir ../android-standalone-toolchain-x86
```

In alternative you can also use the pre-built toolchain, in that case make sure
to set the proper CC and CXX environment variables because there are many
different compilers for each API version in the pre-built toolchain.

For example:

```
export STANDALONE_TOOLCHAIN_PATH=~/Android/Sdk/ndk/20.1.5948944/toolchains/llvm/prebuilt/linux-x86_64/
export CC=x86_64-linux-android21-clang
export CXX=x86_64-linux-android21-clang++
```

Then download the QBDI SDK from website

```
https://qbdi.quarkslab.com/
```

For Android x86_64

```
https://github.com/QBDI/QBDI/releases/download/v0.7.0/QBDI-0.7.0-android-X86_64.tar.gz
```

Then decompress the sdk

```
mkdir android-qbdi-sdk-x86_64
cp QBDI-0.7.0-android-X86_64.tar.gz android-qbdi-sdk-x86_64/
cd android-qbdi-sdk-x86_64/
tar xvf QBDI-0.7.0-android-X86_64.tar.gz
```

Now set the `STANDALONE_TOOLCHAIN_PATH` to the path of standalone-toolchain

```
export STANDALONE_TOOLCHAIN_PATH=/home/hac425/workspace/android-standalone-toolchain-x86_64
```

set the `QBDI_SDK_PATH` to the path of QBDI SDK

```
export QBDI_SDK_PATH=/home/hac425/workspace/AFLplusplus/qbdi_mode/android-qbdi-sdk-x86_64/
```

Then run the build.sh

```
./build.sh x86_64
```

this could build the afl-fuzz and also the qbdi template for android x86_64

### Example

The demo-so.c is an vulnerable library, it has a function for test

```c
int target_func(char *buf, int size) {

  printf("buffer:%p, size:%p\n", buf, size);
  switch (buf[0]) {

    case 1:
      puts("222");
      if (buf[1] == '\x44') {

        puts("null ptr deference");
        *(char *)(0) = 1;

      }

      break;
    case 0xff:
      if (buf[2] == '\xff') {

        if (buf[1] == '\x44') {

          puts("crash....");
          *(char *)(0xdeadbeef) = 1;

        }

      }

      break;
    default: puts("default action"); break;

  }

  return 1;

}
```

This could be built to `libdemo.so`.

Then load the library in template.cpp and find the `target` function address:

```c
    void *handle = dlopen(lib_path, RTLD_LAZY);
	..........................................
	..........................................
	..........................................
    p_target_func = (target_func)dlsym(handle, "target_func");
```

Then read the data from file and call the function in `fuzz_func`:

```c
QBDI_NOINLINE int fuzz_func() {

  if (afl_setup()) { afl_forkserver(); }

  /* Read the input from file */
  unsigned long len = 0;
  char *        data = read_file(input_pathname, &len);

  /* Call the target function with the input data */
  p_target_func(data, len);
  return 1;

}
```

Just compile it

```
./build.sh x86_64
```

Then push the `afl-fuzz`, `loader`, `libdemo.so`, the `libQBDI.so` from the QBDI SDK and the `libc++_shared.so` from android-standalone-toolchain to android device

```
adb push afl-fuzz /data/local/tmp
adb push libdemo.so /data/local/tmp
adb push loader /data/local/tmp
adb push android-qbdi-sdk-x86_64/usr/local/lib/libQBDI.so /data/local/tmp
adb push ../../android-standalone-toolchain-x86_64/sysroot/usr/lib/x86_64-linux-android/libc++_shared.so
/data/local/tmp
```

In android adb shell, run the loader to test if it runs

```
cd /data/local/tmp
export LD_LIBRARY_PATH=/data/local/tmp
mkdir in
echo 0000 > in/1
./loader libdemo.so in/1
p_target_func:0x716d96a98600
	offset:0x600
	offset:0x580
buffer:0x716d96609050, size:0x5
	offset:0x628
	offset:0x646
	offset:0x64b
	offset:0x65c
	offset:0x6df
	offset:0x590
default action
	offset:0x6eb
```

Now run `afl-fuzz` to fuzz the demo library

```
./afl-fuzz -i in -o out -- ./loader /data/local/tmp/libdemo.so @@
```

![screen1](assets/screen1.png)