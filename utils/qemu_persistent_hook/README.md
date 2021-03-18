# QEMU persistent hook example

Compile the test binary and the library:

```
make
```

Fuzz with:

```
export AFL_QEMU_PERSISTENT_ADDR=0x$(nm test | grep "T target_func" | awk '{print $1}')
export AFL_QEMU_PERSISTENT_HOOK=./read_into_rdi.so

mkdir in
echo 0000 > in/in

../../afl-fuzz -Q -i in -o out -- ./test
```
