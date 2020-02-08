# How to use the persistent mode in AFL++'s QEMU mode

## 1) Introduction

Persistent mode let you fuzz your target persistently between to
addresses - without forking for every fuzzing attempt.
This increases the speed by a factor between x2 and x5, hence it is
very, very valuable.

The persistent mode is currently only available for x86/x86_64 targets.


## 2) How use the persistent mode

### 2.1) The START address

The start of the persistent mode has to be set with AFL_QEMU_PERSISTENT_ADDR.

This address must be at the start of a function or the starting address of
basic block. This (as well as the RET address, see below) has to be defined
in hexadecimal with the 0x prefix.

If the target is compiled with position independant code (PIE/PIC), you must
add 0x4000000000 to that address, because qemu loads to this base address.

If this address is not valid, afl-fuzz will error during startup with the
message that the forkserver was not found.


### 2.2) the RET address

The RET address is optional, and only needed if the the return should not be
at the end of the function to which the START address points into, but earlier.

It is defined by setting AFL_QEMU_PERSISTENT_RET, and too 0x4000000000 has to
be set if the target is position independant.


### 2.3) the OFFSET

If the START address is *not* the beginning of a function, and *no* RET has
been set (so the end of the loop will be at the end of the function), the
ESP pointer very likely has to be reset correctly.

The value by which the ESP pointer has to be corrected has to set in the
variable AFL_QEMU_PERSISTENT_RETADDR_OFFSET

Now to get this value right here some help:
1. use gdb on the target 
2. set a breakpoint to your START address
3. set a breakpoint to the end of the same function
4. "run" the target with a valid commandline
5. at the first breakpoint print the ESP value with
```
print $esp
```
6. "continue" the target until the second breakpoint
7. again print the ESP value
8. calculate the difference between the two values - and this is the offset


### 2.4) resetting the register state

It is very, very likely you need to reste the register state when starting
a new loop. Because of this you 99% of the time should set

AFL_QEMU_PERSISTENT_GPR=1


## 3) optional parameters

### 3.1) loop counter value

The more stable your loop in the target, the longer you can run it, the more
unstable it is the lower the loop count should be. A low value would be 100,
the maximum value should be 10000. The default is 1000.
This value can be set with AFL_QEMU_PERSISTENT_CNT

This is the same concept as in the llvm_mode persistent mode with __AFL_LOOP().


### 3.2) a hook for in-memory fuzzing

You can increase the speed of the persistent mode even more by bypassing all
the reading of the fuzzing input via a file by reading directly into the
memory address space of the target process.

All this needs is that the START address has a register pointing to the
memory buffer, and another register holding the value of the read length
(or pointing to the memory where that value is held).

If the target reads from an input file you have to supply an input file
that is of least of the size that your fuzzing input will be (and do not
supply @@).

An example that you can use with little modification for your target can
be found here: [examples/qemu_persistent_hook](../examples/qemu_persistent_hook)
This shared library is specified via AFL_QEMU_PERSISTENT_HOOK

