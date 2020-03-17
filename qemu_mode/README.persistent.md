# How to use the persistent mode in AFL++'s QEMU mode

## 1) Introduction

Persistent mode let you fuzz your target persistently between two
addresses - without forking for every fuzzing attempt.
This increases the speed by a factor between x2 and x5, hence it is
very, very valuable.

The persistent mode is currently only available for x86/x86_64, arm
and aarch64 targets.

## 2) How use the persistent mode

### 2.1) The START address

The start of the persistent loop has to be set with AFL_QEMU_PERSISTENT_ADDR.

This address can be the address of whatever instruction.
Setting this address to the start of a function makes the usage simple.
If the address is however within a function, either RET or OFFSET (see below
in 2.2 and 2.3) have to be set.
This address (as well as the RET address, see below) has to be defined in
hexadecimal with the 0x prefix or as a decimal value.

If the target is compiled with position independant code (PIE/PIC), you must
add 0x4000000000 to that address, because qemu loads to this base address.
On strange setups the base address set by QEMU for PIE executable may change,
you can check it printing the process map using 
`AFL_QEMU_DEBUG_MAPS=1 afl-qemu-trace TARGET-BINARY`

If this address is not valid, afl-fuzz will error during startup with the
message that the forkserver was not found.

### 2.2) the RET address

The RET address is the last instruction of the persistent loop.
The emulator will emit a jump to START when translating the instruction at RET.
It is optional, and only needed if the the return should not be
at the end of the function to which the START address points into, but earlier.

If it is not set, QEMU will assume that START points to a function and will
patch the return address (on stack or in the link register) to return to START
(like WinAFL).

It is defined by setting AFL_QEMU_PERSISTENT_RET, and too 0x4000000000 has to
be set if the target is position independant.

### 2.3) the OFFSET

This option is valid only for x86/x86_64 only, arm/aarch64 do not save the
return address on stack.

If the START address is *not* the beginning of a function, and *no* RET has
been set (so the end of the loop will be at the end of the function but START
will not be at the beginning of it), we need an offset from the ESP pointer
to locate the return address to patch.

The value by which the ESP pointer has to be corrected has to set in the
variable AFL_QEMU_PERSISTENT_RETADDR_OFFSET

Now to get this value right here some help:
1. use gdb on the target 
2. set a breakpoint to "main" (this is required for PIE/PIC binaries so the
   addresses are set up)
3. "run" the target with a valid commandline
4. set a breakpoint to the function in which START is contained
5. set a breakpoint to your START address
6. "continue" to the function start breakpoint
6. print the ESP value with `print $esp` and take note of it
7. "continue" the target until the second breakpoint
8. again print the ESP value
9. calculate the difference between the two values - and this is the offset

### 2.4) resetting the register state

It is very, very likely you need to restore the general purpose registers state
when starting a new loop. Because of this you 99% of the time should set

AFL_QEMU_PERSISTENT_GPR=1

An example, is when you want to use main() as persistent START:

```c
int main(int argc, char **argv) {

  if (argc < 2) return 1;
  
  // do stuffs

}
```

If you don't save and restore the registers in x86_64, the paramteter argc
will be lost at the second execution of the loop.

## 3) Optional parameters

### 3.1) Loop counter value

The more stable your loop in the target, the longer you can run it, the more
unstable it is the lower the loop count should be. A low value would be 100,
the maximum value should be 10000. The default is 1000.
This value can be set with AFL_QEMU_PERSISTENT_CNT

This is the same concept as in the llvm_mode persistent mode with __AFL_LOOP().

### 3.2) A hook for in-memory fuzzing

You can increase the speed of the persistent mode even more by bypassing all
the reading of the fuzzing input via a file by reading directly into the
memory address space of the target process.

All this needs is that the START address has a register that can reach the
memory buffer or that the memory buffer is at a know location. You probably need
the value of the size of the buffer (maybe it is in a register when START is
hitted).

The persistent hook will execute a function on every persistent iteration
(at the start START) defined in a shared object specified with
AFL_QEMU_PERSISTENT_HOOK=/path/to/hook.so.

The signature is:

```c
void afl_persistent_hook(uint64_t* regs, uint64_t guest_base);
```

In this hook, you can inspect and change the saved GPR state at START.

An example that you can use with little modification for your target can
be found here: [examples/qemu_persistent_hook](../examples/qemu_persistent_hook)
