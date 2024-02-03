# Scripting

FRIDA now supports the ability to configure itself using JavaScript. This allows
the user to make use of the convenience of FRIDA's scripting engine (along with
its support for debug symbols and exports) to configure all of the things which
were traditionally configured using environment variables.

By default, FRIDA mode will look for the file `afl.js` in the current working
directory of the target. Alternatively, a script file can be configured using
the environment variable `AFL_FRIDA_JS_SCRIPT`.

This script can make use of all of the standard [frida api
functions](https://frida.re/docs/javascript-api/), but FRIDA mode adds some
additional functions to allow you to interact with FRIDA mode itself. These can
all be accessed via the global `Afl` parameter, e.g., `Afl.print("HELLO
WORLD");`.

If you encounter a problem with your script, then you should set the environment
variable `AFL_DEBUG_CHILD=1` to view any diagnostic information.

## Example

Most of the time, users will likely be wanting to call the functions which
configure an address (e.g., for the entry point or the persistent address).

The example below uses the API
[`DebugSymbol.fromName()`](https://frida.re/docs/javascript-api/#debugsymbol).
Another use API is
[`Module.getExportByName()`](https://frida.re/docs/javascript-api/#module).

```js
/* Use Afl.print instead of console.log */
Afl.print('******************');
Afl.print('* AFL FRIDA MODE *');
Afl.print('******************');
Afl.print('');

/* Print some useful diagnostics stuff */
Afl.print(`PID: ${Process.id}`);

new ModuleMap().values().forEach(m => {
    Afl.print(`${m.base}-${m.base.add(m.size)} ${m.name}`);
});

/*
 * Configure entry-point, persistence etc. This will be what most
 * people want to do.
 */
const persistent_addr = DebugSymbol.fromName('main');
Afl.print(`persistent_addr: ${persistent_addr.address}`);

if (persistent_addr.address.equals(ptr(0))) {
    Afl.error('Cannot find symbol main');
}

const persistent_ret = DebugSymbol.fromName('slow');
Afl.print(`persistent_ret: ${persistent_ret.address}`);

if (persistent_ret.address.equals(ptr(0))) {
    Afl.error('Cannot find symbol slow');
}

Afl.setPersistentAddress(persistent_addr.address);
Afl.setPersistentReturn(persistent_ret.address);
Afl.setPersistentCount(1000000);

/* Control instrumentation, you may want to do this too */
Afl.setInstrumentLibraries();
const mod = Process.findModuleByName("libc-2.31.so")
Afl.addExcludedRange(mod.base, mod.size);

/* Some useful options to configure logging */
Afl.setStdOut("/tmp/stdout.txt");
Afl.setStdErr("/tmp/stderr.txt");

/* Show the address layout. Sometimes helpful */
Afl.setDebugMaps();

/*
 * If you are using these options, then things aren't going
 * very well for you.
 */
Afl.setInstrumentDebugFile("/tmp/instr.log");
Afl.setPrefetchDisable();
Afl.setInstrumentNoOptimize();
Afl.setInstrumentEnableTracing();
Afl.setInstrumentTracingUnique();
Afl.setStatsFile("/tmp/stats.txt");
Afl.setStatsInterval(1);

/* *ALWAYS* call this when you have finished all your configuration */
Afl.done();
Afl.print("done");
```

## Stripped binaries

Lastly, if the binary you're attempting to fuzz has no symbol information and no
exports, then the following approach can be used.

```js
const module = Process.getModuleByName('target.exe');
/* Hardcoded offset within the target image */
const address = module.base.add(0xdeadface);
Afl.setPersistentAddress(address);
```

## Persistent hook

A persistent hook can be implemented using a conventional shared object, sample
source code for a hook suitable for the prototype of `LLVMFuzzerTestOneInput`
can be found in [hook/](hook/). This can be configured using code similar to the
following.

```js
const path = Afl.module.path;
const dir = path.substring(0, path.lastIndexOf("/"));
const mod = Module.load(`${dir}/frida_mode/build/hook.so`);
const hook = mod.getExportByName('afl_persistent_hook');
Afl.setPersistentHook(hook);
```

Alternatively, the hook can be provided by using FRIDA's built-in support for
`CModule`, powered by TinyCC.

```js
const cm = new CModule(`

    #include <string.h>
    #include <gum/gumdefs.h>

    void afl_persistent_hook(GumCpuContext *regs, uint8_t *input_buf,
      uint32_t input_buf_len) {

      memcpy((void *)regs->rdi, input_buf, input_buf_len);
      regs->rsi = input_buf_len;

    }
    `,
    {
        memcpy: Module.getExportByName(null, 'memcpy')
    });
Afl.setPersistentHook(cm.afl_persistent_hook);
```

## Advanced persistence

Consider the following target code...

```c

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void LLVMFuzzerTestOneInput(char *buf, int len) {

  if (len < 1) return;
  buf[len] = 0;

  // we support three input cases
  if (buf[0] == '0')
    printf("Looks like a zero to me!\n");
  else if (buf[0] == '1')
    printf("Pretty sure that is a one!\n");
  else
    printf("Neither one or zero? How quaint!\n");

}

int run(char *file) {

  int    fd = -1;
  off_t  len;
  char * buf = NULL;
  size_t n_read;
  int    result = -1;

  do {

    dprintf(STDERR_FILENO, "Running: %s\n", file);

    fd = open(file, O_RDONLY);
    if (fd < 0) {

      perror("open");
      break;

    }

    len = lseek(fd, 0, SEEK_END);
    if (len < 0) {

      perror("lseek (SEEK_END)");
      break;

    }

    if (lseek(fd, 0, SEEK_SET) != 0) {

      perror("lseek (SEEK_SET)");
      break;

    }

    buf = malloc(len);
    if (buf == NULL) {

      perror("malloc");
      break;

    }

    n_read = read(fd, buf, len);
    if (n_read != len) {

      perror("read");
      break;

    }

    dprintf(STDERR_FILENO, "Running:    %s: (%zd bytes)\n", file, n_read);

    LLVMFuzzerTestOneInput(buf, len);
    dprintf(STDERR_FILENO, "Done:    %s: (%zd bytes)\n", file, n_read);

    result = 0;

  } while (false);

  if (buf != NULL) { free(buf); }

  if (fd != -1) { close(fd); }

  return result;

}

void slow() {

  usleep(100000);

}

int main(int argc, char **argv) {

  if (argc != 2) { return 1; }
  slow();
  return run(argv[1]);

}
```

FRIDA mode supports the replacement of any function, with an implementation
generated by CModule. This allows for a bespoke harness to be written as
follows:

```js
const slow = DebugSymbol.fromName('slow').address;
Afl.print(`slow: ${slow}`);

const LLVMFuzzerTestOneInput = DebugSymbol.fromName('LLVMFuzzerTestOneInput').address;
Afl.print(`LLVMFuzzerTestOneInput: ${LLVMFuzzerTestOneInput}`);

const cm = new CModule(`

    extern unsigned char * __afl_fuzz_ptr;
    extern unsigned int * __afl_fuzz_len;
    extern void LLVMFuzzerTestOneInput(char *buf, int len);

    void slow(void) {

      LLVMFuzzerTestOneInput(__afl_fuzz_ptr, *__afl_fuzz_len);
    }
    `,
    {
        LLVMFuzzerTestOneInput: LLVMFuzzerTestOneInput,
        __afl_fuzz_ptr: Afl.getAflFuzzPtr(),
        __afl_fuzz_len: Afl.getAflFuzzLen()
    });

Afl.setEntryPoint(cm.slow);
Afl.setPersistentAddress(cm.slow);
Afl.setInMemoryFuzzing();
Interceptor.replace(slow, cm.slow);
Afl.print("done");
Afl.done();
```

Here, we replace the function `slow` with our own code. This code is then
selected as the entry point as well as the persistent loop address.

### Replacing LLVMFuzzerTestOneInput

The function `LLVMFuzzerTestOneInput` can be replaced just like any other. Also,
any replaced function can also call itself. In the example below, we replace
`LLVMFuzzerTestOneInput` with `My_LLVMFuzzerTestOneInput` which ignores the
parameters `buf` and `len` and then calls the original `LLVMFuzzerTestOneInput`
with the parameters `__afl_fuzz_ptr` and `__afl_fuzz_len`. This allows us to
carry out in-memory fuzzing without the need for any hook function. It should be
noted that the replacement function and the original *CANNOT* share the same
name, since otherwise the `C` code in the `CModule` will not compile due to a
symbol name collision.

```js
const LLVMFuzzerTestOneInput = DebugSymbol.fromName('LLVMFuzzerTestOneInput').address;
Afl.print(`LLVMFuzzerTestOneInput: ${LLVMFuzzerTestOneInput}`);

const cm = new CModule(`

    extern unsigned char * __afl_fuzz_ptr;
    extern unsigned int * __afl_fuzz_len;
    extern void LLVMFuzzerTestOneInput(char *buf, int len);

    void My_LLVMFuzzerTestOneInput(char *buf, int len) {

      LLVMFuzzerTestOneInput(__afl_fuzz_ptr, *__afl_fuzz_len);

    }
    `,
    {
        LLVMFuzzerTestOneInput: LLVMFuzzerTestOneInput,
        __afl_fuzz_ptr: Afl.getAflFuzzPtr(),
        __afl_fuzz_len: Afl.getAflFuzzLen()
    });

Afl.setEntryPoint(cm.My_LLVMFuzzerTestOneInput);
Afl.setPersistentAddress(cm.My_LLVMFuzzerTestOneInput);
Afl.setInMemoryFuzzing();
Interceptor.replace(LLVMFuzzerTestOneInput, cm.My_LLVMFuzzerTestOneInput);
```

### Hooking `main`

Lastly, it should be noted that using FRIDA mode's scripting support to hook the
`main` function is a special case. This is because the `main` function is
already hooked by the FRIDA mode engine itself and hence the function `main` (or
at least the first basic block already been compiled by Stalker ready for
execution). Hence any attempt to use `Interceptor.replace` like in the example
above will not work. Instead the JS bindings provide a function `setJsMainHook`
for just this scenario as demonstrated in the example below.

```js
const main = DebugSymbol.fromName('main').address;
Afl.print(`main: ${main}`);

const LLVMFuzzerTestOneInput = DebugSymbol.fromName('LLVMFuzzerTestOneInput').address;
Afl.print(`LLVMFuzzerTestOneInput: ${LLVMFuzzerTestOneInput}`);

const cm = new CModule(`

    extern unsigned char * __afl_fuzz_ptr;
    extern unsigned int * __afl_fuzz_len;
    extern void LLVMFuzzerTestOneInput(char *buf, int len);

    int main(int argc, char **argv)  {

      LLVMFuzzerTestOneInput(__afl_fuzz_ptr, *__afl_fuzz_len);

    }
    `,
    {
        LLVMFuzzerTestOneInput: LLVMFuzzerTestOneInput,
        __afl_fuzz_ptr: Afl.getAflFuzzPtr(),
        __afl_fuzz_len: Afl.getAflFuzzLen()
    });

Afl.setEntryPoint(cm.main);
Afl.setPersistentAddress(cm.main);
Afl.setInMemoryFuzzing();
Afl.setJsMainHook(cm.main);
```

### Library Fuzzing

It doesn't take too much imagination to see that the above example can be
extended to use FRIDA's `Module.load` API so that the replaced `main` function
can then call an arbitrary function. In this way, if we have a library which we
wish to fuzz rather than an executable, then a surrogate executable can be used.

## Patching

Consider the [following](test/js/test2.c) test code...

```c
/*
   american fuzzy lop++ - a trivial program to test the build
   --------------------------------------------------------
   Originally written by Michal Zalewski
   Copyright 2014 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:
     https://www.apache.org/licenses/LICENSE-2.0
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

const uint32_t crc32_tab[] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,

  ...

    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

uint32_t
crc32(const void *buf, size_t size)
{
    const uint8_t *p = buf;
    uint32_t crc;
    crc = ~0U;
    while (size--)
        crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    return crc ^ ~0U;
}

/*
 * Don't you hate those contrived examples which CRC their data. We can use
 * FRIDA to patch this function out and always return success. Otherwise, we
 * could change it to actually correct the checksum.
 */
int crc32_check (char * buf, int len) {
  if (len < sizeof(uint32_t)) { return 0; }
  uint32_t expected = *(uint32_t *)&buf[len - sizeof(uint32_t)];
  uint32_t calculated = crc32(buf, len - sizeof(uint32_t));
  return expected == calculated;
}

/*
 * So you've found a really boring bug in an earlier campaign which results in
 * a NULL dereference or something like that. That bug can get in the way,
 * causing the persistent loop to exit whenever it is triggered, and can also
 * cloud your output unnecessarily. Again, we can use FRIDA to patch it out.
 */
void some_boring_bug(char c) {
  switch (c) {
    case 'A'...'Z':
    case 'a'...'z':
      __builtin_trap();
      break;
  }
}

void LLVMFuzzerTestOneInput(char *buf, int len) {

  if (!crc32_check(buf, len)) return;

  some_boring_bug(buf[0]);

  if (buf[0] == '0') {
    printf("Looks like a zero to me!\n");
  }
  else if (buf[0] == '1') {
    printf("Pretty sure that is a one!\n");
  }
  else if (buf[0] == '2') {
    if (buf[1] == '3') {
      if (buf[2] == '4') {
        printf("Oh we, weren't expecting that!");
        __builtin_trap();
      }
    }
  }
  else
    printf("Neither one or zero? How quaint!\n");

}

int main(int argc, char **argv) {

  int    fd = -1;
  off_t  len;
  char * buf = NULL;
  size_t n_read;
  int    result = -1;

  if (argc != 2) { return 1; }

  printf("Running: %s\n", argv[1]);

  fd = open(argv[1], O_RDONLY);
  if (fd < 0) { return 1; }

  len = lseek(fd, 0, SEEK_END);
  if (len < 0) { return 1; }

  if (lseek(fd, 0, SEEK_SET) != 0) { return 1; }

  buf = malloc(len);
  if (buf == NULL) { return 1; }

  n_read = read(fd, buf, len);
  if (n_read != len) { return 1; }

  printf("Running:    %s: (%zd bytes)\n", argv[1], n_read);

  LLVMFuzzerTestOneInput(buf, len);
  printf("Done:    %s: (%zd bytes)\n", argv[1], n_read);

  return 0;
}
```

There are a couple of obstacles with our target application. Unlike when fuzzing
source code, though, we can't just edit it and recompile it. The following
script shows how we can use the normal functionality of FRIDA to modify any
troublesome behavior.

```js
Afl.print('******************');
Afl.print('* AFL FRIDA MODE *');
Afl.print('******************');
Afl.print('');

const main = DebugSymbol.fromName('main').address;
Afl.print(`main: ${main}`);
Afl.setEntryPoint(main);
Afl.setPersistentAddress(main);
Afl.setPersistentCount(10000000);

const crc32_check = DebugSymbol.fromName('crc32_check').address;
const crc32_replacement = new NativeCallback(
    (buf, len) => {
        Afl.print(`len: ${len}`);
        if (len < 4) {
            return 0;
        }

        return 1;
    },
    'int',
    ['pointer', 'int']);
Interceptor.replace(crc32_check, crc32_replacement);

const some_boring_bug = DebugSymbol.fromName('some_boring_bug').address
const boring_replacement = new NativeCallback(
    (c) => { },
    'void',
    ['char']);
Interceptor.replace(some_boring_bug, boring_replacement);

Afl.done();
Afl.print("done");
```

## Advanced patching

Consider the following code fragment...

```c
extern void some_boring_bug2(char c);

__asm__ (
      ".text                                 \n"
      "some_boring_bug2:                     \n"
      ".global some_boring_bug2              \n"
      ".type some_boring_bug2, @function     \n"
      "mov %edi, %eax                        \n"
      "cmp $0xb4, %al                        \n"
      "jne ok                                \n"
      "ud2                                   \n"
      "ok:                                   \n"
      "ret                                   \n");

void LLVMFuzzerTestOneInput(char *buf, int len) {

  ...

  some_boring_bug2(buf[0]);

  ...

}
```

Rather than using FRIDA's `Interceptor.replace` or `Interceptor.attach` APIs, it
is possible to apply much more fine grained modification to the target
application by means of using the Stalker APIs.

The following code locates the function of interest and patches out the UD2
instruction signifying a crash.

```js
/* Modify the instructions */
const some_boring_bug2 = DebugSymbol.fromName('some_boring_bug2').address
const pid = Memory.alloc(4);
pid.writeInt(Process.id);

const cm = new CModule(`
    #include <stdio.h>
    #include <gum/gumstalker.h>

    typedef int pid_t;

    #define STDERR_FILENO 2
    #define BORING2_LEN 10

    extern int dprintf(int fd, const char *format, ...);
    extern void some_boring_bug2(char c);
    extern pid_t getpid(void);
    extern pid_t pid;

    gboolean js_stalker_callback(const cs_insn *insn, gboolean begin,
        gboolean excluded, GumStalkerOutput *output)
    {
        pid_t my_pid = getpid();
        GumX86Writer *cw = output->writer.x86;

        if (GUM_ADDRESS(insn->address) < GUM_ADDRESS(some_boring_bug2)) {

            return TRUE;

        }

        if (GUM_ADDRESS(insn->address) >=
            GUM_ADDRESS(some_boring_bug2) + BORING2_LEN) {

            return TRUE;

        }

        if (my_pid == pid) {

            if (begin) {

                dprintf(STDERR_FILENO, "\n> 0x%016lX: %s %s\n", insn->address,
                        insn->mnemonic, insn->op_str);

            } else {

                dprintf(STDERR_FILENO, "  0x%016lX: %s %s\n", insn->address,
                        insn->mnemonic, insn->op_str);

            }

        }

        if (insn->id == X86_INS_UD2) {

            gum_x86_writer_put_nop(cw);
            return FALSE;

        } else {

            return TRUE;

        }
    }
    `,
    {
        dprintf: Module.getExportByName(null, 'dprintf'),
        getpid: Module.getExportByName(null, 'getpid'),
        some_boring_bug2: some_boring_bug2,
        pid: pid
    });
Afl.setStalkerCallback(cm.js_stalker_callback)
Afl.setStdErr("/tmp/stderr.txt");
```

Note that you will more likely want to find the patch address by using:

```js
const module = Process.getModuleByName('target.exe');
/* Hardcoded offset within the target image */
const address = module.base.add(0xdeadface);
```

OR

```
const address = DebugSymbol.fromName("my_function").address.add(0xdeadface);
```

OR

```
const address = Module.getExportByName(null, "my_function").add(0xdeadface);
```

The function `js_stalker_callback` should return `TRUE` if the original
instruction should be emitted in the instrumented code or `FALSE` otherwise. In
the example above, we can see it is replaced with a `NOP`.

Lastly, note that the same callback will be called when compiling instrumented
code both in the child of the forkserver (as it is executed) and also in the
parent of the forkserver (when prefetching is enabled) so that it can be
inherited by the next forked child. It is **VERY** important that the same
instructions be generated in both the parent and the child or if prefetching is
disabled that the same instructions are generated every time the block is
compiled. Failure to do so will likely lead to bugs which are incredibly
difficult to diagnose. The code above only prints the instructions when running
in the parent process (the one provided by `Process.id` when the JS script is
executed).

## OSX

Note that the JavaScript debug symbol api for OSX makes use of the
`CoreSymbolication` APIs and as such the `CoreFoundation` module must be loaded
into the target to make use of it. This can be done by setting:

```
AFL_PRELOAD=/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
```

It should be noted that `CoreSymbolication` API may take a while to initialize
and build its caches. For this reason, it may be necessary to also increase the
value of the `-t` flag passed to `afl-fuzz`.

## API

```js
class Afl {
  /**
   * This is equivalent to setting a value in `AFL_FRIDA_EXCLUDE_RANGES`,
   * it takes as arguments a `NativePointer` and a `number`. It can be
   * called multiple times to exclude several ranges.
   */
  static addExcludedRange(addressess, size) {
      Afl.jsApiAddExcludeRange(addressess, size);
  }
  /**
   * This is equivalent to setting a value in `AFL_FRIDA_INST_RANGES`,
   * it takes as arguments a `NativePointer` and a `number`. It can be
   * called multiple times to include several ranges.
   */
  static addIncludedRange(addressess, size) {
      Afl.jsApiAddIncludeRange(addressess, size);
  }
  /**
   * This must always be called at the end of your script. This lets
   * FRIDA mode know that your configuration is finished and that
   * execution has reached the end of your script. Failure to call
   * this will result in a fatal error.
   */
  static done() {
      Afl.jsApiDone();
  }
  /**
   * This function can be called within your script to cause FRIDA
   * mode to trigger a fatal error. This is useful if for example you
   * discover a problem you weren't expecting and want everything to
   * stop. The user will need to enable `AFL_DEBUG_CHILD=1` to view
   * this error message.
   */
  static error(msg) {
      const buf = Memory.allocUtf8String(msg);
      Afl.jsApiError(buf);
  }
  /**
   * Function used to provide access to `__afl_fuzz_ptr`, which contains the length of
   * fuzzing data when using in-memory test case fuzzing.
   */
  static getAflFuzzLen() {
      return Afl.jsApiGetSymbol("__afl_fuzz_len");
  }
  /**
   * Function used to provide access to `__afl_fuzz_ptr`, which contains the fuzzing
   * data when using in-memory test case fuzzing.
   */
  static getAflFuzzPtr() {
      return Afl.jsApiGetSymbol("__afl_fuzz_ptr");
  }
  /**
   * Print a message to the STDOUT. This should be preferred to
   * FRIDA's `console.log` since FRIDA will queue it's log messages.
   * If `console.log` is used in a callback in particular, then there
   * may no longer be a thread running to service this queue.
   */
  static print(msg) {
      const STDOUT_FILENO = 2;
      const log = `${msg}\n`;
      const buf = Memory.allocUtf8String(log);
      Afl.jsApiWrite(STDOUT_FILENO, buf, log.length);
  }
  /**
   * See `AFL_FRIDA_STALKER_NO_BACKPATCH`.
   */
  static setBackpatchDisable() {
      Afl.jsApiSetBackpatchDisable();
  }
  /**
   * See `AFL_FRIDA_DEBUG_MAPS`.
   */
  static setDebugMaps() {
      Afl.jsApiSetDebugMaps();
  }
  /**
   * This has the same effect as setting `AFL_ENTRYPOINT`, but has the
   * convenience of allowing you to use FRIDAs APIs to determine the
   * address you would like to configure, rather than having to grep
   * the output of `readelf` or something similarly ugly. This
   * function should be called with a `NativePointer` as its
   * argument.
   */
  static setEntryPoint(address) {
      Afl.jsApiSetEntryPoint(address);
  }
  /**
   * Function used to enable in-memory test cases for fuzzing.
   */
  static setInMemoryFuzzing() {
      Afl.jsApiAflSharedMemFuzzing.writeInt(1);
  }
  /**
   * See `AFL_FRIDA_INST_COVERAGE_FILE`. This function takes a single `string`
   * as an argument.
   */
  static setInstrumentCoverageFile(file) {
      const buf = Memory.allocUtf8String(file);
      Afl.jsApiSetInstrumentCoverageFile(buf);
  }
  /**
   * See `AFL_FRIDA_INST_DEBUG_FILE`. This function takes a single `string` as
   * an argument.
   */
  static setInstrumentDebugFile(file) {
      const buf = Memory.allocUtf8String(file);
      Afl.jsApiSetInstrumentDebugFile(buf);
  }
  /**
   * See `AFL_FRIDA_INST_TRACE`.
   */
  static setInstrumentEnableTracing() {
      Afl.jsApiSetInstrumentTrace();
  }
  /**
   * See `AFL_FRIDA_INST_JIT`.
   */
  static setInstrumentJit() {
      Afl.jsApiSetInstrumentJit();
  }
  /**
   * See `AFL_INST_LIBS`.
   */
  static setInstrumentLibraries() {
      Afl.jsApiSetInstrumentLibraries();
  }
  /**
   * See `AFL_FRIDA_INST_NO_DYNAMIC_LOAD`
   */
  static setInstrumentNoDynamicLoad() {
    Afl.jsApiSetInstrumentNoDynamicLoad();
  }
  /**
   * See `AFL_FRIDA_INST_NO_OPTIMIZE`
   */
  static setInstrumentNoOptimize() {
      Afl.jsApiSetInstrumentNoOptimize();
  }
  /**
   * See `AFL_FRIDA_INST_REGS_FILE`. This function takes a single `string` as
   * an argument.
   */
  public static setInstrumentRegsFile(file: string): void {
    const buf = Memory.allocUtf8String(file);
    Afl.jsApiSetInstrumentRegsFile(buf);
  }
  /*
    * See `AFL_FRIDA_INST_SEED`
    */
  static setInstrumentSeed(seed) {
      Afl.jsApiSetInstrumentSeed(seed);
  }
  /**
   * See `AFL_FRIDA_INST_TRACE_UNIQUE`.
   */
  static setInstrumentTracingUnique() {
      Afl.jsApiSetInstrumentTraceUnique();
  }
  /**
   * See `AFL_FRIDA_INST_UNSTABLE_COVERAGE_FILE`. This function takes a single
   * `string` as an argument.
   */
  static setInstrumentUnstableCoverageFile(file) {
      const buf = Memory.allocUtf8String(file);
      Afl.jsApiSetInstrumentUnstableCoverageFile(buf);
  }
  /*
    * Set a callback to be called in place of the usual `main` function. This see
    * `Scripting.md` for details.
    */
  static setJsMainHook(address) {
      Afl.jsApiSetJsMainHook(address);
  }
  /**
   * This is equivalent to setting `AFL_FRIDA_PERSISTENT_ADDR`, again a
   * `NativePointer` should be provided as it's argument.
   */
  static setPersistentAddress(address) {
      Afl.jsApiSetPersistentAddress(address);
  }
  /**
   * This is equivalent to setting `AFL_FRIDA_PERSISTENT_CNT`, a
   * `number` should be provided as it's argument.
   */
  static setPersistentCount(count) {
      Afl.jsApiSetPersistentCount(count);
  }
  /**
   * See `AFL_FRIDA_PERSISTENT_DEBUG`.
   */
  static setPersistentDebug() {
      Afl.jsApiSetPersistentDebug();
  }
  /**
   * See `AFL_FRIDA_PERSISTENT_ADDR`. This function takes a NativePointer as an
   * argument. See above for examples of use.
   */
  static setPersistentHook(address) {
      Afl.jsApiSetPersistentHook(address);
  }
  /**
   * This is equivalent to setting `AFL_FRIDA_PERSISTENT_RET`, again a
   * `NativePointer` should be provided as it's argument.
   */
  static setPersistentReturn(address) {
      Afl.jsApiSetPersistentReturn(address);
  }
  /**
   * See `AFL_FRIDA_INST_NO_PREFETCH_BACKPATCH`.
   */
  static setPrefetchBackpatchDisable() {
      Afl.jsApiSetPrefetchBackpatchDisable();
  }
  /**
   * See `AFL_FRIDA_INST_NO_PREFETCH`.
   */
  static setPrefetchDisable() {
      Afl.jsApiSetPrefetchDisable();
  }
  /**
   * See `AFL_FRIDA_SECCOMP_FILE`. This function takes a single `string` as
   * an argument.
   */
  static setSeccompFile(file) {
      const buf = Memory.allocUtf8String(file);
      Afl.jsApiSetSeccompFile(buf);
  }
  /**
   * See `AFL_FRIDA_STALKER_ADJACENT_BLOCKS`.
   */
  static setStalkerAdjacentBlocks(val) {
      Afl.jsApiSetStalkerAdjacentBlocks(val);
  }
  /*
    * Set a function to be called for each instruction which is instrumented
    * by AFL FRIDA mode.
    */
  static setStalkerCallback(callback) {
      Afl.jsApiSetStalkerCallback(callback);
  }
  /**
   * See `AFL_FRIDA_STALKER_IC_ENTRIES`.
   */
  static setStalkerIcEntries(val) {
      Afl.jsApiSetStalkerIcEntries(val);
  }
  /**
   * See `AFL_FRIDA_STATS_FILE`. This function takes a single `string` as
   * an argument.
   */
  static setStatsFile(file) {
      const buf = Memory.allocUtf8String(file);
      Afl.jsApiSetStatsFile(buf);
  }
  /**
   * See `AFL_FRIDA_STATS_INTERVAL`. This function takes a `number` as an
   * argument
   */
  static setStatsInterval(interval) {
      Afl.jsApiSetStatsInterval(interval);
  }
  /**
   * See `AFL_FRIDA_OUTPUT_STDERR`. This function takes a single `string` as
   * an argument.
   */
  static setStdErr(file) {
      const buf = Memory.allocUtf8String(file);
      Afl.jsApiSetStdErr(buf);
  }
  /**
   * See `AFL_FRIDA_OUTPUT_STDOUT`. This function takes a single `string` as
   * an argument.
   */
  static setStdOut(file) {
      const buf = Memory.allocUtf8String(file);
      Afl.jsApiSetStdOut(buf);
  }
  /**
   * See `AFL_FRIDA_TRACEABLE`.
   */
  static setTraceable() {
      Afl.jsApiSetTraceable();
  }
  static jsApiGetFunction(name, retType, argTypes) {
      const addr = Afl.module.getExportByName(name);
      return new NativeFunction(addr, retType, argTypes);
  }
  static jsApiGetSymbol(name) {
      return Afl.module.getExportByName(name);
  }
}
```
