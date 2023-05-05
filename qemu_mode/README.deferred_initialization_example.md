# Fuzz ARM32 Python Native Extensions in Binary-only Mode (LLVM fork-based)

This is an example on how to fuzz Python native extensions in LLVM mode with deferred initialization on ARM32.

We use Ubuntu x86_64 to run AFL++ and an Alpine ARMv7 Chroot to build the fuzzing target.

Check [Resources](#resources) for the code used in this example.

## Setup Alpine ARM Chroot on your x86_64 Linux Host

### Use systemd-nspawn

1. Install `qemu-user-binfmt`, `qemu-user-static` and `systemd-container` dependencies.
2. Restart the systemd-binfmt service: `systemctl restart systemd-binfmt.service`
3. Download an Alpine ARM RootFS from https://alpinelinux.org/downloads/
4. Create a new `alpine_sysroot` folder and extract: `tar xfz alpine-minirootfs-3.17.1-armv7.tar.gz -C alpine_sysroot/`
5. Copy `qemu-arm-static` to Alpine's RootFS: `cp $(which qemu-arm-static) ./alpine/usr/bin/`
6. Chroot into the container: `sudo systemd-nspawn -D alpine/ --bind-ro=/etc/resolv.conf`
7. Install dependencies: `apk update && apk add build-base musl-dev clang15 python3 python3-dev py3-pip`
8. Exit the container with `exit`

### Alternatively use Docker

1. Install `qemu-user-binfmt` and `qemu-user-static`
2. Run Qemu container: ```$ docker run --rm --privileged multiarch/qemu-user-static --reset -p yes```
3. Run Alpine container: ```$ docker run -it --rm arm32v7/alpine sh```

## Build AFL++ Qemu Mode with ARM Support

First, build AFL++ as described [here](https://github.com/AFLplusplus/AFLplusplus/blob/dev/docs/INSTALL.md). Then, run the Qemu build script:

```bash
cd qemu_mode && CPU_TARGET=arm ./build_qemu_support.sh
```

## Compile and Build the Fuzzing Project
Build the native extension and the fuzzing harness for ARM using the Alpine container (check [Resources](#resources) for the code):
```bash
ALPINE_ROOT=<your-alpine-sysroot-directory>
FUZZ=<your-path-to-the-code>
sudo systemd-nspawn -D $ALPINE_ROOT --bind=$FUZZ:/fuzz
CC=$(which clang) CFLAGS="-g" LDSHARED="clang -shared" python3 -m pip install /fuzz
clang $(python3-config --embed --cflags) $(python3-config --embed --ldflags) -o /fuzz/fuzz_harness /fuzz/fuzz_harness.c
exit
```

Manually trigger bug:
```bash
echo -n "FUZZ" | qemu-arm-static -L $ALPINE_ROOT $FUZZ/fuzz_harness
```

## Run AFL++
Make sure to start the forkserver *after* loading all the shared objects by setting the `AFL_ENTRYPOINT` environment variable (see [here](https://aflplus.plus/docs/env_variables/#5-settings-for-afl-qemu-trace) for details):

Choose an address just before the `while()` loop, for example:
```bash
qemu-arm-static -L $ALPINE_ROOT $ALPINE_ROOT/usr/bin/objdump -d $FUZZ/fuzz_harness | grep -A 1 "PyObject_GetAttrString"

00000584 <PyObject_GetAttrString@plt>:
 584:	e28fc600 	add	ip, pc, #0, 12
--
 7c8:	ebffff6d 	bl	584 <PyObject_GetAttrString@plt>
 7cc:	e58d0008 	str	r0, [sp, #8]
...
```

Check Qemu memory maps using the instructions from [here](https://aflplus.plus/docs/tutorials/libxml2_tutorial/):
>The binary is position independent and QEMU persistent needs the real addresses, not the offsets. Fortunately, QEMU loads PIE executables at a fixed address, 0x4000000000 for x86_64.
>
> We can check it using `AFL_QEMU_DEBUG_MAPS`. You don’t need this step if your binary is not PIE.

Setup Python environment variables and run `afl-qemu-trace`:
```bash
PYTHONPATH=$ALPINE_ROOT/usr/lib/python3.10/ PYTHONHOME=$ALPINE_ROOT/usr/bin/ QEMU_LD_PREFIX=$ALPINE_ROOT AFL_QEMU_DEBUG_MAPS=1 afl-qemu-trace $FUZZ/fuzz_harness

...
40000000-40001000 r-xp 00000000 103:03 8002276                           fuzz_harness
40001000-4001f000 ---p 00000000 00:00 0
4001f000-40020000 r--p 0000f000 103:03 8002276                           fuzz_harness
40020000-40021000 rw-p 00010000 103:03 8002276                           fuzz_harness
40021000-40022000 ---p 00000000 00:00 0
40022000-40023000 rw-p 00000000 00:00 0
```

Finally, setup Qemu environment variables...
```bash
export QEMU_SET_ENV=PYTHONPATH=$ALPINE_ROOT/usr/lib/python310.zip:$ALPINE_ROOT/usr/lib/python3.10:$ALPINE_ROOT/usr/lib/python3.10/lib-dynload:$ALPINE_ROOT/usr/lib/python3.10/site-packages,PYTHONHOME=$ALPINE_ROOT/usr/bin/
export QEMU_LD_PREFIX=$ALPINE_ROOT
```

... and run AFL++:
```bash
mkdir -p $FUZZ/in && echo -n "FU" > $FUZZ/in/seed
AFL_ENTRYPOINT=0x400007cc afl-fuzz -i $FUZZ/in -o $FUZZ/out -Q -- $FUZZ/fuzz_harness
```

## Resources

### setup.py

```python
from distutils.core import setup, Extension

module = Extension("memory", sources=["fuzz_target.c"])

setup(
    name="memory",
    version="1.0",
    description='A simple "BOOM!" extension',
    ext_modules=[module],
)
```

### fuzz_target.c

```c
#define PY_SSIZE_T_CLEAN
#include <Python.h>

#pragma clang optimize off

static PyObject *corruption(PyObject* self, PyObject* args) {
    char arr[3];
    Py_buffer name;

    if (!PyArg_ParseTuple(args, "y*", &name))
        return NULL;

    if (name.buf != NULL) {
        if (strcmp(name.buf, "FUZZ") == 0) {
            arr[0] = 'B';
            arr[1] = 'O';
            arr[2] = 'O';
            arr[3] = 'M';
        }
    }

    PyBuffer_Release(&name);
    Py_RETURN_NONE;
}

static PyMethodDef MemoryMethods[] = {
    {"corruption", corruption, METH_VARARGS, "BOOM!"},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef memory_module = {
    PyModuleDef_HEAD_INIT,
    "memory",
    "BOOM!",
    -1,
    MemoryMethods
};

PyMODINIT_FUNC PyInit_memory(void) {
    return PyModule_Create(&memory_module);
}
```

### fuzz_harness.c

```c
#include <Python.h>

#pragma clang optimize off

int main(int argc, char **argv) {
    unsigned char buf[1024000];
    ssize_t size;

    Py_Initialize();
    PyObject* name = PyUnicode_DecodeFSDefault("memory");
    PyObject* module = PyImport_Import(name);
    Py_DECREF(name);

    if (module != NULL) {
        PyObject* corruption_func = PyObject_GetAttrString(module, "corruption");

        while ((size = read(0, buf, sizeof(buf))) > 0 ? 1 : 0) {
            PyObject* arg = PyBytes_FromStringAndSize((char *)buf, size);

            if (arg != NULL) {
                PyObject* res = PyObject_CallFunctionObjArgs(corruption_func, arg, NULL);

                if (res != NULL) {
                    Py_XDECREF(res);
                }

                Py_DECREF(arg);
            }
        }

        Py_DECREF(corruption_func);
        Py_DECREF(module);
    }

    // Py_Finalize() leaks memory on certain Python versions (see https://bugs.python.org/issue1635741)
    // Py_Finalize();
    return 0;
}
```
