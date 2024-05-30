# An AFL++ custom mutator using TritonDSE

## Installing the requirements

`pip3 install tritondse`

## How to run with an example

```
../../afl-cc -o ../../test-instr ../../test-instr.c
mkdir -p in
echo aaaa > in/in
AFL_DISABLE_TRIM=1 AFL_CUSTOM_MUTATOR_ONLY=1 AFL_SYNC_TIME=1 AFL_PYTHON_MODULE=aflpp_tritondse PYTHONPATH=. ../../afl-fuzz -i in -o out -- ../../test-instr
```

Note that this custom mutator works differently, new finds are synced
after 10-60 seconds to the fuzzing instance. This is necessary because only
C/C++ custom mutators have access to the internal AFL++ state.

Note that you should run first with `AFL_DEBUG` for 5-10 minutes and see if
all important libraries and syscalls are hooked (look at `WARNING` and `CRITICAL`
output during the run, best use with `AFL_NO_UI=1`)
