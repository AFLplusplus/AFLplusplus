# An AFL++ custom mutator using TritonDSE

## Installing the requirements

`pip3 install tritondse`

## How to run with an example

```
../../afl-cc -o ../../test-instr ../../test-instr.c
mkdir -p in
echo aaaa > in/in
TRITON_DSE_TARGET=../../test-instr AFL_CUSTOM_MUTATOR_ONLY=1 AFL_SYNC_TIME=1 AFL_PYTHON_MODULE=aflpp_tritondse PYTHONPATH=. ../../afl-fuzz -i in -o out -- ../../test-instr
```

Note that this custom mutator works differently, new finds are synced
after 10-60 seconds to the fuzzing instance.
