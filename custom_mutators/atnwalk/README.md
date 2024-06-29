# ATNwalk: Grammar-Based Fuzzing using Only Bit-Mutations

This is a custom mutator integration of ATNwalk that works by communicating via UNIX domain sockets.

Refer to [https://github.com/atnwalk/testbed](https://github.com/atnwalk/testbed) for detailed instructions on how to get ATNwalk running.

## Build

Just type `make` to build `atnwalk.so`.

## Run

**NOTE:** The commands below just demonstrate an example how running ATNwalk looks like and require a working [testbed](https://github.com/atnwalk/testbed)

```bash
# create the required random seed first
mkdir -p ~/campaign/example/seeds
cd ~/campaign/example/seeds
head -c1 /dev/urandom | ~/atnwalk/build/javascript/bin/decode -wb > seed.decoded 2> seed.encoded

# create the required atnwalk directory and copy the seed
cd ../
mkdir -p atnwalk/in
cp ./seeds/seed.encoded atnwalk/in/seed
cd atnwalk

# assign to a single core when benchmarking it, change the CPU number as required
CPU_ID=0

# start the ATNwalk server
nohup taskset -c ${CPU_ID} ${HOME}/atnwalk/build/javascript/bin/server 100 > server.log 2>&1 &

# start AFL++ with ATNwalk
AFL_SKIP_CPUFREQ=1 \
  AFL_DISABLE_TRIM=1 \
  AFL_CUSTOM_MUTATOR_ONLY=1 \
  AFL_CUSTOM_MUTATOR_LIBRARY=${HOME}/AFLplusplus/custom_mutators/atnwalk/atnwalk.so \
  AFL_POST_PROCESS_KEEP_ORIGINAL=1 \
  ~/AFLplusplus/afl-fuzz -t 100 -i in/ -o out -b ${CPU_ID} -- ~/jerryscript/build/bin/jerry

# make sure to kill the ATNwalk server process after you're done
kill "$(cat atnwalk.pid)"
```
