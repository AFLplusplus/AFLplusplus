# Custom Mutators in AFL++

This file describes how you can implement custom mutations to be used in AFL.
For now, we support C/C++ library and Python module, collectivelly named as the
custom mutator.

Implemented by
- C/C++ library (`*.so`): Khaled Yakdan from Code Intelligence (<yakdan@code-intelligence.de>)
- Python module: Christian Holler from Mozilla (<choller@mozilla.com>)

## 1) Introduction

Custom mutators can be passed to `afl-fuzz` to perform custom mutations on test
cases beyond those available in AFL. For example, to enable structure-aware
fuzzing by using libraries that perform mutations according to a given grammar.

The custom mutator is passed to `afl-fuzz` via the `AFL_CUSTOM_MUTATOR_LIBRARY`
or `AFL_PYTHON_MODULE` environment variable, and must export a fuzz function.
Please see [APIs](#2-apis) and [Usage](#3-usage) for detail.

The custom mutation stage is set to be the first non-deterministic stage (right before the havoc stage).

Note: If `AFL_CUSTOM_MUTATOR_ONLY` is set, all mutations will solely be
performed with the custom mutator.

## 2) APIs

C/C++:
```c
void *afl_custom_init(afl_t *afl, unsigned int seed);
size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size, u8 **out_buf, uint8_t *add_buf, size_t add_buf_size, size_t max_size);
size_t afl_custom_pre_save(void *data, uint8_t *buf, size_t buf_size, uint8_t **out_buf);
int32_t afl_custom_init_trim(void *data, uint8_t *buf, size_t buf_size);
size_t afl_custom_trim(void *data, uint8_t **out_buf);
int32_t afl_custom_post_trim(void *data, int success) {
size_t afl_custom_havoc_mutation(void *data, u8 *buf, size_t buf_size, u8 **out_buf, size_t max_size);
uint8_t afl_custom_havoc_mutation_probability(void *data);
uint8_t afl_custom_queue_get(void *data, const uint8_t *filename); void afl_custom_queue_new_entry(void *data, const uint8_t *filename_new_queue, const uint8_t *filename_orig_queue);
void afl_custom_deinit(void *data);
```

Python:
```python
def init(seed):
    pass

def fuzz(buf, add_buf, max_size):
    return mutated_out

def pre_save(buf):
    return out_buf

def init_trim(buf):
    return cnt

def trim():
    return out_buf

def post_trim(success):
    return next_index

def havoc_mutation(buf, max_size):
    return mutated_out

def havoc_mutation_probability():
    return probability # int in [0, 100]

def queue_get(filename):
    return True

def queue_new_entry(filename_new_queue, filename_orig_queue):
    pass
```

### Custom Mutation

- `init`:

    This method is called when AFL++ starts up and is used to seed RNG and set up buffers and state.

- `queue_get` (optional):

    This method determines whether the fuzzer should fuzz the current queue
    entry or not

- `fuzz` (required):

    This method performs custom mutations on a given input. It also accepts an
    additional test case.

- `havoc_mutation` and `havoc_mutation_probability` (optional):

    `havoc_mutation` performs a single custom mutation on a given input. This
    mutation is stacked with the other mutations in havoc. The other method,
    `havoc_mutation_probability`, returns the probability that `havoc_mutation`
    is called in havoc. By default, it is 6%.

- `pre_save` (optional):

    For some cases, the format of the mutated data returned from the custom
    mutator is not suitable to directly execute the target with this input.
    For example, when using libprotobuf-mutator, the data returned is in a
    protobuf format which corresponds to a given grammar. In order to execute
    the target, the protobuf data must be converted to the plain-text format
    expected by the target. In such scenarios, the user can define the
    `pre_save` function. This function is then transforms the data into the
    format expected by the API before executing the target.

- `queue_new_entry` (optional):

    This methods is called after adding a new test case to the queue.

### Trimming Support

The generic trimming routines implemented in AFL++ can easily destroy the
structure of complex formats, possibly leading to a point where you have a lot
of test cases in the queue that your Python module cannot process anymore but
your target application still accepts. This is especially the case when your
target can process a part of the input (causing coverage) and then errors out
on the remaining input.

In such cases, it makes sense to implement a custom trimming routine. The API
consists of multiple methods because after each trimming step, we have to go
back into the C code to check if the coverage bitmap is still the same for the
trimmed input. Here's a quick API description:

- `init_trim` (optional):

    This method is called at the start of each trimming operation and receives
    the initial buffer. It should return the amount of iteration steps possible
    on this input (e.g. if your input has n elements and you want to remove them
    one by one, return n, if you do a binary search, return log(n), and so on).

    If your trimming algorithm doesn't allow you to determine the amount of
    (remaining) steps easily (esp. while running), then you can alternatively
    return 1 here and always return 0 in `post_trim` until you are finished and
    no steps remain. In that case, returning 1 in `post_trim` will end the
    trimming routine. The whole current index/max iterations stuff is only used
    to show progress.

- `trim` (optional)

    This method is called for each trimming operation. It doesn't have any
    arguments because we already have the initial buffer from `init_trim` and we
    can memorize the current state in the data variables. This can also save
    reparsing steps for each iteration. It should return the trimmed input
    buffer, where the returned data must not exceed the initial input data in
    length. Returning anything that is larger than the original data (passed to
    `init_trim`) will result in a fatal abort of AFL++.

- `post_trim` (optional)

    This method is called after each trim operation to inform you if your
    trimming step was successful or not (in terms of coverage). If you receive
    a failure here, you should reset your input to the last known good state.
    In any case, this method must return the next trim iteration index (from 0
    to the maximum amount of steps you returned in `init_trim`).

`deinit` the last method to be called, deinitializing the state.

Omitting any of three methods will cause the trimming to be disabled and trigger
a fallback to the builtin default trimming routine.

### Environment Variables

Optionally, the following environment variables are supported:

- `AFL_CUSTOM_MUTATOR_ONLY`

    Disable all other mutation stages. This can prevent broken testcases
    (those that your Python module can't work with anymore) to fill up your
    queue. Best combined with a custom trimming routine (see below) because
    trimming can cause the same test breakage like havoc and splice.


- `AFL_PYTHON_ONLY`

    Deprecated and removed, use `AFL_CUSTOM_MUTATOR_ONLY` instead
    trimming can cause the same test breakage like havoc and splice.

- `AFL_DEBUG`

    When combined with `AFL_NO_UI`, this causes the C trimming code to emit additional messages about the performance and actions of your custom trimmer. Use this to see if it works :)

## 3) Usage

### Prerequisite

For Python mutator, the python 3 or 2 development package is required. On
Debian/Ubuntu/Kali this can be done:

```bash
sudo apt install python3-dev
# or
sudo apt install python-dev
```

Then, AFL++ can be compiled with Python support. The AFL++ Makefile detects
Python 2 and 3 through `python-config` if it is in the PATH and compiles
`afl-fuzz` with the feature if available.

Note: for some distributions, you might also need the package `python[23]-apt`.
In case your setup is different, set the necessary variables like this:
`PYTHON_INCLUDE=/path/to/python/include LDFLAGS=-L/path/to/python/lib make`.

### Custom Mutator Preparation

For C/C++ mutator, the source code must be compiled as a shared object:
```bash
gcc -shared -Wall -O3 example.c -o example.so
```

### Run

C/C++
```bash
export AFL_CUSTOM_MUTATOR_LIBRARY=/full/path/to/example.so
afl-fuzz /path/to/program
```

Python
```bash
export PYTHONPATH=`dirname /full/path/to/example.py`
export AFL_PYTHON_MODULE=example
afl-fuzz /path/to/program
```

## 4) Example

Please see [example.c](../examples/custom_mutators/example.c) and
[example.py](../examples/custom_mutators/example.py)

## 5) Other Resources

- AFL libprotobuf mutator
    - [bruce30262/libprotobuf-mutator_fuzzing_learning](https://github.com/bruce30262/libprotobuf-mutator_fuzzing_learning/tree/master/4_libprotobuf_aflpp_custom_mutator)
    - [thebabush/afl-libprotobuf-mutator](https://github.com/thebabush/afl-libprotobuf-mutator)
- [XML Fuzzing@NullCon 2017](https://www.agarri.fr/docs/XML_Fuzzing-NullCon2017-PUBLIC.pdf)
    - [A bug detected by AFL + XML-aware mutators](https://bugs.chromium.org/p/chromium/issues/detail?id=930663)
