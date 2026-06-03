# Unstable Edge Symbolization

This utility helps identify and symbolize unstable edges discovered during fuzzing.

## Prerequisites

This utility requires AFL++ to be built with code coverage support enabled. Build AFL++ by invoking:

```
CODE_COVERAGE=1 make
```

This enables a buffer for tracking both edges to PC addresses as well as loaded modules and the edge ID ranges for each module.

## Running AFL++

- To capture unstable edge information, you must run `afl-fuzz` with `AFL_DEBUG=1`.
- To dump both the PC map and module map, you must run `afl-fuzz` with `AFL_DUMP_PC_MAP=1`.

```
AFL_DEBUG=1 AFL_DUMP_PC_MAP=1 afl-fuzz -i input -o output -- /path/to/target
```

## Using symbolize_unstable.py

Once you have completed a fuzzing run with the above configuration, the output directory will contain three files needed for symbolization:

- `fuzzer_stats` - Contains the list of unstable edge IDs in the `var_bytes` field
- `pcmap.dump` - Maps edge IDs to program counter addresses
- `modinfo.txt` - Maps edge ID ranges to binary modules

Run the symbolization script by providing the path to the AFL++ output directory:

```
python3 symbolize_unstable.py /path/to/output/default/
```

## Example Input Files

### fuzzer_stats (partial)
```
...
var_bytes         : 42 191 232
```

### pcmap.dump
```
42 0x1a3f20
191 0x3c5d00
232 0x6f89d0
```

### modinfo.txt
```
/usr/lib/a.so 5   100
/usr/lib/b.so 101 200
/usr/lib/c.so 201 300
```

## Example Output

```
42  0x1a3f20 /src/a/a.c:245
191 0x3c5d00 /src/b/b.c:67
232 0x6f89d0 /usr/c/c.c:412
```

Each line shows:
- Edge ID
- Program counter address (hex)
- Source location (file:line)
